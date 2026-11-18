"""Tests for tools/por_ecl_strings.py (Pool of Radiance inline-string census, 0x80).

Fixture contract (synthetic; no retail data is needed for the default suite):
  * DAX container and signed-byte RLE: GoldBox docs/dax-format.md sections 1-2,
    written by the test-only helpers below (same envelope as test_por_ecl.py).
  * ECL block: uint16 magic 0x1388, five 4-byte far pointers, then a body from
    byte 22. Inline string operand: code 0x80, high = payload byte count, then
    the payload (the decoder's byte-count reading).

These pin OUR census to the documented framing and to the existing decoder. They
do not prove that a retail string means anything. The optional retail anchor at
the end runs only when OPENUA_POR_ECL_STRINGS_INSTALL names a local PoR install
folder, and it is skipped otherwise.
"""
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_ecl as pe  # noqa: E402
import por_ecl_strings as ps  # noqa: E402
from por_convert import PorSourceError  # noqa: E402
from por_map import PorMapError  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RETAIL = os.environ.get("OPENUA_POR_ECL_STRINGS_INSTALL")


# ---- synthetic writers (test-only) -----------------------------------------

def rle_encode(data: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        run = 1
        while i + run < n and data[i + run] == data[i] and run < 127:
            run += 1
        if run >= 3:
            out += bytes([256 - run, data[i]])
            i += run
            continue
        j = i
        while j < n and (j - i) < 126:
            if j + 2 < n and data[j] == data[j + 1] == data[j + 2]:
                break
            j += 1
        if j == i:
            j = i + 1
        out += bytes([j - i - 1]) + data[i:j]
        i = j
    return bytes(out)


def make_dax(blocks) -> bytes:
    """blocks: list of (block_id, raw_bytes). Returns a valid DAX container."""
    toc = bytearray()
    data = bytearray()
    for bid, raw in blocks:
        comp = rle_encode(raw)
        toc += bytes([bid]) + len(data).to_bytes(4, "little") \
            + len(raw).to_bytes(2, "little") + len(comp).to_bytes(2, "little")
        data += comp
    return len(toc).to_bytes(2, "little") + bytes(toc) + bytes(data)


def lit(v: int) -> bytes:
    return bytes([0x00, v & 0xFF])


def var(code: int, high: int, val: int = 0) -> bytes:
    """A non-literal 3-byte operand (codes 0x01, 0x02, 0x03, 0x81 carry val)."""
    return bytes([code, high & 0xFF, val & 0xFF])


def strop(payload: bytes) -> bytes:
    """Inline string: code 0x80, high = packed byte count, then the bytes."""
    return bytes([0x80, len(payload)]) + payload


def bad_strop(declared: int, available: bytes) -> bytes:
    """A string whose declared length runs past the block end."""
    return bytes([0x80, declared]) + available


def ins(op: int, *operands: bytes) -> bytes:
    return bytes([op]) + b"".join(operands)


EXIT = bytes([0x00])


def ecl_block(body: bytes, vbase: int = 0x8000) -> bytes:
    head = bytearray(b"\x88\x13")
    for k in range(5):
        head += b"\x01\x01" + (vbase + 22 + k).to_bytes(2, "little")
    return bytes(head) + body


def full_archives(block: bytes, block_id: int = 18) -> dict:
    """All eight archive names, each a valid one-block DAX."""
    return {"ECL%d.DAX" % n: make_dax([(block_id, block)]) for n in range(1, 9)}


def write_install(root: Path, archives: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in archives.items():
        (root / name).write_bytes(data)
    return root


def run_census(install: Path, out: Path):
    return ps.census(install, out)


def frames_for(result: dict, archive: str, toc: int, framing: str) -> list:
    return [f for f in result["string_frames"]
            if f["archive"] == archive and f["toc_index"] == toc and f["framing"] == framing]


def skipped_for(result: dict, archive: str, toc: int, framing: str) -> list:
    return [s for s in result["skipped_frames"]
            if s["archive"] == archive and s["toc_index"] == toc and s["framing"] == framing]


def _block_result(tmp_path: Path, block: bytes, name="ECL1.DAX", block_id=18):
    """Census a single-archive install (others absent) and return the result."""
    install = write_install(tmp_path / "install", {name: make_dax([(block_id, block)])})
    result, _code = run_census(install, tmp_path / "out")
    return result


# ---- extraction: keep the raw payload, exactly ------------------------------


def test_print_string_keeps_exact_payload_offsets_and_hashes(tmp_path):
    payload = bytes([0x01, 0x02, 0xFF])
    block = ecl_block(ins(0x11, strop(payload)) + EXIT)
    result = _block_result(tmp_path, block)
    frs = frames_for(result, "ECL1.DAX", 0, "conservative")
    assert len(frs) == 1
    f = frs[0]
    assert f["opcode"] == "0x11" and f["mnemonic"] == "PRINT"
    assert f["instruction_offset"] == 22 and f["instruction_complete"] is True
    assert f["operand_offset"] == 23 and f["operand_slot"] == 0
    assert f["declared_length"] == 3 and f["payload_length"] == 3
    assert f["operand_total_length"] == 5
    assert f["payload_offset"] == 25
    assert f["payload_hex"] == "0102ff"
    assert base64.b64decode(f["payload_base64"]) == payload
    assert f["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert f["framing_status"] == ps.FS_BEFORE_MENU
    assert f["zero_length"] is False


def test_source_hash_and_toc_provenance_are_recorded(tmp_path):
    block = ecl_block(ins(0x11, strop(b"\x41")) + EXIT)
    dax = make_dax([(18, block)])
    install = write_install(tmp_path / "install", {"ECL1.DAX": dax})
    result, _ = run_census(install, tmp_path / "out")
    f = frames_for(result, "ECL1.DAX", 0, "conservative")[0]
    assert f["source_sha256"] == hashlib.sha256(dax).hexdigest()
    assert f["toc_index"] == 0 and f["block_id"] == 18
    assert f["raw_size"] == len(block)
    assert f["decoded_sha256"] == hashlib.sha256(block).hexdigest()
    assert f["frame_id"] == "ECL1.DAX/toc0/conservative/0x0017"


def test_count_driven_strings_are_extracted_as_count_operands(tmp_path):
    # ON_GOTO (0x25): two fixed operands, count literal at operand 1 (=2), then
    # two count-driven entries that are both inline strings (one empty).
    body = ins(0x25, lit(0), lit(2), strop(b"\x41"), strop(b"")) + EXIT
    result = _block_result(tmp_path, ecl_block(body))
    frs = frames_for(result, "ECL1.DAX", 0, "conservative")
    assert [(f["operand_kind"], f["operand_slot"]) for f in frs] == [("count", 0), ("count", 1)]
    assert frs[0]["payload_hex"] == "41"
    assert frs[1]["zero_length"] is True and frs[1]["payload_hex"] == ""
    assert result["summary"]["per_framing"]["conservative"]["zero_length_frames"] == 1


def test_census_frames_agree_with_por_ecl_walk(tmp_path):
    body = (ins(0x11, strop(b"abc")) + ins(0x0F, lit(1), strop(b"de"))
            + ins(0x03, lit(0), lit(1)) + EXIT)
    block = ecl_block(body)
    result = _block_result(tmp_path, block)
    insts, _edges, stop = pe.walk_block(block, "conservative")
    assert stop.kind == "end-of-block"
    expected = sum(1 for i in insts for od in i.operands + i.count_operands if od["code"] == 0x80)
    assert expected == len(frames_for(result, "ECL1.DAX", 0, "conservative")) == 2


# ---- duplicate ids ----------------------------------------------------------


def test_duplicate_block_ids_are_all_walked_and_never_merged(tmp_path):
    a = ecl_block(ins(0x11, strop(b"\x01")) + EXIT)
    b = ecl_block(ins(0x11, strop(b"\x02\x02")) + EXIT)
    install = write_install(tmp_path / "install", {"ECL1.DAX": make_dax([(18, a), (18, b)])})
    result, _ = run_census(install, tmp_path / "out")
    blocks = result["archives"][0]["blocks"]
    assert [bl["toc_index"] for bl in blocks] == [0, 1]
    assert all(bl["block_id_repeated"] for bl in blocks)
    assert all(bl["indices_with_block_id"] == [0, 1] for bl in blocks)
    assert frames_for(result, "ECL1.DAX", 0, "conservative")[0]["payload_hex"] == "01"
    assert frames_for(result, "ECL1.DAX", 1, "conservative")[0]["payload_hex"] == "0202"
    assert result["summary"]["blocks_with_repeated_id"] == 2


# ---- malformed and ambiguous frames are reported, never completed -----------


def test_string_overrunning_the_block_is_malformed_not_a_frame(tmp_path):
    block = ecl_block(ins(0x11, bad_strop(10, bytes([1, 2, 3]))))
    result = _block_result(tmp_path, block)
    assert frames_for(result, "ECL1.DAX", 0, "conservative") == []
    sk = skipped_for(result, "ECL1.DAX", 0, "conservative")
    assert len(sk) == 1
    s = sk[0]
    assert s["reason"] == "string-overrun" and s["malformed_string_frame"] is True
    assert s["walk_stop_kind"] == "truncated-operand"
    assert s["malformed"]["declared_length"] == 10
    assert s["malformed"]["available_bytes"] == 3
    assert s["malformed"]["partial_payload_hex"] == "010203"
    assert s["malformed"]["block_offset"] == 23
    assert result["summary"]["per_framing"]["conservative"]["malformed_string_frames"] == 1


def test_valid_string_before_a_failure_in_the_same_instruction_is_kept_as_incomplete(tmp_path):
    # INPUT_NUMBER (0x0F): two fixed operands. The first string is valid; the second overruns.
    block = ecl_block(ins(0x0F, strop(b"ok"), bad_strop(9, bytes([0xEE]))))
    result = _block_result(tmp_path, block)
    frs = frames_for(result, "ECL1.DAX", 0, "conservative")
    assert len(frs) == 1
    assert frs[0]["payload_hex"] == "6f6b"
    assert frs[0]["instruction_complete"] is False
    assert frs[0]["operand_slot"] == 0
    s = skipped_for(result, "ECL1.DAX", 0, "conservative")[0]
    assert s["string_frames_before_failure"] == 1
    assert s["malformed"]["slot"] == 1


def test_ambiguous_count_is_reported_and_no_count_entries_are_guessed(tmp_path):
    # ON_GOTO with a variable count operand (code 0x01): the count is not literal.
    block = ecl_block(ins(0x25, lit(0), var(0x01, 0x02, 0x00), strop(b"\x41")) + EXIT)
    result = _block_result(tmp_path, block)
    assert frames_for(result, "ECL1.DAX", 0, "conservative") == []
    s = skipped_for(result, "ECL1.DAX", 0, "conservative")[0]
    assert s["reason"] == "ambiguous-count"
    assert s["ambiguous_count"]["count_operand_code"] == "0x01"


def test_conservative_menu_stop_is_ambiguous_and_spec_reads_menu_strings(tmp_path):
    # VERTICAL_MENU (0x15): spec framing = three fixed operands, count at operand 2.
    menu = ins(0x15, lit(0), lit(0), lit(1), strop(b"xy"))
    block = ecl_block(menu + EXIT)
    result = _block_result(tmp_path, block)
    cons = skipped_for(result, "ECL1.DAX", 0, "conservative")[0]
    assert cons["reason"] == "ambiguous-framing"
    assert frames_for(result, "ECL1.DAX", 0, "conservative") == []
    spec = frames_for(result, "ECL1.DAX", 0, "spec-menus")
    assert len(spec) == 1
    assert spec[0]["operand_kind"] == "count" and spec[0]["payload_hex"] == "7879"
    assert spec[0]["framing_status"] == ps.FS_SPEC_MENU


def test_strings_after_a_spec_menu_are_flagged_as_framing_dependent(tmp_path):
    block = ecl_block(ins(0x15, lit(0), lit(0), lit(0)) + ins(0x11, strop(b"q")) + EXIT)
    result = _block_result(tmp_path, block)
    after = frames_for(result, "ECL1.DAX", 0, "spec-menus")
    assert len(after) == 1 and after[0]["framing_status"] == ps.FS_AFTER_SPEC_MENU
    assert result["summary"]["per_framing"]["spec-menus"]["frames_after_spec_menu"] == 1


def test_unknown_opcode_stops_and_tail_bytes_are_never_counted_as_strings(tmp_path):
    # After the unknown 0xFF, the bytes 80 02 AA BB look like a string frame. They
    # are raw tail bytes and must not be extracted.
    block = ecl_block(ins(0x11, strop(b"\x05")) + bytes([0xFF]) + bytes([0x80, 0x02, 0xAA, 0xBB]))
    result = _block_result(tmp_path, block)
    frs = frames_for(result, "ECL1.DAX", 0, "conservative")
    assert len(frs) == 1 and frs[0]["payload_hex"] == "05"
    s = skipped_for(result, "ECL1.DAX", 0, "conservative")[0]
    assert s["reason"] == "unknown-opcode"
    # The tail starts at the unknown opcode byte itself: 0xFF + 80 02 AA BB = 5 bytes.
    assert s["tail"]["length"] == 5
    assert s["tail"]["offset"] == s["block_offset"]
    assert "payload_hex" not in s["tail"]


def test_complete_walk_has_no_skipped_frames(tmp_path):
    result = _block_result(tmp_path, ecl_block(ins(0x11, strop(b"a")) + EXIT))
    assert result["skipped_frames"] == []
    assert result["summary"]["per_framing"]["conservative"]["incomplete_walks"] == 0


# ---- determinism, path hygiene, refusals, immutability ----------------------


def _full_install(tmp_path: Path, block=None) -> Path:
    if block is None:
        block = ecl_block(ins(0x11, strop(b"\x01\x02")) + ins(0x0F, lit(0), strop(b"zz")) + EXIT)
    return write_install(tmp_path / "install", full_archives(block))


def test_outputs_are_deterministic_and_path_free(tmp_path):
    install = _full_install(tmp_path)
    out1, out2 = tmp_path / "out1", tmp_path / "out2"
    assert ps.main(["--install", str(install), "-o", str(out1)]) == 0
    assert ps.main(["--install", str(install), "-o", str(out2)]) == 0
    for name in ("por_ecl_strings.json", "por_ecl_strings_report.md"):
        assert (out1 / name).read_bytes() == (out2 / name).read_bytes()
    text = (out1 / "por_ecl_strings.json").read_text(encoding="utf-8")
    assert str(tmp_path) not in text and tmp_path.as_posix() not in text
    assert "timestamp" not in text.lower()
    doc = json.loads(text)
    assert doc["playable"] is False and doc["status"] == "census-only"


def test_source_archives_are_not_written(tmp_path):
    install = _full_install(tmp_path)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_size)
              for p in sorted(install.iterdir())}
    run_census(install, tmp_path / "out")
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_size)
             for p in sorted(install.iterdir())}
    assert before == after


def test_complete_install_is_exit_0_and_partial_install_is_exit_1(tmp_path):
    install = _full_install(tmp_path)
    assert ps.main(["--install", str(install), "-o", str(tmp_path / "ok")]) == 0
    partial = write_install(tmp_path / "partial", {"ECL1.DAX": make_dax([(18, ecl_block(EXIT))])})
    rc = ps.main(["--install", str(partial), "-o", str(tmp_path / "partial-out")])
    assert rc == 1
    doc = json.loads((tmp_path / "partial-out" / "por_ecl_strings.json").read_text(encoding="utf-8"))
    codes = {d["code"] for d in doc["diagnostics"]}
    assert "archive-absent" in codes
    assert doc["summary"]["archives_present"] == 1


def test_container_error_is_a_diagnostic_not_a_crash(tmp_path):
    install = write_install(tmp_path / "install", {"ECL1.DAX": b"\x07\x00garbage"})
    rc = ps.main(["--install", str(install), "-o", str(tmp_path / "out")])
    assert rc == 1
    doc = json.loads((tmp_path / "out" / "por_ecl_strings.json").read_text(encoding="utf-8"))
    assert any(d["code"] == "container-error" for d in doc["diagnostics"])


def test_refusals_exit_2_and_write_nothing(tmp_path):
    install = _full_install(tmp_path)
    # install folder missing
    assert ps.main(["--install", str(tmp_path / "nope"), "-o", str(tmp_path / "o1")]) == 2
    assert not (tmp_path / "o1").exists()
    # output inside the source install
    assert ps.main(["--install", str(install), "-o", str(install / "out")]) == 2
    assert not (install / "out").exists()
    # output inside the repository but not under data/
    inside_repo = REPO_ROOT / "tests" / "_por_ecl_strings_should_not_exist"
    assert ps.main(["--install", str(install), "-o", str(inside_repo)]) == 2
    assert not inside_repo.exists()


def test_ambiguous_archive_is_refused(tmp_path):
    install = _full_install(tmp_path)
    pool = install / "POOLRAD"
    pool.mkdir()
    (pool / "ECL1.DAX").write_bytes(make_dax([(18, ecl_block(EXIT))]))
    with pytest.raises(PorMapError):
        run_census(install, tmp_path / "out")
    assert ps.main(["--install", str(install), "-o", str(tmp_path / "out2")]) == 2


def test_output_inside_source_and_repo_guards_raise(tmp_path):
    install = _full_install(tmp_path)
    with pytest.raises(PorSourceError):
        run_census(install, install / "sub")


def test_archive_lookup_is_case_insensitive_and_reads_poolrad(tmp_path):
    install = tmp_path / "install"
    pool = install / "POOLRAD"
    pool.mkdir(parents=True)
    dax = make_dax([(18, ecl_block(ins(0x11, strop(b"\x09")) + EXIT))])
    for n in range(1, 9):
        name = "ecl%d.dax" % n
        (pool / name).write_bytes(dax)
    result, code = run_census(install, tmp_path / "out")
    assert code == 0
    assert [a["archive"] for a in result["archives"]] == ["ECL%d.DAX" % n for n in range(1, 9)]


# ---- retail anchor (opt-in) -------------------------------------------------


@pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_ECL_STRINGS_INSTALL to a PoR install folder")
def test_retail_census_anchor(tmp_path):
    install = Path(RETAIL)
    data = (install / "ECL2.DAX") if (install / "ECL2.DAX").is_file() else (
        install / "POOLRAD" / "ECL2.DAX")
    assert hashlib.sha256(data.read_bytes()).hexdigest() == (
        "6ad6dc5aa53da82f4dba62dbc47d5a02a3f14c14071bec44e81a692615f08a3d")
    result, code = run_census(install, tmp_path / "retail")
    assert code == 0
    blk = [b for b in result["archives"][1]["blocks"] if b["toc_index"] == 2][0]
    assert blk["decoded_sha256"] == (
        "a1e1dd7a7ffc07f6e3c3ce7fad25d373270c10edd06ec3fa1f1d0edc9a7297ec")
    # Walk-stop anchor from docs/por-ecl-decoder.md: spec framing stops in ECL2 #20.
    spec = blk["walks"]["spec-menus"]
    assert spec["stop"]["kind"] == "truncated-operand" and spec["stop"]["offset"] == 7674
    # Snapshot of the census at the time it was written (2026-11-17): a regression pin.
    per = result["summary"]["per_framing"]
    assert per["conservative"]["string_frames"] == 185
    assert per["spec-menus"]["string_frames"] == 1656
