"""Tests for tools/por_ecl.py (Pool of Radiance ECL decoder, decode only).

Fixture contract (synthetic; no retail data is needed for the default suite):
  * DAX container: 2-byte TOC size, 9-byte TOC entries, contiguous data chain
    closing exactly at EOF, signed-byte RLE blocks (GoldBox docs/dax-format.md
    sections 1-2). `make_dax` writes that layout.
  * ECL block: uint16 magic 0x1388, five 4-byte far pointers, then a body
    starting at byte 22. `ecl_block` writes that layout with synthetic operands.

These pin OUR decoder to the documented framing. They do not prove that a
retail PoR block decodes this way. The optional retail check at the end runs
only when OPENUA_POR_ECL_DAX names a local ECL2.DAX, and it is skipped
otherwise.
"""
import hashlib
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_ecl as pe  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---- synthetic writers (test-only) -----------------------------------------

def rle_encode(data: bytes) -> bytes:
    """Signed-byte RLE with the writer envelope from docs/dax-format.md 2a:
    literal runs capped at 126, repeat runs capped at 127."""
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
        # literal stretch: stop before a repeat run of 3+ or at 126 bytes
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


def opp1(word: int) -> bytes:
    """Code-1 operand: word = (val << 8) | high."""
    return bytes([0x01, word & 0xFF, (word >> 8) & 0xFF])


def strop(payload: bytes) -> bytes:
    """Inline string: code 0x80, high = packed byte count, then the bytes."""
    return bytes([0x80, len(payload)]) + payload


def ins(op: int, *operands: bytes) -> bytes:
    return bytes([op]) + b"".join(operands)


def ecl_block(body: bytes, vbase: int = 0x8000) -> bytes:
    """Magic + five far pointers (segment 0x0101) + body. Pointer vaddrs are
    placed on the body so the header is well formed."""
    head = bytearray(b"\x88\x13")
    for k in range(5):
        head += b"\x01\x01" + (vbase + 22 + k).to_bytes(2, "little")
    return bytes(head) + body


def write_dax_file(tmp_path: Path, blocks, name="ECL2.DAX") -> Path:
    p = tmp_path / "src" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(make_dax(blocks))
    return p


def decode(block_bytes: bytes, framing="conservative", vbase=None):
    """Run the block decode path on a raw ECL block (no DAX) for focused tests."""
    insts, edges, stop = pe.walk_block(block_bytes, framing)
    starts = {i.offset for i in insts}
    decoded_end = pe.ECL_HEADER_LEN + sum(i.length for i in insts)
    resolved = pe.resolve_edges(edges, vbase, len(block_bytes), starts, decoded_end)
    return insts, edges, stop, resolved, block_bytes[decoded_end:]


# ---- DAX container and RLE --------------------------------------------------

def test_rle_roundtrip_mixed_runs():
    raw = b"\x07" * 300 + bytes(range(200)) + b"\xaa" * 5 + b"Z"
    comp = rle_encode(raw)
    assert pe.rle_decode(comp, len(raw)) == raw


def test_rle_control_bytes_stay_in_writer_envelope():
    raw = bytes(range(256)) * 4
    comp = rle_encode(raw)
    i = 0
    while i < len(comp):
        c = comp[i]
        assert c not in (0x7E, 0x7F, 0x80), "writer must not emit 0x7E/0x7F/0x80"
        i += (c + 1 + 1) if c < 0x80 else 2


@pytest.mark.parametrize("comp,raw,msg", [
    (bytes([0x05, 1, 2]), 6, "overruns"),          # literal run needs 6 bytes, has 2
    (bytes([0x81]), 1, "no value byte"),            # repeat with no value byte
    (bytes([0x00, 0x41]), 2, "raw_size"),           # produces 1 byte, TOC says 2
    (bytes([0xFF, 0x41, 0xFF, 0x41]), 1, "exceeds"),  # overproduces
])
def test_rle_rejects_malformed(comp, raw, msg):
    with pytest.raises(pe.EclError, match=msg):
        pe.rle_decode(comp, raw)


def test_dax_toc_and_chain_parse():
    dax = make_dax([(9, b"abc" * 10), (20, b"\x00" * 40)])
    entries, base = pe.parse_dax(dax)
    assert base == 2 + 18
    assert [(e.block_id, e.raw_size) for e in entries] == [(9, 30), (20, 40)]
    assert entries[1].data_offset == entries[0].comp_size
    assert base + sum(e.comp_size for e in entries) == len(dax)


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: b"\x05\x00" + d[2:], "multiple of 9"),
    (lambda d: b"\x00\x00" + d[2:], "multiple of 9"),
    (lambda d: (1800).to_bytes(2, "little") + d[2:], "past end"),  # 200 entries; far past EOF
    (lambda d: d + b"\x00", "end exactly"),
    (lambda d: d[:-1], "past end"),
])
def test_dax_rejects_malformed_container(mutate, msg):
    dax = make_dax([(20, b"\x01" * 12)])
    with pytest.raises(pe.EclError, match=msg):
        pe.parse_dax(mutate(dax))


def test_dax_rejects_broken_chain():
    dax = bytearray(make_dax([(1, b"aa"), (2, b"bb")]))
    # second TOC entry's data_offset (bytes 2+9+1 .. +4) moved off the chain
    dax[2 + 9 + 1] ^= 0x01
    with pytest.raises(pe.EclError, match="contiguous"):
        pe.parse_dax(bytes(dax))


def test_select_block_rules():
    dax = make_dax([(20, b"x" * 5), (9, b"y" * 5), (20, b"z" * 5)])
    entries, _ = pe.parse_dax(dax)
    assert pe.select_entry(entries, 9, None).index == 1
    assert pe.select_entry(entries, None, 2).index == 2
    assert pe.select_entry(entries, 20, 2).index == 2
    with pytest.raises(pe.EclError, match="not requested id"):
        pe.select_entry(entries, 9, 2)
    with pytest.raises(pe.EclError, match="ambiguous"):
        pe.select_entry(entries, 20, None)
    with pytest.raises(pe.EclError, match="no TOC entry"):
        pe.select_entry(entries, 77, None)
    with pytest.raises(pe.EclError, match="out of range"):
        pe.select_entry(entries, None, 9)
    with pytest.raises(pe.EclError, match="--block ID or --index"):
        pe.select_entry(entries, None, None)


# ---- ECL header --------------------------------------------------------------

def test_header_parses_magic_and_pointers():
    blk = ecl_block(b"\x00", vbase=0x8000)
    h = pe.parse_header(blk)
    assert h["magic"] == 0x1388
    assert [p["vaddr"] for p in h["pointers"]] == [0x8016 + k for k in range(5)]
    assert h["segment_all_expected"] is True


def test_header_rejects_bad_magic_and_short_block():
    with pytest.raises(pe.EclError, match="magic"):
        pe.parse_header(b"\x89\x13" + b"\x00" * 30)
    with pytest.raises(pe.EclError, match="22"):
        pe.parse_header(b"\x88\x13" + b"\x00" * 10)


def test_header_flags_unexpected_segment():
    blk = bytearray(ecl_block(b"\x00"))
    blk[2] = 0x02  # first pointer segment is not 0x0101
    h = pe.parse_header(bytes(blk))
    assert h["segment_all_expected"] is False


# ---- instruction walk ---------------------------------------------------------

def test_walk_offsets_and_lengths_for_known_forms():
    s = ins(0x09, lit(5), opp1(0x7D10))           # SAVE: 1 opcode + 2 + 3 bytes = 6
    g = ins(0x01, opp1(0x8000 + 32))              # GOTO at 28 (4 bytes), target EXIT at 32
    x = ins(0x00)                                  # EXIT at 32
    blk = ecl_block(s + g + x)
    insts, edges, stop, _, tail = decode(blk)
    assert [(i.offset, i.mnemonic, i.length) for i in insts] == [
        (22, "SAVE", 6), (28, "GOTO", 4), (32, "EXIT", 1)]
    assert stop.kind == "end-of-block"
    assert tail == b""
    assert len(edges) == 1 and edges[0].target_vaddr == 0x8000 + 32


def test_string_operand_keeps_length_and_hash_not_text():
    payload = b"SECRETTEXT"
    blk = ecl_block(ins(0x11, strop(payload)) + ins(0x00))
    insts, _, stop, _, _ = decode(blk)
    op = insts[0].operands[0]
    assert op["string_len"] == len(payload)
    assert op["string_sha256"] == hashlib.sha256(payload).hexdigest()
    assert payload not in repr(insts[0].operands).encode()
    assert stop.kind == "end-of-block"


def test_on_goto_counts_entries_and_resolves_targets():
    # ON_GOTO: opcode + selector (3) + count literal 2 (2) + two code-1 entries (3 each) = 12 bytes.
    # The EXIT that both targets name therefore sits at offset 22 + 12 = 34.
    exit_off = 22 + 12
    body = ins(0x25, opp1(0x9800), lit(2), opp1(0x8000 + exit_off), opp1(0x8000 + exit_off)) + ins(0x00)
    blk = ecl_block(body)
    insts, edges, stop, resolved, _ = decode(blk, vbase=0x8000)
    assert insts[0].mnemonic == "ON_GOTO" and len(insts[0].count_operands) == 2
    assert insts[0].length == 12
    assert [e["kind"] for e in resolved] == ["on_goto", "on_goto"]
    assert all(e["resolution"] == "instruction-start" for e in resolved)
    assert all(e["target_offset"] == exit_off for e in resolved)
    assert stop.kind == "end-of-block"


def test_edge_resolution_states_are_distinct():
    body = ins(0x01, opp1(0x8000 + 23)) + ins(0x00)   # GOTO into the middle of GOTO
    blk = ecl_block(body)
    _, _, _, resolved, _ = decode(blk, vbase=0x8000)
    assert resolved[0]["resolution"] == "mid-instruction"
    _, _, _, unresolved, _ = decode(blk, vbase=None)
    assert unresolved[0]["resolution"] == "unresolved-no-base"
    far = ins(0x01, opp1(0x9000)) + ins(0x00)
    _, _, _, out_, _ = decode(ecl_block(far), vbase=0x8000)
    assert out_[0]["resolution"] in ("out-of-block", "beyond-decoded-region")
    indirect = ins(0x01, bytes([0x09, 0x01])) + ins(0x00)   # code 0x09 target is not a literal address
    _, edges_i, _, res_i, _ = decode(ecl_block(indirect), vbase=0x8000)
    assert edges_i[0].indirect is True and res_i[0]["resolution"] == "indirect-operand"


def test_unknown_opcode_stops_and_keeps_raw_tail():
    body = ins(0x00) + bytes([0x41, 0xDE, 0xAD, 0xBE, 0xEF])
    blk = ecl_block(body)
    insts, _, stop, _, tail = decode(blk)
    assert [i.mnemonic for i in insts] == ["EXIT"]
    assert stop.kind == "unknown-opcode" and stop.opcode == 0x41 and stop.offset == 23
    assert tail == bytes([0x41, 0xDE, 0xAD, 0xBE, 0xEF])


def test_menu_framing_conservative_stops_and_spec_decodes():
    menu = ins(0x2B, lit(0), lit(1), strop(b"ab"))   # spec: 2 fixed, count at operand 1 = 1
    body = ins(0x00) + menu + ins(0x00)
    blk = ecl_block(body)
    insts, _, stop, _, tail = decode(blk, framing="conservative")
    assert stop.kind == "ambiguous-framing" and stop.opcode == 0x2B
    assert [i.mnemonic for i in insts] == ["EXIT"] and tail[0] == 0x2B
    insts2, _, stop2, _, tail2 = decode(blk, framing="spec-menus")
    assert [i.mnemonic for i in insts2] == ["EXIT", "HORIZONTAL_MENU", "EXIT"]
    assert stop2.kind == "end-of-block" and tail2 == b""
    assert len(insts2[1].count_operands) == 1


def test_vertical_menu_spec_count_is_operand_two():
    menu = ins(0x15, lit(0), strop(b"p"), lit(2), strop(b"a"), strop(b"b"))
    insts, _, stop, _, _ = decode(ecl_block(menu + ins(0x00)), framing="spec-menus")
    assert insts[0].mnemonic == "VERTICAL_MENU"
    assert len(insts[0].count_operands) == 2
    assert stop.kind == "end-of-block"


def test_non_literal_count_is_ambiguous_not_guessed():
    body = ins(0x25, opp1(0x9800), opp1(0x9801), opp1(0x8000 + 40), opp1(0x8000 + 40)) + ins(0x00)
    insts, _, stop, _, tail = decode(ecl_block(body))
    assert stop.kind == "ambiguous-count" and insts == []
    assert tail[0] == 0x25


def test_truncated_operand_stops_and_keeps_tail():
    body = ins(0x00) + bytes([0x09, 0x00])        # SAVE needs two operands, only one present
    insts, _, stop, _, tail = decode(ecl_block(body))
    assert stop.kind == "truncated-operand" and stop.opcode == 0x09
    assert tail == bytes([0x09, 0x00])


def test_string_overrun_is_truncation_not_a_guess():
    body = bytes([0x11, 0x80, 0x0A, 0x01, 0x02])  # PRINT, string claims 10 bytes, 2 present
    insts, _, stop, _, tail = decode(ecl_block(body))
    assert stop.kind == "truncated-operand" and insts == []


def test_opcode_1f_framed_but_semantics_unknown():
    blk = ecl_block(ins(0x1F, lit(0), lit(0)) + ins(0x00))
    insts, _, stop, _, _ = decode(blk)
    assert insts[0].mnemonic == "UNKNOWN_1F" and insts[0].semantics_known is False
    assert stop.kind == "end-of-block"


# ---- end to end, outputs and refusals ----------------------------------------

def test_block_decode_end_to_end_and_determinism(tmp_path):
    body = ins(0x09, lit(5), opp1(0x7D10)) + ins(0x00)
    src = write_dax_file(tmp_path, [(18, ecl_block(body)), (20, ecl_block(body))])
    before = hashlib.sha256(src.read_bytes()).hexdigest()
    data = src.read_bytes()
    res = pe.decode_block(data, 20, None, "conservative", None)
    res_again = pe.decode_block(data, 20, None, "conservative", None)
    r1 = pe.build_result(src.name, hashlib.sha256(data).hexdigest(), res)
    r2 = pe.build_result(src.name, hashlib.sha256(data).hexdigest(), res_again)
    assert r1 == r2
    assert r1["status"] == "decode-only" and r1["playable"] is False
    assert r1["source"]["block_id"] == 20 and r1["source"]["toc_index"] == 1
    assert str(tmp_path) not in pe.render_report(r1)
    out = tmp_path / "out"
    pe.write_outputs(r1, pe.render_report(r1), out)
    text = (out / "por_ecl.json").read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert str(tmp_path.anchor) not in text
    assert hashlib.sha256(src.read_bytes()).hexdigest() == before


def test_output_dir_refusals(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(pe.EclError, match="inside the source"):
        pe.validate_output_dir(src, src / "out")
    repo_out = REPO_ROOT / "tests" / "por_ecl_refused_probe"
    with pytest.raises(pe.EclError, match="under data/"):
        pe.validate_output_dir(src, repo_out)
    ok = pe.validate_output_dir(src, REPO_ROOT / "data" / "work" / "por-ecl-test")
    assert ok.is_relative_to((REPO_ROOT / "data").resolve())


def test_resolve_source_forms(tmp_path):
    f = write_dax_file(tmp_path, [(1, b"x")], name="ECL5.DAX")
    assert pe.resolve_source(str(f), None, None) == f
    root = tmp_path / "install"
    (root / "POOLRAD").mkdir(parents=True)
    (root / "POOLRAD" / "ECL5.DAX").write_bytes(f.read_bytes())
    assert pe.resolve_source(None, str(root), 5).name == "ECL5.DAX"
    with pytest.raises(pe.EclError, match="not found"):
        pe.resolve_source(None, str(root), 6)
    with pytest.raises(pe.EclError, match="--dax PATH"):
        pe.resolve_source(None, None, None)


def test_cli_exit_codes(tmp_path, capsys):
    src = write_dax_file(tmp_path, [(20, ecl_block(ins(0x00)))])
    assert pe.main(["--dax", str(src), "--list"]) == 0
    assert "20" in capsys.readouterr().out
    assert pe.main(["--dax", str(src), "--block", "20", "-o", str(tmp_path / "cli-out")]) == 0
    assert (tmp_path / "cli-out" / "por_ecl.json").is_file()
    assert pe.main(["--dax", str(src), "--block", "99", "-o", str(tmp_path / "o")]) == 2
    assert pe.main(["--dax", str(src), "--block", "20"]) == 2
    assert pe.main(["--dax", str(src), "--block", "20", "--vbase", "zzz",
                    "-o", str(tmp_path / "o2")]) == 2


def test_vbase_parse_bounds():
    assert pe.parse_vbase("0x98FE") == 0x98FE
    assert pe.parse_vbase(None) is None
    with pytest.raises(pe.EclError):
        pe.parse_vbase("0x10000")


# ---- optional retail check ----------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_ECL_DAX")


@pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_ECL_DAX to a local ECL2.DAX to run")
def test_retail_ecl2_block20_anchors():
    data = Path(RETAIL).read_bytes()
    res = pe.decode_block(data, 20, None, "spec-menus", 0x98FE)
    starts = {i.offset: i for i in res["instructions"]}
    # COMBAT at vaddr 0xab90 and 0xabf7, as cited by GoldBox persistent-natural-routes.md.
    assert starts[0xab90 - 0x98FE].mnemonic == "COMBAT"
    assert starts[0xabf7 - 0x98FE].mnemonic == "COMBAT"
    assert res["coverage"]["fraction"] > 0.99
    assert res["stop"].kind == "truncated-operand"
