"""Tests for tools/por_ecl_text_diagnostic.py (diagnostic 6-bit decode of the PoR census).

Synthetic tests always run: quartet boundaries, the 64-value char map, zero skipping
(interior zero followed by nonzero included), partial groups, a cross-check against
the pure reference in tools/por_ecl_codec_static.py, and the census refusals,
determinism, and schema checks. Retail tests run only when OPENUA_POR_INSTALL names
a PoR POOLRAD folder; they cross-check the decoder against the retail-executed
unpacker (GAME.OVR:0x8626) and, when the census is present, against every census
payload. Nothing is written under the install or the census; outputs go to tmp_path.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import random
import sys
from pathlib import Path

import pytest

TOOLS = str(Path(__file__).resolve().parents[1] / "tools")
sys.path.insert(0, TOOLS)
import por_ecl_codec_static as c  # noqa: E402
import por_ecl_text_diagnostic as t  # noqa: E402

INSTALL = os.environ.get("OPENUA_POR_INSTALL", "")
RETAIL = pytest.mark.skipif(not INSTALL, reason="set OPENUA_POR_INSTALL to the POOLRAD folder")
REPO = Path(__file__).resolve().parents[1]
CENSUS = REPO / "data" / "work" / "por-ecl-strings" / "retail" / "por_ecl_strings.json"


# --------------------------------------------------------------------------
# Helpers: synthetic census documents
# --------------------------------------------------------------------------

def make_frame(payload: bytes, *, framing: str = "spec-menus",
               status: str = "spec-menu-frame", toc: int = 0,
               archive: str = "ECL1.DAX", off: int = 0x100, frame_id: str = "") -> dict:
    return {
        "archive": archive,
        "block_id": 18,
        "declared_length": len(payload),
        "frame_id": frame_id or "%s/toc%d/%s/0x%04X" % (archive, toc, framing, off),
        "framing": framing,
        "framing_status": status,
        "instruction_offset": off - 2,
        "mnemonic": "VERTICAL_MENU",
        "opcode": "0x15",
        "operand_offset": off,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "toc_index": toc,
    }


def make_census(frames: list[dict]) -> dict:
    return {
        "schema": "openua.por-ecl-strings",
        "version": 1,
        "status": "census-only",
        "playable": False,
        "tool": "tools/por_ecl_strings.py",
        "string_frames": frames,
    }


def write_census(root: Path, doc: dict) -> Path:
    src = root / "census"
    src.mkdir(parents=True, exist_ok=True)
    path = src / "por_ecl_strings.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


SAMPLE = [
    make_frame(b"\x04\x00\x00", framing="conservative", status="before-first-menu", off=0x140),
    make_frame(b"\x00\x10\x02", framing="spec-menus", status="spec-menu-frame", off=0x200),
    make_frame(b"\x80\x40\x20", framing="spec-menus", status="after-spec-menu", off=0x300),
    make_frame(b"", framing="spec-menus", status="before-first-menu", off=0x400),
]


# --------------------------------------------------------------------------
# Synthetic: codec layout and char map
# --------------------------------------------------------------------------

def test_three_bytes_split_into_four_quartets_msb_first():
    d = t.decode_payload(b"\x04\x00\x00")          # 000001 000000 000000 000000
    assert d["values_total"] == 4
    assert d["values"] == [1]
    assert d["text"] == "A"
    assert d["dropped_tail_bits"] == 0


def test_quartet_boundary_spans_two_bytes():
    # 10000000 01000000 00100000 -> 100000 000100 000000 100000 = 32, 4, 0, 32
    d = t.decode_payload(b"\x80\x40\x20")
    assert d["values_total"] == 4
    assert d["values"] == [32, 4, 32]
    assert d["text"] == " D "
    assert d["zero_values_skipped"] == 1


def test_all_ones_gives_four_values_of_63():
    d = t.decode_payload(b"\xff\xff\xff")
    assert d["values"] == [63, 63, 63, 63]
    assert d["text"] == "????"


@pytest.mark.parametrize("v", range(64))
def test_every_six_bit_value_maps_as_retail(v):
    # v in the top six bits of the first byte, so it is the first 6-bit group.
    payload = bytes([(v << 2) & 0xFF, 0, 0])
    d = t.decode_payload(payload)
    assert d["values"][:1] == ([v] if v else [])
    if v == 0:
        assert d["char_codes"] == []
    elif v <= 0x1F:
        assert d["char_codes"][0] == v + 0x40          # 1..31 -> 0x41..0x5F
    else:
        assert d["char_codes"][0] == v                 # 32..63 -> 0x20..0x3F


def test_char_map_threshold_and_range():
    assert t.char_of(1) == 0x41
    assert t.char_of(31) == 0x5F
    assert t.char_of(32) == 0x20
    assert t.char_of(63) == 0x3F
    with pytest.raises(ValueError):
        t.char_of(0)
    with pytest.raises(ValueError):
        t.char_of(64)


# --------------------------------------------------------------------------
# Synthetic: zero handling (skip, never terminate)
# --------------------------------------------------------------------------

def test_all_zero_payload_emits_nothing():
    d = t.decode_payload(b"\x00\x00\x00")
    assert d["values_total"] == 4
    assert d["values"] == []
    assert d["text"] == ""
    assert d["zero_values_skipped"] == 4


def test_interior_zero_followed_by_nonzero_is_skipped_not_terminated():
    # 000000 000001 000000 000010 -> values 0, 1, 0, 2
    d = t.decode_payload(b"\x00\x10\x02")
    assert d["values"] == [1, 2]
    assert d["text"] == "AB"
    assert d["zero_values_skipped"] == 2
    assert d["zero_then_nonzero"] is True


def test_mid_stream_zero_repeated_block():
    d = t.decode_payload(b"\x04\x00\x00\x04\x00\x00")
    assert d["values"] == [1, 1]
    assert d["text"] == "AA"
    assert d["zero_then_nonzero"] is True


def test_trailing_zeros_are_not_a_flag():
    d = t.decode_payload(b"\x04\x00\x00")
    assert d["zero_then_nonzero"] is False


# --------------------------------------------------------------------------
# Synthetic: partial groups and truncation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n,values,dropped", [
    (0, 0, 0),
    (1, 1, 2),
    (2, 2, 4),
    (3, 4, 0),
    (4, 5, 2),
    (5, 6, 4),
    (6, 8, 0),
])
def test_partial_groups_drop_leftover_bits(n, values, dropped):
    d = t.decode_payload(b"\xff" * n)
    assert d["values_total"] == values
    assert d["dropped_tail_bits"] == dropped
    assert values == (8 * n) // 6


def test_one_byte_payload_is_one_character_and_no_more():
    d = t.decode_payload(b"\xff")
    assert d["text"] == "?"
    assert d["values_total"] == 1


def test_empty_payload_is_empty():
    d = t.decode_payload(b"")
    assert d["values_total"] == 0 and d["text"] == "" and d["dropped_tail_bits"] == 0


# --------------------------------------------------------------------------
# Synthetic: cross-check against the pure reference in por_ecl_codec_static
# --------------------------------------------------------------------------

def test_decoder_agrees_with_static_reference_on_seeded_vectors():
    rng = random.Random(7)
    checked = 0
    for _ in range(600):
        n = rng.randint(0, 16)
        payload = bytes(0 if rng.random() < 0.25 else rng.randrange(256) for _ in range(n))
        d = t.decode_payload(payload)
        ref_all = c.ref_values(payload)
        ref_vals, ref_chars = c.expected_skip_zero(payload)
        assert d["values_total"] == len(ref_all)
        assert d["values"] == ref_vals
        assert d["char_codes"] == ref_chars
        checked += 1
    assert checked == 600


def test_decoder_differs_from_terminator_reading_on_mid_zero():
    payload = b"\x04\x00\x00\x04\x00\x00"
    assert t.decode_payload(payload)["values"] == [1, 1]
    assert c.terminator_reading(payload) == [1]


# --------------------------------------------------------------------------
# Synthetic: census loading, refusals, determinism, schema
# --------------------------------------------------------------------------

def test_run_writes_schema_marked_unaccepted_output(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    out = tmp_path / "out"
    doc = t.run(src, out)
    on_disk = json.loads((out / t.OUT_JSON).read_text(encoding="utf-8"))
    assert on_disk == doc
    assert doc["schema"] == t.SCHEMA and doc["version"] == 1
    assert doc["status"] == "diagnostic-unaccepted"
    assert doc["playable"] is False
    assert doc["summary"]["frames_total"] == len(SAMPLE)
    for f in doc["frames"]:
        assert f["accepted"] is False and f["status"] == "diagnostic-unaccepted"
        assert "source-length-contract" not in f["unresolved"]
        assert "runtime-text-binding" in f["unresolved"]
    assert "source-length-contract" not in {u["code"] for u in doc["unresolved"]}


def test_speculative_reason_only_on_spec_menu_statuses(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    doc = t.diagnose(src)
    by_status = {}
    for f in doc["frames"]:
        by_status.setdefault(f["framing_status"], set()).update(f["unresolved"])
    assert "census-framing-speculative" in by_status["spec-menu-frame"]
    assert "census-framing-speculative" in by_status["after-spec-menu"]
    assert "census-framing-speculative" not in by_status["before-first-menu"]


def test_frames_are_stably_sorted_regardless_of_input_order(tmp_path):
    shuffled = list(SAMPLE)
    random.Random(3).shuffle(shuffled)
    a = t.diagnose(write_census(tmp_path / "a", make_census(SAMPLE)))
    b = t.diagnose(write_census(tmp_path / "b", make_census(shuffled)))
    assert a["frames"] == b["frames"]
    keys = [(f["framing"], f["archive"], f["toc_index"], f["operand_offset"]) for f in a["frames"]]
    assert keys == sorted(keys)


def test_repeated_runs_are_byte_identical(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    t.run(src, tmp_path / "one")
    t.run(src, tmp_path / "two")
    for name in (t.OUT_JSON, t.OUT_MD):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


def test_outputs_have_no_absolute_paths_or_timestamps(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    t.run(src, tmp_path / "out")
    text = (tmp_path / "out" / t.OUT_JSON).read_text(encoding="utf-8")
    text += (tmp_path / "out" / t.OUT_MD).read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert str(REPO) not in text
    assert "timestamp" not in text.lower()
    assert "Caldor" not in text


def test_source_census_is_not_altered(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    before = hashlib.sha256(src.read_bytes()).hexdigest()
    t.run(src, tmp_path / "out")
    assert hashlib.sha256(src.read_bytes()).hexdigest() == before


def test_report_is_marked_unaccepted_and_lists_unresolved(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    t.run(src, tmp_path / "out")
    md = (tmp_path / "out" / t.OUT_MD).read_text(encoding="utf-8")
    assert "diagnostic-unaccepted" in md
    assert "playable: false" in md
    assert "runtime-text-binding" in md
    assert "source-length-contract" not in md


def test_main_returns_zero_on_success(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    assert t.main(["--census", str(src), "-o", str(tmp_path / "out")]) == 0


def test_main_requires_explicit_census_and_out(tmp_path):
    with pytest.raises(SystemExit):
        t.main(["-o", str(tmp_path / "out")])
    with pytest.raises(SystemExit):
        t.main(["--census", str(tmp_path / "x.json")])


def test_refuses_missing_census(tmp_path, capsys):
    assert t.main(["--census", str(tmp_path / "nope.json"), "-o", str(tmp_path / "out")]) == 2
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_refuses_output_inside_census_folder(tmp_path, capsys):
    src = write_census(tmp_path, make_census(SAMPLE))
    assert t.main(["--census", str(src), "-o", str(src.parent / "sub")]) == 2
    assert not (src.parent / "sub").exists()
    assert t.main(["--census", str(src), "-o", str(src.parent)]) == 2


def test_refuses_output_inside_repo_outside_data(tmp_path):
    src = write_census(tmp_path, make_census(SAMPLE))
    target = REPO / "docs" / "should-not-be-written-by-ecl-text-diagnostic"
    assert t.main(["--census", str(src), "-o", str(target)]) == 2
    assert not target.exists()


def test_refuses_wrong_schema_and_status(tmp_path):
    for key, val in (("schema", "openua.other"), ("version", 2), ("status", "accepted"),
                     ("playable", True)):
        doc = make_census(SAMPLE)
        doc[key] = val
        src = write_census(tmp_path / key, doc)
        with pytest.raises(t.DiagnosticError):
            t.diagnose(src)


def test_refuses_non_json_census(tmp_path):
    src = tmp_path / "census" / "por_ecl_strings.json"
    src.parent.mkdir(parents=True)
    src.write_text("not json", encoding="utf-8")
    with pytest.raises(t.DiagnosticError):
        t.diagnose(src)


def _refused(tmp_path, mutate):
    frames = copy.deepcopy(SAMPLE)
    mutate(frames[0])
    src = write_census(tmp_path, make_census(frames))
    with pytest.raises(t.DiagnosticError):
        t.diagnose(src)


def test_refuses_payload_sha_mismatch(tmp_path):
    _refused(tmp_path, lambda f: f.update(payload_sha256="0" * 64))


def test_refuses_length_mismatch(tmp_path):
    _refused(tmp_path, lambda f: f.update(declared_length=5))


def test_refuses_base64_mismatch(tmp_path):
    _refused(tmp_path, lambda f: f.update(payload_base64=base64.b64encode(b"\x01").decode()))


def test_refuses_bad_hex(tmp_path):
    _refused(tmp_path, lambda f: f.update(payload_hex="zz"))


def test_refuses_missing_key(tmp_path):
    _refused(tmp_path, lambda f: f.pop("framing_status"))


def test_refuses_unknown_framing(tmp_path):
    _refused(tmp_path, lambda f: f.update(framing="guess"))


def test_refuses_unknown_framing_status(tmp_path):
    _refused(tmp_path, lambda f: f.update(framing_status="maybe"))


def test_refuses_duplicate_frame_id(tmp_path):
    frames = copy.deepcopy(SAMPLE)
    frames[1]["frame_id"] = frames[0]["frame_id"]
    src = write_census(tmp_path, make_census(frames))
    with pytest.raises(t.DiagnosticError):
        t.diagnose(src)


def test_empty_census_gives_empty_but_valid_output(tmp_path):
    src = write_census(tmp_path, make_census([]))
    doc = t.diagnose(src)
    assert doc["frames"] == [] and doc["summary"]["frames_total"] == 0


def test_codec_claim_states_skip_not_terminator():
    assert "never a terminator" in t.CODEC_CLAIM["zero_handling"]


# --------------------------------------------------------------------------
# Retail (gated): retail-executed unpacker versus this decoder
# --------------------------------------------------------------------------

@RETAIL
def test_retail_unpacker_agrees_with_decoder_on_edge_and_random_vectors():
    ovr = c.read_pinned(Path(INSTALL), c.OVR_NAME)
    vectors = list(c.EDGE_VECTORS) + c.make_vectors(60, 11)[len(c.EDGE_VECTORS):]
    for v in vectors:
        got = c.run_unpack(ovr, v)
        d = t.decode_payload(v)
        assert d["values"] == got["values"], v.hex()
        assert d["char_codes"] == got["chars"], v.hex()
        assert got["consumed"] == len(v)


@RETAIL
@pytest.mark.skipif(not CENSUS.is_file(), reason="census not present under data/")
def test_retail_unpacker_agrees_with_every_census_payload():
    ovr = c.read_pinned(Path(INSTALL), c.OVR_NAME)
    doc = json.loads(CENSUS.read_text(encoding="utf-8"))
    bad = 0
    for fr in doc["string_frames"]:
        payload = bytes.fromhex(fr["payload_hex"])
        got = c.run_unpack(ovr, payload)
        if t.decode_payload(payload)["char_codes"] != got["chars"] or got["consumed"] != len(payload):
            bad += 1
    assert bad == 0
