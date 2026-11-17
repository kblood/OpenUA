"""Tests for tools/por_ecl_native_stream_probe.py.

Synthetic tests run everywhere. They use a framing document in the same shape as the framing probe's
JSON (classes, dispatch cases, operand kinds), hand-built streams, and synthetic DAX/ECL blocks. Retail
tests are gated on OPENUA_POR_INSTALL (the pinned POOLRAD folder) and skip without it; they write only
under pytest's tmp_path.
"""

import json
import os
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl as ecl  # noqa: E402
import por_ecl_native_framing_probe as framing  # noqa: E402
import por_ecl_native_stream_probe as sp  # noqa: E402

# Operand kinds in the probe's JSON shape (tag_set/value_set as [lo, hi] ranges; value None = any).
REL = lambda *rels: [{"rel": r, "reg": 0} for r in rels]  # noqa: E731
KINDS = [
    {"tag_set": [[1, 3]], "value_set": None, "cursor_delta": 3, "reads": REL(1, 2, 3), "open": False},
    {"tag_set": [[128, 128]], "value_set": [[0, 0]], "cursor_delta": 2, "reads": REL(1, 2), "open": False},
    {"tag_set": [[128, 128]], "value_set": [[1, 255]], "cursor_delta": 2, "reads": REL(1, 2), "open": True},
    {"tag_set": [[129, 129]], "value_set": None, "cursor_delta": 3, "reads": REL(1, 2, 3), "open": True},
    {"tag_set": [[0, 0], [4, 127], [130, 255]], "value_set": None, "cursor_delta": 2, "reads": REL(1, 2),
     "open": False},
]


def synth_doc(classes: dict, dispatch: set, kinds: list = None, checks: dict = None) -> dict:
    per = {}
    for v in range(256):
        key = "0x%02X" % v
        if v in classes:
            per[key] = {"arm": "class", "operands_parser": classes[v]}
        else:
            per[key] = {"arm": "default", "operands_parser": 0}
    return {
        "schema": framing.SCHEMA,
        "checks": checks if checks is not None else {"a": True, "b": True},
        "pins": {"GAME.OVR": {"size": 1, "sha256": "x"}},
        "classifier": {"per_opcode": per,
                       "default_arm_with_dispatch_case": ["0x%02X" % v for v in sorted(dispatch)]},
        "parser": {"operand_kinds": KINDS if kinds is None else kinds,
                   "body": {"tiling_complete": True, "tiling_disjoint": True, "refused_paths": []}},
    }


# Opcode values used by the synthetic tests: class 1, 2, 3 and default (with and without a dispatch case).
CLASSES = {0x01: 1, 0x02: 2, 0x03: 3, 0x2D: 1}
DISPATCH = {0x16}
DOC = synth_doc(CLASSES, DISPATCH)
TABLE, KINDS_P = sp.framing_from_probe(DOC)


def walk(stream: bytes) -> dict:
    # Stream-relative offsets (origin 0) so the expectations read directly against the bytes.
    return sp.walk_stream(stream, TABLE, KINDS_P, origin=0)


def make_block(stream: bytes) -> bytes:
    header = b"\x88\x13" + b"".join(b"\x01\x01" + struct.pack("<H", 0x9900 + k) for k in range(5))
    assert len(header) == ecl.ECL_HEADER_LEN
    return header + stream


def rle_literal(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 128):
        chunk = data[i:i + 128]
        out.append(len(chunk) - 1)
        out += chunk
    return bytes(out)


def make_dax(block: bytes, block_id: int = 20, extra_id: int = None) -> bytes:
    comp = rle_literal(block)
    entries = [(block_id, block, comp)]
    if extra_id is not None:
        entries.append((extra_id, block, comp))
    toc = b""
    data = b""
    for bid, blk, c in entries:
        toc += bytes([bid]) + struct.pack("<I", len(data)) + struct.pack("<H", len(blk)) + struct.pack("<H", len(c))
        data += c
    return struct.pack("<H", 9 * len(entries)) + toc + data


# ---------------------------------------------------------------------------------------------
# Operand counts and advance
# ---------------------------------------------------------------------------------------------

def test_class_one_closed_two_byte_operand_advances_three():
    rec = walk(bytes([0x01, 0x00, 0x05]))["records"]
    assert len(rec) == 1 and rec[0]["class"] == 1 and rec[0]["advance"] == 3
    assert rec[0]["operands"][0]["bytes"] == 2 and rec[0]["operands"][0]["label"] == "closed-2-byte"


def test_advance_is_one_plus_sum_of_operand_deltas():
    # class 3: tags 1 (3 bytes), 0x00 (2 bytes), 0x04 (2 bytes) -> advance 1 + 3 + 2 + 2 = 8
    stream = bytes([0x03, 0x01, 0xAA, 0xBB, 0x00, 0x11, 0x04, 0x22, 0x99])
    res = walk(stream)
    assert res["status"] == sp.STATUS_END
    recs = res["records"]
    assert [r["advance"] for r in recs] == [8, 1]
    assert [o["bytes"] for o in recs[0]["operands"]] == [3, 2, 2]


def test_class_two_and_three_counts_match_classifier():
    res = walk(bytes([0x02, 0x00, 0x01, 0x00, 0x02]))
    assert len(res["records"][0]["operands"]) == 2
    res = walk(bytes([0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]))
    assert len(res["records"][0]["operands"]) == 3 and res["records"][0]["advance"] == 7


def test_raw_bytes_are_reported_and_extra_only_for_three_byte_kinds():
    res = walk(bytes([0x01, 0x02, 0x33, 0x44, 0x00, 0x55]))
    ops = res["records"][0]["operands"]
    assert ops[0]["tag"] == "0x02" and ops[0]["value"] == "0x33" and ops[0]["extra"] == "0x44"
    assert ops[0]["label"] == "closed-3-byte"


# ---------------------------------------------------------------------------------------------
# Tag cases
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("tag", [0x00, 0x04, 0x7F, 0x82, 0xFF])
def test_ordinary_tags_are_two_byte_closed(tag):
    res = walk(bytes([0x01, tag, 0x10]))
    assert res["status"] == sp.STATUS_END
    op = res["records"][0]["operands"][0]
    assert op["bytes"] == 2 and op["extra"] is None


@pytest.mark.parametrize("tag", [0x01, 0x02, 0x03])
def test_tags_one_to_three_are_three_byte_closed(tag):
    res = walk(bytes([0x01, tag, 0x10, 0x20]))
    op = res["records"][0]["operands"][0]
    assert op["bytes"] == 3 and op["extra"] == "0x20"


def test_tag_0x80_with_count_zero_is_closed_and_decoded():
    res = walk(bytes([0x01, 0x80, 0x00]))
    assert res["status"] == sp.STATUS_END
    op = res["records"][0]["operands"][0]
    assert op["label"] == "closed-0x80-count0-2-byte" and op["value"] == "0x00" and op["bytes"] == 2


# ---------------------------------------------------------------------------------------------
# Stop positions: open kinds and truncation
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("count", [0x01, 0x05, 0xFF])
def test_tag_0x80_with_nonzero_count_stops_before_operand(count):
    res = walk(bytes([0x01, 0x80, count]))
    assert res["status"] == "stopped-open-operand"
    assert res["records"] == []
    st = res["stop"]
    assert st["block_offset"] == 1 and st["opcode_block_offset"] == 0 and st["operand_index"] == 1
    assert st["label"] == "open-0x80-count-gt-0" and res["covered"] == 0


def test_tag_0x81_stops_before_operand_without_needing_value():
    res = walk(bytes([0x01, 0x81]))
    assert res["status"] == "stopped-open-operand"
    assert res["stop"]["label"] == "open-0x81-post-step" and res["stop"]["value"] is None


def test_stop_at_second_operand_keeps_first_operand_out_of_records():
    # class 2: operand 1 closed (0x00, 0x09); operand 2 is tag 0x81 -> stop at offset 3 (opcode at 1)
    stream = bytes([0x00, 0x02, 0x00, 0x09, 0x81, 0x01, 0x02])
    res = walk(stream)
    assert res["status"] == "stopped-open-operand"
    assert res["records"][0]["opcode"] == "0x00" and res["records"][0]["advance"] == 1
    assert res["stop"]["operand_index"] == 2 and res["stop"]["opcode_block_offset"] == 1
    assert res["stop"]["block_offset"] == 4 and res["covered"] == 1


def test_stop_offset_is_relative_to_stream_and_covered_end():
    res = walk(bytes([0x00, 0x00]))                          # two default records, no stop
    assert [r["advance"] for r in res["records"]] == [1, 1] and res["stop"] is None
    # 0x00 (default, one byte) then class-1 opcode 0x01 at offset 1 whose tag 0x81 is at offset 2
    res = walk(bytes([0x00, 0x01, 0x81, 0x00]))
    assert res["stop"]["opcode_block_offset"] == 1 and res["stop"]["block_offset"] == 2
    assert res["covered"] == 1 and len(res["records"]) == 1


@pytest.mark.parametrize("stream,label", [
    (bytes([0x01]), "no-tag-byte"),
    (bytes([0x01, 0x00]), "no-value-byte"),
    (bytes([0x01, 0x01, 0x00]), "closed-3-byte-runs-past-end"),
])
def test_truncated_operand_is_a_named_stop_not_a_completion(stream, label):
    res = walk(stream)
    assert res["status"] == "stopped-truncated-operand"
    assert res["stop"]["label"] == label and res["stop"]["reason"] == sp.REASON_TRUNC
    assert res["covered"] == 0


# ---------------------------------------------------------------------------------------------
# Default arm and unresolved handler reads
# ---------------------------------------------------------------------------------------------

def test_default_opcode_advances_one_byte():
    res = walk(bytes([0x40, 0x41]))
    assert [r["advance"] for r in res["records"]] == [1, 1]
    assert all(r["handler_reads"] == sp.HANDLER_NO_CASE for r in res["records"])


def test_default_dispatch_case_stops_before_following_bytes():
    res = walk(bytes([0x16, 0x40]))
    assert res["status"] == "stopped-unresolved-handler-read"
    assert res["records"] == [] and res["covered"] == 0
    assert res["stop"] == {"reason": sp.REASON_HANDLER, "block_offset": 0,
                            "opcode": "0x16", "opcode_block_offset": 0,
                            "operand_index": None, "tag": None, "value": None,
                            "label": "default-dispatch-handler-reads-unresolved"}


def test_no_false_completion_when_block_ends_on_unresolved_default():
    block = sp.analyse_block(make_block(bytes([0x40, 0x16])), DOC, {"file": "t"})
    w = block["walk"]
    assert w["status"] == "stopped-unresolved-handler-read"
    assert block["claims"]["complete"] is False
    assert block["claims"]["program_boundary"] == "not-established"
    assert w["records_default_handler_reads_unresolved"] == 1
    assert w["supported_prefix_end_block_offset"] == sp.STREAM_ORIGIN + 1
    assert w["supported_prefix_records"] == 1
    assert w["stop"]["opcode_block_offset"] == sp.STREAM_ORIGIN + 1


def test_supported_prefix_ends_at_stop_when_no_unresolved_default_precedes_it():
    # class-1 record (3 bytes), default 0x40 (1 byte), then class-1 opcode 0x01 at stream offset 4
    # whose tag 0x81 is open: the supported prefix ends at that opcode (block offset 22 + 4).
    block = sp.analyse_block(make_block(bytes([0x01, 0x00, 0x05, 0x40, 0x01, 0x81, 0x00])), DOC, {"file": "t"})
    w = block["walk"]
    assert w["status"] == "stopped-open-operand"
    assert w["supported_prefix_end_block_offset"] == sp.STREAM_ORIGIN + 4
    assert w["supported_prefix_records"] == 2
    assert w["stop"]["opcode_block_offset"] == sp.STREAM_ORIGIN + 4


def test_empty_stream_reaches_end_with_no_records():
    res = walk(b"")
    assert res["status"] == sp.STATUS_END and res["records"] == [] and res["covered"] == 0


# ---------------------------------------------------------------------------------------------
# Framing evidence and refusals
# ---------------------------------------------------------------------------------------------

def test_probe_checks_failed_is_refusal():
    bad = synth_doc(CLASSES, DISPATCH, checks={"a": True, "b": False})
    with pytest.raises(sp.StreamRefusal, match="failed"):
        sp.framing_from_probe(bad)


def test_empty_probe_checks_is_refusal():
    with pytest.raises(sp.StreamRefusal):
        sp.framing_from_probe(synth_doc(CLASSES, DISPATCH, checks={}))


def test_opcode_without_arm_is_framing_gap():
    doc = synth_doc(CLASSES, DISPATCH)
    doc["classifier"]["per_opcode"]["0x44"] = {"arm": "refusal", "reason": "x"}
    with pytest.raises(sp.StreamRefusal, match="opcode 0x44"):
        sp.framing_from_probe(doc)


def test_tiling_not_complete_is_framing_gap():
    doc = synth_doc(CLASSES, DISPATCH)
    doc["parser"]["body"]["tiling_complete"] = False
    with pytest.raises(sp.StreamRefusal, match="tile"):
        sp.framing_from_probe(doc)


def test_closed_kind_delta_must_equal_read_extent():
    kinds = [dict(k) for k in KINDS]
    kinds[0] = dict(kinds[0], cursor_delta=2)               # reads 1,2,3 but delta 2
    with pytest.raises(sp.StreamRefusal, match="read extent"):
        sp.framing_from_probe(synth_doc(CLASSES, DISPATCH, kinds=kinds))


def test_missing_or_repeated_operand_kind_is_refusal():
    with pytest.raises(sp.StreamRefusal, match="0 operand kinds"):
        sp.operand_rule([KINDS[0]], 0x40, 0x00)
    with pytest.raises(sp.StreamRefusal, match="2 operand kinds"):
        sp.operand_rule(KINDS + [KINDS[4]], 0x40, 0x00)


def test_malformed_block_shorter_than_header_is_refusal():
    with pytest.raises(sp.StreamRefusal):
        sp.analyse_block(b"\x88\x13\x01", DOC, {"file": "t"})


def test_wrong_magic_is_refusal():
    bad = bytearray(make_block(b"\x00"))
    bad[0] = 0x00
    with pytest.raises(sp.StreamRefusal, match="magic"):
        sp.analyse_block(bytes(bad), DOC, {"file": "t"})


def test_truncated_dax_is_refusal_via_container():
    dax = make_dax(make_block(b"\x40"))
    with pytest.raises(ecl.EclError):
        sp.load_block(dax[:-3], 20, None)


def test_ambiguous_block_id_needs_index():
    dax = make_dax(make_block(b"\x40"), block_id=20, extra_id=20)
    with pytest.raises(ecl.EclError, match="ambiguous"):
        sp.load_block(dax, 20, None)
    entry, block = sp.load_block(dax, None, 1)
    assert entry.block_id == 20 and block[ecl.ECL_HEADER_LEN:] == b"\x40"


def test_block_loads_and_walks_through_container():
    dax = make_dax(make_block(bytes([0x01, 0x00, 0x05, 0x40])), block_id=20)
    entry, block = sp.load_block(dax, 20, None)
    res = sp.analyse_block(block, DOC, {"file": "t", "toc_index": entry.index, "block_id": entry.block_id})
    assert res["walk"]["status"] == sp.STATUS_END and res["walk"]["records_total"] == 2
    assert res["walk"]["stream_origin_block_offset"] == 22
    assert res["header"]["magic"] == "0x1388" and res["header"]["segment_all_expected"] is True


def test_analysis_is_deterministic_and_path_free():
    block = make_block(bytes([0x01, 0x00, 0x05, 0x16, 0x81, 0x00]))
    src = {"file": "ECL2.DAX", "sha256": "0" * 64}
    a = json.dumps(sp.analyse_block(block, DOC, src, "1" * 64), sort_keys=True)
    b = json.dumps(sp.analyse_block(block, DOC, src, "1" * 64), sort_keys=True)
    assert a == b
    assert not re.search(r"[A-Za-z]:[\\/]", a)
    assert "/" not in a.replace("tools/", "").replace("docs/", "").replace("GoldBox", "")


def test_outputs_refused_inside_install_and_outside_data_work(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(sp.StreamRefusal, match="inside the install"):
        sp.validate_output_dir(install / "out", install, require_data_work=False)
    with pytest.raises(sp.StreamRefusal, match="data/work"):
        sp.validate_output_dir(tmp_path / "out", install, require_data_work=True)


def test_cli_missing_install_is_refusal_2(tmp_path):
    rc = sp.main(["--install", str(tmp_path / "nope"), "--ecl", "2", "--block", "20",
                  "-o", str(ROOT / "data" / "work" / "por-ecl-native-stream" / "test-missing")])
    assert rc == 2


def test_cli_unpinned_files_are_refusal_2(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"x")
    (install / "START.EXE").write_bytes(b"y")
    rc = sp.main(["--install", str(install), "--ecl", "2", "--block", "20",
                  "-o", str(ROOT / "data" / "work" / "por-ecl-native-stream" / "test-unpinned")])
    assert rc == 2


def test_cli_output_outside_data_work_is_refusal_2(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    rc = sp.main(["--install", str(install), "--ecl", "2", "--block", "20", "-o", str(tmp_path / "out")])
    assert rc == 2


def test_failed_framing_probe_checks_are_refusal(tmp_path, monkeypatch):
    install = tmp_path / "install"
    install.mkdir()
    bad = synth_doc(CLASSES, DISPATCH, checks={"pins_match": False})
    monkeypatch.setattr(framing, "probe", lambda inst, out: (bad, 1))
    with pytest.raises(sp.StreamRefusal, match="check"):
        sp.run(install, tmp_path / "out", 2, 20, None)


# ---------------------------------------------------------------------------------------------
# Retail-gated (OPENUA_POR_INSTALL = the pinned POOLRAD folder). Reads only; writes under tmp_path.
# ---------------------------------------------------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
needs_retail = pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_INSTALL to the pinned POOLRAD folder")


@needs_retail
def test_retail_block20_walk_under_probe_framing(tmp_path):
    install = Path(RETAIL)
    result, code = sp.run(install, tmp_path / "out", 2, 20, None)
    assert code == 0, result["checks"]
    assert result["playable"] is False and result["mappings"] == [] and result["claims"]["complete"] is False
    src = result["source"]
    assert src["sha256"] == "6ad6dc5aa53da82f4dba62dbc47d5a02a3f14c14071bec44e81a692615f08a3d"
    assert src["decoded_sha256"] == "a1e1dd7a7ffc07f6e3c3ce7fad25d373270c10edd06ec3fa1f1d0edc9a7297ec"
    assert src["decoded_size"] == 7679
    assert result["records"][0]["block_offset"] == 22 and result["records"][0]["opcode"] == "0x09"
    w = result["walk"]
    assert w["stream_length"] == 7679 - 22
    assert w["records_default_handler_reads_unresolved"] == 1
    assert w["status"] == "stopped-unresolved-handler-read"
    assert w["stop"]["block_offset"] == 34 and w["covered_stream_bytes"] == 12
    assert w["records_total"] == 2
    text = (tmp_path / "out" / sp.RESULT_JSON).read_text(encoding="utf-8")
    assert str(install) not in text and install.as_posix() not in text


@needs_retail
def test_retail_framing_matches_probe_class_sets(tmp_path):
    install = Path(RETAIL)
    doc, code = framing.probe(install, tmp_path / "ev")
    assert code == 0
    table, _ = sp.framing_from_probe(doc)
    cls = {v: table[v]["class"] for v in range(256) if table[v]["class"] is not None}
    assert sorted(cls) == sorted(int(x, 16) for lst in doc["classifier"]["class_sets"].values() for x in lst)
    assert cls[0x2D] == 1 and cls[0x27] == 8 and cls[0x29] == 14 and cls[0x37] == 3
    assert table[0x15]["class"] is None and table[0x2B]["class"] is None
    assert table[0x15]["dispatch_case"] and table[0x2B]["dispatch_case"]
