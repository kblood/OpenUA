"""Tests for tools/por_door_entry_route_census.py (static, stdlib-only, observe-only).

Synthetic tests hand-encode the transfers they classify, with falsifiers. Retail-gated tests run the
census on the pinned install when it is present (OPENUA_POR_INSTALL, else data/work/por-geo-run/POOLRAD).
"""
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = str(Path(__file__).resolve().parents[1] / "tools")
sys.path.insert(0, TOOLS)
import por_door_entry_route_census as ec  # noqa: E402
import por_door_caller_probe as dc  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

DEFAULT_INSTALL = Path(__file__).resolve().parents[1] / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else DEFAULT_INSTALL
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")

BODY_LO, BODY_HI = 0x166CB, 0x166CB + 0x10AC


def _buf(size=0x18000):
    return bytearray(size)


def _near(data, at, opcode, target):
    """E8/E9 rel16 to a file-offset target."""
    rel = target - (at + 3)
    data[at] = opcode
    struct.pack_into("<h", data, at + 1, rel)


def _far(data, at, seg, off):
    data[at] = 0xEA
    struct.pack_into("<HH", data, at + 1, off, seg)


def _insns(data, entries):
    return ec.decoded_map(data, [lh.walk(data, e) for e in entries])


def test_writer_entry_tag_and_body_tag():
    tags = ec.tags_for(ec.WRITER, BODY_LO, BODY_HI)
    assert "writer-0x167D4" in tags and "group-0x166CB-body" in tags


def test_stub1_identity_tag_is_the_file_offset_not_the_proc():
    assert ec.tags_for(ec.STUB1, BODY_LO, BODY_HI) == ["stub1-start-0x0089C"]
    assert "stub1-proc-0x17438" in ec.tags_for(ec.PROC1, BODY_LO, BODY_HI)


def test_decoded_near_jmp_to_writer_is_a_tagged_transfer():
    d = _buf()
    at = 0x17000
    _near(d, at, 0xE9, ec.WRITER)
    d[at + 3] = 0xC3
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    assert [(r["flow"], r["target"]) for r in rows] == [("jmp", ec.WRITER)]
    assert "writer-0x167D4" in rows[0]["tags"]


def test_falsifier_same_bytes_with_a_wrong_displacement_has_no_tag():
    d = _buf()
    at = 0x17000
    _near(d, at, 0xE9, ec.WRITER + 1)
    d[at + 3] = 0xC3
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    assert all("writer-0x167D4" not in r["tags"] for r in rows)


def test_undecoded_raw_call_is_a_raw_hit_and_never_a_transfer_row():
    d = _buf()
    at = 0x17000
    d[at] = 0xC3                        # ret: nothing after it is decoded from this entry
    _near(d, at + 1, 0xE8, ec.CLEARER)  # raw-only call bytes, never walked
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    raw = ec.raw_rows(bytes(d), set(insns), 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    assert rows == []
    assert any(r["at"] == at + 1 and "clearer-0x166CB" in r["tags"] for r in raw)


def test_decoded_far_jmp_to_stub1_under_m1_is_tagged():
    # M1: file = seg*16 + off + 0x7E. seg 0x0081, off 0x000E gives 0x81E + 0x7E = 0x089C.
    d = _buf()
    at = 0x17000
    _far(d, at, 0x0081, 0x000E)
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    m1 = [r for r in rows if r["kind"] == "far" and r["model"] == "M1"]
    assert m1 and m1[0]["target"] == ec.STUB1 and "stub1-start-0x0089C" in m1[0]["tags"]


def test_falsifier_far_jmp_with_a_different_literal_is_not_stub1():
    d = _buf()
    at = 0x17000
    _far(d, at, 0x0081, 0x000F)         # one byte off
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    assert not [r for r in rows if "stub1-start-0x0089C" in r["tags"]]


def test_non_prologue_call_target_is_flagged():
    d = _buf()
    at = 0x17000
    _near(d, at, 0xE8, BODY_LO + 0x10)  # a call into the body that is not a prologue
    d[at + 3] = 0xC3
    d[BODY_LO + 0x10:BODY_LO + 0x13] = b"\x90\x90\x90"
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    calls = [r for r in rows if r["flow"] == "call"]
    assert calls and calls[0]["target_prologue"] is False


def test_prologue_call_target_is_not_flagged_as_non_prologue():
    d = _buf()
    at = 0x17000
    _near(d, at, 0xE8, BODY_LO + 0x10)
    d[at + 3] = 0xC3
    d[BODY_LO + 0x10:BODY_LO + 0x13] = b"\x55\x89\xe5"
    insns = _insns(d, [at])
    rows = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    calls = [r for r in rows if r["flow"] == "call"]
    assert calls and calls[0]["target_prologue"] is True


@needs_retail
def test_retail_load_pinned_accepts_the_pins_and_refuses_a_truncated_ovr(tmp_path):
    ovr, start, pins = dc.load_pinned(RETAIL_INSTALL)
    assert pins["GAME.OVR"]["pin_match"] and pins["START.EXE"]["pin_match"]
    bad = tmp_path / "x"
    bad.mkdir()
    (bad / "GAME.OVR").write_bytes(ovr[:-1])
    (bad / "START.EXE").write_bytes(start)
    with pytest.raises(dc.Refusal):
        dc.load_pinned(bad)


@needs_retail
def test_retail_census_anchors_and_negative_results():
    ovr, start, _ = dc.load_pinned(RETAIL_INSTALL)
    doc = ec.analyse(ovr, start)
    v = doc["verdicts"]
    assert v["trigger_established"] is False
    # Anchors: the six known E8 callers of the writer and clearer, and nothing else tagged.
    near_callers = sorted({r["at"] for r in doc["decoded_transfers"]
                           if r["kind"] == "near" and r["flow"] == "call"
                           and ("writer-0x167D4" in r["tags"] or "clearer-0x166CB" in r["tags"])})
    assert near_callers == sorted(ec.PRIOR_SITES)
    # Negative results of this census (decoded starts only): no decoded transfer of any kind to stub 1.
    assert v["stub1_decoded_near_transfers"] == 0
    assert v["stub1_decoded_far_transfers"] == 0
    assert v["non_prologue_decoded_calls"] == 0
    assert v["new_decoded_near_routes_beyond_prior"] == []
    # Raw hits are reported but never counted as transfers.
    assert not any("writer-0x167D4" in r["tags"] or "stub1-start-0x0089C" in r["tags"] for r in doc["raw_hits"]
                   if r["kind"] == "near")
