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
import por_door_indirect_probe as dip  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402

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


@needs_retail
def test_retail_four_decode_stops_are_the_known_entries_and_bytes():
    """The four decode stops the census reports, pinned as static facts about the retail bytes.

    Each stop is a walk that started at an entry that is not a code start, or fell through a
    non-returning call into data. Decoder support is not added for these bytes (see
    docs/por-door-entry-route-census.md, "Decode stops"). Address model: file = offset in the
    GAME.OVR or START.EXE file; group procs are group.fileofs + proc (no other model).
    """
    ovr, start, _ = dc.load_pinned(RETAIL_INSTALL)
    scan = fr.scan_all(start, ovr)
    allg = scan["groups"] + scan["partial_groups"]
    cache = dc.GroupCache(ovr)
    stops = set()
    for g in allg:
        gw = cache.get(g)
        for w in list(gw.reached.values()) + list(gw.swept.values()):
            for inc in w["incomplete"]:
                stops.add(("GAME.OVR", inc["at"], inc["code"]))
    sc = dip.start_census(start, fr.mz_image_base(start))
    for _, _, w in sc["walks"]:
        for inc in w["incomplete"]:
            stops.add(("START.EXE", inc["at"], inc["code"]))
    assert stops == {
        ("GAME.OVR", 0x0A085, "unsupported-opcode-0x65"),
        ("GAME.OVR", 0x0B3D5, "unsupported-fe-reg-2"),
        ("GAME.OVR", 0x32923, "target-out-of-range"),
        ("START.EXE", 0x003D2, "unsupported-opcode-0x0f"),
    }
    by_fo = {g["fileofs"]: g for g in allg}
    # Stop 1: proc[1] of the group at 0x09807 is 6 bytes before its prologue, and the bytes it lands on are text.
    g1 = by_fo[0x09807]
    assert 0x087A in g1["procs"] and ovr[0x0A081:0x0A087] == b"attle:"
    assert ovr[0x0A087:0x0A08A] == bytes.fromhex("5589e5")
    # Stop 2: proc[1] of the group at 0x0ABC0 lands inside the call far operand at 0x0B3CD.
    g2 = by_fo[0x0ABC0]
    assert 0x080F in g2["procs"] and ovr[0x0B3CD] == 0x9A and 0x0B3CF == 0x0ABC0 + 0x080F
    # Stop 3: proc[1] of the group at 0x3211F is outside its own code (codesz 0xFC) and past EOF.
    g3 = by_fo[0x3211F]
    assert 0x804 in g3["procs"] and g3["codesz"] == 0x00FC and 0x3211F + 0x804 >= len(ovr)
    # Stop 4: a prologue sweep from START 0x002F6 ends in call far at 0x0034C with no ret.
    assert start[0x002F6:0x002F9] == bytes.fromhex("5589e5")
    assert start[0x0034C] == 0x9A and start[0x0034C:0x00351] == bytes.fromhex("9ae900f80a")


# ---- Supplementary candidate root 0x0A087 (candidate-only; never merged into the baseline) ----

def _far_call(data, at, seg, off):
    """9A call far seg:off (a call, so the walk falls through; EA would be an unwalked jmp far)."""
    data[at] = 0x9A
    struct.pack_into("<HH", data, at + 1, off, seg)


def _root_buf(body: bytes):
    d = _buf()
    d[ec.CANDIDATE_ROOT:ec.CANDIDATE_ROOT + len(body)] = body
    return d


def _cand(d, base=frozenset()):
    return ec.candidate_root(bytes(d), 0x200, BODY_LO, BODY_HI, set(base))


# A near call from 0x0A08A cannot reach the body at 0x166CB (displacement 0xC651 is past rel16), so the
# synthetic body transfer is a far call: seg 0x1640 off 0x00CB is 0x166CB under M0 (the clearer), and
# 0x16549 under M1 (outside the body). One instruction, two model rows, one tag.
BODY_FAR = (0x1640, 0x00CB)
PRO = b"\x55\x89\xe5"
FAR_BODY_CALL = PRO + b"\x9a\x00\x00\x00\x00" + b"\xc3"


def test_candidate_root_inclusion_walks_and_tags_a_far_call_into_the_body_under_m0():
    d = _root_buf(FAR_BODY_CALL)
    _far_call(d, ec.CANDIDATE_ROOT + 3, *BODY_FAR)
    c = _cand(d)
    assert c["status"] == "walked" and c["walk"]["complete"] is True
    assert c["walk"]["instruction_count"] == 4
    assert c["new_instruction_count"] == 4
    assert [(r["model"], r["target"]) for r in c["route_rows"]] == [("M0", BODY_LO)]
    assert "clearer-0x166CB" in c["route_rows"][0]["tags"] and "group-0x166CB-body" in c["route_rows"][0]["tags"]
    assert c["new_route_instructions"] == [ec.CANDIDATE_ROOT + 3]


def test_candidate_root_is_labelled_apart_from_baseline_rows():
    d = _root_buf(FAR_BODY_CALL)
    _far_call(d, ec.CANDIDATE_ROOT + 3, *BODY_FAR)
    c = _cand(d)
    assert c["evidence"] == "supplementary-candidate-root" and c["label"] == "candidate-only"
    # Baseline rows from the same bytes carry no candidate marker: the supplement never merges into them.
    insns = _insns(d, [ec.CANDIDATE_ROOT])
    base = ec.transfer_rows(bytes(d), insns, 0x200, BODY_LO, BODY_HI, "GAME.OVR")
    assert base and all("evidence" not in r and "label" not in r for r in base)


def test_candidate_root_does_not_double_count_instructions_already_in_baseline():
    d = _root_buf(FAR_BODY_CALL)
    _far_call(d, ec.CANDIDATE_ROOT + 3, *BODY_FAR)
    starts = {ec.CANDIDATE_ROOT, ec.CANDIDATE_ROOT + 1, ec.CANDIDATE_ROOT + 3, ec.CANDIDATE_ROOT + 8}
    c = _cand(d, base=starts)
    assert c["new_instruction_count"] == 0
    assert c["new_route_instructions"] == []
    # Two model rows for one instruction are one in-baseline instruction, but two route rows.
    assert c["in_baseline_route_rows"] == 1
    assert all(r["in_baseline"] for r in c["transfer_candidates"])


def test_candidate_far_call_is_reported_under_both_models_and_tagged_only_under_m1():
    # M1 0x0081:0x000E -> 0x089C (stub 1). M0 0x0081:0x000E -> 0x0A1E, not tagged. One instruction, two rows.
    d = _root_buf(FAR_BODY_CALL)
    _far_call(d, ec.CANDIDATE_ROOT + 3, 0x0081, 0x000E)
    c = _cand(d)
    far = [r for r in c["transfer_candidates"] if r["kind"] == "far"]
    assert sorted(r["model"] for r in far) == ["M0", "M1"]
    assert [r["model"] for r in c["route_rows"]] == ["M1"]
    assert c["route_rows"][0]["tags"] == ["stub1-start-0x0089C"]
    assert c["new_route_instructions"] == [ec.CANDIDATE_ROOT + 3]
    assert c["new_instruction_count"] == 4


def test_falsifier_changed_prologue_refuses_the_candidate_walk():
    d = _root_buf(b"\x90\x89\xe5" + FAR_BODY_CALL[3:])
    _far_call(d, ec.CANDIDATE_ROOT + 3, *BODY_FAR)
    c = _cand(d)
    assert c["status"] == "refused-prologue-mismatch"
    assert c["prologue_match"] is False and c["walk"] is None
    assert c["route_rows"] == [] and c["transfer_candidates"] == [] and c["new_instruction_count"] == 0


def test_absent_route_is_walked_with_transfer_candidates_but_no_route_rows():
    # A near call to an untagged address (0x0B000 is in rel16 reach and outside every tagged target).
    d = _root_buf(PRO + b"\xe8\x00\x00" + b"\xc3")
    _near(d, ec.CANDIDATE_ROOT + 3, 0xE8, 0x0B000)
    c = _cand(d)
    assert c["status"] == "walked"
    assert [r["target"] for r in c["transfer_candidates"]] == [0x0B000]
    assert c["route_rows"] == [] and c["new_route_instructions"] == [] and c["in_baseline_route_rows"] == 0


@needs_retail
def test_retail_candidate_root_0a087_is_pinned_as_candidate_only():
    ovr, start, pins = dc.load_pinned(RETAIL_INSTALL)
    doc = ec.analyse(ovr, start)
    # Pin identity: the same GAME.OVR the other anchors use.
    assert pins["GAME.OVR"]["size"] == 206105 and pins["GAME.OVR"]["pin_match"]
    assert pins["GAME.OVR"]["sha256"] == "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"
    (c,) = doc["candidate_roots"]
    assert c["evidence"] == "supplementary-candidate-root" and c["label"] == "candidate-only"
    # Group 0x09807 proc[1] (0x087A) is 6 bytes before the prologue; the prologue is 55 89 E5 at 0x0A087.
    assert ovr[0x0A081:0x0A087] == b"attle:" and c["prologue"] == "5589e5" and c["prologue_match"] is True
    assert c["group_relative"] == "0x0880"
    wk = c["walk"]
    assert wk["complete"] is True and wk["instruction_count"] == 108
    assert wk["incomplete"] == [] and wk["overlap_conflicts"] == []
    assert wk["span"] == [0x0A087, 0x0A1BB]
    # Call sites: one near call to 0x0A806 (a prologue in the same group), and ten far calls.
    assert wk["near_calls"] == [{"at": 0x0A11E, "target": 0x0A806, "in_baseline": True}]
    assert [(f["at"], f["seg"], f["off"]) for f in wk["far_calls"]] == [
        (0x0A093, 0x008C, 0x0025), (0x0A09C, 0x0068, 0x007F), (0x0A0C3, 0x00B0, 0x002F),
        (0x0A0CE, 0x00B0, 0x0034), (0x0A12F, 0x0AF8, 0x0B0B), (0x0A134, 0x00BA, 0x1693),
        (0x0A139, 0x00BA, 0x23DB), (0x0A15E, 0x03E0, 0x0052), (0x0A197, 0x0AF8, 0x0B0B),
        (0x0A1A5, 0x03C5, 0x0039)]
    # Every instruction start is already a baseline decoded start (the baseline sweep of group 0x09807),
    # so nothing is new and no route is tagged. This is a fact about the retail bytes, not a route.
    assert c["new_instruction_count"] == 0 and c["new_route_instructions"] == []
    assert c["route_rows"] == [] and c["in_baseline_route_rows"] == 0
    # Baseline is unchanged by the supplement: the pre-change census counts.
    assert len(doc["decoded_transfers"]) == 99 and len(doc["raw_hits"]) == 14
    assert doc["verdicts"]["trigger_established"] is False
