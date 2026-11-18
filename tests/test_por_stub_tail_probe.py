"""Tests for tools/por_stub_tail_probe.py (static, stdlib-only, observe-only).

Synthetic tests hand-build a START.EXE / GAME.OVR pair with one stub group and check each
classification with a falsifier. Retail-gated tests pin the survey on the pinned PoR install
(OPENUA_POR_INSTALL, else data/work/por-geo-run/POOLRAD); they skip, never pass, without it.
"""
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = str(Path(__file__).resolve().parents[1] / "tools")
sys.path.insert(0, TOOLS)
import por_stub_tail_probe as sp  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402

PRO = b"\x55\x89\xe5"
HDR = 0x200                     # MZ image base used by the synthetic START.EXE
P_HDR = 0x250                   # synthetic group header offset in START.EXE
DEFAULT_INSTALL = Path(__file__).resolve().parents[1] / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else DEFAULT_INSTALL
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")


def _pair(procs, tails, fo=0x100, codesz=0x80, fixupsz=0, prologue=True, body=None):
    """A synthetic START/OVR with one group. procs[k] is slot k's proc word, tails[k] its fifth byte.
    body(ovr, target) may write extra code at a slot's target (decoded-reference tests)."""
    ovr = bytearray(0x400)
    ovr[0:4] = b"FBOV"
    start = bytearray(0x400)
    start[0:2] = b"MZ"
    struct.pack_into("<H", start, 0x08, HDR // 16)
    start[P_HDR:P_HDR + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", start, P_HDR + 4, fo, codesz, fixupsz, len(procs))
    st = P_HDR + 0x16
    for k, (pr, t) in enumerate(zip(procs, tails)):
        start[st + 5 * k:st + 5 * k + 5] = b"\xcd\x3f" + struct.pack("<H", pr) + bytes([t])
        target = fo + pr
        if prologue:
            ovr[target:target + 3] = PRO
        if body is not None:
            body(ovr, target, st + 5 * k)
    return bytes(start), bytes(ovr)


def _probe_pieces(start, ovr):
    groups, _ = sp.all_groups(start, ovr)
    lay = sp.layout(start, ovr, groups)
    slots = sp.slot_table(start, ovr, groups)
    return groups, lay, slots


# --- tail placement --------------------------------------------------------------------------

def test_accepted_group_with_zero_tails_has_no_nonzero_tail():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0])
    groups, lay, slots = _probe_pieces(start, ovr)
    assert [g["status"] for g in groups] == ["well-formed"]
    assert sp.tail_summary(slots)["nonzero_tails"] == 0


def test_partial_group_with_nonzero_last_tail_is_reported_at_last_slot():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0x48])
    groups, lay, slots = _probe_pieces(start, ovr)
    assert [g["status"] for g in groups] == ["partial"]
    ts = sp.tail_summary(slots)
    assert ts["nonzero_tails"] == 1
    assert ts["nonzero_tails_at_last_slot"] == 1
    assert ts["nonzero_tails_in_partial_groups"] == 1
    assert ts["partial_last_slots_tail_nonzero"] == 1


def test_falsifier_nonzero_tail_on_a_non_last_slot_is_counted_as_non_last():
    # Four slots, one malformed non-last slot: a valid partial group (3 of 4 well-formed).
    start, ovr = _pair([0x10, 0x20, 0x30, 0x40], [0x13, 0, 0, 0])
    groups, lay, slots = _probe_pieces(start, ovr)
    assert [g["status"] for g in groups] == ["partial"]
    ts = sp.tail_summary(slots)
    assert ts["nonzero_non_last_slots"] == 1
    assert ts["nonzero_tails_at_last_slot"] == 0


def test_falsifier_tail_value_is_read_from_the_fifth_byte_not_the_proc_word():
    # Proc high bytes are nonzero; a reader that took the wrong byte would count them as tails.
    start, ovr = _pair([0x0110, 0x0120, 0x0130], [0, 0, 0x00])
    groups, lay, slots = _probe_pieces(start, ovr)
    assert sp.tail_summary(slots)["nonzero_tails"] == 0
    assert [s["tail"] for s in slots] == [0, 0, 0]


# --- prologue hits by class ----------------------------------------------------------------

def test_nonzero_last_slot_with_prologue_target_is_counted_as_prologue_hit():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0x48])
    _, _, slots = _probe_pieces(start, ovr)
    pc = sp.prologue_by_class(slots)
    assert pc["partial_nonzero_tail"] == {"slots": 1, "prologue_at_fo_plus_proc": 1}


def test_falsifier_nonzero_last_slot_without_prologue_is_not_counted_as_a_hit():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0x48], prologue=False)
    _, _, slots = _probe_pieces(start, ovr)
    assert sp.prologue_by_class(slots)["partial_nonzero_tail"] == {"slots": 1, "prologue_at_fo_plus_proc": 0}


# --- relations (positive control and falsifier) ---------------------------------------------

def test_relation_control_tail_equal_to_proc_lo_is_detected():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0x30])
    groups, lay, slots = _probe_pieces(start, ovr)
    rel = {r["relation"]: r["equal"] for r in sp.relations(slots, lay)}
    assert rel["proc lo"] == 1


def test_falsifier_unrelated_tail_matches_no_relation():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0x61])
    groups, lay, slots = _probe_pieces(start, ovr)
    rel = {r["relation"]: r["equal"] for r in sp.relations(slots, lay)}
    assert rel["proc lo"] == 0 and rel["stub count"] == 0 and rel["slot index"] == 0


# --- post-stub block --------------------------------------------------------------------

def _post(bytes_after_stubs):
    """Classify the bytes written right after a 2-stub group's run (stub end = P_HDR+0x16+10)."""
    start = bytearray(0x400)
    start[0:2] = b"MZ"
    se = P_HDR + 0x16 + 10
    start[se:se + len(bytes_after_stubs)] = bytes_after_stubs
    return sp._post_block(bytes(start), se)


def test_post_block_b2_trailer_at_stub_end_is_gap0():
    p = _post(b"\xb2\x00\x08\x00\xb0")
    assert (p["kind"], p["gap_len"]) == ("b2-trailer", 0)


def test_post_block_b2_trailer_after_one_byte_is_gap1():
    p = _post(b"\x02\xb2\x00\x08\x00\xb0")
    assert (p["kind"], p["gap_len"], p["gap_bytes"]) == ("b2-trailer", 1, "02")


def test_post_block_zero_run_then_header_is_not_a_trailer():
    p = _post(b"\x00\x00\x00\x00\x00\x00" + fr.DESC_MAGIC)
    assert (p["kind"], p["gap_len"]) == ("zero-run-then-header", 6)


def test_falsifier_post_block_of_other_bytes_is_other():
    p = _post(b"\x55\x89\xe5\x5d\xcb")
    assert p["kind"] == "other"


# --- alignment ----------------------------------------------------------------------------

def test_alignment_scores_show_the_chosen_delta_and_zero_for_the_other():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0x48])
    groups, lay, slots = _probe_pieces(start, ovr)
    sc = lay[0]["alignment_scores"]
    assert sc[str(0x16)] == 2 and sc[str(0x17)] == 0


def test_pre_block_matches_its_delta_family():
    start, ovr = _pair([0x10, 0x20, 0x30], [0, 0, 0])
    groups, lay, slots = _probe_pieces(start, ovr)
    assert lay[0]["pre_block_matches_delta"] is False   # synthetic pre-block is zero
    assert sp.PRE_BLOCK[0x16] == b"\xb2\x00\x11\x00\xb0" and sp.PRE_BLOCK[0x17] == b"\xb2\x00\x10\x00\xb0"


# --- decoded references ------------------------------------------------------------------

def _far_into(site_phys_fn):
    """body() that writes CALL FAR seg:off at a slot target so the walk decodes it, then RET."""
    def body(ovr, target, slot_addr):
        if slot_addr is None:
            return
        phys = site_phys_fn(slot_addr)
        off, seg = phys - HDR, 0
        ovr[target + 3:target + 8] = b"\x9a" + struct.pack("<HH", off, seg)
        ovr[target + 8] = 0xC3
    return body


def test_decoded_call_far_to_a_stub_start_is_classified_stub_start():
    start, ovr = _pair([0x10], [0], body=_far_into(lambda a: a))
    groups, lay, slots = _probe_pieces(start, ovr)
    dr = sp.decoded_refs(ovr, start, slots, HDR)
    assert dr["by_class"].get("stub-start") == 1 and "stub-tail" not in dr["by_class"]


def test_decoded_call_far_to_a_stub_tail_is_classified_stub_tail():
    start, ovr = _pair([0x10], [0], body=_far_into(lambda a: a + 4))
    groups, lay, slots = _probe_pieces(start, ovr)
    dr = sp.decoded_refs(ovr, start, slots, HDR)
    assert dr["by_class"].get("stub-tail") == 1 and dr["stub_tail_hits_on_nonzero_tails"] == 0


def test_falsifier_decoded_call_elsewhere_is_other():
    start, ovr = _pair([0x10], [0], body=_far_into(lambda a: a + 0x40))
    groups, lay, slots = _probe_pieces(start, ovr)
    dr = sp.decoded_refs(ovr, start, slots, HDR)
    assert dr["by_class"] == {"other": 1}


def test_falsifier_call_in_an_undecodable_walk_is_not_counted():
    def body(ovr, target, slot_addr):
        ovr[target + 3] = 0x0F                 # an opcode the walker does not support
        ovr[target + 4:target + 8] = b"\x9a" + b"\x00\x00\x00"
    start, ovr = _pair([0x10], [0], body=body)
    groups, lay, slots = _probe_pieces(start, ovr)
    dr = sp.decoded_refs(ovr, start, slots, HDR)
    assert dr["complete_walks"] == 0 and dr["unique_call_far_sites"] == 0


# --- handler pattern ------------------------------------------------------------------------

def test_handler_setup_pattern_is_checked_at_fixed_offsets():
    start = bytearray(0x400)
    start[0:2] = b"MZ"
    ev = sp.handler_evidence(bytes(start), HDR)
    assert ev["setup_pattern_matches"] is False
    assert ev["attributed_to_tail_read"] is None


# --- refusals and determinism -----------------------------------------------------------------

def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"")
    (install / "START.EXE").write_bytes(b"")
    assert sp.main(["--install", str(install), "-o", str(install / "out")]) == 2


def test_missing_install_files_are_refused(tmp_path):
    assert sp.main(["--install", str(tmp_path), "-o", str(tmp_path.parent / "por-stub-tail-missing")]) == 2


# --- retail-pinned -----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def retail_doc(tmp_path_factory):
    if not HAVE_RETAIL:
        pytest.skip("pinned PoR install not present")
    out = tmp_path_factory.mktemp("por-stub-tail")
    doc, code = sp.probe(RETAIL_INSTALL, out)
    return doc


@needs_retail
def test_retail_pins_match_the_resolver_pins(retail_doc):
    pins = retail_doc["source"]["pins"]
    assert retail_doc["source"]["all_pins_match"] is True
    assert pins[fr.OVR_NAME]["size"] == fr.PINNED[fr.OVR_NAME][0]
    assert pins[fr.EXE_NAME]["sha256"] == fr.PINNED[fr.EXE_NAME][1]


@needs_retail
def test_retail_group_and_slot_counts(retail_doc):
    assert retail_doc["groups"]["count"] == 34
    assert (retail_doc["groups"]["accepted"], retail_doc["groups"]["partial"]) == (24, 10)
    assert retail_doc["tail_summary"]["slots"] == 404


@needs_retail
def test_retail_nonzero_tails_are_exactly_ten_last_slots_of_partial_groups(retail_doc):
    ts = retail_doc["tail_summary"]
    assert ts["nonzero_tails"] == 10
    assert ts["nonzero_tails_at_last_slot"] == 10
    assert ts["nonzero_tails_in_partial_groups"] == 10
    assert ts["nonzero_tails_in_accepted_groups"] == 0
    assert ts["nonzero_non_last_slots"] == 0


@needs_retail
def test_retail_accepted_last_slots_are_zero_and_partial_last_slots_are_nonzero(retail_doc):
    ts = retail_doc["tail_summary"]
    assert (ts["accepted_last_slots"], ts["accepted_last_slots_tail_zero"]) == (24, 24)
    assert (ts["partial_last_slots"], ts["partial_last_slots_tail_nonzero"]) == (10, 10)


@needs_retail
def test_retail_nonzero_tail_values_and_slots_are_pinned(retail_doc):
    rows = [(r["header_offset"], r["index"], r["tail"], r["proc"]) for r in retail_doc["tail_summary"]["nonzero_tail_slots"]]
    assert rows == [
        (0x586, 116, "0x48", "0x319b"), (0x8cd, 3, "0x13", "0x382d"), (0x979, 12, "0x40", "0x299c"),
        (0xbb8, 4, "0x18", "0x0329"), (0xbed, 22, "0x72", "0x1869"), (0x3d00, 7, "0x27", "0x11f3"),
        (0x3d92, 7, "0x27", "0x0708"), (0x3dd7, 7, "0x27", "0x10c7"), (0x3e28, 6, "0x22", "0x0909"),
        (0x3e68, 19, "0x63", "0x1298"),
    ]


@needs_retail
def test_retail_prologue_hits_by_class(retail_doc):
    pc = retail_doc["prologue_by_class"]
    assert pc["accepted_zero_tail"] == {"slots": 191, "prologue_at_fo_plus_proc": 186}
    assert pc["partial_zero_tail"] == {"slots": 203, "prologue_at_fo_plus_proc": 203}
    assert pc["partial_nonzero_tail"] == {"slots": 10, "prologue_at_fo_plus_proc": 10}


@needs_retail
def test_retail_no_simple_relation_explains_the_nonzero_tails(retail_doc):
    rel = retail_doc["relations_tested_on_nonzero_tails"]
    assert all(r["of"] == 10 for r in rel)
    assert [r["equal"] for r in rel] == [0] * len(rel)


@needs_retail
def test_retail_pre_block_and_post_block_families(retail_doc):
    g = retail_doc["groups"]
    assert g["pre_block_matches_delta"] == 34
    assert g["post_kind_counts"] == {
        "partial|b2-trailer|gap1": 10,
        "well-formed|b2-trailer|gap0": 5,
        "well-formed|header-direct|gap0": 1,
        "well-formed|other|gap0": 2,
        "well-formed|zero-run-then-header|gap1": 7,
        "well-formed|zero-run-then-header|gap3": 2,
        "well-formed|zero-run-then-header|gap4": 1,
        "well-formed|zero-run-then-header|gap5": 1,
        "well-formed|zero-run-then-header|gap6": 5,
    }


@needs_retail
def test_retail_each_partial_group_matches_only_at_its_own_delta(retail_doc):
    for r in retail_doc["groups"]["layout"]:
        if r["status"] != "partial":
            continue
        own = r["stub_delta"]
        other = 0x17 if own == 0x16 else 0x16
        assert r["alignment_scores"][str(other)] == 0
        assert r["alignment_scores"][str(own)] >= 2


@needs_retail
def test_retail_decoded_references_split_by_class(retail_doc):
    dr = retail_doc["decoded_references"]
    assert dr["walk_targets"] == 399
    assert dr["complete_walks"] == 399
    assert dr["unique_call_far_sites"] == 2077
    assert dr["by_class"] == {"other": 2025, "stub-start": 41, "stub-tail": 11}


@needs_retail
def test_retail_stub_tail_hits_are_all_in_accepted_group_0xa62_with_zero_tails(retail_doc):
    hits = retail_doc["decoded_references"]["stub_tail_hits"]
    assert len(hits) == 11
    assert {h["group_header"] for h in hits} == {"0xa62"}
    assert {h["group_status"] for h in hits} == {"well-formed"}
    assert {h["slot_tail"] for h in hits} == {"0x00"}
    assert retail_doc["decoded_references"]["stub_tail_hits_on_nonzero_tails"] == 0


@needs_retail
def test_retail_no_decoded_stub_start_hit_lands_on_a_nonzero_tail_slot(retail_doc):
    nz = {(r["header_offset"], r["index"]) for r in retail_doc["tail_summary"]["nonzero_tail_slots"]}
    for h in retail_doc["decoded_references"]["stub_start_hits"]:
        assert (int(h["group_header"], 16), h["slot_index"]) not in nz


@needs_retail
def test_retail_handler_setup_bytes_match_and_code_segment_is_unresolved(retail_doc):
    hd = retail_doc["handler"]
    assert hd["setup_pattern_matches"] is True
    assert hd["mz_relocation_count"] == 0
    assert hd["code_segment_of_setup"] == "unresolved"
    assert hd["attributed_to_tail_read"] is None


@needs_retail
def test_retail_probe_output_is_deterministic(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    sp.probe(RETAIL_INSTALL, a)
    sp.probe(RETAIL_INSTALL, b)
    assert (a / "por_stub_tail_byte.json").read_bytes() == (b / "por_stub_tail_byte.json").read_bytes()
    assert (a / "por_stub_tail_byte_report.md").read_bytes() == (b / "por_stub_tail_byte_report.md").read_bytes()
