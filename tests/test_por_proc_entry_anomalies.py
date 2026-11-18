"""Tests for tools/por_proc_entry_anomalies.py (static, stdlib-only, observe-only).

Synthetic tests hand-build the stub groups and bytes they classify, each with a falsifier.
Retail-gated tests pin the survey on the pinned PoR install when it is present
(OPENUA_POR_INSTALL, else data/work/por-geo-run/POOLRAD); they skip, never pass, without it.
"""
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = str(Path(__file__).resolve().parents[1] / "tools")
sys.path.insert(0, TOOLS)
import por_proc_entry_anomalies as pe  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402

PRO = b"\x55\x89\xe5"
THUNK = b"\x55\x89\xe5\x5d\xcb"
DEFAULT_INSTALL = Path(__file__).resolve().parents[1] / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else DEFAULT_INSTALL
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")


def _group(fo, codesz, procs, valid=None, fixupsz=0, header=0x10):
    n = len(procs)
    return {"fileofs": fo, "codesz": codesz, "fixupsz": fixupsz, "header_offset": header,
            "stub_start": header + 0x16, "stub_count": n, "procs": list(procs),
            "stub_valid": list(valid) if valid is not None else [True] * n}


def _ovr(size=0x400):
    return bytearray(size)


def _start(size=0x400):
    return bytearray(size)


# --- proc rows ---------------------------------------------------------------------------

def test_prologue_at_fo_plus_proc_is_not_an_anomaly():
    ovr = _ovr()
    ovr[0x100:0x103] = PRO
    ovr[0x130:0x133] = PRO
    g = _group(0x100, 0x40, [0x0, 0x30])
    rows = pe.slot_rows([(g, "well-formed-group")], ovr, _start())
    assert pe.anomalies(rows) == []


def test_falsifier_non_prologue_at_proc_is_an_anomaly():
    ovr = _ovr()
    ovr[0x100:0x103] = PRO
    ovr[0x130:0x133] = b"\x90\x90\x90"
    g = _group(0x100, 0x40, [0x0, 0x30])
    an = pe.anomalies(pe.slot_rows([(g, "well-formed-group")], ovr, _start()))
    assert [(r["index"], r["proc"]) for r in an] == [(1, 0x30)]


def test_malformed_slot_is_never_an_anomaly_but_is_counted_separately():
    ovr = _ovr()
    ovr[0x100:0x103] = PRO
    ovr[0x130:0x133] = b"\x90\x90\x90"
    g = _group(0x100, 0x40, [0x0, 0x30], valid=[True, False])
    rows = pe.slot_rows([(g, "partial-group")], ovr, _start())
    assert pe.anomalies(rows) == []
    assert [r["class"] for r in rows] == ["well-formed", "malformed"]


def test_falsifier_same_malformed_slot_marked_well_formed_is_an_anomaly():
    ovr = _ovr()
    ovr[0x100:0x103] = PRO
    ovr[0x130:0x133] = b"\x90\x90\x90"
    g = _group(0x100, 0x40, [0x0, 0x30], valid=[True, True])
    assert len(pe.anomalies(pe.slot_rows([(g, "well-formed-group")], ovr, _start()))) == 1


def test_proc_inside_code_flag():
    ovr = _ovr()
    g_in = _group(0x100, 0x40, [0x10])
    g_out = _group(0x100, 0x40, [0x50])
    assert pe.slot_rows([(g_in, "well-formed-group")], ovr, _start())[0]["proc_inside_code"] is True
    assert pe.slot_rows([(g_out, "well-formed-group")], ovr, _start())[0]["proc_inside_code"] is False


# --- layout and stub 0 -------------------------------------------------------------------

def test_contiguous_chain_has_no_break():
    a = _group(0x100, 0x10, [0], fixupsz=4)
    b = _group(0x114, 0x10, [0], fixupsz=0)
    assert pe.chain_breaks([(a, "w"), (b, "w")]) == []


def test_falsifier_one_byte_gap_is_a_chain_break():
    a = _group(0x100, 0x10, [0], fixupsz=4)
    b = _group(0x115, 0x10, [0], fixupsz=0)
    assert pe.chain_breaks([(a, "w"), (b, "w")]) == [
        {"after_fileofs": 0x100, "end": 0x114, "next_fileofs": 0x115, "diff": 1}]


def test_stub0_at_codesz_minus_5_with_exit_thunk():
    ovr = _ovr()
    g = _group(0x100, 0x20, [0x1B])
    ovr[0x100 + 0x1B:0x100 + 0x20] = THUNK
    c = pe.stub0_thunk_census([(g, "w")], ovr)
    assert c == {"groups": 1, "stub0_proc_eq_codesz_minus_5": 1, "exit_thunk_bytes_at_codesz_minus_5": 1}


def test_falsifier_stub0_off_by_one_and_no_thunk():
    ovr = _ovr()
    g = _group(0x100, 0x20, [0x1A])  # proc != codesz-5
    c = pe.stub0_thunk_census([(g, "w")], ovr)
    assert c["stub0_proc_eq_codesz_minus_5"] == 0
    assert c["exit_thunk_bytes_at_codesz_minus_5"] == 0  # no thunk bytes were written


# --- origins, survey, 9A ------------------------------------------------------------------

def test_pred_fo_origin_fixes_one_anomaly_only_when_its_target_is_a_prologue():
    ovr = _ovr()
    ovr[0x110:0x113] = PRO
    a = _group(0x100, 0x40, [0x0])
    b = _group(0x140, 0x40, [0x0, 0x10], header=0x80)
    table = [(a, "w"), (b, "w")]
    an = {"group_fileofs": 0x140, "proc": 0x10}
    o = pe.neighbour_origins(table, ovr, _start(), 0x200, an)
    assert o["pred_fo"] == {"target": 0x110, "prologue": True}
    assert o["next_fo"] is None


def test_falsifier_pred_fo_origin_not_a_prologue():
    ovr = _ovr()
    ovr[0x111:0x114] = PRO  # shifted by one byte: the origin no longer lands on a prologue
    a = _group(0x100, 0x40, [0x0])
    b = _group(0x140, 0x40, [0x0, 0x10], header=0x80)
    o = pe.neighbour_origins([(a, "w"), (b, "w")], ovr, _start(), 0x200,
                             {"group_fileofs": 0x140, "proc": 0x10})
    assert o["pred_fo"]["prologue"] is False


def test_local_survey_reports_deltas_and_chance_rate():
    ovr = _ovr()
    ovr[0x110:0x113] = PRO  # the only body prologue in 0x100..0x140
    ovr[0x206:0x209] = PRO  # target 0x200 + 6
    s = pe.local_prologue_survey(ovr, {"target": 0x200}, 0x100, 0x140)
    assert s["deltas"] == [6]
    assert s["body_prologues"] == 1
    assert s["expected_by_chance"] == round(129 / 64, 3)


def test_falsifier_survey_without_a_window_prologue_has_no_deltas():
    ovr = _ovr()
    s = pe.local_prologue_survey(ovr, {"target": 0x200}, 0x100, 0x140)
    assert s["deltas"] == []


def test_9a_operand_is_offset_then_segment_and_maps_to_m0_image():
    ovr = _ovr()
    ovr[0x20:0x25] = b"\x9a\x5c\x00\x2b\x00"  # call far 002B:005C
    refs = pe.nine_a_refs(ovr, _start(), 0x200, {0x50C, 0x200 + 0x5C * 16 + 0x2B})
    assert refs[0x50C] == [{"file": "GAME.OVR", "at": 0x20, "model": "M0"}]
    assert refs[0x200 + 0x5C * 16 + 0x2B] == []  # the swapped reading names no reference


def test_decoded_call_far_needs_a_complete_walk_from_a_prologue():
    ovr = _ovr()
    ovr[0x100:0x109] = PRO + b"\x9a\x5c\x00\x2b\x00" + b"\xcb"  # push bp; mov bp,sp; call far; retf
    hit = pe.decoded_call_far_entry(ovr, 0x103, 0x100)
    assert hit is not None and hit["walk_entry"] == 0x100


def test_falsifier_unsupported_opcode_makes_the_walk_incomplete():
    ovr = _ovr()
    ovr[0x100:0x109] = PRO + b"\x9a\x5c\x00\x2b\x00" + b"\x0f"  # 0F is refused by the decoder
    assert pe.decoded_call_far_entry(ovr, 0x103, 0x100) is None


def test_falsifier_9a_outside_any_prologue_walk_is_not_decoded():
    ovr = _ovr()
    ovr[0x200:0x205] = b"\x9a\x5c\x00\x2b\x00"  # raw bytes, no prologue walk reaches 0x200
    assert pe.decoded_call_far_entry(ovr, 0x200, 0x100) is None


# --- retail-gated pins ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def retail():
    ovr = (RETAIL_INSTALL / fr.OVR_NAME).read_bytes()
    start = (RETAIL_INSTALL / fr.EXE_NAME).read_bytes()
    return ovr, start, pe.analyze(start, ovr)


@needs_retail
def test_retail_pins_match_the_resolver_pins(retail):
    ovr, start, _ = retail
    import hashlib
    for name, data in ((fr.OVR_NAME, ovr), (fr.EXE_NAME, start)):
        size, sha = fr.PINNED[name]
        assert len(data) == size
        assert hashlib.sha256(data).hexdigest() == sha


@needs_retail
def test_retail_group_counts_and_chain(retail):
    _, _, a = retail
    assert (a["group_count"], a["accepted_group_count"], a["partial_group_count"]) == (34, 24, 10)
    assert a["chain_breaks"] == []


@needs_retail
def test_retail_stub0_is_codesz_minus_5_exit_thunk_in_every_group(retail):
    _, _, a = retail
    assert a["stub0_census"] == {"groups": 34, "stub0_proc_eq_codesz_minus_5": 34,
                                 "exit_thunk_bytes_at_codesz_minus_5": 34}


@needs_retail
def test_retail_slot_prologue_counts(retail):
    _, _, a = retail
    assert a["slot_counts"] == {"well_formed": 394, "well_formed_prologue": 389,
                                "malformed": 10, "malformed_prologue": 10}


@needs_retail
def test_retail_exactly_five_anomalous_well_formed_slots(retail):
    _, _, a = retail
    got = {(d["group_fileofs"], d["index"], d["proc"]) for d in a["anomalies"]}
    assert got == {(0x9AC, 1, 0x8FD), (0x9807, 1, 0x87A), (0xABC0, 1, 0x80F),
                   (0xE5D3, 1, 0x82D), (0x3211F, 1, 0x804)}


@needs_retail
def test_retail_no_consistent_origin_and_no_bias(retail):
    _, _, a = retail
    assert a["consistent_bias_found"] is False
    assert all(not v["fixes_all_anomalies"] for v in a["shared_origin_test"].values())


@needs_retail
def test_retail_only_0x9807_slot_is_reached_by_decoded_far_calls(retail):
    _, _, a = retail
    by = {d["group_fileofs"]: d for d in a["anomalies"]}
    assert [x for x in by[0x9807]["nine_a_refs"] if x["decoded_call_far"]] == [
        {"file": "GAME.OVR", "at": 0x101D, "model": "M0", "decoded_call_far": True, "walk_entry": 0x0FD8},
        {"file": "GAME.OVR", "at": 0x1746, "model": "M0", "decoded_call_far": True, "walk_entry": 0x16DA},
    ]
    for fo in (0x9AC, 0xABC0, 0xE5D3, 0x3211F):
        assert not [x for x in by[fo]["nine_a_refs"] if x["decoded_call_far"]]


@needs_retail
def test_retail_0x9807_stub1_target_is_text_and_prologue_is_six_bytes_later(retail):
    ovr, _, a = retail
    d = {x["group_fileofs"]: x for x in a["anomalies"]}[0x9807]
    assert d["target"] == 0xA081
    assert ovr[0xA081:0xA087] == b"attle:"  # the word names text, not code
    assert ovr[0xA087:0xA08A] == PRO
    assert d["local_prologue_survey"]["deltas"] == [6]


@needs_retail
def test_retail_malformed_slots_have_a_nonzero_trailing_byte_and_land_on_prologues(retail):
    _, _, a = retail
    for m in a["malformed_slots"]:
        assert m["prologue_at_target"] is True
        assert bytes.fromhex(m["slot_bytes"])[:2] == b"\xcd\x3f"
        assert bytes.fromhex(m["slot_bytes"])[4] != 0
