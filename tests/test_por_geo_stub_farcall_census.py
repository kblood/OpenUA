"""Tests for tools/por_geo_stub_farcall_census.py.

Input-free tests (synthetic bytes, integers and tmp_path only) run everywhere: the residue and literal rule,
owner-table membership, the two-pass decode (strong from stub procs, weak from prologues), coverage labels,
and the output refusals. The retail anchor needs OPENUA_POR_INSTALL (the pinned POOLRAD folder) and skips
without it. It reads the install and never writes to it.
"""

import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_geo_stub_farcall_census as c  # noqa: E402

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
needs_retail = pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")

HDR = 0x200
S6 = c.STUB6_F  # 15884 == 0x3E0C


def _group(fileofs, codesz, procs=(0x10,), valid=None, fixupsz=0, status="well-formed"):
    valid = [True] * len(procs) if valid is None else list(valid)
    return {
        "header_offset": 0, "stub_delta": 0x16, "stub_count": len(procs),
        "stub_start": 0, "stub_end": 5 * len(procs), "fileofs": fileofs, "codesz": codesz,
        "fixupsz": fixupsz, "procs": list(procs), "stub_valid": valid, "status": status,
    }


def _body(size=0x80, writes=()):
    buf = bytearray(size)
    for off, data in writes:
        buf[off:off + len(data)] = data
    return bytes(buf)


def _far(seg, off):
    return b"\x9a" + struct.pack("<HH", off, seg)


# ---------------------------------------------------------------------------------------------
# Residue and literal rule (integers)
# ---------------------------------------------------------------------------------------------

def test_stub6_is_0x3e0c_and_needs_residue_c():
    assert S6 == 0x3E0C
    assert (S6 - HDR) % 16 == 0xC


def test_listed_seg_with_residue_c_is_residue_candidate_with_di_constraint():
    at = 0x100 + 0x10
    rec = c.site_eval(at, 0x03C0, 0x0C, 0x100, {0x13}, HDR)
    assert rec["status"] == c.SITE_CANDIDATE_RESIDUE
    assert rec["candidate"] is True
    assert rec["seg_word_listed"] is True
    assert rec["di_constraint_mod64k"] == 0


def test_listed_seg_with_offset_one_past_c_is_incompatible_with_skew_15():
    rec = c.site_eval(0x110, 0x03C0, 0x0D, 0x100, {0x13}, HDR)
    assert rec["status"] == c.SITE_RESIDUE_NO
    assert rec["candidate"] is False
    assert rec["skew_needed_mod16"] == 15


def test_listed_seg_residue_is_offset_only_not_seg_dependent():
    rec = c.site_eval(0x110, 0x0100, 0x1C, 0x100, {0x13}, HDR)
    assert rec["status"] == c.SITE_CANDIDATE_RESIDUE
    assert rec["di_constraint_mod64k"] == ((S6 - HDR - 0x1C) // 16 - 0x0100) % c.SEG_MOD


def test_unlisted_seg_literal_exact_hit_is_candidate():
    rec = c.site_eval(0x110, 0x03C0, 0x0C, 0x100, set(), HDR)
    assert rec["status"] == c.SITE_CANDIDATE_LITERAL
    assert rec["candidate"] is True


def test_falsifier_unlisted_literal_off_by_one_is_miss():
    rec = c.site_eval(0x110, 0x03C0, 0x0D, 0x100, set(), HDR)
    assert rec["status"] == c.SITE_LITERAL_MISS
    assert rec["candidate"] is False


def test_offset_word_listed_is_undecided_never_candidate():
    rec = c.site_eval(0x110, 0x03C0, 0x0C, 0x100, {0x11}, HDR)
    assert rec["status"] == c.SITE_UNDECIDED_OFF
    assert rec["candidate"] is False


def test_both_words_listed_is_undecided():
    rec = c.site_eval(0x110, 0x03C0, 0x0C, 0x100, {0x11, 0x13}, HDR)
    assert rec["status"] == c.SITE_UNDECIDED_BOTH
    assert rec["candidate"] is False


def test_owner_table_is_per_owner_not_global():
    a = c.site_eval(0x110, 0x03C0, 0x0C, 0x100, {0x13}, HDR)
    b = c.site_eval(0x110, 0x03C0, 0x0C, 0x0F0, {0x13}, HDR)  # owner 0xF0: seg body 0x23, not listed
    assert a["seg_word_listed"] is True
    assert b["seg_word_listed"] is False
    assert b["status"] == c.SITE_CANDIDATE_LITERAL


# ---------------------------------------------------------------------------------------------
# Owner table reading
# ---------------------------------------------------------------------------------------------

def test_table_info_reads_fixupsz_words_at_codesz():
    g = _group(0x100, 0x40, fixupsz=4)
    ovr = _body(0x200, [(0x140, struct.pack("<HH", 0x13, 0x30))])
    t = c.table_info(ovr, g)
    assert t["present"] is True
    assert t["listed"] == {0x13, 0x30}
    assert t["bare_offsets"] is True


def test_falsifier_table_past_overlay_is_not_present():
    g = _group(0x100, 0x40, fixupsz=4)
    t = c.table_info(_body(0x142), g)
    assert t["present"] is False
    assert t["listed"] == set()


def test_falsifier_table_word_outside_code_is_not_bare():
    g = _group(0x100, 0x40, fixupsz=2)
    ovr = _body(0x200, [(0x140, struct.pack("<H", 0x50))])
    assert c.table_info(ovr, g)["bare_offsets"] is False


# ---------------------------------------------------------------------------------------------
# Two-pass decode of one group
# ---------------------------------------------------------------------------------------------

def test_far_call_reached_from_stub_proc_is_strong():
    body = _body(0x80, [(0x10, b"\x55\x89\xe5"), (0x13, _far(0x03C0, 0x0C)), (0x18, b"\xc3")])
    ovr = _body(0x100 + 0x80, [(0x100, body)])
    res = c.census_group(ovr, _group(0x100, 0x40, procs=(0x10,)))
    far = res["far_decoded"]
    assert len(far) == 1
    assert far[0]["at"] == 0x113
    assert far[0]["seg"] == 0x03C0 and far[0]["off"] == 0x0C
    assert far[0]["strong"] is True
    assert res["coverage"] == "strong-walk-clean"


def test_falsifier_far_call_only_from_prologue_byte_pattern_is_weak():
    body = _body(0x80, [(0x10, b"\xc3"), (0x30, b"\x55\x89\xe5"), (0x33, _far(0x03C0, 0x0C)), (0x38, b"\xc3")])
    ovr = _body(0x100 + 0x80, [(0x100, body)])
    res = c.census_group(ovr, _group(0x100, 0x40, procs=(0x10,)))
    far = {f["at"]: f for f in res["far_decoded"]}
    assert 0x133 in far
    assert far[0x133]["strong"] is False


def test_out_of_body_near_jump_on_strong_path_labels_group_incomplete():
    body = _body(0x80, [(0x10, b"\xe9\xff\x7f")])
    ovr = _body(0x100 + 0x80, [(0x100, body)])
    res = c.census_group(ovr, _group(0x100, 0x40, procs=(0x10,)))
    assert res["out_of_body_strong"] >= 1
    assert res["coverage"] == "strong-walk-incomplete"


def test_no_stub_seed_labels_group_no_strong_seed():
    body = _body(0x80, [(0x10, b"\x55\x89\xe5"), (0x13, _far(0x03C0, 0x0C)), (0x18, b"\xc3")])
    ovr = _body(0x100 + 0x80, [(0x100, body)])
    res = c.census_group(ovr, _group(0x100, 0x40, procs=(0x10,), valid=(False,)))
    assert res["coverage"] == "no-strong-seed"
    assert res["strong_seed_count"] == 0


def test_malformed_stub_slot_is_never_a_strong_seed():
    assert c.strong_procs(_group(0x100, 0x40, procs=(0x10, 0x20), valid=(True, False))) == [0x10]


def test_near_call_target_is_body_relative_and_decoded():
    body = _body(0x80, [(0x10, b"\xe8" + struct.pack("<h", 0x30 - 0x13)), (0x13, b"\xc3"), (0x30, b"\xc3")])
    ovr = _body(0x100 + 0x80, [(0x100, body)])
    res = c.census_group(ovr, _group(0x100, 0x40, procs=(0x10,)))
    near = {n["at"]: n for n in res["near_decoded"]}
    assert 0x110 in near
    assert near[0x110]["target"] == 0x100 + 0x30
    assert near[0x110]["body_target"] == 0x30
    assert near[0x110]["strong"] is True


def test_decode_is_deterministic():
    body = _body(0x80, [(0x10, b"\x55\x89\xe5"), (0x13, _far(0x03C0, 0x0C)), (0x18, b"\xc3")])
    ovr = _body(0x100 + 0x80, [(0x100, body)])
    g = _group(0x100, 0x40, procs=(0x10,))
    a = c.census_group(ovr, g)
    b = c.census_group(ovr, g)
    a.pop("_starts")
    b.pop("_starts")
    assert a == b


def test_stub6_constants_agree_with_the_0x2e8f7_group_and_proc():
    assert c.STUB6_GROUP_FILEOFS + c.STUB6_PROC == c.WALLDEF_BODY == 0x2F6FF
    assert c.STUB6_BYTES == bytes.fromhex("cd 3f 08 0e 00")


# ---------------------------------------------------------------------------------------------
# Output refusals and status strings
# ---------------------------------------------------------------------------------------------

def test_output_inside_install_is_refused(tmp_path):
    with pytest.raises(c.CensusRefusal):
        c.check_out(tmp_path / "out", tmp_path)


def test_output_outside_data_work_is_refused(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(c.CensusRefusal):
        c.check_out(tmp_path / "out", install)


def test_status_strings_never_say_established():
    for s in (c.STATUS_PRECONDITION, c.STATUS_CANDIDATE, c.STATUS_NONE):
        assert "established" not in s.replace("not-established", "")


# ---------------------------------------------------------------------------------------------
# Retail anchor (needs OPENUA_POR_INSTALL)
# ---------------------------------------------------------------------------------------------

def _retail():
    install = Path(RETAIL)
    return (install / c.OVR_NAME).read_bytes(), (install / c.EXE_NAME).read_bytes()


@needs_retail
def test_retail_pins_match():
    ovr, start = _retail()
    assert len(ovr) == c.PINS[c.OVR_NAME][0]
    assert len(start) == c.PINS[c.EXE_NAME][0]


@needs_retail
def test_retail_stub6_precondition_holds():
    ovr, start = _retail()
    doc = c.analyse(start, ovr)
    assert all(v for k, v in doc["precondition"].items() if isinstance(v, bool))
    assert doc["walldef_body_decoded"] is True


@needs_retail
def test_retail_parsed_groups_and_far_call_totals():
    ovr, start = _retail()
    t = c.analyse(start, ovr)["totals"]
    assert t["parsed_groups"] == 34
    assert t["well_formed_groups"] == 24
    assert t["partial_groups"] == 10
    assert t["far_call_sites"] == 3993
    assert t["far_call_owner_rows"] == 3993
    assert t["near_calls_to_walldef_body"] == 0


@needs_retail
def test_retail_every_far_site_has_listed_seg_word_and_no_literal_test():
    ovr, start = _retail()
    statuses = c.analyse(start, ovr)["totals"]["status_counts"]
    assert set(statuses) <= {c.SITE_CANDIDATE_RESIDUE, c.SITE_RESIDUE_NO}
    assert statuses[c.SITE_CANDIDATE_RESIDUE] + statuses[c.SITE_RESIDUE_NO] == 3993


@needs_retail
def test_retail_candidate_count_is_residue_base_rate_not_a_hit():
    ovr, start = _retail()
    v = c.analyse(start, ovr)["verdict"]
    assert v["candidate_count"] == 181
    assert v["stub6_status"] == c.STATUS_CANDIDATE


@needs_retail
def test_retail_handler_control_matches_0x21_probe_skews():
    ovr, start = _retail()
    rows = c.analyse(start, ovr)["handler_control"]
    assert len(rows) == 11
    assert all(rw["in_handler_group"] and rw["decoded"] for rw in rows)
    assert all(rw["census_skew_mod16"] == rw["residue_probe_skew_mod16"] for rw in rows)


@needs_retail
def test_retail_incomplete_groups_are_labelled():
    ovr, start = _retail()
    doc = c.analyse(start, ovr)
    incomplete = sorted(g["fileofs"] for g in doc["groups"] if g["coverage"] == "strong-walk-incomplete")
    assert incomplete == [0x9807, 0xABC0]
