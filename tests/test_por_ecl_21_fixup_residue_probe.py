"""Tests for tools/por_ecl_21_fixup_residue_probe.py.

Input-free tests run everywhere: residue arithmetic, table facts, header reads, verdict rules and the
output refusals use synthetic integers, bytes and tmp_path only. Retail tests need OPENUA_POR_INSTALL (the
pinned POOLRAD folder) and skip without it. They read the install and never write to it; mutation controls
work on in-memory copies of GAME.OVR and START.EXE.

Positive control: the 0x21 probe's own control (far call at GAME.OVR 0x19C3 set to 9A 0C 00 C0 03, image
15884) must be paragraph-consistent here, with DI = 0. Negative control: moving stub 6's proc word must
remove the stub and the verdict must fall to precondition-failed. Together they show the verdict follows the
bytes in both directions.
"""

import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl_21_fixup_residue_probe as r  # noqa: E402
import por_ecl_21_dispatch_probe as p  # noqa: E402

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
needs_retail = pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")

HDR = 0x200
S6 = r.STUB6_F  # 15884 == 0x3E0C
FILEOFS = 0x0D46
CODESZ = 0x350D


def _retail():
    install = Path(RETAIL)
    return install, (install / "GAME.OVR").read_bytes(), (install / "START.EXE").read_bytes()


# ---------------------------------------------------------------------------------------------
# Residue arithmetic (synthetic integers)
# ---------------------------------------------------------------------------------------------

def test_stub6_offset_is_0x3e0c_and_residue_is_c():
    assert S6 == 0x3E0C
    assert (S6 - HDR) % 16 == 0xC


def test_positive_control_offset_c_is_paragraph_consistent_with_di_zero():
    # 9A 0C 00 C0 03 at 0x19C3: seg 0x03C0, off 0x000C; image 0x200 + 0x3C00 + 0x0C = 0x3E0C.
    rec = r.residue_for(0x0C, 0x03C0, HDR)
    assert rec["paragraph_consistent"] is True
    assert rec["skew_needed_mod16"] == 0
    assert rec["di_needed_mod64k"] == 0


def test_offset_c_mod_16_reaches_with_some_di_value():
    # off 0x1C is also ≡ 0xC (mod 16): paragraph-consistent, with a DI that depends on the literal seg.
    rec = r.residue_for(0x1C, 0x0100, HDR)
    assert rec["paragraph_consistent"] is True
    assert rec["di_needed_mod64k"] == ((S6 - HDR - 0x1C) // 16 - 0x0100) % 0x10000


def test_offset_one_past_c_needs_cok_minus_one_skew():
    rec = r.residue_for(0x0D, 0x03C0, HDR)
    assert rec["paragraph_consistent"] is False
    assert rec["skew_needed_mod16"] == 15
    assert rec["skew_labels"] == ["cok_minus_1"]


def test_quoted_0x50a_displacement_labels_both_signs():
    assert r.SKEW_LABELS["quoted_0x50a_plus"] == 10
    assert r.SKEW_LABELS["quoted_0x50a_minus"] == 6
    assert r.residue_for(0x16, 0x3C0, HDR)["skew_labels"] == ["quoted_0x50a_minus"]


@pytest.mark.parametrize("off,skew", [(0x2A, 2), (0x25, 7), (0x43, 9), (0xB0B, 1), (0x3E, 14),
                                      (0x27D9, 3), (0x767, 5)])
def test_retail_site_offsets_need_nonzero_skew(off, skew):
    rec = r.residue_for(off, 0x0100, HDR)
    assert rec["skew_needed_mod16"] == skew
    assert rec["paragraph_consistent"] is False


# ---------------------------------------------------------------------------------------------
# Site records: listed versus literal (synthetic)
# ---------------------------------------------------------------------------------------------

def test_listed_site_at_offset_c_is_candidate():
    at = FILEOFS + 0xC80 - 3  # seg word body offset 0xC80 (the 0x19C3 site's body position)
    listed = {0xC80}
    rec = r.site_record(at, 0x3C0, 0x0C, FILEOFS, listed, HDR)
    assert rec["seg_word_listed"] is True
    assert rec["stub6_candidate_site"] is True


def test_falsifier_offset_moved_by_one_is_not_candidate():
    at = FILEOFS + 0xC80 - 3
    rec = r.site_record(at, 0x3C0, 0x0D, FILEOFS, {0xC80}, HDR)
    assert rec["stub6_candidate_site"] is False
    assert rec["residue"]["skew_needed_mod16"] == 15


def test_unlisted_seg_word_is_literal_and_hits_only_exact_target():
    at = FILEOFS + 0xC80 - 3
    assert r.site_record(at, 0x3C0, 0x0C, FILEOFS, set(), HDR)["stub6_candidate_site"] is True
    assert r.site_record(at, 0x3C1, 0x0C, FILEOFS, set(), HDR)["stub6_candidate_site"] is False
    assert r.site_record(at, 0x3C0, 0x0C, FILEOFS, set(), HDR)["residue"] is None


def test_listed_offset_word_is_reported_not_hidden():
    at = FILEOFS + 0xC80 - 3
    rec = r.site_record(at, 0x3C0, 0x0C, FILEOFS, {0xC80, 0xC7E}, HDR)
    assert rec["off_word_listed"] is True  # the precondition check in analyse() then fails


# ---------------------------------------------------------------------------------------------
# Table facts and header (synthetic bytes)
# ---------------------------------------------------------------------------------------------

def test_table_bare_sorted_in_range_is_accepted():
    f = r.table_facts([0x2D, 0x32, 0x5F, 0x64], CODESZ)
    assert f["bare_offsets"] is True and f["sorted"] is True and f["duplicates"] == 0


def test_falsifier_unsorted_table_is_not_bare():
    assert r.table_facts([0x32, 0x2D], CODESZ)["bare_offsets"] is False


def test_falsifier_word_outside_code_is_not_bare():
    assert r.table_facts([0x2D, CODESZ], CODESZ)["bare_offsets"] is False


def test_duplicates_are_counted():
    assert r.table_facts([0x2D, 0x2D, 0x32], CODESZ)["duplicates"] == 1


def test_fixup_words_reads_fixupsz_over_2_words():
    ovr = bytearray(FILEOFS + CODESZ + 8)
    struct.pack_into("<4H", ovr, FILEOFS + CODESZ, 0x2D, 0x32, 0x5F, 0x64)
    assert r.fixup_words(bytes(ovr), FILEOFS, CODESZ, 8) == [0x2D, 0x32, 0x5F, 0x64]


def test_fixup_words_refuses_short_overlay():
    with pytest.raises(r.ResidueRefusal, match="too short"):
        r.fixup_words(b"\x00" * 10, FILEOFS, CODESZ, 804)


def _start_with_header(fileofs, codesz, fixupsz, jmpcnt, magic=b"\xcd\x3f\x00\x00"):
    s = bytearray(0x4000)
    s[r.HEADER_AT:r.HEADER_AT + 4] = magic
    struct.pack_into("<IHHH", s, r.HEADER_AT + 4, fileofs, codesz, fixupsz, jmpcnt)
    return bytes(s)


def test_header_reads_expected_group():
    h = r.read_header(_start_with_header(0xD46, 0x350D, 804, 2))
    assert h["matches_expected_group"] is True
    assert h["fileofs"] == 0xD46 and h["fixupsz"] == 804


def test_falsifier_header_with_other_fixupsz_does_not_match():
    h = r.read_header(_start_with_header(0xD46, 0x350D, 806, 2))
    assert h["matches_expected_group"] is False


def test_falsifier_header_with_wrong_magic_does_not_match():
    h = r.read_header(_start_with_header(0xD46, 0x350D, 804, 2, magic=b"\x00\x00\x00\x00"))
    assert h["magic_ok"] is False and h["matches_expected_group"] is False


# ---------------------------------------------------------------------------------------------
# Verdict rules
# ---------------------------------------------------------------------------------------------

_OK = {"a": True, "b": True}


def test_no_candidate_and_preconditions_hold_gives_none_status():
    rows = [{"at": "0x19C3", "stub6_candidate_site": False}]
    v = r.decide(rows, _OK)
    assert v["stub6_status"] == r.STATUS_NONE
    assert v["candidate_sites"] == []


def test_candidate_gives_candidate_status_never_established():
    rows = [{"at": "0x19C3", "stub6_candidate_site": True}]
    v = r.decide(rows, _OK)
    assert v["stub6_status"] == r.STATUS_CANDIDATE
    assert v["candidate_sites"] == ["0x19C3"]
    assert v["stub6_status"] != "established"


def test_failed_precondition_gives_precondition_status_even_with_candidate():
    rows = [{"at": "0x19C3", "stub6_candidate_site": True}]
    v = r.decide(rows, {"a": True, "b": False})
    assert v["stub6_status"] == r.STATUS_PRECONDITION
    assert v["failed_preconditions"] == ["b"]


# ---------------------------------------------------------------------------------------------
# Output refusals (input-free)
# ---------------------------------------------------------------------------------------------

def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    with pytest.raises(r.ResidueRefusal, match="inside the install"):
        r.check_out(install / "out", install)


def test_output_outside_data_work_is_refused(tmp_path):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    with pytest.raises(r.ResidueRefusal, match="under data/work"):
        r.check_out(tmp_path / "elsewhere", install)


def test_missing_input_is_refused(tmp_path):
    with pytest.raises(p.ProbeRefusal, match="not found"):
        p.load_inputs(tmp_path)


# ---------------------------------------------------------------------------------------------
# Retail anchor (install-gated, read-only)
# ---------------------------------------------------------------------------------------------

@needs_retail
def test_retail_verdict_is_no_site_reaches_stub6_under_paragraph_base():
    _, ovr, start = _retail()
    doc = r.analyse(start, ovr)
    assert all(doc["preconditions"].values()), doc["preconditions"]
    assert doc["verdict"]["stub6_status"] == r.STATUS_NONE
    assert doc["verdict"]["candidate_sites"] == []
    assert doc["fixup_records_give_base"] is False
    assert doc["di_established"] is False


@needs_retail
def test_retail_all_eleven_seg_words_listed_and_no_offset_word_listed():
    _, ovr, start = _retail()
    doc = r.analyse(start, ovr)
    assert doc["listed_seg_word_count"] == 11
    assert all(s["seg_word_listed"] for s in doc["sites"])
    assert not any(s["off_word_listed"] for s in doc["sites"])


@needs_retail
def test_retail_each_site_needs_the_expected_nonzero_skew():
    _, ovr, start = _retail()
    doc = r.analyse(start, ovr)
    expected = {"0x19C3": 2, "0x19DA": 7, "0x1A27": 9, "0x1A53": 1, "0x1A5E": 7,
                "0x1A77": 14, "0x1A9E": 14, "0x1AAA": 14, "0x1AD6": 14, "0x1B1A": 3, "0x1B27": 5}
    got = {s["at"]: s["residue"]["skew_needed_mod16"] for s in doc["sites"]}
    assert got == expected
    assert doc["skew_summary"]["paragraph_consistent_sites"] == []


@needs_retail
def test_retail_stub6_is_index_6_of_group_0x3dd7_with_expected_bytes():
    _, ovr, start = _retail()
    doc = r.analyse(start, ovr)
    assert start[S6:S6 + 5] == r.STUB6_BYTES
    rows = doc["stub6"]["candidate_rows"]
    assert len(rows) == 1 and rows[0]["stub_index"] == 6 and rows[0]["stub_image_f"] == S6


@needs_retail
def test_positive_control_offset_c_site_becomes_candidate():
    # Same edit the 0x21 probe uses as its positive control: 0x19C3 -> 9A 0C 00 C0 03 (image 15884).
    _, ovr, start = _retail()
    mut = bytearray(ovr)
    mut[0x19C3:0x19C8] = bytes.fromhex("9a 0c 00 c0 03")
    doc = r.analyse(start, bytes(mut))
    assert doc["verdict"]["stub6_status"] == r.STATUS_CANDIDATE
    assert doc["verdict"]["candidate_sites"] == ["0x19C3"]
    row = next(s for s in doc["sites"] if s["at"] == "0x19C3")
    assert row["residue"]["di_needed_mod64k"] == 0


@needs_retail
def test_negative_control_moved_stub6_proc_word_removes_stub():
    _, ovr, start = _retail()
    mut = bytearray(start)
    mut[S6 + 2] = (mut[S6 + 2] + 1) & 0xFF  # proc word 0x0E08 -> 0x0E09 (low byte; in START.EXE)
    doc = r.analyse(bytes(mut), ovr)
    assert doc["verdict"]["stub6_status"] == r.STATUS_PRECONDITION
    assert doc["preconditions"]["stub6_is_index6_of_0x3DD7"] is False


@needs_retail
def test_negative_control_moved_call_offset_loses_candidate_status():
    # Moving the positive-control call's offset by one moves its residue off 0xC: no candidate.
    _, ovr, start = _retail()
    mut = bytearray(ovr)
    mut[0x19C3:0x19C8] = bytes.fromhex("9a 0d 00 c0 03")
    doc = r.analyse(start, bytes(mut))
    assert doc["verdict"]["candidate_sites"] == []
    assert doc["verdict"]["stub6_status"] == r.STATUS_NONE


@needs_retail
def test_table_mutation_that_lists_an_offset_word_fails_precondition():
    _, ovr, start = _retail()
    mut = bytearray(ovr)
    n = r.EXPECT_GROUP["fixupsz"] // 2
    base = FILEOFS + CODESZ
    words = list(struct.unpack_from("<%dH" % n, mut, base))
    words[0] = 0xC7E  # lists the 0x19C3 site's offset word (body 0xC7E); the table is no longer sorted
    struct.pack_into("<%dH" % n, mut, base, *words)
    doc = r.analyse(start, bytes(mut))
    assert doc["verdict"]["stub6_status"] == r.STATUS_PRECONDITION


@needs_retail
def test_retail_analysis_is_deterministic():
    _, ovr, start = _retail()
    assert r.analyse(start, ovr) == r.analyse(start, ovr)
