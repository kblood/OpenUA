"""Tests for tools/por_geo_stub_farcall_argpush_shape.py.

Input-free tests (synthetic bytes and tmp_path only) run everywhere: the instruction-aligned shape scan and its
falsifiers, the fall-through chain, the branch-join and entry rules, the strong-walk mirror against the census, the
ambiguity label, and the output refusals. The retail anchor needs OPENUA_POR_INSTALL (the pinned POOLRAD folder)
and skips without it. It runs the probe only (no output is written) and checks that the inputs are unchanged.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as h  # noqa: E402
import por_geo_stub_farcall_census as c  # noqa: E402
import por_geo_loader_caller_frame_probe as lcf  # noqa: E402
import por_geo_stub_farcall_argpush_shape as a  # noqa: E402

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
needs_retail = pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")

DOC_ID = bytes.fromhex("8a46fe50")      # mov al,[bp-2]; push ax  (documented id form)
IMM_ID = bytes.fromhex("b00150")        # mov al,1; push ax       (variant id form)
PTR_A = bytes.fromhex("8d7efb" "16" "57")   # lea di,[bp-5]; push ss; push di
PTR_B = bytes.fromhex("8d7efa" "16" "57")   # lea di,[bp-6]; push ss; push di
PTR_ONE = bytes.fromhex("8d7efa" "16" "57")

EXPECTED_STRONG_LOADER_SHAPE_AT = {
    "0x14C4E", "0x17D07", "0x18168", "0x1820A", "0x182A0", "0x183B9", "0x18422", "0x1861E", "0x1C900",
}


def _nearest(blob: bytes) -> list:
    """Linear decode of a shape-only blob, returned nearest-first (the instruction before 'the call')."""
    out = []
    q = 0
    while q < len(blob):
        ins = h.decode(blob, q)
        out.append(ins)
        q = ins.end
    assert q == len(blob)
    return list(reversed(out))


def _scan(blob: bytes) -> dict:
    return a.shape_scan(_nearest(blob))


def _walk_group(blob: bytes, seeds=(0,)):
    insns, owned, errors = {}, {}, []
    stats = {"out_of_body": 0, "overlaps": 0, "budget": False}
    c._walk(blob, 0, len(blob), list(seeds), insns, owned, True, errors, stats)
    return insns, owned


def _group(fileofs, codesz, procs=(0,)):
    return {
        "header_offset": 0, "stub_delta": 0x16, "stub_count": len(procs), "stub_start": 0,
        "stub_end": 5 * len(procs), "fileofs": fileofs, "codesz": codesz, "fixupsz": 0,
        "procs": list(procs), "stub_valid": [True] * len(procs), "status": "well-formed",
    }


# ---------------------------------------------------------------------------------------------
# Shape scan (instruction-aligned)
# ---------------------------------------------------------------------------------------------

def test_documented_id_two_pointers_is_loader_shape():
    s = _scan(DOC_ID + PTR_A + PTR_B)
    assert s["class"] == a.CLS_DOC
    assert s["pointer_pairs"] == 2
    assert s["id_form"] == a.ID_BP_FORM
    assert s["lea_disp"] == [-6, -5]
    assert s["id_operand"] == -2


def test_imm_id_two_pointers_is_loader_shape_variant():
    s = _scan(IMM_ID + PTR_A + PTR_B)
    assert s["class"] == a.CLS_IMM
    assert s["id_form"] == a.ID_IMM_FORM
    assert s["id_operand"] == 1
    assert s["consumed"] == 8


def test_two_pointers_without_id_is_pair_no_id():
    s = _scan(PTR_A + PTR_B)
    assert s["class"] == a.CLS_PAIR_NOID
    assert s["id_form"] is None


def test_one_pointer_with_id_is_one_pointer():
    s = _scan(IMM_ID + PTR_ONE)
    assert s["class"] == a.CLS_ONE
    assert s["pointer_pairs"] == 1


def test_no_pointer_is_no_pointer_pair():
    s = _scan(IMM_ID)
    assert s["class"] == a.CLS_NONE
    assert s["pointer_pairs"] == 0
    assert s["id_form"] == a.ID_IMM_FORM


def test_three_pointers_is_more_than_two():
    s = _scan(PTR_A + PTR_B + PTR_B)
    assert s["class"] == a.CLS_MORE


def test_push_cs_pointer_is_not_the_loader_shape():
    # Falsifier: the same pointer shape pushed with CS instead of SS is not the loader's push.
    push_cs_a = bytes.fromhex("8d7efb" "0e" "57")
    push_cs_b = bytes.fromhex("8d7efa" "0e" "57")
    s = _scan(DOC_ID + push_cs_a + push_cs_b)
    assert s["class"] == a.CLS_NONE
    assert s["pointer_pairs"] == 0


def test_swapped_ss_di_order_is_not_a_pointer():
    # Falsifier: push di before push ss (the far-pointer order is seg then off).
    swapped = bytes.fromhex("8d7efb" "57" "16")
    s = _scan(DOC_ID + swapped + swapped)
    assert s["pointer_pairs"] == 0


def test_lea_si_is_not_the_loader_pointer():
    # Falsifier: lea si rather than lea di.
    lea_si = bytes.fromhex("8d76fb" "16" "57")
    s = _scan(DOC_ID + lea_si + PTR_B)
    assert s["class"] == a.CLS_ONE
    assert s["pointer_pairs"] == 1


def test_id_pushed_after_pointers_is_not_the_id_slot():
    # Falsifier: the id pair must sit before the two pointers, not after them.
    s = _scan(PTR_A + PTR_B + DOC_ID)
    assert s["pointer_pairs"] == 0
    assert s["id_form"] == a.ID_BP_FORM  # the id is nearest-first last; the scan sees it only at pos 0
    assert s["class"] == a.CLS_NONE


def test_scan_is_deterministic():
    blob = IMM_ID + PTR_A + PTR_B
    assert _scan(blob) == _scan(blob)


def test_scan_agrees_with_byte_regex_on_synthetic_shapes():
    for blob in (DOC_ID + PTR_A + PTR_B, IMM_ID + PTR_A + PTR_B, PTR_A + PTR_B, DOC_ID + PTR_A):
        s = _scan(blob)
        hit = lcf.SHAPE_RE.search(blob) is not None  # SHAPE_RE is anchored at the end of the pushed bytes
        assert hit == (s["class"] in a.LOADER_SHAPE_CLASSES)


# ---------------------------------------------------------------------------------------------
# Fall-through chain, joins and entries (classify_site on a synthetic group)
# ---------------------------------------------------------------------------------------------

CALL = bytes.fromhex("9a" "0000" "8500")         # far call to 0085:0000


def _site_blob(pre: bytes) -> bytes:
    return pre + PTR_A + PTR_B + CALL


def test_clean_shape_with_no_branch_is_clean():
    blob = _site_blob(IMM_ID)
    at = len(blob) - len(CALL)
    insns, owned = _walk_group(blob)
    row = a.classify_site(blob, insns, owned, a.branch_targets(insns), at)
    assert row["shape_class"] == a.CLS_IMM
    assert row["clean_shape"] is True
    assert row["raw_bytes_match_input"] is True
    assert row["window_branch_joins"] == []
    assert row["entered_by_branch"] is False


def test_branch_into_the_window_is_a_join_not_clean():
    # je +2 at offset 0 lands on the push ax of the id pair (offset 4): a join inside the shape window.
    blob = bytes.fromhex("7402") + _site_blob(IMM_ID)
    at = len(blob) - len(CALL)
    insns, owned = _walk_group(blob)
    row = a.classify_site(blob, insns, owned, a.branch_targets(insns), at)
    assert row["shape_class"] == a.CLS_IMM
    assert row["window_branch_joins"] == ["0x4"]
    assert row["clean_shape"] is False


def test_branch_to_the_call_itself_is_entered_by_branch_not_clean():
    # je to the call's own offset (2 + 13 = 15): a second path reaches the call with other pushes.
    pre = IMM_ID + PTR_A + PTR_B
    blob = bytes([0x74, len(pre)]) + pre + CALL
    at = len(blob) - len(CALL)
    insns, owned = _walk_group(blob)
    row = a.classify_site(blob, insns, owned, a.branch_targets(insns), at)
    assert row["entered_by_branch"] is True
    assert row["clean_shape"] is False
    assert row["shape_class"] == a.CLS_IMM


def test_no_fallthrough_predecessor_is_ambiguous():
    # Falsifier: nothing decoded abuts the call, so no immediate stack setup can be claimed.
    row = a.classify_site(CALL, {}, {}, {}, 0)
    assert row["fallthrough_predecessor"] is None
    assert row["shape_class"] == a.CLS_AMBIG
    assert row["clean_shape"] is False


def test_strong_mirror_matches_census_far_set_on_synthetic_group():
    blob = IMM_ID + PTR_A + PTR_B + CALL + bytes.fromhex("c3")
    g = _group(0, len(blob))
    insns, _owned, far = a.strong_walk(blob, g)
    cg = c.census_group(blob, g)
    assert far == {f["at"] for f in cg["far_decoded"] if f["strong"]}
    assert len(far) == 1


def test_control_linear_chain_matches_byte_regex_on_synthetic_proc():
    # A linear chain from proc 0 to the site must give the same answer as the byte-level regex.
    blob = DOC_ID + PTR_A + PTR_B
    back = a.linear_chain(blob, 0, len(blob))
    assert back is not None
    assert a.shape_scan(back)["class"] == a.CLS_DOC


def test_linear_chain_refuses_when_it_does_not_land_on_site():
    blob = DOC_ID + PTR_A + PTR_B
    assert a.linear_chain(blob, 0, len(blob) + 1) is None


# ---------------------------------------------------------------------------------------------
# Refusals (no output)
# ---------------------------------------------------------------------------------------------

def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "inst"
    install.mkdir()
    with pytest.raises(a.c.CensusRefusal):
        c.check_out(install / "out", install)
    assert a.main(["--install", str(install), "-o", str(install / "out")]) == 2


def test_output_outside_data_work_is_refused(tmp_path):
    install = tmp_path / "inst"
    install.mkdir()
    assert a.main(["--install", str(install), "-o", str(tmp_path / "elsewhere")]) == 2


# ---------------------------------------------------------------------------------------------
# Retail anchor (OPENUA_POR_INSTALL; read-only)
# ---------------------------------------------------------------------------------------------

@needs_retail
def test_retail_pins_and_counts():
    install = Path(RETAIL)
    out_dir = a.DATA_WORK / "por-geo-stub-farcall-argpush-shape" / "pytest-not-written"
    before = c._hashes(install)
    doc, code = a.probe(install, out_dir)
    after = c._hashes(install)
    assert before == after
    assert doc["inputs_pinned"] is True
    assert code == 0, [x for x in doc["self_checks"] if not x["ok"]]
    t = doc["totals"]
    assert t["census_candidate_sites"] == 181
    assert t["strong_candidate_sites"] == 166
    assert t["analysed_strong_sites"] == 166
    assert t["mismatched_strong_sites"] == 0
    assert t["ambiguous_no_fallthrough_predecessor"] == 0
    assert t["entered_by_branch"] == 0
    assert t["loader_shape_documented_id"] == 0
    assert t["loader_shape_imm_id"] == 9
    assert t["loader_shape_clean"] == 9
    assert t["shape_class_counts"] == {"loader-shape-imm-id": 9, "no-pointer-pair": 155, "one-pointer": 2}
    assert t["distinct_callees_of_loader_shape"] == ["0x85:0x5C"]
    assert doc["verdict"]["shape_status"] == a.VERDICT_IMM


@needs_retail
def test_retail_nine_loader_shape_sites_are_exactly_the_pinned_set():
    install = Path(RETAIL)
    doc, _code = a.probe(install, a.DATA_WORK / "por-geo-stub-farcall-argpush-shape" / "pytest-not-written")
    got = {r["at"] for r in doc["loader_shape_rows"]}
    assert got == EXPECTED_STRONG_LOADER_SHAPE_AT


@needs_retail
def test_retail_control_has_ten_sites_nine_documented_one_imm():
    install = Path(RETAIL)
    doc, _code = a.probe(install, a.DATA_WORK / "por-geo-stub-farcall-argpush-shape" / "pytest-not-written")
    ctrl = doc["control"]
    assert len(ctrl) == 10
    assert sum(1 for r in ctrl if r["shape_class"] == a.CLS_DOC) == 9
    assert sum(1 for r in ctrl if r["shape_class"] == a.CLS_IMM) == 1
    assert all(r["scan_agrees_with_byte_regex"] for r in ctrl)
