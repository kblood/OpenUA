"""Tests for tools/por_geo_stub_farcall_argpush_frame.py.

Input-free tests (synthetic bytes, no retail input) run everywhere: the frame equation K = 10 + L and its falsifiers,
the chain of two sites sharing a callee, the loader-identity refusal (0x12 is never borrowed), the push r/m16 model
gap (FF /6) against the existing Walk, the unmodelled-form refusal, the joint rule, and the refusals.

The retail anchors need OPENUA_POR_INSTALL (or the default data/work/por-geo-run/POOLRAD) and skip without it. The
probe is run once per session (about a minute) and writes nothing: probe() does not write; main() does.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_geo_loader_caller_frame_probe as L  # noqa: E402
import por_geo_stub_farcall_argpush_shape as A  # noqa: E402
import por_geo_stub_farcall_argpush_frame as F  # noqa: E402

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
DEFAULT_INSTALL = F.DEFAULT_INSTALL
RETAIL_PATH = Path(RETAIL) if RETAIL else DEFAULT_INSTALL
HAVE_RETAIL = (RETAIL_PATH / F.OVR_NAME).exists() and (RETAIL_PATH / F.EXE_NAME).exists()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned POOLRAD install not present")

PROLOGUE = bytes.fromhex("55 89 e5")                       # push bp; mov bp,sp
SHAPE = bytes.fromhex("b0 01 50" "8d 7e fb 16 57" "8d 7e fa 16 57")   # mov al,1; push ax; 2 far pointers (13 bytes)
CALL_857 = bytes.fromhex("9a 5c 00 85 00")                 # call 0085:005C
CALL_LOADER = bytes.fromhex("9a 16 07 02 08")              # call 0802:0716 (the GEO loader identity)
PUSH_AX = bytes.fromhex("50")
PUSH_MEM = bytes.fromhex("ff 36 94 5d")                    # push word [0x5D94]: FF /6, not modelled by the existing Walk
EXE_STUB = bytes(16)                                       # the copy-routine base is not used by synthetic windows


def _site_of(img: bytes, call: bytes, nth: int = 0) -> int:
    pos, k = -1, -1
    while True:
        pos = img.find(call, pos + 1)
        if pos < 0:
            raise AssertionError("call not found")
        k += 1
        if k == nth:
            return pos


def _single(pre: bytes) -> tuple[bytes, int]:
    img = PROLOGUE + pre + SHAPE + CALL_857
    return img, len(PROLOGUE) + len(pre) + len(SHAPE)


def _sweep_balanced(img: bytes, at: int) -> set:
    """K values (on the grid) for which the site's own frame balances, computed by the probe's own walk."""
    out = set()
    for K in F.K_GRID_A:
        r = F.walk_site(img, EXE_STUB, at, {F.TARGET: K})
        if r["walk_ok"] and F.bytes_above_floor(K, r["leftover_bytes"]) == 0:
            out.add(K)
    return out


# ---- the frame equation and its falsifiers --------------------------------------------------

def test_single_site_with_one_leftover_word_balances_only_at_twelve():
    img, at = _single(PUSH_AX)                         # one leftover word: L = 2
    r = F.walk_site(img, EXE_STUB, at, {F.TARGET: 12})
    assert r["walk_ok"] and r["leftover_bytes"] == 2
    assert _sweep_balanced(img, at) == {12}


def test_loader_retf_0x12_does_not_balance_a_two_byte_leftover():
    img, at = _single(PUSH_AX)
    assert F.bytes_above_floor(0x12, 2) == 6          # the over-pop the loader's 0x12 would leave here
    assert 0x12 not in _sweep_balanced(img, at)


def test_positive_control_eight_byte_leftover_balances_at_eighteen():
    # two far pointers left over before the shape (the loader's own leftover shape): L = 8, so K = 18
    left = bytes.fromhex("8d 7e f6 16 57" "8d 7e f0 16 57")
    img, at = _single(left)
    r = F.walk_site(img, EXE_STUB, at, {F.TARGET: 18})
    assert r["walk_ok"] and r["leftover_bytes"] == 8
    assert _sweep_balanced(img, at) == {18}


def test_balance_equation_is_k_minus_ten_minus_leftover():
    assert F.bytes_above_floor(12, 2) == 0
    assert F.bytes_above_floor(18, 8) == 0
    assert F.bytes_above_floor(18, 2) == 6            # over-pop into locals
    assert F.bytes_above_floor(10, 2) == -2           # leftover remains


# ---- the chain: two sites sharing a callee --------------------------------------------------

def test_two_sites_sharing_a_callee_have_no_common_balancing_pop(monkeypatch):
    # shape, call, shape, call: the first call's pop feeds the second site's leftover (L2 = 12 - K)
    img = PROLOGUE + PUSH_AX + SHAPE + CALL_857 + SHAPE + CALL_857
    at1 = _site_of(img, CALL_857, 0)
    at2 = _site_of(img, CALL_857, 1)
    assert at1 < at2
    assert _sweep_balanced(img, at1) == {12}
    assert _sweep_balanced(img, at2) == set()         # K = 10 + (12 - K) has no word-aligned solution


def test_joint_rule_is_empty_when_two_decided_sites_disagree(monkeypatch):
    img = PROLOGUE + PUSH_AX + SHAPE + CALL_857 + SHAPE + CALL_857
    at1 = _site_of(img, CALL_857, 0)
    at2 = _site_of(img, CALL_857, 1)
    monkeypatch.setitem(F.SITE_PARAMS, at1, (F.TARGET,))
    monkeypatch.setitem(F.SITE_PARAMS, at2, (F.TARGET,))
    sw = {at1: F.sweep_site(img, EXE_STUB, at1), at2: F.sweep_site(img, EXE_STUB, at2)}
    assert sw[at1]["walk_ok"] > 0 and sw[at2]["walk_ok"] > 0
    joint = F.joint_over_swept(sw)
    assert joint["joint_tuple_count"] == 0
    assert joint["joint_K_a_over_decided_sites"] == []


def test_undecided_site_is_listed_not_refuted():
    sw = {0x1000: {"swept": True, "walk_ok": 0, "parameters": ["K_a"], "balanced_K": [],
                   "walk_failed_by_reason": {"loop-not-modelled": 3}},
          0x2000: {"swept": True, "walk_ok": 5, "parameters": ["K_a"],
                   "balanced_K": [{"K": {"K_a": 12}}], "walk_failed_by_reason": {}}}
    joint = F.joint_over_swept(sw)
    assert joint["decided_sites"] == ["0x02000"]
    assert "0x01000" in joint["undecided_sites"]
    assert joint["joint_K_a_over_decided_sites"] == ["0x0C"]


# ---- the loader identity is never borrowed -------------------------------------------------

def test_call_to_the_loader_identity_fails_closed_not_twelve_or_eighteen():
    img, at = _single(CALL_LOADER + PUSH_AX)          # a loader call before the shape, then one word
    r = F.walk_site(img, EXE_STUB, at, {F.TARGET: 18})
    assert r["walk_ok"] is False
    assert "unknown callee 0802:0716" in r["fail"]
    assert F.classify_failure(r["fail"]) == "unknown-callee"


def test_site_target_must_be_a_far_call():
    img = PROLOGUE + SHAPE + b"\x90" * 5
    with pytest.raises(F.Refusal):
        F.site_target(img, len(PROLOGUE) + len(SHAPE))


def test_site_target_reads_offset_then_segment():
    img = PROLOGUE + SHAPE + CALL_857
    assert F.site_target(img, len(PROLOGUE) + len(SHAPE)) == (0x0085, 0x005C)


# ---- the push r/m16 gap (FF /6) in the existing walk ---------------------------------------

def test_existing_walk_ignores_push_memory_and_frame_walk_counts_it():
    img, at = _single(PUSH_MEM + PUSH_AX)              # two leftover words: L = 4 under FrameWalk
    proc, _ = L.find_proc(img, at)
    base = L.Walk(img, proc, at, F.resolver_for(EXE_STUB, {F.TARGET: 12}))
    base.run()
    assert base.fail is None and base.snapshot is not None
    assert sum(s.get("size", 2) for s in base.snapshot["slots"]) == 2   # the gap: the memory push is not counted
    r = F.walk_site(img, EXE_STUB, at, {F.TARGET: 14})
    assert r["walk_ok"] and r["leftover_bytes"] == 4
    assert F.bytes_above_floor(14, 4) == 0


def test_unmodelled_stack_form_fails_closed():
    img, at = _single(bytes.fromhex("68 00 00"))       # push imm16: not modelled
    r = F.walk_site(img, EXE_STUB, at, {F.TARGET: 12})
    assert r["walk_ok"] is False
    assert F.classify_failure(r["fail"] or "") in ("unmodelled-stack-op", "other")
    assert r["fail"] is not None


def test_classify_failure_labels():
    assert F.classify_failure("consumes below the pushed words (14 bytes, 12 pushed)") == "infeasible-over-pop"
    assert F.classify_failure("unknown callee 03c5:0039 at 0x18192 (no base)") == "unknown-callee"
    assert F.classify_failure("branch into 0x181AD with a different stack state") == "join-depth-mismatch"
    assert F.classify_failure("backward branch inside the window at 0x1C602") == "loop-not-modelled"
    assert F.classify_failure("stack op 0x68 at 0x10 is not modelled") == "unmodelled-stack-op"


# ---- refusals ------------------------------------------------------------------------------

def test_pins_refuse_unpinned_bytes():
    with pytest.raises(L.Refusal):
        L.check_pins(b"not GAME.OVR", b"not START.EXE")


def test_site_set_refuses_a_missing_or_altered_site():
    rows = [{"at": "0x%05X" % a, "owner_fileofs": "0x%X" % owner, "id_operand": imm,
             "lea_bp_disp": list(lea), "shape_class": A.CLS_IMM, "clean_shape": True}
            for a, (owner, imm, lea) in F.EXPECT_SITES.items()]
    assert F.verify_site_set(rows)["count"] == 9
    with pytest.raises(F.Refusal):
        F.verify_site_set(rows[:-1])
    bad = [dict(r) for r in rows]
    bad[0]["id_operand"] = 9
    with pytest.raises(F.Refusal):
        F.verify_site_set(bad)


def test_output_outside_data_work_or_inside_install_is_refused(tmp_path):
    with pytest.raises(F.Refusal):
        F.check_out(tmp_path / "out", tmp_path / "install")          # outside data/work
    install = F.DATA_WORK / "tmp-frame-install-test"
    with pytest.raises(F.Refusal):
        F.check_out(install / "out", install)                         # inside the install


def test_probe_with_no_retail_input_refuses_before_reading(tmp_path):
    with pytest.raises(F.Refusal):
        F.probe(tmp_path, F.DEFAULT_OUT)                              # out is under data/work, install is empty
    # (the install folder has no GAME.OVR; the read fails before any output is written)


# ---- retail anchors ------------------------------------------------------------------------

@pytest.fixture(scope="module")
def retail_doc():
    if not HAVE_RETAIL:
        pytest.skip("pinned POOLRAD install not present")
    doc, code = F.probe(RETAIL_PATH, F.DEFAULT_OUT)                   # probe() writes nothing
    return doc, code


@needs_retail
def test_retail_site_set_and_census_counts_are_exact(retail_doc):
    doc, _ = retail_doc
    assert doc["site_set"]["count"] == 9
    assert doc["census_counts"] == F.EXPECT_CENSUS
    assert doc["summary"]["target_0085_005C"] == 9


@needs_retail
def test_retail_inputs_unchanged_and_all_self_checks_pass(retail_doc):
    doc, code = retail_doc
    assert doc["inputs_hashes_before"] == doc["inputs_hashes_after"]
    assert code == 0
    assert all(c["ok"] for c in doc["self_checks"])


@needs_retail
def test_retail_single_callee_sites_need_a_pop_of_twelve_not_eighteen(retail_doc):
    doc, _ = retail_doc
    for at in ("0x14C4E", "0x17D07", "0x18168", "0x183B9"):
        r = next(x for x in doc["sites"] if x["at"] == at)["sweep"]
        assert r["leftover_bytes_seen"] == [2]
        assert r["balanced_K"] and {row["K"]["K_a"] for row in r["balanced_K"]} == {12}
        assert all(row["K"]["K_a"] != 0x12 for row in r["balanced_K"])


@needs_retail
def test_retail_joint_over_decided_sites_is_twelve_only_and_chain_sites_are_undecided(retail_doc):
    doc, _ = retail_doc
    j = doc["joint"]
    assert j["joint_K_a_over_decided_sites"] == ["0x0C"]
    assert j["joint_tuple_count"] == 7
    assert set(j["decided_sites"]) == {"0x14C4E", "0x17D07", "0x18168", "0x1820A", "0x183B9", "0x18422"}
    assert set(j["undecided_sites"]) == {"0x182A0", "0x1861E", "0x1C900"}


@needs_retail
def test_retail_loop_blocks_0x182a0_and_windows_are_too_large_for_the_rest(retail_doc):
    doc, _ = retail_doc
    s182 = next(x for x in doc["sites"] if x["at"] == "0x182A0")
    assert s182["sweep"]["walk_ok"] == 0
    assert s182["sweep"]["walk_failed_by_reason"].get("loop-not-modelled", 0) > 0
    assert s182["backward_branches_in_window"]
    s1c = next(x for x in doc["sites"] if x["at"] == "0x1C900")
    assert s1c["sweep"]["swept"] is False and len(s1c["static_unknown_callees"]) >= 5


@needs_retail
def test_retail_existing_walk_join_failure_is_the_push_memory_gap(retail_doc):
    doc, _ = retail_doc
    img = (RETAIL_PATH / F.OVR_NAME).read_bytes()
    exe = (RETAIL_PATH / F.EXE_NAME).read_bytes()
    proc, _ = L.find_proc(img, 0x1820A)
    base = L.Walk(img, proc, 0x1820A, F.resolver_for(exe, {F.TARGET: 12, F.CALLEE_C: 10}))
    base.run()
    # The existing walk fails at the near call 0x181A4: its retf 4 (6 bytes) finds only 2 pushed bytes, because
    # the two memory pushes [0x5D94], [0x5D92] before it were not counted. FrameWalk counts them and walks on.
    assert base.fail and "near call at 0x181A4" in base.fail and "consumes below" in base.fail
    fw = F.walk_site(img, exe, 0x1820A, {F.TARGET: 12, F.CALLEE_C: 10, F.CALLEE_G: 0})
    assert fw["walk_ok"]


@needs_retail
def test_retail_loader_controls_still_balance_under_their_own_twelve_eighteen(retail_doc):
    doc, _ = retail_doc
    for c in doc["control_loader_sites"]:
        assert c["walk_ok"] and c["leftover_bytes"] == 8 and c["balanced_with_loader_K"]
        assert c["frame_walk_agrees"]
