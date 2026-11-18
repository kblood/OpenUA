"""Tests for tools/por_ecl_21_dispatch_probe.py.

Input-free tests run everywhere: the pin refusals and the output-folder refusals use dummy files and
tmp_path only. Retail tests need OPENUA_POR_INSTALL (the pinned POOLRAD folder) and skip without it.
They read the install and write only under pytest's tmp_path (the probe's CLI output rule is
exercised separately, with a refusal).

Mutation controls work on in-memory copies of the retail GAME.OVR. Each mutation changes one thing and
the named verdict or self-check must change with it. The positive control retargets one far call onto
the GEO stub and must flip the status to candidate-edge; the negative control moves that stub's proc
word and must remove the candidate. Together they show the verdict follows the bytes, both ways.
"""

import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl_21_dispatch_probe as p  # noqa: E402

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
needs_retail = pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")

ARM_CMP_AT = 0x3D9A           # cmp al,0x21 (3C 21)
ARM_CALL_AT = 0x3DA3          # E8 rel16 into the 0x19BA handler (after push cs at 0x3DA2)
FAR_19C3 = 0x19C3             # 9A 2A 00 2B 00  call 0x002B:0x002A (stub 21 of group 0x74D3)
GEO_STUB_OFF = 15884          # START.EXE offset: stub index 6 of partial group (run at 15854): CD 3F <0E08> 00
GEO_PROC = 0x0E08             # 3592: 0x2E8F7 + 0xE08 == 0x2F6FF (the proc word is in START.EXE, not GAME.OVR)


def _retail():
    install = Path(RETAIL)
    return install, (install / "GAME.OVR").read_bytes(), (install / "START.EXE").read_bytes()


# ---------------------------------------------------------------------------------------------
# Input-free: refusals and the output rule
# ---------------------------------------------------------------------------------------------

def test_missing_input_is_refused(tmp_path):
    with pytest.raises(p.ProbeRefusal, match="not found"):
        p.load_inputs(tmp_path)


def test_unpinned_input_is_refused(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the retail overlay")
    (tmp_path / "START.EXE").write_bytes(b"not the retail resident")
    with pytest.raises(p.ProbeRefusal, match="does not match its pin"):
        p.load_inputs(tmp_path)


def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    with pytest.raises(p.ProbeRefusal, match="inside the install"):
        p._check_out(install / "out", install)


def test_output_outside_data_work_is_refused(tmp_path):
    with pytest.raises(p.ProbeRefusal, match="under data/work"):
        p._check_out(tmp_path / "out", tmp_path / "POOLRAD")


def test_output_under_data_work_is_accepted(tmp_path):
    p._check_out(p.DATA_WORK / "por-ecl-21-dispatch-probe-test", tmp_path / "POOLRAD")


def test_pins_are_the_retail_sizes():
    assert p.PINS["GAME.OVR"][0] == 206105
    assert p.PINS["START.EXE"][0] == 65231
    assert p.GEO_BODY == 0x2F6FF
    assert p.LOOP_ENTRY == 0x3EB7 and p.DISPATCH_ENTRY == 0x3C73


# ---------------------------------------------------------------------------------------------
# Retail: expected reading, the GEO entry, and the reachability limit
# ---------------------------------------------------------------------------------------------

@needs_retail
def test_retail_arm_0x21_is_a_direct_edge_to_0x19ba():
    _, ovr, _ = _retail()
    arm = p.dispatch_arm(ovr, 0x21)
    assert arm["present"] is True
    assert arm["form"] == "je-group"
    assert arm["compare_at"] == "0x3D9A"
    assert arm["call_at"] == "0x3DA3"
    assert arm["handler"] == "0x19BA"
    assert arm["direct_e8_edge"] is True
    assert arm["cross_check_consistent"] is True


@needs_retail
def test_retail_control_0x37_shares_the_handler():
    _, ovr, _ = _retail()
    assert p.dispatch_arm(ovr, 0x37)["handler"] == "0x19BA"


@needs_retail
def test_retail_loop_reaches_the_dispatcher_by_a_key_store_then_call():
    _, ovr, _ = _retail()
    lp = p.loop_report(ovr)
    assert lp["sequence_found"] is True
    assert lp["key_store_at"] == "0x3EE7"
    assert lp["dispatch_call_at"] == "0x3EEB"
    assert lp["dispatch_call_target"] == "0x3C73"
    assert lp["key_store_immediately_before_call"] is True
    assert lp["loop_advances_cursor"] is False
    assert lp["raw_e8_caller_count"] == 9
    assert lp["reachability"].startswith("not-established")


@needs_retail
def test_retail_handler_has_no_near_or_indirect_calls_and_eleven_far_calls():
    _, ovr, _ = _retail()
    hr = p.handler_report(ovr, 0x19BA)
    assert hr["walk_complete"] is True
    assert hr["near_calls"] == []
    assert hr["indirect"] == []
    assert len(hr["far_calls"]) == 11
    assert hr["far_calls"][0]["text"] == "call 0x002b:0x002a"
    assert hr["far_calls"][1]["text"] == "call 0x002b:0x0025"


@needs_retail
def test_retail_geo_body_is_a_prologue_with_one_partial_stub_candidate():
    install, ovr, start = _retail()
    assert ovr[p.GEO_BODY:p.GEO_BODY + 3] == p.GEO_BODY_PRO
    cands = p.geo_stub_candidates(start, ovr, p.GEO_BODY)
    valid = [c for c in cands if c["stub_valid"]]
    assert len(valid) == 1
    assert valid[0]["group_fileofs"] == "0x2E8F7"
    assert valid[0]["group_status"] == "partial"
    assert valid[0]["stub_index"] == 6
    assert valid[0]["stub_image_f"] == 15884


@needs_retail
def test_retail_far_calls_do_not_reach_the_geo_stub_under_zero_skew():
    _, ovr, start = _retail()
    doc = p.analyse(ovr, start)
    assert doc["geo"]["geo_call_status"] == "not-established"
    assert doc["geo"]["zero_skew_edges_to_geo"] == []
    assert len(doc["geo"]["model_dependent_far_calls"]) == 9
    stub_rows = [r for r in doc["far"]["rows"] if r["stub"] is not None]
    assert [r["stub"]["gameovr_target"] for r in stub_rows] == ["0x92C3", "0x9196"]


@needs_retail
def test_retail_self_checks_pass_and_inputs_are_unchanged(tmp_path):
    install, _, _ = _retail()
    before = {n: p._sha((install / n).read_bytes()) for n in p.PINS}
    doc, code = p.probe(install, tmp_path)
    assert code == 0, [c for c in doc["self_checks"] if not c["ok"]]
    assert all(c["ok"] for c in doc["self_checks"])
    after = {n: p._sha((install / n).read_bytes()) for n in p.PINS}
    assert before == after


@needs_retail
def test_retail_analysis_is_deterministic():
    _, ovr, start = _retail()
    assert p.analyse(ovr, start) == p.analyse(ovr, start)


# ---------------------------------------------------------------------------------------------
# Mutation and falsification controls (retail bytes, in memory only)
# ---------------------------------------------------------------------------------------------

@needs_retail
def test_control_moved_compare_removes_the_arm():
    """Change the 0x21 compare value to one the dispatcher does not use. The arm must disappear."""
    _, ovr, start = _retail()
    assert 0xEE not in [c["case"] for c in p.h.dispatch_cases(ovr)["cases"]]
    m = bytearray(ovr)
    assert m[ARM_CMP_AT:ARM_CMP_AT + 2] == b"\x3c\x21"
    m[ARM_CMP_AT + 1] = 0xEE
    doc = p.analyse(bytes(m), start)
    assert doc["arm"]["present"] is False
    assert doc["geo"]["geo_call_status"] == "arm-absent"


@needs_retail
def test_control_retargeted_dispatch_call_breaks_the_handler_check():
    """Move the dispatch E8 at 0x3DA3 by one byte. The arm still decodes, but its handler is no longer 0x19BA."""
    _, ovr, start = _retail()
    m = bytearray(ovr)
    assert m[ARM_CALL_AT] == 0xE8
    rel = struct.unpack_from("<h", m, ARM_CALL_AT + 1)[0]
    struct.pack_into("<h", m, ARM_CALL_AT + 1, rel + 1)
    doc = p.analyse(bytes(m), start)
    assert doc["arm"]["handler"] != "0x19BA"
    checks = {c["name"]: c["ok"] for c in p.self_checks(doc, {}, {})}
    assert checks["arm_handler_is_expected"] is False


@needs_retail
def test_positive_control_far_call_onto_geo_stub_flips_to_candidate_edge():
    """Retarget the 0x19C3 far call to seg:off 0x03C0:0x000C. Image 512+0x3C0*16+0xC == 15884, the GEO stub."""
    _, ovr, start = _retail()
    m = bytearray(ovr)
    assert m[FAR_19C3:FAR_19C3 + 5] == b"\x9a\x2a\x00\x2b\x00"
    m[FAR_19C3:FAR_19C3 + 5] = b"\x9a\x0c\x00\xc0\x03"
    doc = p.analyse(bytes(m), start)
    assert doc["geo"]["geo_call_status"] == "candidate-edge"
    hits = doc["geo"]["zero_skew_edges_to_geo"]
    assert [(h["at"], h["group_header"], h["stub_index"]) for h in hits] == [("0x19C3", "0x3DD7", 6)]


def _moved_geo_stub(start: bytes) -> bytes:
    s = bytearray(start)
    assert s[GEO_STUB_OFF:GEO_STUB_OFF + 4] == b"\xcd\x3f" + struct.pack("<H", GEO_PROC)[:2]
    struct.pack_into("<H", s, GEO_STUB_OFF + 2, GEO_PROC + 1)
    return bytes(s)


@needs_retail
def test_negative_control_moved_geo_stub_removes_the_candidate():
    """Move the GEO stub's proc word (in START.EXE) by one byte. No stub now names 0x2F6FF: no candidate."""
    _, ovr, start = _retail()
    s2 = _moved_geo_stub(start)
    assert p.geo_stub_candidates(start, ovr, p.GEO_BODY) != []
    assert p.geo_stub_candidates(s2, ovr, p.GEO_BODY) == []
    doc = p.analyse(ovr, s2)
    assert doc["geo"]["geo_stub_candidates"] == []
    assert doc["geo"]["geo_call_status"] == "not-established"


@needs_retail
def test_positive_and_negative_controls_are_independent():
    """The candidate-edge verdict needs both the stub and the far call. Losing the stub loses it."""
    _, ovr, start = _retail()
    m = bytearray(ovr)
    m[FAR_19C3:FAR_19C3 + 5] = b"\x9a\x0c\x00\xc0\x03"
    assert p.analyse(bytes(m), start)["geo"]["geo_call_status"] == "candidate-edge"
    doc = p.analyse(bytes(m), _moved_geo_stub(start))
    assert doc["geo"]["geo_call_status"] == "not-established"
    assert doc["geo"]["zero_skew_edges_to_geo"] == []
