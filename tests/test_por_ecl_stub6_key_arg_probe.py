"""Falsifiers for tools/por_ecl_stub6_key_arg_probe.py.

Synthetic tests run without the retail install. Retail tests need the pinned install
(OPENUA_POR_INSTALL or data/work/por-geo-run/POOLRAD) and skip otherwise. Mutations are applied to
in-memory copies; the install is never written.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
_spec = importlib.util.spec_from_file_location("por_ecl_stub6_key_arg_probe", TOOLS / "por_ecl_stub6_key_arg_probe.py")
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)
import por_overlay_group_map as pogm  # noqa: E402

DUMP_PID = ROOT / "data" / "work" / "por-live-memory-pid34644" / "ram-000000-100000.bin"
DUMP_WHEEL = ROOT / "data" / "work" / "por-wheel-live-capture" / "ram-000000-100000.bin"


def _install():
    """The env-var install, else the default data/work copy; None if neither is present."""
    for cand in (None, ROOT / "data" / "work" / "por-geo-run" / "POOLRAD"):
        try:
            return pogm.find_install(cand)
        except Exception:
            continue
    return None


INSTALL = _install()
retail = pytest.mark.skipif(INSTALL is None or not (DUMP_PID.exists() and DUMP_WHEEL.exists()),
                            reason="needs pinned POOLRAD install and both RAM dumps under data/work")


def _patch(data: bytes, off: int, new: bytes) -> bytes:
    b = bytearray(data)
    b[off:off + len(new)] = new
    return bytes(b)


def _inputs():
    ovr = (INSTALL / "GAME.OVR").read_bytes()
    exe = (INSTALL / "START.EXE").read_bytes()
    dumps = [("por-live-memory-pid34644/ram", DUMP_PID.read_bytes()),
             ("por-wheel-live-capture/ram", DUMP_WHEEL.read_bytes())]
    return ovr, exe, dumps


def _failed(report):
    return {c["name"] for c in report["checks"] if not c["ok"]}


# ---- synthetic (no install) ----

def test_walk_is_instruction_aligned_on_a_synthetic_stub6_pushes_block():
    # mov al,0 ; push ax ; mov al,1 ; push ax ; call 0x03D5:0x003E
    code = bytes.fromhex("b0 00 50 b0 01 50 9a 3e 00 d5 03")
    insns = probe._walk(code, 0, len(code))
    assert sorted(insns) == [0, 2, 3, 5, 6]
    assert probe.STUB6_CALL == code[6:11]


def test_path_patterns_are_the_bytes_that_precede_each_site():
    for site, (label, pat, _, _) in probe.PATH_PATTERNS.items():
        assert label in "ABCD" and len(pat) in (6, 7, 8)
        assert probe.STUB6_SITES.count(site) == 1


# ---- retail-gated falsifiers ----

@retail
def test_pinned_run_is_ok_with_27_checks_and_no_execution_claim():
    ovr, exe, dumps = _inputs()
    rep = probe.analyze(ovr, exe, dumps)
    assert rep["status"] == "ok", _failed(rep)
    assert len(rep["checks"]) == 27
    assert rep["execution_established"] is False and rep["playable"] is False
    assert rep["route"]["stub6_sites_key_side"] == "non-0x21 (0x37 case)"
    assert rep["selector"]["stub6_route_writes_5376"] is False


@retail
def test_wrapper_name_pieces_are_walldef_not_geo():
    ovr, exe, dumps = _inputs()
    rep = probe.analyze(ovr, exe, dumps)
    assert "WALLDEF" in rep["wrapper"]["name_pieces"]
    byname = {c["name"]: c["ok"] for c in rep["checks"]}
    assert byname["wrapper_stem_literal_is_WALLDEF"] is True
    assert byname["wrapper_does_not_copy_GEO_stem"] is True


@retail
def test_dumps_show_no_wrapper_body_window_in_either_dump():
    ovr, exe, dumps = _inputs()
    rep = probe.analyze(ovr, exe, dumps)
    assert [r["wrapper_window_hits"] for r in rep["dumps"]] == [[], []]
    assert all(r["handler_prologue_at_expected"] for r in rep["dumps"])


@retail
def test_flipping_key_jnz_to_jz_moves_stub6_onto_the_0x21_side():
    ovr, exe, dumps = _inputs()
    mut = _patch(ovr, probe.KEY_JNZ, b"\x74")                  # jnz -> jz
    rep = probe.analyze(mut, exe, dumps, check_pins=False)
    assert rep["status"] == "diagnostic"
    assert "handler_key_split_0x21_vs_other" in _failed(rep)


@retail
def test_stub6_site_moved_into_0x21_side_is_caught():
    ovr, exe, dumps = _inputs()
    # replace the stub7 call at 0x1A27 with the stub6 call bytes: a 0x21-side stub6 site
    mut = _patch(ovr, probe.STUB7_SITE, probe.STUB6_CALL)
    rep = probe.analyze(mut, exe, dumps, check_pins=False)
    assert "no_stub6_site_on_0x21_side" in _failed(rep)


@retail
def test_wrapper_selector_replaced_by_constant_removes_the_selector_read():
    ovr, exe, dumps = _inputs()
    mut = _patch(ovr, probe.WRAPPER_SEL_LOAD, b"\xb0\x01\x90")  # mov al,1 ; nop
    rep = probe.analyze(mut, exe, dumps, check_pins=False)
    failed = _failed(rep)
    assert "wrapper_selector_read" in failed
    assert "wrapper_only_selector_access_is_load" in failed


@retail
def test_loader_id_from_bp6_instead_of_bp8_is_caught():
    ovr, exe, dumps = _inputs()
    mut = _patch(ovr, probe.WRAPPER_ID_LOAD, b"\x8a\x46\x06")  # mov al,[bp+6]
    rep = probe.analyze(mut, exe, dumps, check_pins=False)
    assert "wrapper_id_from_bp8_to_loader" in _failed(rep)


@retail
def test_path_b_guard_inverted_is_caught():
    ovr, exe, dumps = _inputs()
    mut = _patch(ovr, 0x1A89, b"\x75")                         # jz -> jnz
    rep = probe.analyze(mut, exe, dumps, check_pins=False)
    assert "stub6_path_B_guard" in _failed(rep)


@retail
def test_id_array_store_changed_is_caught():
    ovr, exe, dumps = _inputs()
    mut = _patch(ovr, probe.ARG_LOOP_STORE, b"\x88\x53\xfd")  # store to the wrong slot
    rep = probe.analyze(mut, exe, dumps, check_pins=False)
    assert "id_array_from_call_0x002B_0x0025" in _failed(rep)


@retail
def test_pinned_check_refuses_a_mutated_game_ovr():
    ovr, exe, dumps = _inputs()
    mut = _patch(ovr, probe.KEY_JNZ, b"\x74")
    with pytest.raises(pogm.Refusal):
        probe.analyze(mut, exe, dumps)


@retail
def test_output_outside_data_work_is_refused(tmp_path):
    assert probe.main(["--install", str(INSTALL), "--out", str(tmp_path / "x")]) == 2
    assert not (tmp_path / "x").exists()
