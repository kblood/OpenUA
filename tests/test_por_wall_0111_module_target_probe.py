"""Tests for tools/por_wall_0111_module_target_probe.py (far module targets 0x0AF8:0x023F and 0x0AF8:0x0254).

Synthetic fixtures (default) check each claim with a mutated-byte falsifier that must change the result:
the call-site bytes, the wrapper template and its derived targets (retf imm, carry branch, error code),
the window identity (memory agreement, disagreement, repeated placement, degenerate window), the exit tail of
a near helper, and the wall-helper byte patterns. The retail test runs only when OPENUA_POR_INSTALL names the
local Pool of Radiance DOS install and is skipped otherwise; it reads the install and the ignored RAM dumps
read-only and writes nothing.
"""
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_0111_module_target_probe as mp  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
BASE = 0x100                                   # synthetic module base in the fake START.EXE
LIVE_SEG = mp.MODULE_SEG + mp.EXPECT_LOAD      # 0x235E


def _exe_with(placements: dict, size: int = 0x800) -> bytes:
    """A zero-filled fake START.EXE with byte strings placed at file offsets."""
    out = bytearray(size)
    for at, data in placements.items():
        out[at:at + len(data)] = data
    return bytes(out)


def _dump_at_live(off: int, window: bytes) -> ogm.Dump:
    """A dump that covers exactly the live window of module offset `off` (base = its linear address)."""
    lin = LIVE_SEG * mp.PARA + off
    return ogm.Dump(bytes(window), lin)


def _wrapper_bytes(off: int) -> bytes:
    return mp.WRAPPER[off]


def _win32(off: int) -> bytes:
    """The probe compares a 32-byte window; the wrapper template is shorter, so pad with zeros as the file does."""
    return (_wrapper_bytes(off) + bytes(mp.WINDOW))[:mp.WINDOW]


# -- call-site bytes -------------------------------------------------------------------------------

def test_call_bytes_encode_the_module_far_call():
    assert mp.call_bytes(0x023F) == bytes.fromhex("9a 3f 02 f8 0a")
    assert mp.call_bytes(0x0254) == bytes.fromhex("9a 54 02 f8 0a")
    assert mp.call_bytes(0x023F) != mp.call_bytes(0x0254)


# -- wrapper template and derived targets ------------------------------------------------------

@pytest.mark.parametrize("off", mp.TARGETS)
def test_wrapper_matches_template_and_derives_near_helper(off):
    exe = _exe_with({BASE + off: _wrapper_bytes(off)})
    w = mp.wrapper_facts(exe, BASE, off)
    assert w["matched"] is True
    assert w["retf_imm"] == mp.RETF_IMM[off]
    assert w["error_code_loaded"] == mp.ERR_CODE[off]
    assert w["jump_target_module"] == mp._hex(mp.ERR_JOIN)
    assert w["carry_branch_skips_retf"] is True


def test_wrapper_near_helpers_are_0x308_and_0x3d3():
    exe = _exe_with({BASE + 0x023F: _wrapper_bytes(0x023F), BASE + 0x0254: _wrapper_bytes(0x0254)})
    assert mp.wrapper_facts(exe, BASE, 0x023F)["near_call_target_module"] == "0x308"
    assert mp.wrapper_facts(exe, BASE, 0x0254)["near_call_target_module"] == "0x3D3"


@pytest.mark.parametrize("off,pos,new", [
    (0x023F, 12, 0x04),        # retf 2 -> retf 4 (wrong argument count)
    (0x0254, 18, 0x04),        # retf 6 -> retf 4
    (0x023F, 10, 0x02),        # carry branch offset changed
    (0x0254, 21, 0xCD),        # error code 0xCC -> 0xCD
])
def test_wrapper_falsified_by_one_byte(off, pos, new):
    bad = bytearray(_wrapper_bytes(off))
    bad[pos] = new
    exe = _exe_with({BASE + off: bytes(bad)})
    w = mp.wrapper_facts(exe, BASE, off)
    assert w["template_matched"] is False and w["matched"] is False


# -- window identity -------------------------------------------------------------------------------

@pytest.mark.parametrize("off", mp.TARGETS)
def test_identity_unique_when_dumps_agree_with_file(off):
    win = _win32(off)
    exe = _exe_with({BASE + off: win})
    dumps = [{"label": "d", "dump": _dump_at_live(off, win), "load": mp.EXPECT_LOAD}]
    res = mp.identity(exe, BASE, dumps)["0x%04X" % off]
    assert res["verdict"] == "identified-by-bytes-in-pinned-dumps"
    assert res["per_dump"][0]["window"]["state"] == "memory-agrees-unique-placement"


def test_identity_falsified_by_one_byte_in_the_dump():
    off = 0x023F
    win = _win32(off)
    exe = _exe_with({BASE + off: win})
    bad = bytearray(win)
    bad[7] ^= 0x01
    dumps = [{"label": "d", "dump": _dump_at_live(off, bytes(bad)), "load": mp.EXPECT_LOAD}]
    res = mp.identity(exe, BASE, dumps)["0x023F"]
    assert res["verdict"] == "unresolved"
    assert res["per_dump"][0]["window"]["state"] == "memory-disagrees"


def test_identity_falsified_when_the_window_repeats_in_the_file():
    off = 0x0254
    win = _win32(off)
    exe = _exe_with({BASE + off: win, 0x500: win})
    dumps = [{"label": "d", "dump": _dump_at_live(off, win), "load": mp.EXPECT_LOAD}]
    res = mp.identity(exe, BASE, dumps)["0x0254"]
    assert res["verdict"] == "unresolved"
    assert res["per_dump"][0]["window"]["state"] == "placement-not-unique"


def test_identity_refused_as_degenerate_when_mostly_zero():
    off = 0x023F
    win = bytes(32)
    exe = _exe_with({BASE + off: win})
    dumps = [{"label": "d", "dump": _dump_at_live(off, win), "load": mp.EXPECT_LOAD}]
    res = mp.identity(exe, BASE, dumps)["0x023F"]
    assert res["per_dump"][0]["window"]["state"] == "degenerate-window"
    assert res["verdict"] == "unresolved"


def test_identity_unresolved_when_the_live_window_is_not_covered():
    off = 0x023F
    win = _win32(off)
    exe = _exe_with({BASE + off: win})
    dumps = [{"label": "d", "dump": ogm.Dump(b"\x00" * 16, 0), "load": mp.EXPECT_LOAD}]
    res = mp.identity(exe, BASE, dumps)["0x023F"]
    assert res["per_dump"][0]["window"]["state"] == "memory-not-covered"
    assert res["verdict"] == "unresolved"


# -- near helper exit tail ------------------------------------------------------------------------

def test_helper_exit_tail_recognised_and_falsified():
    good = bytes.fromhex("8b 46 06 58 5a f8 c3")        # mov ax,[bp+6]; pop ax; pop dx; clc; ret
    bad = bytes.fromhex("8b 46 06 58 59 f8 c3")         # pop cx instead of pop dx
    ok = mp.helper_summary(_exe_with({BASE + 0x10: good}), BASE, 0x10, mp.EXIT_TAIL[0x023F])
    no = mp.helper_summary(_exe_with({BASE + 0x10: bad}), BASE, 0x10, mp.EXIT_TAIL[0x023F])
    assert ok["exit_tail_ok"] is True
    assert no["exit_tail_ok"] is False


def test_helper_reports_direct_ds_operands_and_immediates():
    code = bytes.fromhex("a3 54 87 bf 0c 44 26 3b 36 06 44 c3")   # mov [0x8754],ax; mov di,0x440C; cmp es:[0x4406],si; ret
    h = mp.helper_summary(_exe_with({BASE + 0x20: code}), BASE, 0x20, None)
    assert "0x8754" in h["ds_direct_addresses"]
    assert "0x4406" in h["ds_direct_addresses"]
    assert any(r["imm"] == "0x440C" for r in h["mov_imm16"])


# -- wall-helper byte patterns --------------------------------------------------------------------

def _wall_exe() -> bytes:
    placements = {off: bytes.fromhex(hx) for _, off, hx in mp.WALL_PATTERNS}
    return _exe_with(placements, size=0x6D00)


def test_wall_patterns_all_match_when_placed():
    rows = mp.wall_pattern_rows(_wall_exe())
    assert len(rows) == len(mp.WALL_PATTERNS)
    assert all(r["matched"] for r in rows)


def test_wall_pattern_falsified_by_callee_change_at_alloc_site():
    exe = bytearray(_wall_exe())
    exe[0x6B39 + 1] = 0x54                              # call 0x0AF8:0x023F becomes 0x0AF8:0x0254 at 0x6B39
    rows = {r["label"]: r for r in mp.wall_pattern_rows(bytes(exe))}
    assert rows["alloc-main-size-bp-4-plus-17"]["matched"] is False
    assert all(r["matched"] for k, r in rows.items() if k != "alloc-main-size-bp-4-plus-17")


def test_wall_pattern_falsified_by_size_expression_at_release():
    exe = bytearray(_wall_exe())
    exe[0x6C8D + 1] = 0x00                              # release main size reads [bp-0] instead of [bp-2]
    rows = {r["label"]: r for r in mp.wall_pattern_rows(bytes(exe))}
    assert rows["release-main-size-bp-2-plus-17"]["matched"] is False


def test_wall_pattern_falsified_by_missing_flag_guard():
    exe = bytearray(_wall_exe())
    exe[0x6C4F + 2] = 0x00                              # cmp [DS:4A1E],1 becomes cmp ...,0
    rows = {r["label"]: r for r in mp.wall_pattern_rows(bytes(exe))}
    assert rows["release-flag-one-test"]["matched"] is False


# -- probe-level refusals -----------------------------------------------------------------------

def test_cli_refuses_output_outside_data_work(tmp_path):
    rc = mp.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")])
    assert rc == 2


def test_cli_refuses_unpinned_install(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"\x00" * 10)
    (tmp_path / "START.EXE").write_bytes(b"\x00" * 10)
    rc = mp.main(["--install", str(tmp_path), "-o", str(mp.DEFAULT_OUT)])
    assert rc == 2


def test_cli_returns_failure_when_a_probe_self_check_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "DATA_WORK", tmp_path)
    bad = {
        "identity": {"target": {"verdict": "unresolved"}},
        "wrappers": {"target": {"matched": False}},
        "wall_helper_patterns": [{"matched": False}],
        "self_checks_passed": False,
    }
    monkeypatch.setattr(mp, "probe", lambda install, dumps: bad)
    out = tmp_path / "out"
    rc = mp.main(["--install", str(tmp_path / "install"), "-o", str(out)])
    assert rc == 1
    assert (out / "por_wall_0111_module_target_probe.json").exists()


# -- retail (gated) -------------------------------------------------------------------------------

@pytest.mark.skipif(not os.environ.get(ENV), reason=f"set {ENV} to the Pool of Radiance install")
def test_retail_identity_wrappers_and_wall_patterns():
    install = Path(os.environ[ENV])
    dumps = mp.DEFAULT_DUMPS
    doc = mp.probe(install, dumps)
    assert doc["inputs"]["pins"]["GAME.OVR"]["pinned"] and doc["inputs"]["pins"]["START.EXE"]["pinned"]
    for key in ("0x023F", "0x0254"):
        assert doc["identity"][key]["verdict"] == "identified-by-bytes-in-pinned-dumps"
        assert all(p["window"]["state"] == "memory-agrees-unique-placement"
                   for p in doc["identity"][key]["per_dump"])
    assert doc["wrappers"]["0x023F"]["near_call_target_module"] == "0x308"
    assert doc["wrappers"]["0x0254"]["near_call_target_module"] == "0x3D3"
    assert doc["near_helpers"]["0x023F"]["exit_tail_ok"] is True
    assert doc["near_helpers"]["0x0254"]["exit_tail_ok"] is True
    assert {"0x4406", "0x8754"} <= set(doc["near_helpers"]["0x023F"]["ds_direct_addresses"])
    assert {"0x4400", "0x4402", "0x4404", "0x4406"} <= set(doc["near_helpers"]["0x0254"]["ds_direct_addresses"])
    assert all(r["matched"] for r in doc["wall_helper_patterns"])
    start_sites = doc["call_site_byte_counts"]
    assert {"0x6B39", "0x6BAA", "0x6BDE"} <= set(start_sites["0x023F"]["START.EXE"])
    assert {"0x6C69", "0x6C7E", "0x6C94"} <= set(start_sites["0x0254"]["START.EXE"])
    assert doc["playable_claim"] is False and doc["executed"] == "not_established"
