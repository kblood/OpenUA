"""Tests for tools/por_runtime_capture_plan.py (PoR runtime-capture readiness and plan).

The default suite uses synthetic blobs and temp folders. It never launches an emulator.
The retail test runs only when OPENUA_POR_INSTALL names a PoR install folder; it reads
the install read-only and writes its output to a temp folder.
"""
import json
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_runtime_capture_plan as p  # noqa: E402
import por_farcall_resolve as fc  # noqa: E402
from por_convert import PorSourceError  # noqa: E402


def _targets_by_id():
    return {t["id"]: t for t in p.build_targets()}


def test_handler_and_call_sites_map_into_descriptor_3():
    t = _targets_by_id()
    assert t["handler_entry"]["descriptor"] == 3
    assert t["handler_entry"]["rel_off"] == "0xC74"
    assert t["handler_entry"]["route_candidates"][0]["cs_ip_candidate"] == "3581:0C74"
    assert t["far_call_a_site"]["rel_off"] == "0xC7D"
    assert t["far_call_b_site"]["rel_off"] == "0xC94"
    assert t["dispatch_case_37"]["rel_off"] == "0x3058"


def test_stub_targets_and_parser_map_into_descriptor_7():
    t = _targets_by_id()
    assert t["far_call_a_proc"]["descriptor"] == 7
    assert t["far_call_a_proc"]["rel_off"] == "0x1DF0"
    assert t["far_call_b_proc"]["rel_off"] == "0x1CC3"
    assert t["operand_parser"]["rel_off"] == "0x0"
    routes = {c["cs_ip_candidate"] for c in t["operand_parser"]["route_candidates"]}
    assert routes == {"30CF:0000", "3089:0000"}


def test_every_candidate_is_observed_false_and_source_labelled():
    for t in p.build_targets():
        for c in t["route_candidates"]:
            assert c["observed_in_this_run"] is False
            assert c["source"]


def test_descriptor_coverage_is_checked_not_assumed():
    assert p._descriptor_for(0x19BA)[0] == 3
    assert p._descriptor_for(0x74D3)[0] == 7
    assert p._descriptor_for(0x0100) is None


def _synthetic_pair():
    ovr = bytearray(0x9400)
    start = bytearray(0x800)
    for site in p.CALL_SITES:
        f = site["file_off"]
        ovr[f] = 0x9A
        ovr[f + 1:f + 3] = site["off"].to_bytes(2, "little")
        ovr[f + 3:f + 5] = site["seg"].to_bytes(2, "little")
        t = site["target_file_off"]
        ovr[t:t + 3] = b"\x55\x89\xe5"
        image = 0x200 + site["seg"] * 16 + site["off"]
        start[image:image + 5] = b"\xcd\x3f" + site["stub_proc_off"].to_bytes(2, "little") + b"\x00"
    ovr[p.HANDLER_FILE_OFF:p.HANDLER_FILE_OFF + 3] = b"\x55\x89\xe5"
    ovr[p.PARSER_FILE_OFF:p.PARSER_FILE_OFF + 3] = b"\x55\x8b\xec"
    ovr[p.DISPATCH_CASE_37_FILE_OFF:p.DISPATCH_CASE_37_FILE_OFF + 2] = b"\x3c\x37"
    k = p.DISPATCH_CALL_FILE_OFF
    ovr[k] = 0xE8
    ovr[k + 1:k + 3] = ((p.HANDLER_FILE_OFF - (k + 3)) & 0xFFFF).to_bytes(2, "little")
    return bytes(ovr), bytes(start)


def test_static_checks_pass_on_matching_synthetic_bytes():
    ovr, start = _synthetic_pair()
    checks = p.check_static_bytes(ovr, start)
    assert checks and all(c["ok"] for c in checks), [c for c in checks if not c["ok"]]


def test_static_check_fails_when_stub_bytes_differ():
    ovr, start = _synthetic_pair()
    bad = bytearray(start)
    bad[0x4DA] = 0x90
    checks = {c["check"]: c["ok"] for c in p.check_static_bytes(ovr, bytes(bad))}
    assert checks["far_call_a_stub_bytes"] is False
    assert checks["far_call_b_stub_bytes"] is True


def test_static_check_fails_when_dispatch_call_misses_handler():
    ovr, start = _synthetic_pair()
    bad = bytearray(ovr)
    bad[p.DISPATCH_CALL_FILE_OFF + 1] ^= 0x01
    checks = {c["check"]: c["ok"] for c in p.check_static_bytes(bytes(bad), start)}
    assert checks["dispatch_case_37_near_call"] is False


def test_emulator_probe_reports_missing_and_present(tmp_path):
    missing = p.probe_emulator(None)
    assert missing["found"] is False and missing["sha_matches_pin"] is False
    gone = p.probe_emulator(tmp_path / "nope.exe")
    assert gone["found"] is False
    exe = tmp_path / "dosbox-x.exe"
    exe.write_bytes(b"not the real binary")
    present = p.probe_emulator(exe)
    assert present["found"] is True
    assert present["sha256"] and present["sha_matches_pin"] is False


def _fake_install(root: Path, ovr: bytes, start: bytes) -> Path:
    inst = root / "POOLRAD"
    inst.mkdir()
    (inst / "GAME.OVR").write_bytes(ovr)
    (inst / "START.EXE").write_bytes(start)
    return inst


def test_unpinned_install_is_refused_without_flag(tmp_path):
    ovr, start = _synthetic_pair()
    inst = _fake_install(tmp_path, ovr, start)
    with pytest.raises(PorSourceError):
        p.plan(inst, None, allow_unpinned=False)


def test_unpinned_plan_is_marked_not_retail_and_never_performed(tmp_path):
    ovr, start = _synthetic_pair()
    inst = _fake_install(tmp_path, ovr, start)
    doc, code = p.plan(inst, None, allow_unpinned=True)
    assert doc["playable"] is False
    assert doc["runtime_capture"]["performed"] is False
    assert doc["source"]["all_pins_match"] is False
    assert code == 1
    assert any(b["id"] == "emulator-missing" for b in doc["blockers"])


def test_main_refuses_output_inside_install(tmp_path):
    ovr, start = _synthetic_pair()
    inst = _fake_install(tmp_path, ovr, start)
    rc = p.main(["--install", str(inst), "-o", str(inst / "out"), "--allow-unpinned"])
    assert rc == 2
    assert not (inst / "out").exists()


def test_main_writes_playable_false_outputs(tmp_path):
    ovr, start = _synthetic_pair()
    inst = _fake_install(tmp_path, ovr, start)
    out = tmp_path / "out"
    rc = p.main(["--install", str(inst), "-o", str(out), "--allow-unpinned"])
    assert rc == 1
    doc = json.loads((out / "por_runtime_capture_plan.json").read_text(encoding="utf-8"))
    assert doc["playable"] is False and doc["runtime_capture"]["performed"] is False
    assert doc["schema"] == p.SCHEMA
    assert (out / "por_runtime_capture_plan_report.md").is_file()


def test_retail_targets_when_install_is_named(tmp_path):
    install = os.environ.get("OPENUA_POR_INSTALL")
    if not install:
        pytest.skip("OPENUA_POR_INSTALL not set")
    root = Path(install)
    if not (root / fc.OVR_NAME).is_file():
        pytest.skip("retail install not found at OPENUA_POR_INSTALL")
    emulator = os.environ.get(p.EMULATOR_ENV)
    doc, code = p.plan(root, Path(emulator) if emulator else None, allow_unpinned=False)
    assert doc["source"]["all_pins_match"] is True
    failed = [c for c in doc["static_bytes"] if not c["ok"]]
    assert failed == []
    assert doc["runtime_capture"]["performed"] is False
    assert code == (0 if doc["emulator"]["found"] else 1)
