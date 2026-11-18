"""Synthetic falsifiers and the local pinned-dump check for the 0x21 stub-6 probe."""
import hashlib
from pathlib import Path
import struct
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import por_ecl_21_stub6_dump_probe as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
DUMPS = [REPO / "data" / "work" / name / "ram-000000-100000.bin"
         for name in ("por-live-memory-pid34644", "por-wheel-live-capture")]


def fixture():
    ovr = bytearray((i * 73 + i // 11 + 0x35) & 255 for i in range(0x30000))
    exe = bytearray((i * 31 + i // 7 + 0x19) & 255 for i in range(0x4000))
    codesz = 0x350D
    fixups = [site - p.HANDLER_FILE + 3 for site in p.CALL_SITES]
    exe[p.HANDLER_DESC:p.HANDLER_DESC + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", exe, p.HANDLER_DESC + 4, p.HANDLER_FILE, codesz, len(fixups) * 2, 2)
    struct.pack_into("<%dH" % len(fixups), ovr, p.HANDLER_FILE + codesz, *fixups)
    for site in p.CALL_SITES:
        ovr[site:site + 5] = p.CALL_BYTES

    exe[p.OWNER_DESC:p.OWNER_DESC + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", exe, p.OWNER_DESC + 4,
                     p.OWNER_FILE, p.OWNER_CODESZ, 0x20, 8)
    exe[p.STUB_FILE:p.STUB_FILE + 5] = p.STUB_BYTES
    ovr[p.PROC_FILE:p.PROC_FILE + 3] = p.PROC_PROLOGUE

    dump = bytearray(0x100000)
    dump[p.HANDLER_BASE:p.HANDLER_BASE + codesz] = ovr[p.HANDLER_FILE:p.HANDLER_FILE + codesz]
    for site in p.CALL_SITES:
        linear = p.HANDLER_BASE + site - p.HANDLER_FILE
        struct.pack_into("<H", dump, linear + 3, p.LIVE_SEG)
    dump[p.LIVE_TARGET:p.LIVE_TARGET + 5] = p.STUB_BYTES
    pins = {
        "GAME.OVR": {"size": len(ovr), "sha256": hashlib.sha256(ovr).hexdigest()},
        "START.EXE": {"size": len(exe), "sha256": hashlib.sha256(exe).hexdigest()},
    }
    return bytes(ovr), bytes(exe), bytes(dump), pins


def run(ovr=None, exe=None, dump=None, pins=None):
    base = fixture()
    ovr, exe, dump, pins = (ovr or base[0], exe or base[1], dump or base[2], pins or base[3])
    return p.analyze(ovr, exe, [("ram-000000-100000.bin", dump)], pins=pins)


def repin(ovr, exe):
    return {"GAME.OVR": {"size": len(ovr), "sha256": hashlib.sha256(ovr).hexdigest()},
            "START.EXE": {"size": len(exe), "sha256": hashlib.sha256(exe).hexdigest()}}


def test_complete_synthetic_stub6_chain_passes_without_execution_claim():
    result = run()
    assert result["status"] == "ok"
    row = result["dumps"][0]
    assert len(row["calls"]) == 4
    assert all(call["target_matches_stub6"] for call in row["calls"])
    assert result["execution_established"] is False


@pytest.mark.parametrize("site", p.CALL_SITES)
def test_each_static_call_site_is_required(site):
    ovr, exe, dump, _pins = fixture()
    changed = bytearray(ovr)
    changed[site + 1] ^= 1
    result = run(bytes(changed), exe, dump, repin(bytes(changed), exe))
    assert result["file_side"]["checks"]["four_static_far_call_sites"] is False


def test_unlisted_segment_word_is_diagnostic():
    ovr, exe, dump, _pins = fixture()
    changed = bytearray(ovr)
    fix_at = p.HANDLER_FILE + 0x350D
    struct.pack_into("<H", changed, fix_at, p.CALL_SITES[0] - p.HANDLER_FILE + 4)
    result = run(bytes(changed), exe, dump, repin(bytes(changed), exe))
    assert result["file_side"]["checks"]["all_four_segment_words_fixup_listed"] is False


def test_wrong_stub_proc_word_or_owner_prologue_is_diagnostic():
    ovr, exe, dump, _pins = fixture()
    changed_exe = bytearray(exe)
    struct.pack_into("<H", changed_exe, p.STUB_FILE + 2, p.PROC_OFF + 1)
    result = run(ovr, bytes(changed_exe), dump, repin(ovr, bytes(changed_exe)))
    assert result["file_side"]["checks"]["stub6_proc_word"] is False

    changed_ovr = bytearray(ovr)
    changed_ovr[p.PROC_FILE] ^= 1
    result = run(bytes(changed_ovr), exe, dump, repin(bytes(changed_ovr), exe))
    assert result["file_side"]["checks"]["proc_file_has_prologue"] is False


def test_live_target_byte_mismatch_is_diagnostic():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    changed[p.LIVE_TARGET + 2] ^= 1
    row = run(ovr, exe, bytes(changed), pins)["dumps"][0]
    assert row["checks"]["all_four_targets_match_exact_stub6"] is False
    assert row["status"] == "diagnostic"


def test_changed_live_segment_is_diagnostic():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    call_linear = p.HANDLER_BASE + p.CALL_SITES[0] - p.HANDLER_FILE
    struct.pack_into("<H", changed, call_linear + 3, p.LIVE_SEG + 1)
    row = run(ovr, exe, bytes(changed), pins)["dumps"][0]
    assert row["checks"]["all_four_live_segments_equal_1c3b"] is False


def test_retail_pinned_dumps_if_available():
    if not INSTALL.is_dir() or not all(path.is_file() for path in DUMPS):
        pytest.skip("local pinned install or RAM dumps unavailable")
    ovr, exe = (INSTALL / "GAME.OVR").read_bytes(), (INSTALL / "START.EXE").read_bytes()
    report = p.analyze(ovr, exe, [(str(path), path.read_bytes()) for path in DUMPS])
    assert report["status"] == "ok"
    for row in report["dumps"]:
        assert row["group_base"] == p.HANDLER_BASE
        assert len(row["calls"]) == 4
        assert all(call["target_linear"] == p.LIVE_TARGET for call in row["calls"])
        assert all(call["target_bytes"] == p.STUB_BYTES.hex(" ") for call in row["calls"])
