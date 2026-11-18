"""Synthetic falsifiers and the optional pinned-retail check for the 0x1B helper probe."""
import hashlib
import struct
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import por_ecl_1b_classifier_dump_probe as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
DUMPS = [REPO / "data" / "work" / name / "ram-000000-100000.bin"
         for name in ("por-live-memory-pid34644", "por-wheel-live-capture")]


def fixture():
    ovr = bytearray((i * 37 + 11) & 255 for i in range(0xA000))
    exe = bytearray((i * 19 + 7) & 255 for i in range(0x1000))
    codesz = 0x350D
    fix = p.HELPER_CALL - p.GROUP_FILE + 3
    exe[p.GROUP_DESC:p.GROUP_DESC + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", exe, p.GROUP_DESC + 4, p.GROUP_FILE, codesz, 2, 0)
    struct.pack_into("<H", ovr, p.GROUP_FILE + codesz, fix)
    ovr[p.HANDLER_ENTRY + 3:p.HANDLER_ENTRY + 7] = bytes.fromhex("ff 06 ed 49")
    ovr[0x1900:0x190C] = bytes.fromhex("80 3e 7d 6f 00 75 05 9a 8e 00 2b 00")
    # Minimal complete far-returning body for synthetic mapping tests.
    body = bytes.fromhex("55 89 e5") + b"\x90" * (p.CLASSIFIER_LEN - 4) + b"\xcb"
    ovr[p.CLASSIFIER_FILE:p.CLASSIFIER_FILE + p.CLASSIFIER_LEN] = body

    dump = bytearray(0x100000)
    dump[p.GROUP_BASE:p.GROUP_BASE + codesz] = ovr[p.GROUP_FILE:p.GROUP_FILE + codesz]
    call_linear = p.GROUP_BASE + p.HELPER_CALL - p.GROUP_FILE
    struct.pack_into("<H", dump, call_linear + 3, p.LIVE_SEG)
    dump[p.THUNK_LINEAR:p.THUNK_LINEAR + 5] = p.THUNK
    dump[p.CLASSIFIER_LINEAR:p.CLASSIFIER_LINEAR + p.CLASSIFIER_LEN] = body
    pins = {"GAME.OVR": {"size": len(ovr), "sha256": hashlib.sha256(ovr).hexdigest()},
            "START.EXE": {"size": len(exe), "sha256": hashlib.sha256(exe).hexdigest()}}
    return bytes(ovr), bytes(exe), bytes(dump), pins


def check(ovr=None, exe=None, dump=None, pins=None):
    base = fixture()
    ovr, exe, dump, pins = (ovr or base[0], exe or base[1], dump or base[2], pins or base[3])
    return p.analyze(ovr, exe, [("ram-000000-100000.bin", dump)], pins=pins)


def _repin(ovr, exe, pins):
    return {"GAME.OVR": {"size": len(ovr), "sha256": hashlib.sha256(ovr).hexdigest()},
            "START.EXE": {"size": len(exe), "sha256": hashlib.sha256(exe).hexdigest()}}


def test_complete_synthetic_call_thunk_classifier_chain_passes():
    result = check()
    assert result["status"] == "ok"
    row = result["dumps"][0]
    assert row["call"]["target_linear"] == p.THUNK_LINEAR
    assert row["thunk"]["destination_linear"] == p.CLASSIFIER_LINEAR
    assert row["classifier"]["bytes_match_game"] is True
    assert result["execution_established"] is False


def test_wrong_static_call_is_diagnostic():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[p.HELPER_CALL + 1] ^= 1
    result = check(bytes(changed), exe, dump, _repin(changed, exe, pins))
    assert result["file_side"]["checks"]["guarded_1b_helper_call_bytes"] is False


def test_unlisted_helper_segment_word_is_diagnostic():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    fixup_at = p.GROUP_FILE + 0x350D
    struct.pack_into("<H", changed, fixup_at, p.HELPER_CALL - p.GROUP_FILE + 4)
    result = check(bytes(changed), exe, dump, _repin(changed, exe, pins))
    assert result["file_side"]["checks"]["helper_call_segment_word_fixup_listed"] is False


@pytest.mark.parametrize("offset", [p.HANDLER_ENTRY + 3, 0x1905])
def test_wrong_guard_path_order_is_diagnostic(offset):
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[offset] ^= 1
    result = check(bytes(changed), exe, dump, _repin(changed, exe, pins))
    assert result["file_side"]["checks"][
        "1b_cursor_increment_before_guard" if offset == p.HANDLER_ENTRY + 3
        else "1b_guard_and_call_order"] is False


def test_live_segment_change_breaks_mapped_target():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    call = p.GROUP_BASE + p.HELPER_CALL - p.GROUP_FILE
    struct.pack_into("<H", changed, call + 3, p.LIVE_SEG + 1)
    assert check(ovr, exe, bytes(changed), pins)["dumps"][0]["status"] == "diagnostic"


def test_wrong_far_jump_thunk_breaks_chain():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    changed[p.THUNK_LINEAR + 1] ^= 1
    row = check(ovr, exe, bytes(changed), pins)["dumps"][0]
    assert row["checks"]["target_is_expected_far_jmp_thunk"] is False
    assert row["status"] == "diagnostic"


def test_classifier_destination_mutation_breaks_exact_match():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    changed[p.CLASSIFIER_LINEAR + 20] ^= 1
    row = check(ovr, exe, bytes(changed), pins)["dumps"][0]
    assert row["checks"]["destination_matches_complete_classifier"] is False


def test_classifier_file_mutation_breaks_dump_match():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[p.CLASSIFIER_FILE + 20] = 0x91
    result = check(bytes(changed), exe, dump, _repin(changed, exe, pins))
    assert result["dumps"][0]["checks"]["destination_matches_complete_classifier"] is False


def test_changed_call_operand_does_not_pass():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[p.HELPER_CALL + 4] ^= 1
    result = check(bytes(changed), exe, dump, _repin(changed, exe, pins))
    assert result["file_side"]["checks"]["guarded_1b_helper_call_bytes"] is False


def test_retail_pinned_dumps_if_available():
    if not INSTALL.is_dir() or not all(path.is_file() for path in DUMPS):
        pytest.skip("local pinned install or RAM dumps unavailable")
    ovr, exe = (INSTALL / "GAME.OVR").read_bytes(), (INSTALL / "START.EXE").read_bytes()
    result = p.analyze(ovr, exe, [(str(path), path.read_bytes()) for path in DUMPS])
    assert result["status"] == "ok"
    assert all(row["call"]["bytes"] == "9a 8e 00 91 18" for row in result["dumps"])
    assert all(row["thunk"]["bytes"] == p.THUNK.hex(" ") for row in result["dumps"])
    assert all(row["classifier"]["bytes_match_game"] for row in result["dumps"])
    assert all(row["classifier"]["instruction_bytes_matching"] == 133 for row in result["dumps"])
