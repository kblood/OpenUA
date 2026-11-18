"""Synthetic falsifiers and an optional pinned-retail check for the ECL helper dump probe."""
import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import por_ecl_21_operand_helper_dump_probe as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
DUMPS = [REPO / "data" / "work" / name / "ram-000000-100000.bin"
         for name in ("por-live-memory-pid34644", "por-wheel-live-capture")]
BODY = bytes.fromhex(
    "55 89 e5 83 ec 0a 8a 46 06 98 8b f8 8a 85 85 70 88 46 f7 "
    "8a 46 06 98 8b f8 8a 85 45 70 88 46 f6 8a 46 06 98 8b f8 "
    "8a 85 05 70 3c 00 75 0a 8a 46 f7 30 e4 89 46 fe eb 3f "
    "3c 01 74 08 3c 03 74 04 3c 80 75 1c 8a 46 f7 30 e4 8b d0 "
    "8a 46 f6 30 e4 b1 08 d3 e0 03 c2 50 0e e8 7b 0c 89 46 fe "
    "eb 17 3c 02 74 04 3c 81 75 0f 8a 46 f7 50 8a 46 f6 50 0e "
    "e8 05 05 89 46 fe 8b 46 fe 89 ec 5d ca 02 00")


def _descriptor(exe, off, fileofs, codesz, fixupsz, jmpcnt=0):
    exe[off:off + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", exe, off + 4, fileofs, codesz, fixupsz, jmpcnt)


def fixture():
    ovr = bytearray((i * 37 + 11) & 255 for i in range(0x8000))
    exe = bytearray((i * 19 + 7) & 255 for i in range(0x1000))
    codesz, body = 0xD00, p.HANDLER_CALL - p.GROUP_FILE
    _descriptor(exe, p.GROUP_DESC, p.GROUP_FILE, codesz, 2)
    code = memoryview(ovr)[p.GROUP_FILE:p.GROUP_FILE + codesz]
    code[body:body + 5] = bytes.fromhex("9a 25 00 2b 00")
    struct.pack_into("<H", ovr, p.GROUP_FILE + codesz, body + 3)
    ovr[p.HELPER_FILE:p.HELPER_END] = BODY

    dump = bytearray(0x100000)
    dump[p.GROUP_BASE:p.GROUP_BASE + codesz] = code
    struct.pack_into("<H", dump, p.GROUP_BASE + body + 3, p.LIVE_SEG)
    dump[p.THUNK_LINEAR:p.THUNK_LINEAR + 5] = p.THUNK
    dump[p.HELPER_LINEAR:p.HELPER_LINEAR + len(BODY)] = BODY
    pins = {"GAME.OVR": {"size": len(ovr), "sha256": hashlib.sha256(ovr).hexdigest()},
            "START.EXE": {"size": len(exe), "sha256": hashlib.sha256(exe).hexdigest()}}
    return bytes(ovr), bytes(exe), bytes(dump), pins


def check(ovr=None, exe=None, dump=None, pins=None):
    base = fixture()
    ovr, exe, dump, pins = (ovr or base[0], exe or base[1], dump or base[2], pins or base[3])
    return p.analyze(ovr, exe, [("ram-000000-100000.bin", dump)], pins=pins)


def test_complete_synthetic_dump_chain_passes():
    result = check()
    assert result["status"] == "ok"
    row = result["dumps"][0]
    assert row["call"]["target_linear"] == p.THUNK_LINEAR
    assert row["thunk"]["destination_linear"] == p.HELPER_LINEAR
    assert row["helper"]["bytes_match_game"] is True


@pytest.mark.parametrize("offset,value", [(p.HANDLER_CALL, 0xE8), (p.GROUP_FILE + 0xD00, 0x00)])
def test_bad_call_or_fixup_table_is_diagnostic(offset, value):
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[offset] = value
    pins = {"GAME.OVR": {"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest()},
            "START.EXE": pins["START.EXE"]}
    assert check(changed, exe, dump, pins)["file_side"]["checks"][
        "handler_call_is_002b_0025" if offset == p.HANDLER_CALL else "handler_call_segment_fixup_listed"] is False


def test_live_segment_change_breaks_target_chain():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    struct.pack_into("<H", changed, p.LIVE_CALL + 3, p.LIVE_SEG + 1)
    assert check(ovr, exe, bytes(changed), pins)["dumps"][0]["status"] == "diagnostic"


def test_wrong_thunk_target_breaks_chain():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    changed[p.THUNK_LINEAR + 1] ^= 1
    assert check(ovr, exe, bytes(changed), pins)["dumps"][0]["status"] == "diagnostic"


def test_wrong_helper_body_breaks_chain():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    changed[p.HELPER_LINEAR + 0x20] ^= 1
    assert check(ovr, exe, bytes(changed), pins)["dumps"][0]["status"] == "diagnostic"


def test_wrong_file_helper_body_breaks_static_check():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[p.HELPER_FILE + 0x20] ^= 1
    pins = {"GAME.OVR": {"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest()},
            "START.EXE": pins["START.EXE"]}
    assert check(bytes(changed), exe, dump, pins)["file_side"]["checks"]["helper_body_sha256"] is False


def test_retail_pinned_dumps_if_available():
    if not INSTALL.is_dir() or not all(path.is_file() for path in DUMPS):
        pytest.skip("local pinned install or RAM dumps unavailable")
    ovr, exe = (INSTALL / "GAME.OVR").read_bytes(), (INSTALL / "START.EXE").read_bytes()
    result = p.analyze(ovr, exe, [(str(path), path.read_bytes()) for path in DUMPS])
    assert result["status"] == "ok"
    assert all(row["call"]["bytes"] == "9a 25 00 91 18" for row in result["dumps"])
    assert all(row["thunk"]["bytes"] == p.THUNK.hex(" ") for row in result["dumps"])
    assert all(row["helper"]["bytes_match_game"] for row in result["dumps"])
