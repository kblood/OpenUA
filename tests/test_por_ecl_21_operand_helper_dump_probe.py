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
PARSER_BODY = bytes.fromhex(
    "55 89 e5 83 ec 08 c6 46 fe 00 8a 46 06 88 46 f9 b0 01 3a 46 f9 76 03 e9 12 01 88 46 ff eb 03 fe 46 ff "
    "a1 ed 49 40 c4 3e de 49 03 f8 26 8a 95 00 67 8a 46 ff 30 e4 8b f8 88 95 05 70 a1 ed 49 40 40 c4 3e de 49 "
    "03 f8 26 8a 95 00 67 8a 46 ff 30 e4 8b f8 88 95 85 70 a1 ed 49 40 40 a3 ed 49 8a 46 ff 30 e4 8b f8 8a 85 "
    "05 70 3c 01 74 08 3c 02 74 04 3c 03 75 20 ff 06 ed 49 a1 ed 49 c4 3e de 49 03 f8 26 8a 95 00 67 8a 46 ff "
    "30 e4 8b f8 88 95 45 70 e9 8b 00 3c 80 75 39 fe 46 fe 8a 46 ff 30 e4 8b f8 8a 85 85 70 30 e4 89 46 fa 83 "
    "7e fa 00 76 0e 8a 46 fa 50 8a 46 fe 50 0e e8 94 10 eb 10 8a 46 fe 30 e4 8b f8 b1 08 d3 e7 c6 85 c8 6f 00 "
    "eb 4e 3c 81 75 4a fe 46 fe ff 06 ed 49 a1 ed 49 c4 3e de 49 03 f8 26 8a 95 00 67 8a 46 ff 30 e4 8b f8 "
    "88 95 45 70 8a 46 ff 30 e4 8b f8 8a 85 85 70 50 8a 46 ff 30 e4 8b f8 8a 85 45 70 50 0e e8 9c 05 89 46 fc "
    "8a 46 fe 50 ff 76 fc 0e e8 da 11 8a 46 ff 3a 46 f9 74 03 e9 f3 fe ff 06 ed 49 89 ec 5d ca 02 00")
WORD_HELPER_BODY = bytes.fromhex(
    "55 89 e5 83 ec 02 8a 46 08 30 e4 8b d0 8a 46 06 30 e4 b1 08 d3 e0 03 c2 89 46 fe "
    "8b 46 fe 89 ec 5d ca 04 00")


def _descriptor(exe, off, fileofs, codesz, fixupsz, jmpcnt=0):
    exe[off:off + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", exe, off + 4, fileofs, codesz, fixupsz, jmpcnt)


def fixture():
    ovr = bytearray((i * 37 + 11) & 255 for i in range(0x9000))
    exe = bytearray((i * 19 + 7) & 255 for i in range(0x1000))
    codesz, body = 0x350D, p.HANDLER_CALL - p.GROUP_FILE
    fixups = [body + 3] + [at - p.GROUP_FILE + 3 for at in p.MENU_CALLS]
    fixups.extend(at - p.GROUP_FILE + 3 for at in p.WORD_CALLS)
    _descriptor(exe, p.GROUP_DESC, p.GROUP_FILE, codesz, len(fixups) * 2)
    code = memoryview(ovr)[p.GROUP_FILE:p.GROUP_FILE + codesz]
    code[body:body + 5] = bytes.fromhex("9a 25 00 2b 00")
    for at, (operand, _) in p.MENU_CALLS.items():
        code[at - p.GROUP_FILE:at - p.GROUP_FILE + 5] = bytes((0x9A, operand, 0, 0x2B, 0))
    for at in p.WORD_CALLS:
        code[at - p.GROUP_FILE:at - p.GROUP_FILE + 5] = bytes.fromhex("9a 4d 00 2b 00")
    for i, fixup in enumerate(sorted(fixups)):
        struct.pack_into("<H", ovr, p.GROUP_FILE + codesz + i * 2, fixup)
    ovr[p.HELPER_FILE:p.HELPER_END] = BODY
    ovr[p.PARSER_FILE:p.PARSER_END] = PARSER_BODY
    # Minimal far-returning stand-ins for the helper's near-call targets. The
    # retail-specific complete closure is exercised by the gated test.
    for target in (0x82DF, 0x7BCE, 0x7C8F, 0x7C29):
        ovr[target:target + 3] = bytes.fromhex("ca 02 00")
    ovr[p.WORD_HELPER_FILE:p.WORD_HELPER_END] = WORD_HELPER_BODY

    dump = bytearray(0x100000)
    dump[p.GROUP_BASE:p.GROUP_BASE + codesz] = code
    struct.pack_into("<H", dump, p.GROUP_BASE + body + 3, p.LIVE_SEG)
    for at in p.MENU_CALLS:
        struct.pack_into("<H", dump, p.GROUP_BASE + at - p.GROUP_FILE + 3, p.MENU_LIVE_SEG)
    for at in p.WORD_CALLS:
        struct.pack_into("<H", dump, p.GROUP_BASE + at - p.GROUP_FILE + 3, p.MENU_LIVE_SEG)
    dump[p.PARSER_THUNK_LINEAR:p.PARSER_THUNK_LINEAR + 5] = p.PARSER_THUNK
    dump[p.PARSER_LINEAR:p.PARSER_LINEAR + len(PARSER_BODY)] = PARSER_BODY
    dump[p.WORD_THUNK_LINEAR:p.WORD_THUNK_LINEAR + 5] = p.WORD_THUNK
    dump[p.WORD_TARGET_LINEAR:p.WORD_TARGET_LINEAR + len(WORD_HELPER_BODY)] = WORD_HELPER_BODY
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


@pytest.mark.parametrize("offset,value", [(p.HANDLER_CALL, 0xE8), (p.GROUP_FILE + 0x350D, 0x00)])
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


@pytest.mark.parametrize("call_at", list(p.MENU_CALLS))
def test_menu_call_site_mutation_is_diagnostic(call_at):
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[call_at + 1] ^= 1
    pins = {"GAME.OVR": {"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest()},
            "START.EXE": pins["START.EXE"]}
    result = check(bytes(changed), exe, dump, pins)
    assert result["file_side"]["checks"][p.MENU_CALLS[call_at][1] + "_call_bytes"] is False


def test_helper_near_closure_fails_on_direct_cursor_operand():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[p.HELPER_FILE:p.HELPER_FILE + 3] = bytes.fromhex("a1 ed 49")
    pins = {"GAME.OVR": {"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest()},
            "START.EXE": pins["START.EXE"]}
    result = check(bytes(changed), exe, dump, pins)
    assert result["file_side"]["checks"][
        "helper_near_closure_complete_without_direct_cursor_reference"] is False


def test_menu_call_without_listed_segment_fixup_is_diagnostic():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    fixup_table = p.GROUP_FILE + 0x350D
    # Keep the table sorted and its declared size; replace one menu segment-word offset.
    struct.pack_into("<H", changed, fixup_table + 2, 0x1C6B - p.GROUP_FILE + 4)
    pins = {"GAME.OVR": {"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest()},
            "START.EXE": pins["START.EXE"]}
    result = check(bytes(changed), exe, dump, pins)
    assert result["file_side"]["checks"]["0x15-first_segment_fixup_listed"] is False


def test_2b4d_word_helper_body_mutation_is_diagnostic():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(dump)
    changed[p.WORD_TARGET_LINEAR + 10] ^= 1
    result = check(ovr, exe, bytes(changed), pins)
    assert result["dumps"][0]["checks"]["word_helper_memory_matches_game_body"] is False


def test_2b4d_formula_is_reported_with_four_byte_cleanup():
    result = check()
    word_helper = result["file_side"]["word_helper"]
    assert word_helper["return_formula"] == "((byte [bp+6]) << 8) | byte [bp+8]"
    assert word_helper["argument_cleanup"] == 4


def test_2b4d_file_body_hash_falsifier():
    ovr, exe, dump, pins = fixture()
    changed = bytearray(ovr)
    changed[p.WORD_HELPER_FILE + 10] ^= 1
    pins = {"GAME.OVR": {"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest()},
            "START.EXE": pins["START.EXE"]}
    result = check(bytes(changed), exe, dump, pins)
    assert result["file_side"]["checks"]["word_helper_body_sha256"] is False


def test_parser_live_body_and_menu_thunks_are_cross_checked():
    result = check()
    row = result["dumps"][0]
    assert row["checks"]["parser_memory_matches_complete_game_body"] is True
    assert row["checks"]["menu_2b_calls_map_to_expected_thunks"] is True
    assert row["checks"]["word_calls_map_to_expected_thunk"] is True
    assert row["checks"]["word_helper_memory_matches_game_body"] is True
    assert len(row["menu_calls"]) == 6
    assert all(site["matches_expected"] for site in row["menu_calls"])
    assert len(row["word_calls"]) == 2
    assert all(call["target_linear"] == p.WORD_THUNK_LINEAR for call in row["word_calls"])
    closure = result["file_side"]["helper_near_closure"]
    assert all(item["complete"] and not item["far_calls"] and not item["indirect"]
               and not item["direct_absolute_cursor_reference"] for item in closure)


def test_retail_pinned_dumps_if_available():
    if not INSTALL.is_dir() or not all(path.is_file() for path in DUMPS):
        pytest.skip("local pinned install or RAM dumps unavailable")
    ovr, exe = (INSTALL / "GAME.OVR").read_bytes(), (INSTALL / "START.EXE").read_bytes()
    result = p.analyze(ovr, exe, [(str(path), path.read_bytes()) for path in DUMPS])
    assert result["status"] == "ok"
    assert all(row["call"]["bytes"] == "9a 25 00 91 18" for row in result["dumps"])
    assert all(row["thunk"]["bytes"] == p.THUNK.hex(" ") for row in result["dumps"])
    assert all(row["helper"]["bytes_match_game"] for row in result["dumps"])
    closure = result["file_side"]["helper_near_closure"]
    assert {item["entry"] for item in closure} == {0x7609, 0x82DF, 0x7B82, 0x7BCE, 0x7C8F, 0x7C29}
    assert sum(item["instruction_count"] for item in closure) == 494
