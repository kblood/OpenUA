from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_walldef_table_link_probe as probe


def synthetic_group():
    return {"header_offset": probe.HEADER, "fileofs": probe.GROUP_FILE,
            "codesz": probe.GROUP_SIZE, "stub_delta": probe.GROUP_STUB_DELTA,
            "stub_count": 8, "valid_stub_count": 7, "status": "partial",
            "procs": [0x1206, 0x155, 0x47B, 0x350, 0x57A, 0x5FD,
                      probe.STUB_PROC, 0x10C7],
            "stub_valid": [True, True, True, True, True, True, True, False]}


def synthetic_ovr():
    data = bytearray(probe.GROUP_FILE + probe.GROUP_SIZE)
    anchors = {
        probe.GROUP_FILE + probe.WALLDEF_OFFSET: probe.EXPECTED["wall_piece"],
        probe.GROUP_FILE + probe.SUFFIX_OFFSET: probe.EXPECTED["suffix_piece"],
        probe.GROUP_FILE + 0x0E3E: probe.EXPECTED["wall_ref"],
        probe.GROUP_FILE + 0x0E58: probe.EXPECTED["suffix_ref"],
        probe.LOADER + 0x16: probe.EXPECTED["selector_read"],
        probe.LOADER + 0x68: probe.EXPECTED["loader_call"],
        probe.LOADER + 0x7F: probe.EXPECTED["record_divisor"],
        probe.LOADER + 0xEF: probe.EXPECTED["copy_destination"],
        probe.LOADER + 0x1B7: bytes.fromhex("c4 3e 58 6a"),
        probe.LOADER + 0x1EF: bytes.fromhex("c4 3e 58 6a"),
        probe.CONSUMER + 0x9E: probe.EXPECTED["consumer_scale"],
        probe.CONSUMER + 0xA3: bytes.fromhex("c4 3e 58 6a"),
        probe.CONSUMER + 0xD4: bytes.fromhex("c4 3e 58 6a"),
    }
    for offset, raw in anchors.items():
        data[offset:offset + len(raw)] = raw

    # The owner has eighteen decoded E8 calls to the 156-byte consumer.
    at = probe.OWNER
    for _ in range(18):
        rel = probe.CONSUMER - (at + 3)
        data[at:at + 3] = b"\xe8" + (rel & 0xFFFF).to_bytes(2, "little")
        at += 3
    data[at:at + 3] = bytes.fromhex("ca 06 00")
    return bytes(data)


def check(report, check_id):
    return next(row for row in report["checks"] if row["id"] == check_id)


def test_synthetic_walldef_name_and_shared_780_156_table_path():
    report = probe.analyze_group(synthetic_ovr(), synthetic_group())
    assert report["answer"] == "WALLDEF-name-and-shared-table-path-byte-checked"
    assert all(row["ok"] for row in report["checks"])
    assert report["table_shape"]["slices_per_record"] == 5
    assert report["table_shape"]["copy_direction"] == "conditional-on-helper-0AF8-1685-ABI"
    assert report["consumer"]["owner_near_call_count"] == 18
    assert report["mappings"] == []
    assert report["playable"] is False


@pytest.mark.parametrize(("offset", "new_byte", "check_id"), [
    (probe.GROUP_FILE + probe.WALLDEF_OFFSET + 1, ord("X"), "wall_piece"),
    (probe.GROUP_FILE + 0x0E3E, 0xBE, "wall_ref"),
    (probe.GROUP_FILE + 0x0E58, 0xBE, "suffix_ref"),
    (probe.LOADER + 0x16, 0xA1, "selector_read"),
    (probe.LOADER + 0x68, 0x90, "loader_call"),
    (probe.LOADER + 0x7F, 0xBA, "record_divisor"),
    (probe.LOADER + 0xEF, 0x90, "copy_destination"),
    (probe.CONSUMER + 0x9E, 0xB8, "consumer_scale"),
])
def test_each_anchor_fails_when_its_bytes_change(offset, new_byte, check_id):
    data = bytearray(synthetic_ovr())
    data[offset] = new_byte
    report = probe.analyze_group(bytes(data), synthetic_group())
    assert check(report, check_id)["ok"] is False


def test_partial_stub_descriptor_must_retain_valid_stub_six():
    group = synthetic_group()
    group["stub_valid"][6] = False
    report = probe.analyze_group(synthetic_ovr(), group)
    assert check(report, "partial_group_and_stub6")["ok"] is False


def test_group_identity_must_match():
    group = synthetic_group()
    group["fileofs"] += 1
    report = probe.analyze_group(synthetic_ovr(), group)
    assert check(report, "partial_group_and_stub6")["ok"] is False


def test_missing_table_pointer_read_fails_shared_path_check():
    data = bytearray(synthetic_ovr())
    at = probe.LOADER + 0x1B7
    data[at:at + 4] = b"\x90" * 4
    report = probe.analyze_group(bytes(data), synthetic_group())
    assert check(report, "table_pointer_reads")["ok"] is False


def test_retail_pins_when_configured(tmp_path):
    install = os.environ.get("OPENUA_POR_INSTALL")
    if not install:
        pytest.skip("OPENUA_POR_INSTALL is not set")
    report, code = probe.run(Path(install), tmp_path / "retail")
    assert code == 0
    assert report["checks_passed"] == report["checks_total"] == 22
    assert report["source_unchanged"] is True
    assert report["source_pins"]["GAME.OVR"]["matched"] is True
    assert report["source_pins"]["START.EXE"]["matched"] is True
    assert report["mappings"] == []
