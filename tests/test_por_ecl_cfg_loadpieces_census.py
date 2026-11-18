"""Synthetic checks for the comparative CFG LOAD_PIECES census."""
from __future__ import annotations

import sys
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl as pe  # noqa: E402
import por_ecl_cfg_loadpieces_census as census  # noqa: E402


def make_block(code: bytes) -> bytes:
    raw = bytearray(22 + len(code))
    raw[:2] = pe.ECL_MAGIC.to_bytes(2, "little")
    for slot in range(5):
        off = 2 + 4 * slot
        raw[off:off + 2] = pe.ECL_SEGMENT_EXPECTED.to_bytes(2, "little")
        raw[off + 2:off + 4] = (0x9914).to_bytes(2, "little")
    raw[22:] = code
    return bytes(raw)


def test_candidate_flow_finds_load_pieces_after_linear_unknown_byte():
    # GOTO 0x9919 (offset 27), an unknown 0x4B at 26, then LOAD_PIECES.
    raw = make_block(bytes.fromhex("01 01 19 99 4b 37 00 01 00 02 00 03 00"))
    result = census.analyze_block(raw)
    assert result["linear_offsets"] == []
    assert result["candidate_offsets"] == [27]
    assert result["candidate_only_offsets"] == [27]
    assert len(result["candidate_operands"][0]["operands"]) == 3
    assert result["candidate_operands"][0]["discovered_from"] == "edge-from-0016"
    assert result["candidate_edges"][0]["target_offset"] == 27


def test_terminal_assumption_can_make_linear_site_absent_from_candidate_set():
    # The existing linear walk continues after EXIT; the CFG candidate treats it as terminal.
    raw = make_block(bytes.fromhex("00 37 00 01 00 02 00 03 00"))
    result = census.analyze_block(raw)
    assert result["linear_offsets"] == [23]
    assert result["candidate_offsets"] == []
    assert result["linear_only_offsets"] == [23]


def test_offset_comparison_deduplicates_and_sorts():
    result = census.compare_offsets([7, 2, 7], [3, 2, 3])
    assert result == {
        "linear_offsets": [2, 7],
        "candidate_offsets": [2, 3],
        "candidate_only_offsets": [3],
        "linear_only_offsets": [7],
        "same_offsets": False,
    }


def test_matching_sets_are_not_misreported_as_new_sites():
    result = census.compare_offsets([22, 44], [44, 22])
    assert result["same_offsets"] is True
    assert result["candidate_only_offsets"] == []
    assert result["linear_only_offsets"] == []


def test_archive_hash_is_checked_and_recorded(tmp_path):
    raw = make_block(bytes.fromhex("00"))
    comp = bytes([len(raw) - 1]) + raw
    toc = struct.pack("<HBIHH", 9, 20, 0, len(raw), len(comp))
    path = tmp_path / "ECL1.DAX"
    path.write_bytes(toc + comp)
    record, diagnostics = census.census_archive(path, "ECL1.DAX", "spec-menus")
    assert record["container"] == "ok"
    assert record["source_unchanged"] is True
    assert record["blocks"][0]["status"] == "ok"
    assert diagnostics == []


def test_bad_archive_still_records_unchanged_source(tmp_path):
    path = tmp_path / "ECL1.DAX"
    path.write_bytes(b"bad")
    record, diagnostics = census.census_archive(path, "ECL1.DAX", "spec-menus")
    assert record["container"] == "error"
    assert record["source_unchanged"] is True
    assert diagnostics[0]["code"] == "container-error"
