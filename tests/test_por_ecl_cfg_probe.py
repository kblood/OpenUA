"""Synthetic falsifiers for the conditional PoR ECL CFG diagnostic."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl as pe  # noqa: E402
import por_ecl_cfg_probe as probe  # noqa: E402


def block(code: bytes, roots=(22, 22, 22, 22, 22)) -> tuple[bytes, dict]:
    raw = bytearray(22 + len(code))
    raw[0:2] = pe.ECL_MAGIC.to_bytes(2, "little")
    for slot, offset in enumerate(roots):
        base = 2 + slot * 4
        raw[base:base + 2] = pe.ECL_SEGMENT_EXPECTED.to_bytes(2, "little")
        raw[base + 2:base + 4] = ((pe.POR_VBASE + offset) & 0xFFFF).to_bytes(2, "little")
    raw[22:] = code
    return bytes(raw), pe.parse_header(raw)


def test_goto_can_reach_code_after_linear_unknown_byte():
    # GOTO 0x9919 (block offset 27), then an unvisited 0x4B byte, then EXIT.
    data, header = block(bytes.fromhex("01 01 19 99 4b 00"))
    result = probe.analyze_block(data, header)
    assert [row["offset"] for row in result["candidate_instructions"]] == [22, 27]
    assert result["candidate_instructions"][0]["operands"][0]["word"] == 0x9919
    assert not result["stops"]
    assert result["runtime_reachability_established"] is False


def test_out_of_block_jump_target_is_recorded_as_a_stop():
    data, header = block(bytes.fromhex("01 01 99 99 00"))
    result = probe.analyze_block(data, header)
    assert any(row["reason"] == "edge-target-out-of-block" for row in result["stops"])


def test_conditional_opcode_marks_uncertainty_and_keeps_candidate_fallthrough():
    data, header = block(bytes.fromhex("16 00"))
    result = probe.analyze_block(data, header)
    assert [row["offset"] for row in result["candidate_instructions"]] == [22, 23]
    assert result["uncertainties"][0]["reason"] == "conditional-branch-semantics-open"


def test_gosub_tracks_target_and_return_fallthrough():
    # GOSUB to offset 27, with RETURN at 26 on the caller's fallthrough.
    data, header = block(bytes.fromhex("02 01 19 99 13 00"))
    result = probe.analyze_block(data, header)
    assert [row["offset"] for row in result["candidate_instructions"]] == [22, 26, 27]
    assert {edge["target_offset"] for edge in result["candidate_edges"]} == {27}


def test_invalid_base_root_is_reported_not_decoded():
    data, header = block(bytes.fromhex("00"), roots=(0xFFFF,) * 5)
    result = probe.analyze_block(data, header)
    assert not result["candidate_instructions"]
    assert len(result["invalid_roots"]) == 5


def test_unknown_framing_refuses():
    data, header = block(bytes.fromhex("00"))
    try:
        probe.analyze_block(data, header, framing="invented")
    except pe.EclError as exc:
        assert "unknown framing" in str(exc)
    else:
        raise AssertionError("unknown framing accepted")


def test_output_is_explicitly_nonplayable_and_conditional():
    data, header = block(bytes.fromhex("00"))
    result = probe.analyze_block(data, header)
    assert result["playable"] is False
    assert result["vbase_evidence"] == "conditional"
    assert result["runtime_reachability_established"] is False


def test_output_inside_source_archive_directory_is_refused(tmp_path):
    source_root = tmp_path / "POOLRAD"
    source_root.mkdir()
    try:
        probe._out_dir(str(source_root / "probe-output"), source_root)
    except pe.EclError as exc:
        assert "inside the source archive directory" in str(exc)
    else:
        raise AssertionError("source-adjacent output accepted")
