"""Tests for the PoR DAX open-path byte probe."""
import os
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import por_geo_loader_open_probe as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") else p.DEFAULT_INSTALL
HAVE_RETAIL = (INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR START.EXE not present")


def _synthetic_open_contract() -> bytearray:
    b = bytearray(0xC0D0)
    b[p.OPEN_WRAPPER:p.OPEN_WRAPPER + len(p.OPEN_SETUP)] = p.OPEN_SETUP
    b[0xC0BD:0xC0C4] = bytes.fromhex("26 80 7d 30 00 74 12")
    b[0xC0C4:0xC0C4 + len(p.OPEN_INT)] = p.OPEN_INT
    return b


def test_open_wrapper_reports_ah_3d_and_es_di_path_plus_30():
    got = p.inspect_open_call_contract(_synthetic_open_contract())
    assert got == {
        "setup_matches": True,
        "path_guard_matches": True,
        "open_sequence_matches": True,
        "all_match": True,
        "path_offset": 0x30,
        "dos_ah": 0x3D,
    }


def test_near_and_far_call_targets_are_decoded_from_rel16_and_immediates():
    b = bytearray(0x20)
    b[4:7] = bytes.fromhex("e8 05 00")
    b[12:17] = bytes.fromhex("9a 34 12 f8 0a")
    assert p._near_call(b, 4) == 12
    assert p._far_call(b, 12) == "0AF8:1234"


@pytest.mark.parametrize("at, value", [
    (p.OPEN_WRAPPER + 4, 0x3C),  # AH=3Dh changed to AH=3Ch
    (0xC0C0, 0x31),              # path offset +0x30 changed to +0x31
    (0xC0CC, 0x20),              # INT 21h changed to INT 20h
])
def test_open_wrapper_falsifiers(at, value):
    b = _synthetic_open_contract()
    b[at] = value
    got = p.inspect_open_call_contract(b)
    assert got["all_match"] is False


def test_selector_chain_is_exactly_index_times_30_plus_2614():
    b = bytearray(0x8700)
    b[0x8671:0x8671 + len(p.NAME_INDEX_CHAIN)] = p.NAME_INDEX_CHAIN
    assert p._at(b, 0x8671, p.NAME_INDEX_CHAIN)
    b[0x8678] ^= 1
    assert not p._at(b, 0x8671, p.NAME_INDEX_CHAIN)


def test_unpinned_start_is_refused():
    with pytest.raises(p.Refusal, match="pinned"):
        p.inspect_start(b"not START.EXE")


@needs_retail
def test_retail_start_walks_and_open_contract_match():
    doc = p.probe(INSTALL)
    assert doc["pins"]["START.EXE"]["sha256"] == p.START_PIN["sha256"]
    assert doc["pins"]["START.EXE"]["unchanged_after"] is True
    assert doc["all_byte_checks_match"] is True
    assert doc["routine_call_edges"]["expected_edges_match"] is True
    assert doc["routine_call_edges"]["direct_targets"]["8624_to_82b4"] == "0x082B4"
    assert doc["routine_call_edges"]["direct_targets"]["82b4_to_8342"] == "0x08342"
    assert doc["open_contract"]["path_pointer"] == "ES:DI+0x30 at wrapper entry"
    assert doc["verdict"]["archive"] == "not_established"
    assert doc["verdict"]["requested_block"] == "not_established"
    assert doc["verdict"]["playable"] is False


def test_render_is_deterministic_and_marks_unknowns():
    doc = {
        "pins": {"START.EXE": {"sha256": "00" * 32, "size": 1}},
        "path_selector": {"bytes": "00", "chain_matches": False},
        "open_contract": {"open_call_sequence_bytes": "00", "open_call_sequence_matches": False},
        "routine_call_edges": {"expected_edges_match": False},
        "all_byte_checks_match": False,
        "verdict": {"open_abi": "incomplete", "path_construction": "unknown",
                    "archive": "not_established", "requested_block": "not_established",
                    "geo_block_identity": "not_established"},
        "not_established": ["archive identity"],
    }
    assert p.render_report(doc) == p.render_report(doc)
    assert "archive identity" in p.render_report(doc)


def test_cli_refuses_output_outside_data_work(tmp_path):
    assert p.main(["--install", str(tmp_path), "-o", str(tmp_path / "outside")]) == 2
