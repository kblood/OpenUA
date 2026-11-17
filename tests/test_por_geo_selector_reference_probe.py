"""Tests for the bounded PoR selector-global reference census."""
import os
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import por_geo_selector_reference_probe as p  # noqa: E402


def test_les_of_49d6_is_a_pointer_read():
    assert p.classify_reference("c43ed649", "les [0x49d6]") == "far-pointer-read"


def test_mov_to_49d6_is_a_write():
    assert p.classify_reference("a3d649", "mov [0x49d6]") == "write"


def test_segment_word_write_is_a_write():
    assert p.classify_reference("8916d849", "mov [0x49d8]") == "write"


def test_constant_assignment_to_selector_is_a_write():
    assert p.classify_reference("c606765301", "mov [0x5376], 0x1") == "write"


def test_moffs_load_of_selector_is_read_or_compare():
    assert p.classify_reference("a07653", "mov [0x5376]") == "read-or-compare"


@pytest.mark.parametrize("raw,expected", [
    ("bf7653", 0x5376),
    ("b8d649", 0x49D6),
    ("a27653", None),
    ("bf7853", None),
    ("not-hex", None),
])
def test_address_constants_are_separate_from_memory_access(raw, expected):
    assert p.address_constant(raw) == expected


def test_report_marks_census_bounded_and_nonplayable():
    report = {
        "coverage": {"candidate_descriptors": 1, "prologue_roots": 1,
                     "complete_walks": 1, "walks_incomplete": 0},
        "targets": {"0x49D6": {"decoded_sites": 1, "far_pointer_reads": 1,
                                "writes": 0, "read_or_compare": 0},
                    "0x49D8": {"decoded_sites": 0, "far_pointer_reads": 0,
                                "writes": 0, "read_or_compare": 0},
                    "0x5376": {"decoded_sites": 1, "far_pointer_reads": 0,
                                "writes": 1, "read_or_compare": 0}},
        "address_constants": [],
    }
    text = p.render_report(report)
    assert "not an exhaustive" in text
    assert "archive and area mappings remain unresolved" in text


@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"), reason="retail install not selected")
def test_retail_reference_census_anchors():
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    report = p.analyze((install / "GAME.OVR").read_bytes(), (install / "START.EXE").read_bytes())
    assert report["coverage"]["candidate_descriptors"] == 35
    assert report["coverage"]["prologue_roots"] == 675
    assert report["coverage"]["complete_walks"] == 675
    assert report["targets"]["0x49D6"]["far_pointer_reads"] == 143
    assert report["targets"]["0x49D6"]["writes"] == 1
    assert report["targets"]["0x49D8"]["writes"] == 1
    assert report["targets"]["0x5376"]["writes"] == 3
    assert [r["site"] for r in report["targets"]["0x5376"]["sites"] if r["access"] == "write"] == [
        "0x0E9A3", "0x19AE7", "0x1FBB0"]
    assert report["address_constants"]
