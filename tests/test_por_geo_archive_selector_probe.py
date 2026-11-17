"""Tests for the bounded PoR GEO archive-selector trace (static; retail anchor env-gated)."""
import os
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import por_geo_archive_selector_probe as p  # noqa: E402
import por_overlay_group_map as groups  # noqa: E402


def image(data: bytes, roots=(0,), name="SYNTH"):
    return p.Image(name, data, list(roots))


# Byte fixtures (each is one procedure starting at offset 0 with `push bp; mov bp,sp`).
PRO = bytes.fromhex("55 89 e5")
EPI = bytes.fromhex("5d c3")                       # pop bp; ret
SAVE = bytes.fromhex("a0 76 53 30 e4 c4 3e d6 49 26 89 85 24 06")   # selector copy into field
RESTORE = bytes.fromhex("c4 3e d6 49 26 8a 85 24 06 a2 76 53")      # field low byte -> selector
SLOT_INIT = bytes.fromhex("b8 00 08 50 9a 3f 02 f8 0a a3 d6 49")    # alloc 0x800 -> [0x49D6]


# --- field access and value chains -------------------------------------------------

def test_zero_extended_copy_into_field_is_classified():
    img = image(PRO + SAVE + EPI)
    rows = p.field_census(img)["rows"]
    assert len(rows) == 1
    row = rows[0]
    assert row["access"] == "write" and row["segment"] == "ES" and row["base"] == "di"
    assert row["value_source"] == "zero_extended_selector_copy"
    assert row["base_source"].startswith("far-pointer slot")


def test_field_restore_is_classified_as_selector_copy_back():
    img = image(PRO + RESTORE + EPI)
    rows = p.field_census(img)["rows"]
    assert len(rows) == 1 and rows[0]["access"] == "read"
    assert rows[0]["value_sink"] == "copy_low_byte_to_selector"


def test_non_contiguous_copy_is_not_claimed():
    # A nop between the selector load and the zero-extension breaks the straight-line run.
    bad = bytes.fromhex("55 89 e5 a0 76 53 90 30 e4 c4 3e d6 49 26 89 85 24 06 5d c3")
    rows = p.field_census(image(bad))["rows"]
    assert rows and rows[0]["value_source"] == "unclassified"


def test_displacement_off_by_one_is_not_the_field():
    off = bytes.fromhex("55 89 e5 c4 3e d6 49 26 8a 85 25 06 5d c3")    # disp 0x625
    assert p.field_census(image(off))["rows"] == []


def test_load_without_es_prefix_is_not_an_es_field_access():
    no_es = bytes.fromhex("55 89 e5 c4 3e d6 49 8a 85 24 06 5d c3")
    rows = p.field_census(image(no_es))["rows"]
    assert rows and all(r["segment"] != "ES" for r in rows)
    assert all(r.get("value_sink") is None for r in rows)


# --- selector writers and readers ------------------------------------------------

def test_constant_store_is_a_constant_source():
    rows = p.selector_writes(image(PRO + bytes.fromhex("c6 06 76 53 03") + EPI), p.SELECTOR)
    assert [(r["source_class"], r["value"]) for r in rows] == [("constant", 3)]


def test_parameter_store_is_classified_from_bp_plus_6():
    rows = p.selector_writes(image(bytes.fromhex("55 89 e5 8a 46 06 a2 76 53 5d ca 02 00")), p.SELECTOR)
    assert [r["source_class"] for r in rows] == ["parameter_bp+6"]


def test_save_slot_copy_is_classified():
    rows = p.selector_writes(image(bytes.fromhex("55 89 e5 a0 77 53 a2 76 53 5d c3")), p.SELECTOR)
    assert [r["source_class"] for r in rows] == ["copy_of_save_slot_0x5377"]


def test_plain_load_is_a_read_not_a_write():
    img = image(PRO + bytes.fromhex("a0 76 53") + EPI)
    assert p.selector_writes(img, p.SELECTOR) == []
    reads = p.selector_reads(img)
    assert len(reads) == 1 and reads[0]["access"] == "read"


def test_address_immediate_is_not_a_write_but_is_a_pass():
    img = image(PRO + bytes.fromhex("bf 76 53 1e 57 9a 0b 0b f8 0a") + EPI)
    assert p.selector_writes(img, p.SELECTOR) == []
    passes = p.pointer_passes(img, (p.SELECTOR,))
    assert len(passes) == 1 and passes[0]["next_call_target"] == "0x0AF8:0x0B0B"


def test_row_select_read_is_classified_by_stride_0x1e():
    row_select = bytes.fromhex("a0 76 53 30 e4 ba 1e 00 f7 e2")
    rows = p.selector_reads(image(PRO + row_select + EPI))
    assert [r["consumer_class"] for r in rows] == ["row_select_stride_0x1E"]


def test_slot_store_argument_is_recovered_from_contiguous_run():
    rows = p.slot_census(image(PRO + SLOT_INIT + EPI), p.SLOT_OFF)["rows"]
    store = [r for r in rows if r["access"] == "write"]
    assert len(store) == 1
    producer = store[0]["producer"]
    assert producer["is_allocator"] is True
    assert producer["argument"] == 0x800


def test_slot_store_without_contiguous_argument_is_not_claimed():
    gap = bytes.fromhex("55 89 e5 b8 00 08 90 50 9a 3f 02 f8 0a a3 d6 49 5d c3")
    rows = p.slot_census(image(gap), p.SLOT_OFF)["rows"]
    store = [r for r in rows if r["access"] == "write"][0]
    assert store["producer"]["argument"] is None


# --- verdict and refusals ----------------------------------------------------------

def _doc(unique: bool, classes: dict) -> dict:
    return {"conclusion": {
        "slot_49D6_single_initializer_from_allocator": True,
        "field_0x624_single_save_and_restore": True,
        "selector_origin_unique": unique,
        "selector_writer_classes": classes,
        "set_and_restore_procedures_have_no_direct_call_sites": True,
    }}


def test_several_writer_classes_make_the_origin_not_unique():
    v = p.verdict(_doc(False, {"constant": ["a"], "field_low_byte": ["b"]}))
    assert v["handoff_status"] == "no_unique_selector_origin"
    assert v["archive"] == "not_established" and v["playable"] is False
    claim = {c["id"]: c for c in v["claims"]}
    assert claim["A4"]["status"] == "not_established_not_unique"
    assert claim["A6"]["status"] == "not_established"


def test_unpinned_inputs_are_refused():
    with pytest.raises(groups.Refusal):
        p.analyze(b"not-game-ovr", b"not-start-exe")


def test_output_outside_data_work_is_refused(tmp_path):
    assert p.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")]) == 2


def test_missing_install_is_refused(tmp_path):
    assert p.main(["--install", str(tmp_path / "absent")]) == 2


# --- retail anchor (runs only when the pinned install is selected) ------------------

@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"), reason="retail install not selected")
def test_retail_selector_trace_anchors():
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    doc = p.probe(install)
    cov = doc["coverage"]
    assert cov["ovr_candidate_descriptors"] == 35
    assert cov["ovr_prologue_roots"] == 675 and cov["ovr_complete_walks"] == 675
    assert cov["exe_prologue_roots"] == 132

    slot = [r for r in doc["slot_49D6"]["ovr"]["rows"] if r["access"].startswith("write")]
    assert [r["at"] for r in slot] == ["0x0E620"]
    assert slot[0]["producer"]["argument"] == 0x800 and slot[0]["producer"]["is_allocator"]
    assert [r["at"] for r in doc["slot_49D8"]["ovr"]["rows"]] == ["0x0E623"]
    assert doc["slot_49D6"]["pointer_loads_in_ovr"] == 143

    field = doc["field_0x624"]
    assert field["exe"]["rows"] == []
    assert sorted((r["at"], r["access"]) for r in field["ovr"]["rows"]) == [
        ("0x1FBAB", "read"), ("0x1FEFE", "write")]
    write = [r for r in field["ovr"]["rows"] if r["access"] == "write"][0]
    assert write["value_source"] == "zero_extended_selector_copy"
    read = [r for r in field["ovr"]["rows"] if r["access"] == "read"][0]
    assert read["value_sink"] == "copy_low_byte_to_selector"

    writes = doc["selector_0x5376"]["writes"]
    assert [(w["at"], w["source_class"]) for w in writes["GAME.OVR"]] == [
        ("0x0E9A3", "constant"), ("0x19AE7", "constant"), ("0x1FBB0", "field_low_byte")]
    assert [w["value"] for w in writes["GAME.OVR"] if w["source_class"] == "constant"] == [1, 3]
    assert [(w["at"], w["source_class"]) for w in writes["START.EXE"]] == [
        ("0x089AD", "parameter_bp+6"), ("0x089BA", "copy_of_save_slot_0x5377")]
    assert [(w["at"], w["source_class"]) for w in doc["save_slot_0x5377"]["writes"]["GAME.OVR"]] == [
        ("0x0E9A8", "constant")]
    assert [(w["at"], w["source_class"]) for w in doc["save_slot_0x5377"]["writes"]["START.EXE"]] == [
        ("0x089A7", "copy_of_selector")]

    passes = doc["selector_0x5376"]["address_passes"]["GAME.OVR"]
    assert [(r["at"], r["next_call_target"]) for r in passes] == [
        ("0x1F7C1", "0x0AF8:0x14FB"), ("0x1FF09", "0x0AF8:0x1502")]

    assert doc["callers"]["set_selector_0x89A1"]["decoded_near_calls"] == []
    assert doc["callers"]["set_selector_0x89A1"]["raw_near_e8"] == []
    assert doc["callers"]["restore_selector_0x89B4"]["raw_far_offset_matches"] == []
    assert [c["site"] for c in doc["callers"]["save_field_0x1FD3E"]["decoded_near_calls"]] == ["0x203B8"]

    assert len(doc["consumers"]["formatter_call_within_16"]) == 12
    assert [r["at"] for r in doc["consumers"]["row_select"]] == ["0x0EB37", "0x1EB6D", "0x08671"]

    assert doc["conclusion"]["selector_origin_unique"] is False
    assert doc["verdict"]["handoff_status"] == "no_unique_selector_origin"
    assert doc["verdict"]["archive"] == "not_established" and doc["playable"] is False
