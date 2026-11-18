"""Tests for the PoR GEO selector format and filename chain probe (static; retail anchors env-gated)."""
import json
import os
import random
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import por_geo_selector_format_probe as p  # noqa: E402
import por_overlay_group_map as groups  # noqa: E402

POWERS = p.POWERS_OF_TEN


# --- formatter: decimal text, width clip, padding order -----------------------------------

def test_helper_text_matches_decimal_for_signed_32bit_samples():
    rng = random.Random(20261118)
    samples = [0, 1, 9, 10, 99, 100, 255, -1, -2147483648, 2147483647]
    samples += [rng.randint(-2 ** 31, 2 ** 31 - 1) for _ in range(400)]
    for v in samples:
        assert p.helper_text(v, POWERS) == str(v), v


def test_width_one_field_is_the_leading_character_for_every_selector_byte():
    for v in range(256):
        assert p.format_field(v, 0, 1, POWERS) == bytes([1]) + str(v)[0].encode("ascii"), v


def test_padding_is_written_before_the_digits_and_width_clips_the_copy():
    assert p.format_field(7, 5, 3, POWERS) == b"\x03" + b"  " + b"7"      # right-justified in min 5 -> width 3
    assert p.format_field(255, 0, 3, POWERS) == b"\x03255"
    assert p.format_field(255, 0, 2, POWERS) == b"\x0225"                  # falsifier: width is the clip
    assert p.format_field(10, 0, 1, POWERS) == b"\x011"


def test_model_depends_on_the_table_values():
    bad = list(POWERS)
    bad[8] = 20                                   # falsifier: table entry 10^1 changed
    assert p.helper_text(10, POWERS) == "10"
    assert p.helper_text(10, bad) != "10"


# --- Pascal copy, append, clamp and the record writer -------------------------------------

def test_fill_name_for_selector_one_and_three_with_probe_prefixes():
    f1 = p.fill_name(1, b"\x00", POWERS)
    assert f1["p20_geo_piece"] == "GEO1" and f1["p16_suffix_piece"] == ".dax"
    assert f1["composed_name"] == "GEO1.dax"
    assert f1["record_state_word"] == "0xD7B0"
    f3 = p.fill_name(3, b"\x03ABC", POWERS)
    assert f3["composed_name"] == "ABCGEO3.dax"


def test_digit_follows_geo_and_precedes_suffix_under_the_prefix():
    for v in (0, 9, 10, 255):
        name = p.fill_name(v, b"\x02AB", POWERS)["composed_name"]
        assert name == "ABGEO%s.dax" % str(v)[0], v


def test_prefix_longer_than_32_clips_the_suffix_at_the_40_character_clamp():
    prefix = b"\x21" + b"P" * 33                  # 33 characters
    fill = p.fill_name(1, prefix, POWERS)
    assert fill["composed_name"] == "P" * 33 + "GEO1" + ".da"
    assert len(fill["composed_name"]) == 40


def test_copy_clamp_takes_min_of_length_and_count_low_byte():
    src = b"\x19" + b"A" * 25
    assert p.p_copy_clamp(src, 0x14) == b"\x14" + b"A" * 20
    assert p.p_copy_clamp(src, 0x28) == b"\x19" + b"A" * 25


def test_record_path_is_nul_terminated_at_offset_0x30():
    rec = p.p_record(b"\x04GEO1")
    assert rec[0x30:0x35] == b"GEO1\x00"
    assert rec[2:4] == (0xD7B0).to_bytes(2, "little")


# --- control flow: must-pass and avoid witnesses ------------------------------------------

def test_unguarded_write_is_on_every_path_and_guarded_write_is_not():
    unguarded = bytes.fromhex("c6 06 76 53 01 c3")
    assert p.must_pass(unguarded, 0, 0) is True
    guarded = bytes.fromhex("74 05 c6 06 76 53 01 c3")      # jz 7 skips the write at 2
    assert p.must_pass(guarded, 0, 2) is False
    witness = p.avoid_witness(guarded, 0, 2)
    assert witness and witness[0]["flow"] == "jcc" and witness[0]["arm"] == "taken"


def test_span_ends_at_first_return():
    assert p.span(bytes.fromhex("55 89 e5 5d ca 04 00 90"), 0) == (0, 7)


# --- byte-site checks ---------------------------------------------------------------------

def test_site_check_fails_when_one_byte_changes():
    sites = [(10, "9a6613f80a", "call 0x0AF8:0x1366")]
    good = bytearray(32)
    good[10:15] = bytes.fromhex("9a6613f80a")
    assert all(row["ok"] for row in p.site_check(bytes(good), "t", sites))
    bad = bytearray(good)
    bad[12] ^= 0x01                           # falsifier: one changed byte in the call operand
    assert not all(row["ok"] for row in p.site_check(bytes(bad), "t", sites))


def test_digit_map_counts_and_absent_files_for_the_install_listing():
    install = {"GEO%d.DAX" % d for d in range(1, 9)}
    m = p.digit_map(POWERS, install)
    assert m["digit_counts"] == {"0": 1, "1": 111, "2": 67, "3": 11, "4": 11, "5": 11,
                                 "6": 11, "7": 11, "8": 11, "9": 11}
    assert m["files_named_by_some_value_absent_from_install"] == ["GEO0.DAX", "GEO9.DAX"]
    assert m["per_value"]["10"]["file"] == "GEO1.DAX"


# --- refusals -----------------------------------------------------------------------------

def test_output_outside_data_work_is_refused(tmp_path):
    with pytest.raises(p.Refusal):
        p.validate_output(tmp_path, tmp_path / "install")


def test_output_inside_the_install_is_refused():
    inside = p.DATA_WORK / "x"
    with pytest.raises(p.Refusal):
        p.validate_output(inside, p.DATA_WORK)


def test_missing_install_is_a_named_refusal(tmp_path):
    with pytest.raises(groups.Refusal):
        p.find_install(tmp_path)
    assert p.main(["--install", str(tmp_path)]) == 2


def test_unpinned_install_is_refused_before_any_output(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"x")
    (tmp_path / "START.EXE").write_bytes(b"y")
    assert p.main(["--install", str(tmp_path), "--out", str(p.DATA_WORK / "unused-test-out")]) == 2
    assert not (p.DATA_WORK / "unused-test-out").exists()


# --- retail anchors (runs only when the pinned install is selected) -----------------------

@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"), reason="retail install not selected")
def test_retail_format_chain_anchors():
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    doc, code = p.probe(install)
    assert code == 0 and doc["checks_failed"] == []
    assert doc["input_unchanged"] is True
    cov = doc["coverage"]
    assert cov["ovr_prologue_roots"] == 675 and cov["ovr_complete_walks"] == 675
    assert cov["fill_walk_complete"] is True and cov["fill_group_base"] == "0x2E8F7"
    assert doc["formatter"]["table_values"] == POWERS
    assert doc["verdict"]["selector_literal_values"] == [1, 3]
    writers = {(w["image"], w["at"]): w for w in doc["writers"]}
    for key in (("GAME.OVR", "0x0E9A3"), ("GAME.OVR", "0x19AE7"), ("GAME.OVR", "0x1FBB0"),
                ("START.EXE", "0x089AD"), ("START.EXE", "0x089BA")):
        assert key in writers
    restore = writers[("GAME.OVR", "0x1FBB0")]
    assert restore["must_pass_entry_per_root"] == {"0x1F5E8": False}
    assert restore["avoid_path_decisions_per_root"]["0x1F5E8"]
    assert doc["chain"]["prefix_empty"]["1"]["composed_name"] == "GEO1.dax"
    assert doc["chain"]["prefix_empty"]["3"]["composed_name"] == "GEO3.dax"
    assert doc["digit_mapping"]["files_named_by_some_value_absent_from_install"] == ["GEO0.DAX", "GEO9.DAX"]
    passes = {r["at"]: r["next_call_target"] for r in doc["address_passes"]}
    assert passes == {"0x1F7C1": "0x0AF8:0x14FB", "0x1FF09": "0x0AF8:0x1502"}
    assert doc["fill"]["decoded_direct_callers"] == []


@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"), reason="retail install not selected")
def test_retail_output_is_deterministic():
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    p.probe(install)
    first = (p.DEFAULT_OUT / p.OUT_JSON).read_bytes()
    p.probe(install)
    second = (p.DEFAULT_OUT / p.OUT_JSON).read_bytes()
    assert first == second
    assert json.loads(first)["playable"] is False
