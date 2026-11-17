"""Tests for tools/por_door_indirect_probe.py (indirect callers of PoR stub 1, START 0x089C).

Synthetic tests use hand-encoded 8086 bytes and need no install. Each has a falsifier: a single
changed byte or field must change the reported fact, or the probe must refuse. The retail tests
run only when a pinned PoR install is present (OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD)
and pin the byte facts the probe reports. They test no PoR semantics beyond those bytes.
"""
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_door_indirect_probe as d  # noqa: E402
import por_door_caller_probe as dc  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")


def _rows(code: bytes, at: int = 0) -> list[dict]:
    w = lh.walk(code, at)
    return d.decoded_ind_sites(code, [("A", at, w)], "synthetic")


# ---------------------------------------------------------------- decode and class I


def test_ff_slash2_is_near_and_slash3_is_far():
    # 0: FF 16 34 12 = call near [0x1234]; 4: FF 1E 34 12 = call far [0x1234]; 8: ret
    code = bytes.fromhex("ff163412") + bytes.fromhex("ff1e3412") + b"\xc3"
    rows = _rows(code)
    assert [(r["site"], r["kind"], r["operand"], r["direct_ds_disp"]) for r in rows] == [
        ("0x00000", "near", "direct-ds", 0x1234),
        ("0x00004", "far", "direct-ds", 0x1234),
    ]


def test_falsifier_slash4_and_slash5_are_jumps_not_calls():
    # FF 26 = jmp near [disp] (reg 4); FF 2E = jmp far [disp] (reg 5). Neither is a census row.
    code = bytes.fromhex("ff263412") + b"\xc3"
    assert _rows(code) == []
    code = bytes.fromhex("ff2e3412") + b"\xc3"
    assert _rows(code) == []


def test_falsifier_slash2_changed_to_slash4_removes_the_row():
    base = bytes.fromhex("ff163412") + b"\xc3"
    assert len(_rows(base)) == 1
    alt = bytes.fromhex("ff263412") + b"\xc3"
    assert _rows(alt) == []


def test_operand_classes_cover_register_bp_base_index_and_invalid_far():
    cases = {
        "ffd0": ("near", "register"),          # call ax
        "ffd8": ("far", "invalid-far-register"),  # reg 3 with mod 3 is not a memory operand
        "ff18": ("far", "base-index"),         # call far [bx+si]
        "ff5e04": ("far", "bp-based"),         # call far [bp+4]
        "ff163412": ("near", "direct-ds"),     # call near [0x1234]
    }
    for hexbytes, (kind, operand) in cases.items():
        ins = lh.decode(bytes.fromhex(hexbytes) + b"\xc3", 0)
        got = d.operand_class(ins)
        assert (got["kind"], got["operand"]) == (kind, operand), hexbytes


def test_bp_operand_carries_its_displacement():
    ins = lh.decode(bytes.fromhex("ff5e04") + b"\xc3", 0)
    assert d.operand_class(ins)["bp_disp"] == 4


def test_decode_boundary_immediate_bytes_are_not_instruction_starts():
    # B8 FF 16 = mov ax, 0x16FF. The FF 16 bytes are the immediate, not a call.
    code = bytes.fromhex("b8ff16") + b"\xc3"
    assert _rows(code) == []
    cov, starts = d.covered_map([lh.walk(code, 0)], 0, len(code))
    counts = d.ff_byte_census(code, 0, len(code), cov, starts)["counts"]
    assert counts == {"inside-decoded-insn": 1}


def test_falsifier_real_call_after_the_immediate_is_a_start():
    # mov ax, 0x16FF (3 bytes) then FF 16 00 00 = call near [0] at offset 3, then ret.
    code = bytes.fromhex("b8ff16") + bytes.fromhex("ff160000") + b"\xc3"
    rows = _rows(code)
    assert [r["site"] for r in rows] == ["0x00003"]
    cov, starts = d.covered_map([lh.walk(code, 0)], 0, len(code))
    counts = d.ff_byte_census(code, 0, len(code), cov, starts)["counts"]
    assert counts == {"inside-decoded-insn": 1, "decoded-start": 1}


def test_raw_uncovered_ff_byte_is_raw_and_walking_it_changes_the_class():
    # ret at 0, then data: FF 16 00 00 at offset 1 is never walked, so it is a raw candidate.
    code = b"\xc3" + bytes.fromhex("ff160000")
    cov, starts = d.covered_map([lh.walk(code, 0)], 0, len(code))
    assert d.ff_byte_census(code, 0, len(code), cov, starts)["counts"] == {"raw-uncovered": 1}
    # falsifier: a walk that reaches offset 1 makes it a decoded start
    code2 = bytes.fromhex("ff160000") + b"\xc3"
    cov2, starts2 = d.covered_map([lh.walk(code2, 0)], 0, len(code2))
    assert d.ff_byte_census(code2, 0, len(code2), cov2, starts2)["counts"] == {"decoded-start": 1}


# ---------------------------------------------------------------- table resolution (class T)


def test_resolve_table_reads_the_word_at_ds_plus_disp():
    data = bytearray(64)
    struct.pack_into("<H", data, 0x10 + 0x20, 0x069C)
    data = bytes(data)
    assert d.resolve_table(data, 0x10, 0x20) == 0x069C
    # falsifier: no DS base stated, or displacement outside the file, resolves nothing
    assert d.resolve_table(data, None, 0x20) is None
    assert d.resolve_table(data, 0x10, 0x1000) is None


def test_table_candidate_points_to_stub1_only_for_the_exact_word():
    data = bytearray(64)
    struct.pack_into("<H", data, 0x10 + 0x20, 0x069C)
    data = bytes(data)
    rows = [{"operand": "direct-ds", "site": "0x00000", "direct_ds_disp": 0x20}]
    res = d.table_candidates(data, rows, [0x10], hdr=0x200)
    assert res["resolved"][0]["points_to_stub1"] is True
    # falsifier: one unit off is not stub 1
    bad = bytearray(data)
    struct.pack_into("<H", bad, 0x10 + 0x20, 0x069D)
    res2 = d.table_candidates(bytes(bad), rows, [0x10], hdr=0x200)
    assert res2["resolved"][0]["points_to_stub1"] is False


def test_no_ds_base_means_no_resolved_table_on_retail_style_input():
    rows = [{"operand": "direct-ds", "site": "0x00000", "direct_ds_disp": 0x43F0}]
    assert d.table_candidates(b"\x00" * 0x8000, rows, [], hdr=0x200)["resolved"] == []


def test_non_direct_operands_are_never_table_resolved():
    rows = [{"operand": "base-index", "site": "0x00000", "direct_ds_disp": None},
            {"operand": "bp-based", "site": "0x00004", "direct_ds_disp": None}]
    assert d.table_candidates(b"\x00" * 64, rows, [0x0], hdr=0x200)["resolved"] == []


# ---------------------------------------------------------------- stub-1 reach and raw candidates


def test_decoded_reach_counts_exact_models_and_falsifier_one_off():
    # near E8 to 0x089C; far under M0: seg*16+off = 0x069C; far under M1: seg*16+off = 0x081E
    w = {"near_calls": [{"at": 0x1000, "target": 0x089C}],
         "far_calls": [{"at": 0x2000, "seg": 0x0069, "off": 0x000C},
                       {"at": 0x3000, "seg": 0x0081, "off": 0x000E}]}
    r = d.stub1_decoded_reach(0x200, {"GAME.OVR": [w]})
    assert len(r["near_E8_to_stub1"]) == 1
    assert len(r["far_M0_to_stub1"]) == 1
    assert len(r["far_M1_to_stub1"]) == 1
    # falsifier: off one unit different from either model -> not reached under that model
    w2 = {"near_calls": [], "far_calls": [{"at": 0x2000, "seg": 0x0069, "off": 0x000D}]}
    r2 = d.stub1_decoded_reach(0x200, {"GAME.OVR": [w2]})
    assert r2["far_M0_to_stub1"] == []


def test_raw_candidates_find_near_word_and_far_pair_by_bytes():
    data = bytearray(64)
    struct.pack_into("<H", data, 0, 0x069C)            # near word, M0 value
    struct.pack_into("<HH", data, 8, 0x000C, 0x0069)   # far pair 0069:000C = 0x069C
    data = bytes(data)
    rc = d.raw_candidates(0x200, {"X": data})
    assert rc["near_words"]["M0_value_0x069C"]["hits"]["X"] == ["0x00000"]
    # 0000:069C is also a seg*16+off = 0x69C pair: its bytes 9C 06 00 00 are the near word plus zero padding
    assert sorted(rc["far_pairs"]["M0"]["pairs_with_hits"]) == ["0000:069C", "0069:000C"]
    assert rc["far_pairs"]["M0"]["total_hits"] == 2
    # falsifier: off by one removes the 0069:000C pair hit (the 0000:069C hit is unaffected)
    bad = bytearray(data)
    struct.pack_into("<HH", bad, 8, 0x000D, 0x0069)
    rc2 = d.raw_candidates(0x200, {"X": bytes(bad)})
    assert "0069:000C" not in rc2["far_pairs"]["M0"]["pairs_with_hits"]
    assert "0069:000D" not in rc2["far_pairs"]["M0"]["pairs_with_hits"]


def test_stub1_identity_bytes_are_the_stub_run_fingerprint():
    assert d.STUB1_BYTES == bytes.fromhex("cd3f6d0d00")
    assert d.STUB1_PROC_REL == 0x0D6D and d.PROC1_FILE == 0x17438


# ---------------------------------------------------------------- verdict, pins, output


def test_verdict_is_not_established_without_a_decoded_or_resolved_caller():
    res = {"stub1_decoded_reach": {"near_E8_to_stub1": [], "far_M0_to_stub1": [], "far_M1_to_stub1": []},
           "table_resolution": {"resolved": []}}
    assert d.verdict(res)["trigger_established"] is False
    res["stub1_decoded_reach"]["near_E8_to_stub1"] = [{"file": "START.EXE", "site": "0x00100"}]
    assert d.verdict(res)["trigger_established"] is True


def test_unpinned_input_is_refused(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the pinned overlay")
    (tmp_path / "START.EXE").write_bytes(b"not the pinned resident")
    with pytest.raises(dc.Refusal):
        dc.load_pinned(tmp_path)


def test_recheck_pins_refuses_a_changed_file(tmp_path):
    pins = {fr.OVR_NAME: {"size": 3, "sha256": fr._sha(b"abc")},
            fr.EXE_NAME: {"size": 3, "sha256": fr._sha(b"xyz")}}
    (tmp_path / fr.OVR_NAME).write_bytes(b"abc")
    (tmp_path / fr.EXE_NAME).write_bytes(b"xyz")
    after = d.recheck_pins(tmp_path, pins)
    assert after[fr.OVR_NAME]["sha256"] == pins[fr.OVR_NAME]["sha256"]
    # falsifier: one byte changed during the run is a refusal
    (tmp_path / fr.OVR_NAME).write_bytes(b"abd")
    with pytest.raises(d.Refusal):
        d.recheck_pins(tmp_path, pins)


def test_main_refuses_output_outside_data_work(tmp_path):
    assert d.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")]) == 2


def test_main_refuses_output_inside_the_install():
    install = d.DEFAULT_INSTALL
    assert d.main(["--install", str(install), "-o", str(install / "out")]) == 2


# ---------------------------------------------------------------- retail (pinned)


@needs_retail
def test_retail_pins_match_and_are_unchanged_by_the_run():
    ovr, start, pins = dc.load_pinned(RETAIL_INSTALL)
    assert pins[fr.OVR_NAME]["sha256"] == "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"
    assert pins[fr.EXE_NAME]["sha256"] == "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"
    doc = d.probe(RETAIL_INSTALL)
    assert doc["pins"]["unchanged"] is True
    assert doc["pins"]["before"][fr.OVR_NAME] == doc["pins"]["after"][fr.OVR_NAME]


@needs_retail
def test_retail_stub1_has_no_decoded_direct_or_resolved_caller():
    doc = d.probe(RETAIL_INSTALL)
    reach = doc["analysis"]["stub1_decoded_reach"]
    assert reach["near_E8_to_stub1"] == [] and reach["far_M0_to_stub1"] == [] and reach["far_M1_to_stub1"] == []
    assert doc["analysis"]["table_resolution"]["resolved"] == []
    assert doc["verdict"]["trigger_established"] is False


@needs_retail
def test_retail_census_counts_and_stub1_identity():
    doc = d.probe(RETAIL_INSTALL)
    counts = doc["analysis"]["decoded_indirect_counts"]
    assert counts["FF_2_near"] == 0
    assert counts["FF_3_far"] == 5
    assert doc["analysis"]["raw_candidates"]["stub1_identity_bytes"]["START.EXE"] == ["0x0089C"]


@needs_retail
def test_retail_group_0x166cb_is_walked_complete():
    doc = d.probe(RETAIL_INSTALL)
    g = next(x for x in doc["analysis"]["ovr"]["groups"] if x["fileofs"] == 0x166CB)
    assert g["coverage"]["walks"] == 14
    assert g["coverage"]["walks_complete"] == 14
    assert g["ind_sites"] == []


@needs_retail
def test_retail_start_handler_sets_ds_before_indirect_far_call():
    _, start, _ = dc.load_pinned(RETAIL_INSTALL)
    trace = d.start_indirect_ds_trace(start)
    assert trace["walk_complete"] is True
    assert trace["bytes_match_expected_chain"] is True
    assert trace["ds_write_between_load_and_call"] is False
    assert trace["ax_load"]["file_immediate"] == 0x0C7C
    assert trace["ds_load"]["file_immediate_before_relocation"] == 0x0C7C
    assert trace["indirect_call"]["ds_displacement"] == 0x43F0
    assert trace["static_unrelocated_table_linear"] == 0x10BB0
    assert trace["runtime_executed"] is False
