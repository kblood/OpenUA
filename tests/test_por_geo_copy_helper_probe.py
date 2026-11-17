"""Tests for tools/por_geo_copy_helper_probe.py (PoR far copy helper 0x0AF8:0x1685, observe-only).

Synthetic tests build small START-like and dump-like buffers and check each gate with a falsifier: a
changed byte must change the verdict, or the probe must refuse. Retail tests run only when a pinned
PoR install is present (OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD) and pin the facts the
probe reports on the retail bytes and the two pinned dumps. They test no PoR semantics beyond that.
"""
import os
import random
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_copy_helper_probe as cp  # noqa: E402
import por_overlay_group_map as om  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL_DUMPS = cp.DEFAULT_DUMPS
RETAIL = pytest.mark.skipif(not ((RETAIL_INSTALL / "GAME.OVR").exists() and (RETAIL_INSTALL / "START.EXE").exists()
                                 and all(d.exists() for d in RETAIL_DUMPS)),
                            reason="pinned PoR install and both pinned dumps are needed")

BASE = 0x2000                       # synthetic module base in the synthetic START buffer
LOAD = 0x1866                       # synthetic load segment (the pinned runs' value)
LIN_MOD = (cp.TARGET_SEG + LOAD) * 16   # module linear base in the synthetic dump


def _random_module(seed: int = 1, n: int = 0x1800) -> bytes:
    """Distinct bytes so that no anchor recurs by chance in a synthetic buffer."""
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(n))


def _start_with_module(module: bytes = None, text_at_zero_skew: bool = True) -> bytearray:
    start = bytearray(0x10000)
    mod = bytearray(module if module is not None else _random_module())
    # The routine-B handler at module+0xD7, the copy helper at module+0x1685 with a return before it.
    mod[cp.ROUTINE_B_HANDLER_OFF:cp.ROUTINE_B_HANDLER_OFF + len(cp.ROUTINE_B_HANDLER)] = cp.ROUTINE_B_HANDLER
    mod[0x1685 - 3:0x1685] = bytes.fromhex("ca 08 00")
    mod[0x1685:0x1685 + cp.BODY_LEN] = cp.BODY
    start[BASE:BASE + len(mod)] = mod
    zero_skew = cp.HDR + cp.TARGET_SEG * 16 + cp.TARGET_OFF
    if text_at_zero_skew:
        start[zero_skew:zero_skew + 10] = b"FIRE GIANT"
    return start


def _dump_with_module(start: bytes, load: int = LOAD, size: int = 0x30000) -> om.Dump:
    d = bytearray(size)
    lin = (cp.TARGET_SEG + load) * 16
    d[lin:lin + 0x1800] = start[BASE:BASE + 0x1800]
    return om.Dump(bytes(d), 0)


def _rows(start: bytes, dump: om.Dump) -> list[dict]:
    mod = cp.dump_module(dump, start, BASE)
    ent = {"status": "absent"}
    return cp.translation_rows(start, dump, BASE, mod, ent)


# ---- ABI: byte-exact sequence and its falsifiers ---------------------------------------

def test_abi_matches_exact_sequence_and_reads_pushes_in_order():
    abi = cp.abi_decode(bytes(cp.BODY), 0)
    assert abi["matched"] is True
    lay = abi["entry_layout_from_sp"]
    assert (lay["count"], lay["dst_off"], lay["dst_seg"], lay["src_off"], lay["src_seg"]) == (4, 6, 8, 10, 12)
    assert abi["retf_imm"] == 0x0A and abi["callee_pops_bytes"] == 10


def test_abi_falsifier_retf_immediate_changes_the_match():
    bad = bytearray(cp.BODY)
    bad[-2] = 0x06                                   # retf 6 instead of 0x0A
    assert cp.abi_decode(bytes(bad), 0)["matched"] is False


def test_abi_falsifier_jnb_displacement_changes_the_match():
    bad = bytearray(cp.BODY)
    bad[20] = 0x06                                   # jnb +6 instead of +7
    assert cp.abi_decode(bytes(bad), 0)["matched"] is False


def test_abi_refuses_missing_target():
    assert cp.abi_decode(bytes(cp.BODY), None)["matched"] is False
    assert cp.abi_decode(bytes(cp.BODY[:20]), 0)["matched"] is False


def test_push_order_check_requires_five_word_shape_on_all_four_copies():
    abi = cp.abi_decode(bytes(cp.BODY), 0)
    good = [{"ok": True}] * 4
    assert cp.push_order_check(abi, good)["agrees"] is True
    bad = [{"ok": True}] * 3 + [{"ok": False}]
    assert cp.push_order_check(abi, bad)["agrees"] is False
    assert cp.push_order_check(abi, good[:3])["agrees"] is False


# ---- file shape ------------------------------------------------------------------------

def test_code_evidence_text_is_data_and_return_before_body_is_code():
    text = b"FIRE GIANT" + b"\x00" * 6
    assert cp.code_evidence(text, 0)["data_like"] is True
    body_site = b"\x00\x00\x00" + b"\xca\x08\x00" + bytes(cp.BODY)
    ev = cp.code_evidence(body_site, 6)
    assert ev["ret_before"] is True and ev["data_like"] is False and ev["code_shape"] is True


def test_code_evidence_falsifier_without_return_or_prologue_is_not_code():
    no_ret = b"\x90\x90\x90" + bytes(cp.BODY)
    assert cp.code_evidence(no_ret, 3)["code_shape"] is False


# ---- module base from the routine-B handler --------------------------------------------

def test_handler_base_unique_and_refuses_ambiguity():
    start = _start_with_module()
    assert cp.handler_base(bytes(start))["base_file"] == BASE
    twice = bytes(start) + cp.ROUTINE_B_HANDLER
    with pytest.raises(om.Refusal):
        cp.handler_base(twice)
    with pytest.raises(om.Refusal):
        cp.handler_base(bytes(0x100))


# ---- dump: module placement and translations -------------------------------------------

def test_dump_module_locates_load_segment_from_the_anchor():
    start = bytes(_start_with_module())
    dump = _dump_with_module(start)
    mod = cp.dump_module(dump, start, BASE)
    assert mod["status"] == "unique" and mod["load_seg"] == LOAD
    assert mod["seg"] == cp.TARGET_SEG + LOAD


def test_dump_module_falsifier_unaligned_anchor_is_not_a_segment():
    start = bytes(_start_with_module())
    dump = _dump_with_module(start)
    shifted = om.Dump(b"\x00" + dump.data, 0)        # module now starts at an odd byte
    assert cp.dump_module(shifted, start, BASE)["status"] == "unaligned"


def test_identity_by_bytes_when_memory_agrees_and_file_is_unique():
    start = bytes(_start_with_module())
    dump = _dump_with_module(start)
    rows = _rows(start, dump)
    good = [r for r in rows if r["state"] == "memory-agrees-and-body"]
    assert len(good) == 1 and good[0]["file_map"] == "routine-b-module-base"
    assert good[0]["dump_window_file_placements"] == ["0x%X" % (BASE + cp.TARGET_OFF)]
    decided = cp.decide_identity([{"dump": "d1", "rows": rows}])
    assert decided["verdict"] == "identified-by-bytes-in-pinned-dumps"
    assert decided["file_offset"] == "0x%X" % (BASE + cp.TARGET_OFF)


def test_zero_skew_translation_is_rejected_as_data():
    start = bytes(_start_with_module())
    rows = _rows(start, _dump_with_module(start))
    zs = [r for r in rows if r["file_map"] == "contiguous-mz" and r["load_source"] == "module-anchor-in-dump"]
    assert zs and zs[0]["state"] == "file-data-like"


def test_falsifier_one_changed_dump_byte_breaks_identity():
    start = bytes(_start_with_module())
    dump = _dump_with_module(start)
    raw = bytearray(dump.data)
    raw[LIN_MOD + 0x1685 + 5] ^= 0xFF                 # one byte of the helper differs in memory
    rows = _rows(start, om.Dump(bytes(raw), 0))
    target = [r for r in rows if r["file_map"] == "routine-b-module-base" and r["load_source"] == "module-anchor-in-dump"]
    assert target[0]["state"] == "memory-disagrees"
    assert cp.decide_identity([{"dump": "d1", "rows": rows}])["verdict"] == "unresolved"


def test_identity_fails_closed_when_two_file_offsets_both_identify():
    code_row = {"state": "memory-agrees-and-body", "live_covered": True, "load_source": "a",
                "file_code_evidence": {"code_shape": True}, "dump_window_degenerate": False,
                "dump_window_file_placements": ["0x100"], "file_offset": "0x100"}
    other = dict(code_row, file_offset="0x200", dump_window_file_placements=["0x200"])
    res = cp.decide_identity([{"dump": "d1", "rows": [code_row, other]}])
    assert res["verdict"] == "ambiguous" and res["file_offsets"] == ["0x100", "0x200"]


def test_identity_needs_every_covering_dump_to_agree():
    code_row = {"state": "memory-agrees-and-body", "live_covered": True, "load_source": "a",
                "file_code_evidence": {"code_shape": True}, "dump_window_degenerate": False,
                "dump_window_file_placements": ["0x100"], "file_offset": "0x100"}
    disagree = dict(code_row, state="memory-disagrees")
    res = cp.decide_identity([{"dump": "d1", "rows": [code_row]}, {"dump": "d2", "rows": [disagree]}])
    assert res["verdict"] == "unresolved"


def test_identity_refuses_a_non_unique_file_placement():
    row = {"state": "memory-agrees-and-body", "live_covered": True, "load_source": "a",
           "file_code_evidence": {"code_shape": True}, "dump_window_degenerate": False,
           "dump_window_file_placements": ["0x100", "0x300"], "file_offset": "0x100"}
    assert cp.decide_identity([{"dump": "d1", "rows": [row]}])["verdict"] == "unresolved"


# ---- resident call sites and the seg rewrite -------------------------------------------

def test_resident_seg_words_histogram_and_falsifier():
    raw = bytes.fromhex("9a 85 16 5e 23") * 2 + bytes.fromhex("9a 85 16 f8 0a") + b"\x00" * 4
    assert cp.resident_seg_words(raw, cp.CALL_PREFIX) == {"0x235E": 2, "0x0AF8": 1}
    changed = raw.replace(bytes.fromhex("9a 85 16 5e 23"), bytes.fromhex("9a 85 16 5e 24"), 1)
    assert cp.resident_seg_words(changed, cp.CALL_PREFIX) == {"0x235E": 1, "0x245E": 1, "0x0AF8": 1}


def test_printable_run_and_pins_refusal():
    assert cp.printable_run(b"ab\x00cdefghij") == 8
    with pytest.raises(om.Refusal):
        cp.check_pins(b"not GAME.OVR", b"not START.EXE")


def test_main_refuses_output_outside_data_work(tmp_path):
    assert cp.main(["-o", str(tmp_path / "out")]) == 2


def test_dump_base_taken_from_the_pinned_name():
    assert om.resolve_dump_base("ram-000000-100000.bin", 0x100000, None) == 0


# ---- retail-gated pins -----------------------------------------------------------------

@RETAIL
def test_retail_identity_abi_and_segment_rule():
    doc = cp.probe(RETAIL_INSTALL, RETAIL_DUMPS)
    assert doc["identity"]["verdict"] == "identified-by-bytes-in-pinned-dumps"
    assert doc["identity"]["file_offset"] == "0xC2FB"
    assert doc["abi"]["matched"] is True and doc["abi"]["retf_imm"] == 0x0A
    assert doc["push_order_check"]["callee_read_offsets_in_push_order"] == [12, 10, 8, 6, 4]
    assert doc["segment_rule"]["verdict"] == "memory-checked"


@RETAIL
def test_retail_both_dumps_link_the_same_load_and_resident_calls_use_it():
    doc = cp.probe(RETAIL_INSTALL, RETAIL_DUMPS)
    assert len(doc["per_dump"]) == 2
    for d in doc["per_dump"]:
        assert d["module"]["status"] == "unique" and d["module"]["load_seg"] == 0x1866
        assert d["link_word_equals_module_load"] is True
        assert set(d["resident_copy_call_seg_words"]) == {"0x235E"}
        for row in d["group_scan"]["copy_group_rows"]:
            for s in row["sites"]:
                assert s["match"] is True and s["seg_word_fixup_listed"] is True


@RETAIL
def test_retail_static_claims_and_fill_not_established():
    doc = cp.probe(RETAIL_INSTALL, RETAIL_DUMPS)
    assert doc["playable"] is False and doc["fill_established"] is False and doc["executed"] == "not_established"
    assert doc["static_copy_call_sites_count"] == 31
    assert all(s["seg_word_listed_as_fixup"] for s in doc["static_copy_call_sites"])
    assert doc["caller"]["copy_simulation_ok"] is True
