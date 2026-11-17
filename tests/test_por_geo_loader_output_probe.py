"""Tests for tools/por_geo_loader_output_probe.py (PoR loader body: output far pointer, escapes, rules).

Synthetic tests hand-assemble small byte sequences and check each recogniser and mapping with a falsifier:
a changed store register, a DI-overwriting instruction between a pointer load and its store, a
branch offset that moves the target, a control byte outside the rule, a swapped TOC field order, a live
window that differs in one byte. Retail tests run only when the pinned PoR install and both pinned
dumps are present (OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD); they pin the bytes the probe
reports on the pinned files. They test no PoR semantics beyond the bytes.
"""
import os
import random
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_loadpieces_handler as lh  # noqa: E402
import por_map as pm  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_geo_loader_output_probe as op  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL = pytest.mark.skipif(
    not ((RETAIL_INSTALL / "GAME.OVR").exists() and (RETAIL_INSTALL / "START.EXE").exists()
         and all(d.exists() for d in op.DEFAULT_DUMPS)),
    reason="pinned PoR install and both pinned dumps are needed")


def _ins(data: bytes, off: int = 0):
    ins, err = lh.linear(data, off, 80, stop_on_ret=True)
    assert err is None, err
    return ins


# ---- recognisers ---------------------------------------------------------------------------

def test_les_bp_di_reads_the_bp_displacement():
    assert op.is_les_bp_di(bytes.fromhex("c4 7e 06")) == 6
    assert op.is_les_bp_di(bytes.fromhex("c4 be 0a 00")) == 10


def test_falsifier_les_of_a_direct_address_or_other_register_is_not_a_bp_pointer():
    assert op.is_les_bp_di(bytes.fromhex("c4 3e 7e 55")) is None      # les di,[0x557e]
    assert op.is_les_bp_di(bytes.fromhex("c5 7e 06")) is None         # lds di,[bp+6]
    assert op.is_les_bp_di(bytes.fromhex("c4 5e 06")) is None         # les bx,[bp+6]


def test_store_through_di_names_register_disp_and_es_prefix():
    assert op.store_through_di(bytes.fromhex("26 89 05")) == {"reg": "ax", "disp": 0, "width": 2, "es": True}
    assert op.store_through_di(bytes.fromhex("26 89 45 02"))["disp"] == 2
    assert op.store_through_di(bytes.fromhex("26 89 55 02"))["reg"] == "dx"


def test_falsifier_loads_and_direct_stores_are_not_counted():
    assert op.store_through_di(bytes.fromhex("26 8b 05")) is None     # load, not a store
    assert op.store_through_di(bytes.fromhex("26 89 06 00 00")) is None  # direct [addr], not [di]


def test_di_overwrite_is_recognised_so_a_pointer_does_not_carry_past_it():
    assert op.writes_di(bytes.fromhex("bf 00 00"))           # mov di,imm
    assert op.writes_di(bytes.fromhex("26 c4 3d"))           # es les di,[di]
    assert not op.writes_di(bytes.fromhex("26 89 05"))
    assert not op.writes_di(bytes.fromhex("89 7e 06"))       # mov [bp+6],di reads DI, does not write it


# ---- census on synthetic bodies -----------------------------------------------------------

def test_census_finds_both_stores_and_their_zero_provenance():
    body = bytes.fromhex("c4 7e 06 31 c0 26 89 05 26 89 45 02 c3")
    c = op.body_census(_ins(body), body)
    assert [(s["pointer_var_bp"], s["field_disp"], s["reg"]) for s in c["stores"]] == [(6, 0, "ax"), (6, 2, "ax")]
    assert all(s["provenance"]["kind"] == "xor-zero" for s in c["stores"])


def test_falsifier_removing_the_zeroing_leaves_the_value_unknown():
    body = bytes.fromhex("c4 7e 06 26 89 05 c3")
    c = op.body_census(_ins(body), body)
    assert c["stores"][0]["provenance"]["kind"] == "unknown"


def test_falsifier_di_overwrite_between_load_and_store_drops_the_store():
    body = bytes.fromhex("c4 7e 06 bf 00 00 26 89 05 c3")
    assert op.body_census(_ins(body), body)["stores"] == []


def test_store_from_a_far_call_return_names_the_callee():
    body = bytes.fromhex("9a 3f 02 f8 0a c4 7e 06 26 89 05 26 89 55 02 c3")
    c = op.body_census(_ins(body), body)
    assert [s["provenance"]["kind"] for s in c["stores"]] == ["far-call-return", "far-call-return"]
    assert c["stores"][0]["provenance"]["target"] == "0x0AF8:0x023F"


def test_pointer_passed_to_a_callee_is_an_escape_with_the_callee():
    body = bytes.fromhex("c4 7e 0a 06 57 9a 00 00 99 08 c3")
    c = op.body_census(_ins(body), body)
    assert c["escapes"] and c["escapes"][0]["pointer_var_bp"] == 10
    assert c["escapes"][0]["callee"] == {"flow": "call_far", "target": "0x0899:0x0000"}


def test_falsifier_escape_needs_push_es_then_push_di():
    body = bytes.fromhex("c4 7e 0a 57 06 9a 00 00 99 08 c3")       # pushed in the wrong order
    assert op.body_census(_ins(body), body)["escapes"] == []


# ---- gates, offsets and the read order ------------------------------------------------------

def test_gate_target_is_branch_plus_two_plus_rel8():
    exe = bytes.fromhex("08 c0 75 17")
    g = op.gate_check(exe, {"test": 0, "branch": 2, "target": 2 + 2 + 0x17, "op": 0x75})
    assert g["target_matches"] is True and g["op_matches"] is True and g["test_is_or_al_al"] is True


def test_falsifier_changed_rel8_moves_the_target_and_fails_the_gate():
    exe = bytes.fromhex("08 c0 75 18")
    g = op.gate_check(exe, {"test": 0, "branch": 2, "target": 2 + 2 + 0x17, "op": 0x75})
    assert g["target_matches"] is False


def test_read_order_holds_only_for_the_body_order():
    reads = [{"args": {"dst": {"op": "lea", "value": -49}, "count": 1}},
             {"args": {"dst": {"op": "lea", "value": -48}, "count": 4}},
             {"args": {"dst": {"op": "les", "value": 10}, "count": 2}},
             {"args": {"dst": {"op": "lea", "value": -44}, "count": 2}}]
    assert op._read_order_fits(reads)["all_hold"] is True
    swapped = [reads[0], reads[1], reads[3], reads[2]]               # comp before status
    assert op._read_order_fits(swapped)["all_hold"] is False


def test_read_args_recovers_handle_destination_count_and_result():
    body = bytes.fromhex("8d be cd fe 16 57 c4 7e 0a 06 57 b8 02 00 50 8d 7e cd 16 57 9a fb 14 f8 0a c3")
    ins = _ins(body)
    k = next(i for i, x in enumerate(ins) if x.flow == "call_far")
    a = op.read_args(ins, k, body)
    assert a["handle"] == {"op": "lea", "kind": "bp", "value": -307}
    assert a["dst"] == {"op": "les", "kind": "bp", "value": 10}
    assert a["result"] == {"op": "lea", "kind": "bp", "value": -51}
    assert a["count"] == 2


def test_falsifier_push_of_a_memory_count_is_reported_not_an_immediate():
    body = bytes.fromhex("8d be cd fe 16 57 c4 7e 0a 06 57 ff 76 d4 8d 7e cd 16 57 9a fb 14 f8 0a c3")
    ins = _ins(body)
    k = next(i for i, x in enumerate(ins) if x.flow == "call_far")
    assert op.read_args(ins, k, body)["count"] == {"push_mem_bp": -44}


def test_falsifier_missing_pointer_gives_no_read_args():
    body = bytes.fromhex("c4 7e 0a 06 57 b8 02 00 50 9a fb 14 f8 0a c3")   # only two pointers
    ins = _ins(body)
    k = next(i for i, x in enumerate(ins) if x.flow == "call_far")
    assert op.read_args(ins, k, body) is None


# ---- provenance of an address-passed slot ----------------------------------------------------

def test_slot_passed_by_address_is_reported_with_its_callee():
    body = bytes.fromhex("8d be cb fe 16 57 9a 00 00 99 08 8b 86 cb fe c3")
    ins = _ins(body)
    k = next(i for i, x in enumerate(ins) if x.off == 0xB)   # the load of [bp-309]
    # provenance asks for the writer before an index: query the instruction after the load (the ret)
    p = op.provenance(ins, k + 1, "ax", body)
    assert p["kind"] == "load-from-bp-slot" and p["address_passed_to"] == "0x0899:0x0000"


def test_falsifier_store_into_the_slot_is_followed_to_its_writer():
    body = bytes.fromhex("31 c0 89 86 cb fe 8b 86 cb fe c3")         # xor ax,ax ; store slot ; load slot
    ins = _ins(body)
    k = next(i for i, x in enumerate(ins) if x.off == 0x6)           # the load
    p = op.provenance(ins, k + 1, "ax", body)
    assert p["kind"] == "load-from-bp-slot" and p["via"]["kind"] == "xor-zero"


# ---- the control rule against por_map.rle_decode -----------------------------------------------

def test_rule_reads_literal_repeat_and_end_forms():
    assert op.rle_body_rule(bytes.fromhex("02 61 62 63")) == b"abc"
    assert op.rle_body_rule(bytes.fromhex("ff 41")) == b"A"
    assert op.rle_body_rule(bytes.fromhex("81 41")) == b"A" * 127
    assert op.rle_body_rule(b"") == b""


def test_falsifier_undefined_controls_and_truncation_are_refused():
    with pytest.raises(ValueError):
        op.rle_body_rule(bytes.fromhex("7f 00"))                    # 0x7F: not decoded by the body
    with pytest.raises(ValueError):
        op.rle_body_rule(bytes.fromhex("80 41"))                    # 0x80: not decoded by the body
    with pytest.raises(ValueError):
        op.rle_body_rule(bytes.fromhex("03 61"))                    # literal past the end


def test_rule_matches_por_map_on_random_valid_streams():
    rng = random.Random(0x5EED)
    for _ in range(200):
        comp, want = bytearray(), bytearray()
        for _ in range(rng.randint(1, 12)):
            if rng.random() < 0.5:
                c = rng.randint(0, 0x7E)
                chunk = bytes(rng.randrange(256) for _ in range(c + 1))
                comp += bytes((c,)) + chunk
                want += chunk
            else:
                c = rng.randint(0x81, 0xFF)
                v = rng.randrange(256)
                comp += bytes((c, v))
                want += bytes((v,)) * (256 - c)
        assert op.rle_body_rule(bytes(comp)) == bytes(want)
        assert pm.rle_decode(bytes(comp), len(want)) == bytes(want)


def test_falsifier_por_map_and_the_body_rule_diverge_on_0x7f():
    comp = bytes((0x7F,)) + bytes(range(128))
    assert len(pm.rle_decode(comp, 128)) == 128                     # por_map reads 0x7F as a literal
    with pytest.raises(ValueError):
        op.rle_body_rule(comp)                                       # the body's bytes do not


# ---- TOC order and memory mappings -----------------------------------------------------------

def test_toc_record_reads_id_offset_status_then_comp():
    raw9 = bytes([3]) + (0x1234).to_bytes(4, "little") + (1026).to_bytes(2, "little") + (934).to_bytes(2, "little")
    r = op.toc_record(raw9)
    assert r == {"id": 3, "offset": 0x1234, "status_word": 1026, "comp": 934}


def test_falsifier_swapped_toc_order_would_not_give_the_gate_value():
    raw9 = bytes([3]) + (0).to_bytes(4, "little") + (934).to_bytes(2, "little") + (1026).to_bytes(2, "little")
    assert op.toc_record(raw9)["status_word"] != op.GEO_RAW_GATE


def test_mem_check_places_a_window_uniquely_only_when_it_is_exact():
    start = random.Random(7).randbytes(1024)        # non-periodic, so a 16-byte window is unique
    file_off = 0x40
    live = start[file_off:file_off + 16]
    raw = b"\x00" * 0x100 + live                       # the live window sits at linear 0x100
    dump = om.Dump(raw, 0)
    ok = op.mem_check(start, dump, "syn", file_off, 0x10, 0, 0, 16)
    assert ok["covered"] and ok["agrees_at_file"] and ok["unique_at_file"]
    bad = bytearray(raw)
    bad[0x100 + 5] ^= 0xFF
    fal = op.mem_check(start, om.Dump(bytes(bad), 0), "syn", file_off, 0x10, 0, 0, 16)
    assert fal["agrees_at_file"] is False


def test_mem_check_reports_uncovered_windows():
    dump = om.Dump(b"\x00" * 64, 0)
    row = op.mem_check(b"\x00" * 64, dump, "syn", 0, 0x1000, 0, 0, 16)
    assert row == {"dump": "syn", "covered": False}


# ---- refusals --------------------------------------------------------------------------------

def test_unpinned_install_is_refused(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the retail file")
    (tmp_path / "START.EXE").write_bytes(b"not the retail file")
    code = op.main(["--install", str(tmp_path), "-o", str(op.DATA_WORK / "por-geo-loader-output-probe-test")])
    assert code == 2


def test_output_outside_data_work_is_refused(tmp_path):
    assert op.main(["-o", str(tmp_path / "out")]) == 2


def test_output_inside_the_install_is_refused():
    code = op.main(["--install", str(op.DATA_WORK / "por-geo-run" / "POOLRAD"),
                    "-o", str(op.DATA_WORK / "por-geo-run" / "POOLRAD" / "out")])
    assert code == 2


# ---- retail-gated: the pinned bytes and the two dumps ----------------------------------------

@pytest.fixture(scope="module")
def retail_doc():
    return op.probe(RETAIL_INSTALL, list(op.DEFAULT_DUMPS))


@RETAIL
def test_retail_identity_is_the_conditional_body_at_0x876d(retail_doc):
    assert retail_doc["target_identity"]["file_offset"] == "0x876D"
    assert retail_doc["target_identity"]["verdict"].startswith("identified")


@RETAIL
def test_retail_output_store_census_is_exactly_the_expected_eight(retail_doc):
    b = retail_doc["body"]
    assert b["expected_store_set_matches"] is True
    assert b["unexpected_stores"] == [] and b["missing_stores"] == []
    out = {s["at"]: s["provenance"]["kind"] for s in b["stores"] if s["pointer_var_bp"] == 6}
    assert out == {"0x87E0": "xor-zero", "0x87E3": "xor-zero", "0x88F0": "xor-zero", "0x88F3": "xor-zero",
                   "0x8924": "far-call-return", "0x8927": "far-call-return"}


@RETAIL
def test_retail_gates_and_read_order_hold(retail_doc):
    assert retail_doc["gates"]["A"]["target_matches"] is True and retail_doc["gates"]["A"]["branch"] == "0x87D1"
    assert retail_doc["gates"]["B"]["is_cmp_al_bp14"] is True
    assert retail_doc["gates"]["B"]["branch"]["target"] == "0x890A"
    assert retail_doc["read_order_fits_toc"]["all_hold"] is True


@RETAIL
def test_retail_alloc_and_seek_terms_are_as_the_bytes_say(retail_doc):
    s = retail_doc["seeks"][0]
    assert s["at"] == "0x893F"
    assert tuple(s["offset_add"]["operand"]) == ("bp", -48)
    assert s["offset_add"]["ax_before_add"]["address_passed_to"] == "0x8624"
    assert retail_doc["alloc_calls"] == ["0x891C"]


@RETAIL
def test_retail_tempsize_literal_is_on_the_clamp_path_and_agrees_in_both_dumps(retail_doc):
    cs = [x for x in retail_doc["literals"] if x["seg"] == "cs"]
    assert cs and cs[0]["pascal_text"] == "tempsize " and cs[0]["path"] == "clamp-block"
    assert all(m["agrees_with_file_at_mapped_offset"] for m in cs[0]["memory"])
    assert any(x["seg"] == "ds" and x["state"] == "ds-not-established" for x in retail_doc["literals"])


@RETAIL
def test_retail_clamp_gate_skips_the_clamp_block_for_every_pinned_comp(retail_doc):
    c = retail_doc["gates"]["C"]
    assert c["cmp_matches"] is True and c["target_matches"] is True and c["target"] == "0x88A9"
    assert retail_doc["toc"]["comp_all_under_clamp"] is True
    assert retail_doc["toc"]["comp_max"] <= 0x8CA0


@RETAIL
def test_retail_helpers_and_near_callees_place_in_both_dumps(retail_doc):
    rows = list(retail_doc["helpers"].values()) + list(retail_doc["near_callees"].values())
    for h in rows:
        for m in h["mem"]:
            assert m["covered"] is True and m["agrees_at_file"] is True and m["unique_at_file"] is True, h


@RETAIL
def test_retail_output_var_is_not_written_by_the_rle_decoder(retail_doc):
    assert retail_doc["near_callees"]["rle_decode_8566"]["es_stores"] == []
    assert retail_doc["near_callees"]["rle_decode_8566"]["return"]["pops"] == 0x10


@RETAIL
def test_retail_rle_rule_equals_por_map_on_all_29_blocks(retail_doc):
    r = retail_doc["rle_cross_check"]
    assert r["blocks"] == 29 and r["equal_to_por_map"] == 29
    assert r["mismatch"] == [] and r["undefined_control_hits"] == []


@RETAIL
def test_retail_toc_gate_and_id_facts(retail_doc):
    t = retail_doc["toc"]
    assert len(t["archives"]) == 8
    assert sum(a["toc_entries"] for a in t["archives"]) == 29
    assert all(a["status_gate_all"] for a in t["archives"])
    assert t["ids_total"] == 29 and t["ids_distinct"] == 29


@RETAIL
def test_retail_verdict_is_unresolved_and_not_playable(retail_doc):
    v = retail_doc["verdict"]
    assert v["status"] == "archive-and-id-not-established"
    assert v["geo_output"] == "not_established" and v["plane2_binding"] == "not claimed"
    assert v["playable"] is False and retail_doc["playable"] is False
