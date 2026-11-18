"""Tests for tools/por_door_reader_branch_probe.py (branch arms after the PoR plane-3 reader call).

Synthetic tests run hand-encoded 8086 bytes and need no install. Each one has a falsifier: a single
changed byte must change the reported fact. The retail tests run only when a pinned PoR install is
present (OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD) and pin the byte facts the probe
reports. They test no PoR semantics beyond those bytes. Nothing here writes a file.
"""
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_door_reader_branch_probe as rb  # noqa: E402
import por_door_caller_probe as dcp  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")

LIT = (0x03D5, 0x002F)


def _hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# A caller that reads the three party bytes, calls the reader (site at 0x0F), and on R==1 adds 1 to
# DS:6AAD (a computed store to a reader-argument byte); on R==0 the jnz is taken and it returns.
GATE = _hx("55 89e5"
           "a0ad6a 50 a0ae6a 50 a0af6a 50"          # 0x03..0x0E: push DS:6AAD, 6AAE, 6AAF
           "9a2f00d503"                             # 0x0F: call far 03D5:002F (site)
           "3c01"                                   # 0x14: cmp al,1
           "7508"                                   # 0x16: jnz 0x20
           "a0ad6a 0401 a2ad6a"                     # 0x18: mov al,[6AAD]; add al,1; mov [6AAD],al
           "5d cb")                                 # 0x20: pop bp; retf


# A caller whose only party store is the constant clamp 0x0F, on the R!=0 arm (0x16 jz skips it on R==0).
CLAMP = _hx("55 89e5"
            "a0ad6a 50 a0ae6a 50 a0af6a 50"
            "9a2f00d503"
            "08c0"                                  # 0x14: or al,al
            "7405"                                  # 0x16: jz 0x1D
            "c606ad6a0f"                            # 0x18: mov byte [6AAD], 0x0F
            "5d cb")                                # 0x1D: pop bp; retf


def _site_result(code: bytes, site: int = 0x0F, owner=None) -> dict:
    owner = owner or (0, len(code))
    return rb.analyse_site(code, site, 0, False, owner)


# ---------------------------------------------------------------- synthetic: verdicts


def test_gate_computed_store_only_on_r1_arm():
    res = _site_result(GATE)
    # the gate is cmp al,1 : only R==1 falls through to the store
    assert res["verdict_by_run"] == {"R=0": "classifier-only", "R=1": "computed-party-byte-store",
                                     "R=2": "classifier-only", "R=3": "classifier-only"}
    assert res["verdict"] == "computed-party-byte-store"
    # the store is to the reader-argument byte DS:6AAD and is non-constant
    nonconst = res["verdict_basis"]["party_arg_ds_writes_nonconst"]
    assert nonconst and all(w["addr"] == "0x6AAD" for w in nonconst)


def test_falsifier_store_to_other_address_is_nonparty():
    code = bytearray(GATE)
    code[0x1D + 1] = 0xB0          # a2 ad 6a -> a2 b0 6a: store moves to DS:6AB0, not a reader argument
    res = _site_result(bytes(code))
    assert res["verdict"] == "state-write-nonparty"
    assert res["verdict_basis"]["party_arg_ds_writes"] == []


def test_falsifier_flipped_gate_moves_the_store_to_r0():
    code = bytearray(GATE)
    code[0x16] = 0x74              # jnz -> jz: now the computed store runs on R==0, not R==1
    res = _site_result(bytes(code))
    assert res["verdict_by_run"]["R=0"] == "computed-party-byte-store"
    assert res["verdict_by_run"]["R=1"] == "classifier-only"


def test_constant_clamp_is_edge_clamp_only():
    res = _site_result(CLAMP)
    assert res["verdict"] == "edge-clamp-only"
    assert res["verdict_by_run"]["R=0"] == "classifier-only"
    assert res["verdict_by_run"]["R=1"] == "edge-clamp-only"
    assert all(w["value"]["const"] == "0x000F" for w in res["verdict_basis"]["party_arg_ds_writes"])
    assert res["verdict_basis"]["party_arg_ds_writes_nonconst"] == []


def test_falsifier_clamp_to_other_address_is_nonparty():
    code = bytearray(CLAMP)
    code[0x18 + 2] = 0xB0          # c6 06 ad 6a -> c6 06 b0 6a
    res = _site_result(bytes(code))
    assert res["verdict"] == "state-write-nonparty"


def test_store_before_the_reader_call_is_not_attributed_to_an_arm():
    # the constant store to DS:6AAD happens before the call, so it is common to every arm
    pre = _hx("55 89e5" "c606ad6a0f" "a0ad6a 50 a0ae6a 50 a0af6a 50" "9a2f00d503" "5d cb")
    res = _site_result(pre, site=0x14)
    assert set(res["verdict_by_run"].values()) == {"classifier-only"}
    assert res["verdict_basis"]["party_arg_ds_writes"] == []


def test_falsifier_same_store_after_the_call_is_attributed_to_every_arm():
    post = _hx("55 89e5" "a0ad6a 50 a0ae6a 50 a0af6a 50" "9a2f00d503" "c606ad6a0f" "5d cb")
    res = _site_result(post, site=0x0F)
    assert set(res["verdict_by_run"].values()) == {"edge-clamp-only"}


def test_missing_reader_call_is_reported_not_guessed():
    code = bytearray(GATE)
    code[0x0F:0x14] = b"\x90" * 5  # replace the call with nops
    res = _site_result(bytes(code))
    assert "error" in res


# ---------------------------------------------------------------- synthetic: the engine


def _run(code: bytes, entry: int = 0) -> dict:
    return rb.Machine(code, None, False, None, None).run(entry)


def test_unknown_call_invalidates_known_ds_bytes():
    # mov byte [1000],7 ; call near (+0) ; mov al,[1000] ; ret
    code = _hx("c606001007" "e80000" "a00010" "c3")
    ret = _run(code)["returns"][0]["al"]
    assert ret["prov"] == "DS:1000" and ret["const"] is None


def test_falsifier_without_the_call_the_byte_is_still_known():
    code = _hx("c606001007" "909090" "a00010" "c3")
    ret = _run(code)["returns"][0]["al"]
    assert ret["const"] == "0x0007"


def test_constant_flags_make_the_branch_exact():
    # mov al,0 ; or al,al ; jz +2 ; mov al,1 ; ret   -> jz always taken, AL=0 at the ret
    p1 = _hx("b000" "08c0" "7402" "b001" "c3")
    r1 = _run(p1)
    assert r1["reached"] == 4                       # 0x00, 0x02, 0x04, 0x08 only
    assert r1["returns"][0]["al"]["const"] == "0x0000"
    # falsifier: mov al,1 -> or al,1 is nonzero, jz not taken, the mov al,1 arm is reached
    p2 = _hx("b001" "08c0" "7402" "b001" "c3")
    r2 = _run(p2)
    assert r2["reached"] == 5
    assert r2["returns"][0]["al"]["const"] == "0x0001"


def test_unknown_flags_fork_both_arms():
    # or al,al with AL unknown: both the jz target and the fallthrough are reached
    p = _hx("08c0" "7402" "b001" "c3")
    assert _run(p)["reached"] == 4


def test_shift_keeps_an_upper_bound_from_the_mask():
    # and al,0xC0 ; mov cl,6 ; shr al,cl ; ret   -> AL in [0,3], the reader's field width
    code = _hx("24c0" "b106" "d2e8" "c3")
    al = _run(code)["returns"][0]["al"]
    assert al["const"] is None and al["ub"] == "0x0003"


def test_falsifier_different_shift_count_changes_the_bound():
    code = _hx("24c0" "b104" "d2e8" "c3")          # shr by 4: bound 0x0C
    al = _run(code)["returns"][0]["al"]
    assert al["ub"] == "0x000C"


def test_static_guard_found_for_a_branch_that_decides_the_site():
    # or al,al ; jz +5 ; call far 03D5:002F (site at 4) ; ret
    code = _hx("08c0" "7405" "9a2f00d503" "c3")
    guards = rb.guards_for(code, 0, 0x04)
    assert [(g["pc"], g["branch"], g["site_reached_via"]) for g in guards] == [("0x00002", "jz", "fallthrough")]


def test_falsifier_no_guard_when_both_arms_reach_the_site():
    # jz target and fallthrough both lead to the same call
    code = _hx("08c0" "7400" "9a2f00d503" "c3")   # jz +0: target == next insn == site
    assert rb.guards_for(code, 0, 0x04) == []


def test_operand_decoder_reads_bp_and_direct_forms():
    d = rb.lh.decode(_hx("8a46fe"), 0)          # mov al,[bp-2]
    o = rb.rm_operand(d)
    assert o["kind"] == "mem" and o["form"] == "bp" and o["disp"] == -2
    d3 = rb.lh.decode(_hx("c606ad6a0f"), 0)     # mov byte [0x6aad],0x0f
    o3 = rb.rm_operand(d3)
    assert o3["form"] == "direct" and o3["addr"] == 0x6AAD


def test_census_static_write_addresses():
    # add [0x6aad],al (00 06 ad 6a) writes DS:6AAD; cmp [0x6aad],0 (80 3e ad 6a 00) does not
    assert rb.static_ds_writes(rb.lh.decode(_hx("0006ad6a"), 0)) == 0x6AAD
    assert rb.static_ds_writes(rb.lh.decode(_hx("803ead6a00"), 0)) is None


def test_refusal_for_missing_install_and_for_output_outside_data_work(tmp_path):
    # nothing is written: a missing install and an output path outside data/work are both refused
    assert rb.main(["--install", str(REPO / "data" / "work" / "no-such-install"),
                    "-o", str(REPO / "data" / "work" / "unused-out")]) == 2
    assert rb.main(["--install", str(RETAIL_INSTALL), "-o", str(tmp_path / "out")]) == 2


# ---------------------------------------------------------------- retail-gated


@pytest.fixture(scope="module")
def retail():
    ovr, start, _ = dcp.load_pinned(RETAIL_INSTALL)
    return rb.probe(RETAIL_INSTALL)["analysis"], ovr


def _site(analysis: dict, site: int) -> dict:
    return next(r for r in analysis["sites"] if r["check"]["site"] == "0x%05X" % site)


@needs_retail
def test_retail_site_bytes_owner_and_caller(retail):
    analysis, _ = retail
    want = {0x0C726: ("0x0C5D1", "0x0C6FC"), 0x1699F: ("0x166CB", "0x1695F"),
            0x16D8B: ("0x166CB", "0x16D58"), 0x17469: ("0x166CB", "0x17438")}
    for site, (owner, caller) in want.items():
        c = _site(analysis, site)["check"]
        assert c["bytes_match"] and c["seg_word_in_fixup_table"] and c["ok"]
        assert c["owner_group"] == owner and c["caller_entry"] == caller


@needs_retail
def test_retail_reader_return_set_and_no_ds_writes(retail):
    analysis, _ = retail
    rf = analysis["reader"]
    assert rf["return_count"] == 1
    assert rf["return_al_upper_bounds"] == ["0x0003"]        # AL in [0,3] at the one retf 6
    assert rf["return_kinds"] == ["retf 6"]
    assert rf["ds_write_events"] == 0 and rf["incomplete"] == []


@needs_retail
def test_retail_0C726_is_a_classifier_with_a_second_check_on_r_nonzero(retail):
    analysis, _ = retail
    a = _site(analysis, 0x0C726)["analysis"]
    assert a["verdict"] == "calls-only"
    assert [x["prov"] for x in a["reader_args_top_first"].values()] == ["BP:+8", "BP:+10", "BP:+12"]
    assert a["verdict_by_run"]["R=0"] == "classifier-only"
    assert all(a["verdict_by_run"]["R=%d" % r] == "calls-only" for r in (1, 2, 3))
    assert a["verdict_basis"]["party_arg_ds_writes"] == []


@needs_retail
def test_retail_1699F_neighbour_look_has_no_party_store(retail):
    analysis, _ = retail
    a = _site(analysis, 0x1699F)["analysis"]
    assert a["party_bytes_from_args"] == ["DS:6AAF", "DS:6AAE", "DS:6AAD"]
    assert a["verdict"] == "state-write-nonparty"
    assert a["verdict_basis"]["party_arg_ds_writes"] == []


@needs_retail
def test_retail_16D8B_trial_is_constant_clamp_only(retail):
    analysis, _ = retail
    a = _site(analysis, 0x16D8B)["analysis"]
    assert a["verdict"] == "edge-clamp-only"
    assert a["verdict_basis"]["party_arg_ds_writes_nonconst"] == []
    assert len(a["verdict_basis"]["party_arg_ds_writes"]) == 12
    assert all(r["callees"] == [] for r in a["runs"].values())   # 0x16D58 calls no in-group routine


@needs_retail
def test_retail_17469_r1_arm_reaches_the_table_step_0x16E06(retail):
    analysis, _ = retail
    a = _site(analysis, 0x17469)["analysis"]
    assert a["verdict"] == "computed-party-byte-store"
    assert a["verdict_by_run"]["R=0"] == "state-write-nonparty"
    callees = {k: [c["entry"] for c in v["callees"]] for k, v in a["runs"].items()}
    assert "0x16E06" in callees["R=1"] and "0x16E06" not in callees["R=0"]
    stores = {(w["run"], w["addr"]) for w in a["verdict_basis"]["party_arg_ds_writes_nonconst"]}
    assert ("R=1", "0x6AAD") in stores and ("R=1", "0x6AAE") in stores
    assert all(w["via"] == "0x16E06" for w in a["verdict_basis"]["party_arg_ds_writes_nonconst"])


@needs_retail
def test_retail_17469_guards_are_the_0x49FA_test_and_the_es_compare(retail):
    analysis, _ = retail
    g = _site(analysis, 0x17469)["analysis"]["static_guards_to_site"]
    assert [(x["pc"], x["branch"]) for x in g] == [("0x17448", "jz"), ("0x17458", "jb")]


@needs_retail
def test_retail_census_finds_the_move_and_the_direction_stores(retail):
    analysis, _ = retail
    hits = analysis["census"]["party_byte_writes"]
    assert len(hits) == 17
    move = [h for h in hits if h["fn"] == "0x16E06"]
    assert {h["addr"] for h in move} == {"0x6AAD", "0x6AAE"} and len(move) == 6
    assert {h["addr"] for h in hits if h["fn"] == "0x16D58"} == {"0x6AAD", "0x6AAE"}


@needs_retail
def test_retail_byte_facts_wrap_in_0x16E06_and_clamp_in_0x16D58(retail):
    _, ovr = retail
    # 0x16E06: signed byte compares; below 0 stores 0x0F (wrap), above 15 stores 0x00 (wrap)
    assert ovr[0x16E30:0x16E3C] == _hx("803ead6a00 7d05 c606ad6a0f")
    assert ovr[0x16E3C:0x16E43] == _hx("803ead6a0f 7e05")
    assert ovr[0x16E43:0x16E48] == _hx("c606ad6a00")
    # 0x16D58: word compare; above 15 stores 0x0F (clamp), below 0 stores 0x00 (clamp)
    assert ovr[0x16DAA:0x16DB0] == _hx("837efe0f 7e10")
    assert ovr[0x16DB0:0x16DB5] == _hx("c606ad6a0f")


@needs_retail
def test_retail_site_falsifier_changed_literal_byte_is_refused(retail):
    _, ovr = retail
    start = (RETAIL_INSTALL / "START.EXE").read_bytes()
    mod = bytearray(ovr)
    mod[0x0C727] = 0x2E                       # 9a 2f -> 9a 2e: the literal no longer matches
    scan = fr.scan_all(start, ovr)
    allg = scan["groups"] + scan["partial_groups"]
    chk = rb.site_check(bytes(mod), allg, 0x0C726, dcp.GroupCache(bytes(mod)))
    assert chk["bytes_match"] is False and chk["ok"] is False
