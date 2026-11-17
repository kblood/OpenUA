"""Tests for tools/por_geo_loader_caller_frame_probe.py (PoR loader call sites, caller stack frames).

Synthetic tests build small procedures from hand-assembled bytes and check each stack rule with a
falsifier: a changed callee pop count, a missing CS word, a branch that changes depth, an unknown
callee, a missing prologue, a missing argument shape. Retail tests run only when a pinned PoR install
is present (OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD) and both pinned dumps exist; they pin
the static stack facts the probe reports on the retail bytes. They test no PoR semantics beyond that.
"""
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_loader_caller_frame_probe as cf  # noqa: E402
import por_overlay_group_map as om  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL = pytest.mark.skipif(
    not ((RETAIL_INSTALL / "GAME.OVR").exists() and (RETAIL_INSTALL / "START.EXE").exists()
         and all(d.exists() for d in cf.DEFAULT_DUMPS)),
    reason="pinned PoR install and both pinned dumps are needed")

SHAPE = bytes.fromhex("8a 46 06 50 8d 7e fe 16 57 8d 7e fa 16 57")   # id push, status and output far pointers
SITE_CALL = bytes.fromhex("9a 16 07 02 08")                          # call 0x0802:0x0716
COPY_0B0B = bytes.fromhex("9a 0b 0b f8 0a")                          # call 0x0AF8:0x0B0B
TABLE_RETF4 = {(0x0AF8, 0x0B0B): {"retf": 4, "conditional": False, "file": "synthetic", "source": "test"}}


def _resolver(table):
    def resolve(seg, off):
        return table.get((seg, off))
    return resolve


def _fill_like(retf_for_copy: int = 4, alloc: bytes = bytes.fromhex("81 ec 10 01")) -> bytes:
    """Two Pascal-copy calls, each leaving a destination far pointer on the stack, then the shape."""
    b = bytearray(bytes.fromhex("55 89 e5")) + bytearray(alloc)
    b += bytes.fromhex("8d be f5 fe 16 57 bf 9d 10 0e 57") + COPY_0B0B       # dst [bp-267], src cs:0x109d
    b += bytes.fromhex("8d be f0 fe 16 57 bf a1 10 0e 57") + COPY_0B0B       # dst [bp-272], src cs:0x10a1
    b += SHAPE + SITE_CALL
    return bytes(b)


def _walk(img: bytes, table, proc: int = 0):
    site = img.index(SITE_CALL)
    w = cf.Walk(img, proc, site, _resolver(table))
    w.run()
    return w


# ---- stack accounting -------------------------------------------------------------------

def test_leftover_pointers_and_allocation_are_read_from_the_bytes():
    img = _fill_like()
    w = _walk(img, TABLE_RETF4)
    assert w.fail is None
    row = cf.balance_row(w.snapshot)
    assert row["allocation_bytes"] == 0x110
    assert row["leftover_bytes"] == 8
    assert row["stack_balance"] == "balanced"
    assert row["sp_after_retf18_minus_floor_bytes"] == 0
    # the top leftover pair is the later push (lea [bp-272]); the next is lea [bp-267]
    assert [p["offset_prov"] for p in row["leftover_pairs_top_first"]] == ["lea [bp-272]", "lea [bp-267]"]
    assert row["target_bp16_caller_bp_rel"] == -(0x110 + 8)
    assert row["target_bp20_caller_bp_rel"] == -(0x110 + 8) + 4


def test_falsifier_copy_routine_popping_all_its_args_leaves_no_leftover():
    img = _fill_like()
    w = _walk(img, {(0x0AF8, 0x0B0B): {"retf": 8, "conditional": False, "file": "x", "source": "x"}})
    row = cf.balance_row(w.snapshot)
    assert row["leftover_bytes"] == 0
    assert row["stack_balance"] == "over-pop-into-locals"       # retf 18 would pop 8 bytes of the locals


def test_falsifier_allocation_changes_the_bp_relative_address():
    img = _fill_like(alloc=bytes.fromhex("81 ec 08 00"))
    row = cf.balance_row(_walk(img, TABLE_RETF4).snapshot)
    assert row["allocation_bytes"] == 8
    assert row["target_bp16_caller_bp_rel"] == -16
    assert row["stack_balance"] == "balanced"                    # the leftover, not the allocation, balances


def test_balance_rule_is_eight_minus_leftover():
    def words(n):
        return [{"at": 0, "reg": "di", "prov": "x", "size": 2}] * n
    four = cf.balance_row({"alloc": 0, "slots": words(4), "prov": {}})
    assert four["leftover_bytes"] == 8 and four["sp_after_retf18_minus_floor_bytes"] == 0
    assert four["stack_balance"] == "balanced"
    none = cf.balance_row({"alloc": 0, "slots": [], "prov": {}})
    assert none["sp_after_retf18_minus_floor_bytes"] == 8 and none["stack_balance"] == "over-pop-into-locals"
    three = cf.balance_row({"alloc": 0, "slots": words(3), "prov": {}})          # 6 bytes
    assert three["sp_after_retf18_minus_floor_bytes"] == 2
    assert three["stack_balance"] == "over-pop-into-locals"
    seven = cf.balance_row({"alloc": 0, "slots": words(7), "prov": {}})         # 14 bytes
    assert seven["sp_after_retf18_minus_floor_bytes"] == -6
    assert seven["stack_balance"] == "leftover-remains"


# ---- near calls: the far-return-via-near-call idiom -------------------------------------

def _near_idiom(callee_ret: bytes, push_cs: bool = True, extra_pairs: int = 2) -> bytes:
    """Two dst far pointers (8 bytes), then push es; push di; [push cs]; near call to a callee at 0x40."""
    body = bytearray(bytes.fromhex("55 89 e5 81 ec 10 01"))
    for _ in range(extra_pairs):
        body += bytes.fromhex("8d be f5 fe 16 57")
    body += bytes.fromhex("c4 7e 06 06 57")              # les di,[bp+6]; push es; push di (6 bytes with cs)
    if push_cs:
        body += bytes.fromhex("0e")
    call_at = len(body)
    body += b"\xe8\x00\x00"                             # patched below
    body += SHAPE + SITE_CALL
    rel = 0x40 - (call_at + 3)
    body[call_at + 1:call_at + 3] = (rel & 0xFFFF).to_bytes(2, "little")
    if len(body) < 0x40:
        body += b"\x90" * (0x40 - len(body))
    assert len(body) >= 0x40
    body[0x40:0x40 + len(callee_ret)] = callee_ret
    return bytes(body)


def test_near_call_to_retf4_callee_consumes_its_pushed_cs_and_the_args():
    img = _near_idiom(bytes.fromhex("55 89 e5 5d ca 04 00"))
    w = _walk(img, {})
    assert w.fail is None, w.fail
    row = cf.balance_row(w.snapshot)
    # 8 bytes of dst pointers + 6 bytes pushed for the near call; the near callee consumes 6 (cs + 4)
    assert row["leftover_bytes"] == 8
    assert row["stack_balance"] == "balanced"


def test_falsifier_near_retf_callee_without_pushed_cs_is_refused():
    img = _near_idiom(bytes.fromhex("55 89 e5 5d ca 04 00"), push_cs=False)
    w = _walk(img, {})
    assert w.fail is not None and "no pushed CS word" in w.fail


def test_falsifier_near_ret4_callee_leaves_the_cs_word_on_the_stack():
    img = _near_idiom(bytes.fromhex("55 89 e5 5d c2 04 00"))     # near ret 4: consumes 4, not 6
    w = _walk(img, {})
    assert w.fail is None
    row = cf.balance_row(w.snapshot)
    assert row["leftover_bytes"] == 10
    assert row["stack_balance"] == "leftover-remains"


# ---- branches, unknown callees, prologue and shape ------------------------------------------

def test_falsifier_branch_that_skips_a_push_changes_the_depth_and_is_refused():
    # jz +1 jumps over push ax to the nop at 0x0A, which is inside the window: depth 0 vs depth 2
    img = bytearray(bytes.fromhex("55 89 e5 81 ec 04 00 74 01 50 90"))
    img += SHAPE + SITE_CALL
    w = _walk(bytes(img), {})
    assert w.fail is not None and "different stack state" in w.fail


def test_branch_that_skips_nothing_keeps_the_depth():
    # jz +0 targets the nop inside the window; both paths arrive with equal depth
    img = bytearray(bytes.fromhex("55 89 e5 81 ec 04 00 74 00 90"))
    img += SHAPE + SITE_CALL
    w = _walk(bytes(img), {})
    assert w.fail is None and w.snapshot is not None


def test_unknown_far_callee_fails_closed():
    img = _fill_like()
    w = _walk(img, {})                                  # no callee table: the 0x0B0B pop is unknown
    assert w.fail is not None and "unknown callee 0af8:0b0b" in w.fail
    assert w.snapshot is None


def test_missing_prologue_is_refused():
    img = bytearray(_fill_like())
    img[0] = 0x90
    w = _walk(bytes(img), TABLE_RETF4)
    assert w.fail is not None


def test_proc_search_refuses_a_return_between_prologue_and_site():
    img = bytearray(bytes.fromhex("55 89 e5 c3 90 90"))
    img += SHAPE + SITE_CALL
    proc, valid = cf.find_proc(bytes(img), img.index(SITE_CALL))
    assert proc is None and valid == []


def test_proc_search_finds_the_nearest_prologue_that_reaches_the_site():
    img = _fill_like()
    site = img.index(SITE_CALL)
    proc, valid = cf.find_proc(img, site)
    assert proc == 0 and valid == [0]


def test_missing_shape_has_no_site():
    img = bytearray(_fill_like())
    img[img.index(SHAPE)] = 0x90                       # break the id push
    assert cf.shape_start(bytes(img), img.index(SITE_CALL)) is None


# ---- literal decode (Pascal strings) ---------------------------------------------------------

def test_pascal_literal_decodes_length_prefixed_names():
    assert cf.decode_pascal(b"\x03GEO\x04.dax", 0) == {"code_offset": "0x0000", "length_byte": 3,
                                                        "text": "GEO", "printable": True}
    assert cf.decode_pascal(b"\x04.dax", 0)["text"] == ".dax"


def test_pascal_literal_with_a_non_printable_body_is_not_a_name():
    row = cf.decode_pascal(b"\x03\x01\x02\x03", 0)
    assert row["printable"] is False and row["text"] is None


def test_pascal_literal_past_the_end_is_refused():
    assert cf.decode_pascal(b"\x03G", 5) is None


# ---- refusals and output -------------------------------------------------------------------

def test_unpinned_install_is_refused(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the retail file")
    (tmp_path / "START.EXE").write_bytes(b"not the retail file")
    code = cf.main(["--install", str(tmp_path), "-o", str(cf.DATA_WORK / "por-geo-loader-caller-frame-probe-test")])
    assert code == 2


def test_output_outside_data_work_is_refused(tmp_path):
    code = cf.main(["-o", str(tmp_path / "out")])
    assert code == 2


def test_output_inside_the_install_is_refused():
    code = cf.main(["--install", str(cf.DATA_WORK / "por-geo-run" / "POOLRAD"),
                    "-o", str(cf.DATA_WORK / "por-geo-run" / "POOLRAD" / "out")])
    assert code == 2


# ---- retail-gated: the pinned bytes and the two dumps ---------------------------------------

@RETAIL
def test_retail_fill_site_stack_equations_and_literals():
    doc = cf.probe(RETAIL_INSTALL, list(cf.DEFAULT_DUMPS))
    fill = next(r for r in doc["sites"] if r["site"] == "0x2FA17")
    assert fill["proc"] == "0x2F9BE"
    assert fill["stack"]["allocation_bytes"] == 0x110
    assert fill["stack"]["leftover_bytes"] == 8
    assert fill["stack"]["target_bp16_caller_bp_rel"] == -280
    assert fill["stack"]["target_bp20_caller_bp_rel"] == -276
    assert fill["stack"]["sp_after_retf18_minus_floor_bytes"] == 0
    assert fill["stack"]["stack_balance"] == "balanced"
    assert [p["offset_prov"] for p in fill["stack"]["leftover_pairs_top_first"]] == \
        ["lea [bp-272]", "lea [bp-267]"]
    texts = [x["pascal"]["text"] for x in fill["literals_consumed_by_copy_calls"]]
    assert texts == ["GEO", ".dax"]


@RETAIL
def test_retail_six_sites_walk_balanced_and_four_stay_unknown():
    doc = cf.probe(RETAIL_INSTALL, list(cf.DEFAULT_DUMPS))
    assert doc["summary"]["sites_total"] == 10
    assert sorted(doc["summary"]["balanced"]) == sorted(["0x1EF0D", "0x2E246", "0x2F767", "0x2FA17",
                                                         "0x047E0", "0x07276"])
    assert doc["summary"]["not_balanced"] == []
    assert sorted(doc["summary"]["unknown"]) == sorted(["0x0279E", "0x078A6", "0x1F0A8", "0x1F190"])
    assert doc["playable"] is False


@RETAIL
def test_retail_copy_routines_place_uniquely_at_the_base_in_both_dumps():
    doc = cf.probe(RETAIL_INSTALL, list(cf.DEFAULT_DUMPS))
    for row in doc["copy_routine_memory_checks"]:
        for d in row["dumps"]:
            assert d["covered"] is True
            assert d["agrees_with_base"] is True, row
