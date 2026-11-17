"""Tests for tools/por_geo_loader_target_probe.py (PoR loader target 0x0802:0x0716, observe-only).

Synthetic tests build small START-like buffers and check each gate with a falsifier: a changed byte,
a wrong load, a duplicate placement, or a changed push shape must change the verdict or be refused.
Retail tests run only when a pinned PoR install is present (OPENUA_POR_INSTALL, or
data/work/por-geo-run/POOLRAD) and both pinned dumps exist; they pin the facts the probe reports on the
retail bytes and the two dumps. They test no PoR semantics beyond that.
"""
import os
import random
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_loader_target_probe as lt  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_overlay_group_map as om  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL = pytest.mark.skipif(
    not ((RETAIL_INSTALL / "GAME.OVR").exists() and (RETAIL_INSTALL / "START.EXE").exists()
         and all(d.exists() for d in lt.DEFAULT_DUMPS)),
    reason="pinned PoR install and both pinned dumps are needed")

LOAD = 0x1866


def _rand(n: int, seed: int = 7) -> bytes:
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(n))


def _start_with_window(window: bytes, at: int, size: int = 0x4000) -> bytearray:
    s = bytearray(_rand(size))
    s[at:at + len(window)] = window
    return s


# ---- masked placement ----------------------------------------------------------------------

def test_exact_window_matches_with_no_span():
    body = bytes.fromhex("55 89 e5 81 ec 3e 02 c4 7e 14 06 57 8d 7e eb 16")
    start = _start_with_window(body, 0x100)
    assert lt.masked_match(bytes(start), 0x100, body, LOAD) == []


def test_segment_literal_rewritten_by_load_is_accepted():
    # file: call 0x0AF8:0x0B25 (9a 25 0b f8 0a); memory: the same call with seg 0x0AF8+load = 0x235E
    file_w = bytes.fromhex("55 89 e5 9a 25 0b f8 0a 8d be c3")
    live_w = bytes.fromhex("55 89 e5 9a 25 0b 5e 23 8d be c3")
    start = _start_with_window(file_w, 0x80)
    assert lt.masked_match(bytes(start), 0x80, live_w, LOAD) == [6]   # the f8 0a word starts at index 6


def test_falsifier_non_literal_byte_change_is_rejected():
    file_w = bytes.fromhex("55 89 e5 9a 25 0b f8 0a 8d be c3")
    live_w = bytearray.fromhex("55 89 e5 9a 25 0b 5e 23 8d be c3")
    live_w[9] ^= 0x01                       # not part of the literal pair
    start = _start_with_window(file_w, 0x80)
    assert lt.masked_match(bytes(start), 0x80, bytes(live_w), LOAD) is None


def test_falsifier_wrong_load_is_rejected():
    file_w = bytes.fromhex("55 89 e5 9a 25 0b f8 0a 8d be c3")
    live_w = bytes.fromhex("55 89 e5 9a 25 0b 5e 23 8d be c3")
    start = _start_with_window(file_w, 0x80)
    assert lt.masked_match(bytes(start), 0x80, live_w, LOAD + 1) is None


def test_falsifier_literal_pair_not_shifted_by_load_is_rejected():
    file_w = bytes.fromhex("55 89 e5 9a 25 0b f8 0a 8d be c3")
    live_w = bytes.fromhex("55 89 e5 9a 25 0b 00 00 8d be c3")   # changed to zero, not file+load
    start = _start_with_window(file_w, 0x80)
    assert lt.masked_match(bytes(start), 0x80, live_w, LOAD) is None


def test_placement_is_unique_or_reported_as_duplicate():
    body = bytes.fromhex("55 89 e5 81 ec 3e 02 c4 7e 14 06 57 8d 7e eb 16 57 b8 14 00 50")
    start = _start_with_window(body, 0x200)
    start[0x900:0x900 + len(body)] = body                 # a second copy of the same bytes
    got = [p["file_offset"] for p in lt.placements(bytes(start), body, LOAD)]
    assert got == [0x200, 0x900]                         # two placements: the gate must refuse a unique claim


def test_placement_single_offset_when_unique():
    body = bytes.fromhex("55 89 e5 81 ec 3e 02 c4 7e 14 06 57 8d 7e eb 16 57 b8 14 00 50")
    start = _start_with_window(body, 0x3000)
    got = [p["file_offset"] for p in lt.placements(bytes(start), body, LOAD)]
    assert got == [0x3000]


# ---- call sites and the caller shape --------------------------------------------------------

def _caller(id_form: bytes, s1: bytes, s2: bytes) -> bytes:
    return id_form + s1 + s2 + bytes.fromhex("9a 16 07 02 08")


def test_caller_shape_accepts_disp8_and_disp16_forms():
    disp8 = _caller(bytes.fromhex("8a 46 06 50"), bytes.fromhex("8d 7e fe 16 57"), bytes.fromhex("8d 7e fa 16 57"))
    disp16 = _caller(bytes.fromhex("8a 46 0e 50"), bytes.fromhex("8d be ed fe 16 57"),
                     bytes.fromhex("8d be e7 fe 16 57"))
    const_id = _caller(bytes.fromhex("b0 c9 50"), bytes.fromhex("8d 7e fe 16 57"), bytes.fromhex("8d 7e fa 16 57"))
    for img in (disp8, disp16, const_id):
        site = len(img) - 5
        r = lt.caller_shape(img, site)
        assert r == {"shape_matched": True, "pushed_bytes": 10}


def test_falsifier_extra_push_changes_shape():
    extra = _caller(bytes.fromhex("8a 46 06 50 50"), bytes.fromhex("8d 7e fe 16 57"),
                    bytes.fromhex("8d 7e fa 16 57"))
    site = len(extra) - 5
    assert lt.caller_shape(extra, site)["shape_matched"] is False


def test_falsifier_missing_far_pointer_changes_shape():
    short = _caller(bytes.fromhex("8a 46 06 50"), bytes.fromhex("8d 7e fe 16 57"), bytes.fromhex("8d 7e fa 90"))
    site = len(short) - 5
    assert lt.caller_shape(short, site)["shape_matched"] is False


def test_call_sites_find_the_loader_bytes_only():
    img = bytes.fromhex("90 9a 16 07 02 08 90 9a 16 07 02 09")
    assert lt.call_sites(img) == [1]


# ---- the body's contract ------------------------------------------------------------------

def _body(retf_imm: int, extra: bytes = b"") -> bytes:
    """push bp; mov bp,sp; mov ax,[bp+14]; les di,[bp+6]; xor ax,ax; es mov [di],ax; mov sp,bp; pop bp;
    retf imm. A minimal body that reads the id at +14 and writes through the output pointer at +6."""
    return (bytes.fromhex("55 89 e5 8b 46 0e c4 7e 06 31 c0 26 89 05")
            + extra + bytes.fromhex("89 ec 5d")
            + bytes([0xCA, retf_imm & 0xFF, retf_imm >> 8]))


def test_contract_reads_pops_and_stores_from_bytes():
    exe = bytes(_rand(0x100, 3)) + _body(10)
    c = lt.contract(exe, 0x100)
    assert c["retf_pops_bytes"] == 10
    assert c["decode_error"] is None
    assert 6 in c["pointer_params_loaded_far"]
    assert 14 in c["bp_params_read"]
    assert any(s["via_bp_pointer"] == 6 for s in c["pointer_stores"])


def test_contract_matches_callers_when_pops_equal_pushes():
    exe = bytes(_rand(0x100, 3)) + _body(10)
    c = lt.contract(exe, 0x100)
    callers = [{"shape_matched": True, "pushed_bytes": 10}] * 3
    p = lt.contract_vs_callers(c, callers)
    assert p["prototype_match"] is True and p["reasons"] == []


def test_falsifier_pop_count_conflict_is_reported():
    exe = bytes(_rand(0x100, 3)) + _body(18)
    c = lt.contract(exe, 0x100)
    callers = [{"shape_matched": True, "pushed_bytes": 10}] * 3
    p = lt.contract_vs_callers(c, callers)
    assert p["prototype_match"] is None
    assert p["extra_pop_bytes_beyond_explicit_pushes"] == 8
    assert any("caller-frame accounting needed" in r for r in p["reasons"])


def test_falsifier_read_above_pushed_region_is_reported():
    extra = bytes.fromhex("c4 7e 14")                      # les di,[bp+20]: a pointer above the pushes
    exe = bytes(_rand(0x100, 3)) + _body(10, extra)
    c = lt.contract(exe, 0x100)
    callers = [{"shape_matched": True, "pushed_bytes": 10}] * 3
    p = lt.contract_vs_callers(c, callers)
    assert p["prototype_match"] is None
    assert 20 in p["params_read_above_pushed_region"]


def test_no_caller_shape_is_not_a_match():
    c = {"retf_pops_bytes": 10, "bp_params_read": [6], "bp_params_read_before_first_branch": []}
    p = lt.contract_vs_callers(c, [{"shape_matched": False}])
    assert p["prototype_match"] is False


# ---- verdicts -------------------------------------------------------------------------

def _row(dump: str, offs: list, covered: bool = True) -> dict:
    return {"dump": dump, "covered": covered, "placements": [{"file_offset": o, "segment_literal_spans": 0}
                                                             for o in offs]}


def _seg(dump: str, n_unique: int, live: int = 0x2068) -> dict:
    rows = [{"site": "0x%X" % i, "map_status": "unique", "live_seg_value": live,
             "live_seg_minus_raw": "0x1866"} for i in range(n_unique)]
    return {dump: rows}


def test_identity_requires_two_rewritten_sites_per_covering_dump():
    rows = [_row("a", [0x876D]), _row("b", [0x876D])]
    assert lt.identity_verdict(rows, _seg("a", 2) | _seg("b", 1), LOAD)["verdict"] == "unresolved"
    ok = lt.identity_verdict(rows, _seg("a", 2) | _seg("b", 2), LOAD)
    assert ok["verdict"] == "identified-by-memory-bytes-conditional-on-live-segment"
    assert ok["file_offset"] == "0x876D"


def test_identity_refuses_ambiguous_placement():
    rows = [_row("a", [0x100, 0x900]), _row("b", [0x100, 0x900])]
    assert lt.identity_verdict(rows, _seg("a", 2) | _seg("b", 2), LOAD)["verdict"] == "ambiguous"


def test_identity_refuses_dumps_that_disagree():
    rows = [_row("a", [0x876D]), _row("b", [0x1234])]
    assert lt.identity_verdict(rows, _seg("a", 2) | _seg("b", 2), LOAD)["verdict"] == "unresolved"


def test_overall_is_never_promoted_to_geo():
    ident = {"verdict": "identified-by-memory-bytes-conditional-on-live-segment", "file_offset": "0x876D"}
    ok = {"prototype_match": True, "reasons": []}
    bad = {"prototype_match": False, "reasons": ["body pops fewer bytes than explicit caller pushes"]}
    unknown = {"prototype_match": None, "reasons": ["caller-frame accounting required"]}
    assert lt.overall(ident, ok)["status"] == "contract-consistent-output-unproven"
    assert lt.overall(ident, bad)["status"] == "unresolved-prototype-conflict"
    assert lt.overall(ident, unknown)["status"] == "caller-frame-accounting-required"
    assert lt.overall({"verdict": "unresolved", "reason": "x"}, ok)["status"] == "unresolved"
    for v in (lt.overall(ident, ok), lt.overall(ident, bad)):
        assert v["geo_output"] == "not_established" and v["plane2_binding"] == "not claimed"


def test_contiguous_candidate_offset_is_the_zero_skew_map():
    assert lt.CONTIG_FILE == 0x200 + 0x0802 * 16 + 0x0716 == 0x8936


# ---- refusals ---------------------------------------------------------------------------

def test_unpinned_install_is_refused(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the pinned file")
    (tmp_path / "START.EXE").write_bytes(b"not the pinned file")
    with pytest.raises(om.Refusal):
        lt.probe(tmp_path, [])


def test_output_outside_data_work_is_refused(tmp_path):
    assert lt.main(["-o", str(tmp_path / "out"), "--install", str(tmp_path)]) == 2


# ---- retail gated -------------------------------------------------------------------------

@RETAIL
def test_retail_identity_contract_and_control():
    doc = lt.probe(RETAIL_INSTALL, lt.DEFAULT_DUMPS)
    assert doc["loader"]["seg"] == "0x0802" and doc["loader"]["off"] == "0x0716"
    assert doc["start_load_from_rewrite"] == "0x1866"
    assert doc["caller_shape_matched"] == doc["caller_shape_total"] == 10
    assert doc["identity"]["verdict"] == "identified-by-memory-bytes-conditional-on-live-segment"
    assert doc["identity"]["file_offset"] == "0x876D"
    assert doc["body_contract"]["retf_pops_bytes"] == 18
    assert doc["body_contract"]["return_count"] == 1
    assert doc["prototype"]["prototype_match"] is None
    assert doc["prototype"]["extra_pop_bytes_beyond_explicit_pushes"] == 8
    assert doc["prototype"]["params_read_above_pushed_region"] == [16, 20]
    assert doc["positive_control"]["passes_all"] is True
    for t in doc["target"]:
        assert [p["file_offset"] for p in t["placements"]] == [0x876D]
        assert t["contiguous_candidate"]["state"] == "memory-disagrees"
    assert doc["verdict"]["status"] == "caller-frame-accounting-required"
    assert doc["verdict"]["geo_output"] == "not_established"
