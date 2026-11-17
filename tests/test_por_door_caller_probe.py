"""Tests for tools/por_door_caller_probe.py (static callers of the PoR plane-3 door routines).

Synthetic tests run on hand-encoded 8086 bytes and need no install. Each has a falsifier: a
single changed byte must change the reported fact, or the probe must refuse. The retail tests
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
import por_door_caller_probe as d  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")


# ---------------------------------------------------------------- synthetic


def _group_code(call_rel: int) -> bytes:
    """A two-function group. A at 0 calls B (at 20) through an E8 whose rel16 is ``call_rel``.

    A: 55 89 e5 | e8 rel16 (site 6) | 5d c3      B at 20: 55 89 e5 5d c3
    """
    code = bytearray(64)
    code[0:3] = bytes.fromhex("5589e5")
    code[3] = 0xE8
    code[4:6] = struct.pack("<h", call_rel)
    code[6:8] = bytes.fromhex("5dc3")
    code[20:25] = bytes.fromhex("5589e55dc3")
    return bytes(code)


def _grp(fileofs: int = 0, codesz: int = 64) -> dict:
    return {"fileofs": fileofs, "codesz": codesz, "procs": [0], "stub_valid": [True]}


def test_closure_follows_in_group_call_to_callee():
    # site at 3, next insn at 6, so target 20 => rel = 20 - 6 = 14
    code = _group_code(call_rel=14)
    fns = d.closure(code, _grp(), [0])
    assert set(fns) == {0, 20}
    assert any(c["at"] == 3 and c["target"] == 20 for c in fns[0]["near_calls"])


def test_closure_falsifier_out_of_group_call_is_not_followed():
    code = _group_code(call_rel=0x1000)  # target far outside the 64-byte group
    fns = d.closure(code, _grp(), [0])
    assert set(fns) == {0}


def test_byte_only_site_is_not_a_caller_when_undecoded():
    code = bytearray(_group_code(call_rel=14))
    # data bytes at 40: E8 with rel to 20 (rel = 20 - 43 = -23); not a decoded start
    code[40:43] = b"\xe8" + struct.pack("<h", -23)
    code = bytes(code)
    hits = d.byte_only_near(code, _grp(), 20, decoded_sites={3})
    assert [h["site"] for h in hits] == ["0x00028"]
    # falsifier: once the site is a decoded start it is excluded from the byte-only list
    assert d.byte_only_near(code, _grp(), 20, decoded_sites={3, 40}) == []


def test_m1_delta_and_stride_literals_match_the_callee_anchor():
    # anchor: caller literal 03D5:0034 reaches stub 4 at START 0x3E02 (callee-identity doc)
    assert d.M1_DELTA == 0x7E
    assert d.STUB_SEG_RAW * 16 + 0x34 + d.M1_DELTA == 0x3E02
    # stride: stub 3 at 0x3DFD => literal 03D5:002F; stub 7 at 0x3E11 => 03D5:0043
    assert 0x3DFD - d.M1_DELTA - d.STUB_SEG_RAW * 16 == 0x2F
    assert 0x3E11 - d.M1_DELTA - d.STUB_SEG_RAW * 16 == 0x43


def test_far_m0_hits_zero_skew_arithmetic_and_falsifier():
    ovr = bytearray(32)
    ovr[10] = 0x9A
    ovr[11:13] = struct.pack("<H", 0x0010)   # offset
    ovr[13:15] = struct.pack("<H", 0x0001)   # segment
    ovr = bytes(ovr)
    hdr = 0x200
    assert d.far_m0_hits(ovr, hdr, hdr + 0x10 + 0x10) == [{"site": "0x0000A", "literal": "0001:0010"}]
    # falsifier: one slot off changes the result
    assert d.far_m0_hits(ovr, hdr, hdr + 0x10 + 0x11) == []


def test_far_m1_any_segment_counts_only_exact_images():
    ovr = bytearray(32)
    ovr[4] = 0x9A
    ovr[5:7] = struct.pack("<H", 0x002F)
    ovr[7:9] = struct.pack("<H", 0x03D5)
    ovr = bytes(ovr)
    slot = 0x3DFD
    assert d.far_m1_any_segment(ovr, slot)["count"] == 1
    assert d.far_m1_any_segment(ovr, slot + 1)["count"] == 0


def test_load_pinned_refuses_unpinned_files(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the pinned game overlay")
    (tmp_path / "START.EXE").write_bytes(b"not the pinned resident")
    with pytest.raises(d.Refusal):
        d.load_pinned(tmp_path)


def test_main_refuses_output_outside_data_work(tmp_path):
    # tmp_path is outside the repository's data/work, so the probe must refuse before reading input
    assert d.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")]) == 2


def test_group_cache_reuses_one_walk_per_fileofs():
    code = _group_code(call_rel=14)
    cache = d.GroupCache(code)
    g = _grp()
    assert cache.get(g) is cache.get(dict(g))


# ---------------------------------------------------------------- retail (pinned bytes only)


@pytest.fixture(scope="module")
def retail_doc():
    if not HAVE_RETAIL:
        pytest.skip("pinned PoR install not present")
    dumps = [REPO / "data" / "work" / "por-live-memory-pid34644" / "ram-000000-100000.bin",
             REPO / "data" / "work" / "por-wheel-live-capture" / "ram-000000-100000.bin"]
    return d.probe(RETAIL_INSTALL, dumps)


def _target(doc, name):
    return next(t for t in doc["analysis"]["targets"] if t["name"] == name)


@needs_retail
def test_retail_pins_match(retail_doc):
    assert all(v["pin_match"] for v in retail_doc["pins"].values())


@needs_retail
def test_retail_owner_groups(retail_doc):
    clear = _target(retail_doc, "clear_field")
    setter = _target(retail_doc, "set_field_01")
    reader = _target(retail_doc, "plane3_reader")
    assert clear["owner"]["fileofs"] == setter["owner"]["fileofs"] == "0x166CB"
    assert clear["owner"]["status"] == "well-formed"
    assert clear["owner"]["entry_proc_rel"] == "0x0000"
    assert setter["owner"]["entry_proc_rel"] == "0x0109"
    assert reader["owner"]["fileofs"] == "0x2E8F7"
    assert reader["owner"]["status"] == "partial"
    assert reader["owner"]["entry_proc_rel"] == "0x0350"


@needs_retail
def test_retail_decoded_in_group_callers(retail_doc):
    clear = _target(retail_doc, "clear_field")
    setter = _target(retail_doc, "set_field_01")
    reader = _target(retail_doc, "plane3_reader")
    assert sorted(r["site"] for r in clear["near_callers_decoded"]) == ["0x17558", "0x17697"]
    assert sorted(r["site"] for r in setter["near_callers_decoded"]) == \
        ["0x16B5C", "0x16B9A", "0x16C28", "0x16C66"]
    assert reader["near_callers_decoded"] == []
    assert all(r["tier"] == "A-stub-closure" for r in clear["near_callers_decoded"] + setter["near_callers_decoded"])


@needs_retail
def test_retail_reader_stride_candidates_are_decoded_and_fixup_listed(retail_doc):
    reader = _target(retail_doc, "plane3_reader")
    m1 = reader["root_stubs"][0]["M1_literal_03D5"]
    sites = m1["sites"]
    assert m1["literal"] == "03D5:002F"
    assert sorted(s["site"] for s in sites) == ["0x0C726", "0x1699F", "0x16D8B", "0x17469"]
    assert all(s["decoded_call_insn"] and s["seg_word_in_fixup_table"] for s in sites)


@needs_retail
def test_retail_no_far_literal_reaches_writer_or_clearer_stub(retail_doc):
    for name in ("clear_field", "set_field_01"):
        for r in _target(retail_doc, name)["root_stubs"]:
            assert r["stub_file"] == "0x0089C"
            assert r["M0_zero_skew_hits"] == []
            assert r["M1_any_segment"]["count"] == 0
            assert r["START_exe_byte_counts"] == {"M0_count": 0, "M1_count": 0}


@needs_retail
def test_retail_zero_skew_model_misses_reader_stub(retail_doc):
    root = _target(retail_doc, "plane3_reader")["root_stubs"][0]
    assert root["stub_file"] == "0x03DFD"
    assert root["M0_zero_skew_hits"] == []


@needs_retail
def test_retail_dump_calibration_and_stub3_bytes(retail_doc):
    dl = retail_doc["analysis"]["dump_live_check"]
    usable = [e for e in dl["dumps"] if e.get("status") == "read"]
    assert usable, "neither pinned dump is present"
    for e in usable:
        cal = {r["site"]: r for r in e["calibration_sites"] if "live_segment" in r}
        assert cal["0x03A4C"]["live_segment"] == "0x1C3B"
        assert cal["0x03F08"]["live_segment"] == "0x1C3B"
        assert cal["0x08F1A"]["live_segment"] == "0x1C3B"
        assert e["stub3_bytes_match"] is True
        assert e["group_map"]["0x166CB"]["status"] == "absent"
