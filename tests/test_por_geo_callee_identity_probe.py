"""Tests for tools/por_geo_callee_identity_probe.py (PoR far call 03D5:0034, read-only).

Default tests run on hand-encoded 8086 bytes and synthetic dumps; no install is needed.
The retail test runs only when OPENUA_POR_INSTALL names a PoR install folder and the
pid34644 RAM dump exists under data/work. It pins the facts the probe reports; it does
not test any PoR semantics beyond those byte facts.
"""
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_callee_identity_probe as p  # noqa: E402
import por_overlay_group_map as om  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_DUMP = REPO / "data" / "work" / "por-live-memory-pid34644" / "ram-000000-100000.bin"


def _pad(buf: bytes, n: int) -> bytes:
    return buf + b"\x00" * (n - len(buf))


# ---- hand-encoded procedures -------------------------------------------------

RANGE_GATE = bytes.fromhex(
    "55 89 e5"                      # push bp; mov bp,sp
    "80 7e 08 0f 7f 12"             # cmp [bp+8],15 ; jg
    "80 7e 08 00 7c 0c"             # cmp [bp+8],0  ; jl
    "80 7e 06 0f 7f 06"             # cmp [bp+6],15 ; jg
    "80 7e 06 00 7d 06"             # cmp [bp+6],0  ; jge
    "c6 46 ff 00 eb 04"             # mov [bp-1],0 ; jmp
    "c6 46 ff 01"                   # mov [bp-1],1
    "8a 46 ff 89 ec 5d ca 04 00"    # mov al,[bp-1]; mov sp,bp; pop bp; retf 4
)

READ = bytes.fromhex(
    "55 89 e5"                      # push bp; mov bp,sp
    "8a 46 08 98 8b d0"             # mov al,[bp+8]; cbw; mov dx,ax
    "8a 46 06 98 b1 04 d3 e0"       # mov al,[bp+6]; cbw; mov cl,4; shl ax,cl
    "c4 3e 5c 6a 03 f8 03 fa"       # les di,[6a5c]; add di,ax; add di,dx
    "26 8a 85 00 02"                # es: mov al,[di+512]
    "88 46 ff 8a 46 ff 89 ec 5d"    # mov [bp-1],al; mov al,[bp-1]; mov sp,bp; pop bp
    "ca 04 00"                      # retf 4
)


def test_range_gate_shape_accepts_the_expected_test():
    assert p.range_gate_shape(RANGE_GATE, 0)["range_test_shape"] is True


def test_range_gate_shape_rejects_swapped_axes():
    swapped = bytearray(RANGE_GATE)
    swapped[3:6] = bytes.fromhex("80 7e 06")     # the first compare now tests [bp+6]
    assert p.range_gate_shape(bytes(swapped), 0)["range_test_shape"] is False


def test_proc_facts_reads_the_single_plane_read_and_pointer_load():
    f = p.proc_facts(READ, {"fileofs": 0, "codesz": len(READ)}, 0)
    assert f["prologue"] is True
    assert len(f["far_ptr_les"]) == 1
    assert [e["mem"] for e in f["es_reads"]] == ["[di+512]"]
    assert f["shl_cl4_offsets"] and int(f["shl_cl4_offsets"][0], 16) < int(f["far_ptr_les"][0], 16)
    assert f["ret"] == "retf 0x4"


def test_proc_facts_has_no_pointer_load_in_the_range_gate():
    f = p.proc_facts(RANGE_GATE, {"fileofs": 0, "codesz": len(RANGE_GATE)}, 0)
    assert f["far_ptr_les"] == [] and f["es_reads"] == []


def test_callee_report_checks_need_the_range_gate_and_wrap_compares():
    # The read body alone has no range gate, so its checks cannot all hold.
    group = {"fileofs": 0, "codesz": len(READ)}
    rep = p.callee_report(READ, group, 0)
    assert rep["checks"]["single_es_read_disp_0x200"] is True
    assert rep["checks"]["range_gate_shape"] is False
    assert rep["checks_ok"] is False


# ---- literal sites and group membership --------------------------------------

def test_literal_sites_find_every_occurrence():
    ovr = _pad(b"\x90\x90" + p.LITERAL + b"\x90" + p.LITERAL, 0x40)
    assert p.find_literal_sites(ovr) == [2, 2 + len(p.LITERAL) + 1]


def test_owner_group_refuses_overlapping_groups():
    g1 = {"fileofs": 0x100, "codesz": 0x80, "header_offset": 0x10, "status": "well-formed"}
    g2 = {"fileofs": 0x120, "codesz": 0x80, "header_offset": 0x20, "status": "partial"}
    with pytest.raises(om.Refusal):
        p.owner_group([g1, g2], 0x130)


def test_owner_group_returns_none_outside_every_group():
    g1 = {"fileofs": 0x100, "codesz": 0x80, "header_offset": 0x10, "status": "well-formed"}
    assert p.owner_group([g1], 0x80) is None
    assert p.owner_group([g1], 0x100) is g1


# ---- stub owner ----------------------------------------------------------------

def _stub_exe(start, n, proc=0x057A, valid=True):
    exe = bytearray(0x400)
    for k in range(n):
        at = start + 5 * k
        exe[at:at + 5] = b"\xcd\x3f" + (proc + k).to_bytes(2, "little") + b"\x00"
    return bytes(exe)


def test_stub_owner_names_index_proc_and_group():
    exe = _stub_exe(0x100, 4, proc=0x057A)
    g = {"header_offset": 0xF0, "fileofs": 0x2E8F7, "codesz": 0x120B, "status": "partial",
         "stub_start": 0x100, "stub_end": 0x114, "stub_valid": [True, True, True, True]}
    o = p.stub_owner([g], exe, 0x100 + 5 * 2)
    assert o["stub_index"] == 2 and o["proc"] == 0x057A + 2
    assert o["proc_file"] == 0x2E8F7 + 0x057A + 2
    assert o["stub_well_formed"] is True


def test_stub_owner_refuses_offset_that_is_not_a_stub_start():
    exe = _stub_exe(0x100, 4)
    g = {"header_offset": 0xF0, "fileofs": 0x2000, "codesz": 0x100, "status": "well-formed",
         "stub_start": 0x100, "stub_end": 0x114, "stub_valid": [True] * 4}
    assert p.stub_owner([g], exe, 0x101) is None


def test_stub_owner_refuses_offset_claimed_by_two_runs():
    exe = _stub_exe(0x100, 4)
    g = {"header_offset": 0xF0, "fileofs": 0x2000, "codesz": 0x100, "status": "well-formed",
         "stub_start": 0x100, "stub_end": 0x114, "stub_valid": [True] * 4}
    assert p.stub_owner([g, dict(g, header_offset=0xF8)], exe, 0x105) is None


# ---- live identity from bytes -------------------------------------------------

def _window(n=32, seed=7):
    """A stub-shaped window: CD 3F then bytes that do not repeat in the synthetic images."""
    body = bytes((seed * 31 + i * 17) & 0xFF for i in range(n - 2))
    return b"\xcd\x3f" + body


def test_identity_established_on_unique_start_window_and_stub_owner():
    win = _window()
    exe = bytearray(0x400)
    exe[0x100:0x100 + 32] = win
    exe = bytes(exe)
    g = {"header_offset": 0xF0, "fileofs": 0x2000, "codesz": 0x100, "status": "partial",
         "stub_start": 0x100, "stub_end": 0x120, "stub_valid": [True] * 4}
    dump = om.Dump(_pad(b"\x11" * 0x30 + win, 0x200), 0x1000)
    row = p.identity_from_dump(dump, exe, [g], 0x1000 + 0x30)
    assert row["status"] == "established-by-live-bytes"
    assert row["start_hits_16"] == ["0x100"]


def test_identity_refused_when_window_repeats_in_start():
    win = _window()
    exe = bytes(win + b"\x00" * 8 + win + b"\x00" * 0x300)
    dump = om.Dump(_pad(win, 0x100), 0x1000)
    row = p.identity_from_dump(dump, exe, [], 0x1000)
    assert row["status"] == "not-established"
    assert "matches 2 places" in row["reason"]


def test_identity_refused_when_target_is_outside_dump():
    dump = om.Dump(b"\x00" * 0x40, 0x1000)
    row = p.identity_from_dump(dump, b"\x00" * 0x40, [], 0x2000)
    assert row["status"] == "not-established"


def test_identity_refused_when_matched_start_offset_is_not_a_stub():
    win = _window()
    exe = bytes(b"\x00" * 0x100 + win + b"\x00" * 0x100)
    dump = om.Dump(_pad(win, 0x100), 0x1000)
    row = p.identity_from_dump(dump, exe, [], 0x1000)
    assert row["status"] == "not-established"
    assert "stub" in row["reason"]


# ---- argument push order and pointer references -----------------------------

def test_arg_push_order_accepts_x_then_y():
    code = bytes.fromhex("a0 ad 6a 50 a0 ae 6a 50 9a 34 00 d5 03")
    r = p.arg_push_order(code, 8)
    assert r["push_order_ok"] is True


def test_arg_push_order_rejects_swapped_pushes():
    code = bytes.fromhex("a0 ae 6a 50 a0 ad 6a 50 9a 34 00 d5 03")
    assert p.arg_push_order(code, 8)["push_order_ok"] is False


def test_pointer_refs_classify_store_and_les_load():
    code = bytes.fromhex("a3 5c 6a 90 90 c4 3e 5c 6a")
    rows = p.classify_ptr_refs(code, [])
    assert [r["class"] for r in rows] == ["store AX to [disp16]", "les DI (far pointer load)"]


# ---- refusals and output location --------------------------------------------

def test_probe_refuses_unpinned_input(tmp_path):
    ovr = tmp_path / "GAME.OVR"
    exe = tmp_path / "START.EXE"
    ovr.write_bytes(b"\x00" * 16)
    exe.write_bytes(b"\x00" * 16)
    with pytest.raises(om.Refusal):
        p.probe(tmp_path, tmp_path / "out", None)


def test_main_refuses_output_outside_data_work(tmp_path):
    assert p.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")]) == 2


def test_main_refuses_output_inside_the_install(tmp_path):
    inside = p.DATA_WORK / "por-geo-callee-identity-probe-refusal-test"
    assert p.main(["--install", str(inside.parent), "-o", str(inside)]) == 2


# ---- retail anchor (gated) -----------------------------------------------------

_INSTALL = os.environ.get("OPENUA_POR_INSTALL")


@pytest.mark.skipif(not _INSTALL or not RETAIL_DUMP.exists(),
                    reason="needs OPENUA_POR_INSTALL and the pid34644 RAM dump under data/work")
def test_retail_anchor_identity_callee_and_store(tmp_path):
    doc, code = p.probe(Path(_INSTALL), tmp_path, RETAIL_DUMP)
    assert doc["playable"] is False and doc["consumer_established"] is False
    assert [s["file_offset"] for s in doc["literal"]["sites"]] == [0x3A4C, 0x3F08, 0x8F1A,
                                                                 0x16E8D, 0x2DD22]
    mapped = [c for c in doc["callers"] if c["map_status"] == "unique"]
    assert {c["file_offset"] for c in mapped} == {"0x3A4C", "0x3F08", "0x8F1A"}
    assert {c["target_linear"] for c in mapped} == {"0x1C3E4"}
    assert doc["identity"]["status"] == "established-by-live-bytes"
    assert doc["identity"]["stub_owner"]["fileofs"] == 0x2E8F7
    assert doc["identity"]["stub_owner"]["stub_index"] == 4
    assert doc["identity"]["stub_owner"]["proc"] == 0x057A
    assert doc["callee"]["checks_ok"] is True
    assert doc["callee"]["range_gate_entry"] == "0x2EC16"
    assert [s["context"][3] for s in doc["pointer_store_context"]] == [
        "0xE66B call 0x0af8:0x023f"]
    assert code == 0
