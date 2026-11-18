"""Tests for tools/por_8x8d_archive_chain_probe.py (bounded 8X8D DAX read-path trace, static).

Synthetic byte fixtures, hand-assembled, so each rule has a falsifier: a length byte that does
not match its piece is not a Pascal piece, an AAS byte is not a MOV AH, a pointer that lands
on no piece does not make a base consistent, a site past a ret is not contained, and so on.
The retail anchor runs only when OPENUA_POR_INSTALL names the local Pool of Radiance DOS
install and is skipped otherwise. Nothing here writes outside a temporary folder.
"""
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, TESTS)
import por_8x8d_archive_chain_probe as P  # noqa: E402
import por_loadpieces_handler as h  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
RETAIL = os.environ.get(ENV)
needs_retail = pytest.mark.skipif(not RETAIL, reason="set %s to the PoR DOS install" % ENV)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def mz(code=None, size=0x1000) -> bytes:
    """A synthetic MZ image with a 0x200-byte header (cparhdr 0x20), as START.EXE has."""
    b = bytearray(size)
    b[0:2] = b"MZ"
    struct.pack_into("<H", b, 0x08, 0x20)
    for off, blob in (code or {}).items():
        assert off >= 0x200 and off + len(blob) <= size, off
        b[off:off + len(blob)] = blob
    return bytes(b)


def rel(site: int, target: int) -> bytes:
    return struct.pack("<h", target - (site + 3))


# --------------------------------------------------------------------------
# Name pieces
# --------------------------------------------------------------------------

def test_pascal_piece_needs_matching_length_byte():
    good = b"\x00" * 4 + b"\x05" + b"8X8d1" + b"\x04" + b".dax"
    rows = {r["kind"]: r for r in P.pieces(good) if r["pascal"]}
    assert rows["stem"]["length_byte"] == 4 and rows["stem"]["text"] == "8X8d1"
    assert rows["ext"]["length_byte"] == 10
    # falsifier: a length byte that is not the piece length is not a Pascal piece
    bad = b"\x00" * 4 + b"\x07" + b"8X8d1" + b"\x04" + b".dax"
    assert not [r for r in P.pieces(bad) if r["kind"] == "stem" and r["pascal"]]


def test_message_piece_is_found_case_insensitively():
    data = b"\x13Unable to load 8x8D"
    rows = [r for r in P.pieces(data) if r["kind"] == "message"]
    assert rows and rows[0]["pascal"] and rows[0]["length_byte"] == 0


def test_pascal_printable_reads_only_printable_strings():
    assert P.pascal_printable(b"\x01-", 0) == "-"
    assert P.pascal_printable(b"\x02ab", 0) == "ab"
    assert P.pascal_printable(b"\x00", 0) is None           # empty is not a printable string here
    assert P.pascal_printable(b"\x02\x01\x02", 0) is None   # falsifier: non-printable body
    assert P.pascal_printable(b"\x05ab", 0) is None         # falsifier: length past end of data


# --------------------------------------------------------------------------
# INT 21h AH lookback
# --------------------------------------------------------------------------

def test_int21_ah_from_immediate_predecessor():
    inv = P.int21_inventory(b"\xb4\x3d\xcd\x21" + b"\xb8\x00\x3f\xcd\x21")
    assert [s["ah"] for s in inv["sites"]] == [0x3D, 0x3F]
    assert inv["by_ah"] == {"0x3d": 1, "0x3f": 1}


def test_int21_ah_falsifiers():
    # 0x3F alone is AAS, one byte that ends at the INT: it must not be read as an AH setter
    assert P.int21_inventory(b"\x3f\xcd\x21")["sites"][0]["ah"] is None
    # a NOP between the MOV AH and the INT means the AH value is not the immediate predecessor's
    assert P.int21_inventory(b"\xb4\x3f\x90\xcd\x21")["sites"][0]["ah"] is None
    assert P.int21_inventory(b"\xcd\x21")["sites"][0]["ah"] is None


# --------------------------------------------------------------------------
# Routine walks
# --------------------------------------------------------------------------

ROUTINE_CODE = (b"\x55\x89\xe5"                 # push bp; mov bp,sp
                b"\xbf\x71\x01"                 # mov di,0x171
                b"\x0e\x57"                     # push cs; push di
                b"\x9a\x0b\x0b\xf8\x0a"         # call far 0x0af8:0x0b0b
                b"\xb0\xc9"                     # mov al,0xc9
                b"\x5d\xca\x04\x00")            # pop bp; retf 4


def test_routine_reports_pointer_constant_and_far_call():
    data = mz({0x300: ROUTINE_CODE})
    r = P.routine(data, 0x300)
    assert r["status"] == "ret-complete" and r["last_flow"] == "retf"
    assert r["cs_pointer_pushes"] == [{"at": 0x303, "imm": 0x171, "reg": "di"}]
    assert r["byte_constants"] == [{"at": 0x30D, "imm": 0xC9}]
    assert r["far_calls"] == [{"at": 0x308, "seg": 0x0AF8, "off": 0x0B0B}]


def test_routine_falsifier_unsupported_opcode_is_incomplete():
    data = mz({0x300: b"\x55\x89\xe5\x0f\x5d\xca\x00\x00"})
    r = P.routine(data, 0x300)
    assert r["status"] == "walk-incomplete"


# --------------------------------------------------------------------------
# Pointer base consistency
# --------------------------------------------------------------------------

def test_base_check_consistent_pointers_match_pieces():
    data = bytearray(0x400)
    data[0x300:0x306] = b"\x05" + b"8X8d1"
    data[0x306:0x30B] = b"\x04" + b".dax"
    rows = P.pieces(bytes(data))
    ptrs = [{"at": 1, "imm": 0x100}, {"at": 2, "imm": 0x106}]   # base 0x200 puts both on length bytes
    res = P.base_check(bytes(data), ptrs, rows)
    best = res["candidates"][0]
    assert best["cs_base"] == "0x00200" and len(best["matched"]) == 2 and not best["unmatched"]


def test_base_check_falsifier_one_pointer_is_not_two_matches():
    data = bytearray(0x400)
    data[0x300:0x306] = b"\x05" + b"8X8d1"
    data[0x306:0x30B] = b"\x04" + b".dax"
    rows = P.pieces(bytes(data))
    ptrs = [{"at": 1, "imm": 0x100}, {"at": 2, "imm": 0x107}]   # second pointer misses the .dax length byte
    res = P.base_check(bytes(data), ptrs, rows)
    best = res["candidates"][0]
    assert len(best["matched"]) == 1 and len(best["unmatched"]) == 1


def test_base_check_preferred_base_is_tested_alone():
    data = bytearray(0x400)
    data[0x320:0x325] = b"\x04" + b"8x8d"
    rows = P.pieces(bytes(data))
    ptrs = [{"at": 1, "imm": 0x20}, {"at": 2, "imm": 0x39}]
    res = P.base_check(bytes(data), ptrs, rows, preferred=0x300)
    pref = res["preferred"]
    assert pref["cs_base"] == "0x00300" and len(pref["matched"]) == 1
    assert pref["unmatched"][0]["other"] == "not-a-printable-pascal"


# --------------------------------------------------------------------------
# Containment, callers
# --------------------------------------------------------------------------

def test_containing_routine_requires_ret_stop_and_membership():
    data = mz({0x300: b"\x55\x89\xe5\xb4\x3d\xcd\x21\x5d\xca\x00\x00"})
    assert [c["entry"] for c in P.containing_routines(data, 0x305)] == [0x300]
    # falsifier: an address after the ret is not contained in the routine
    assert P.containing_routines(data, 0x30B) == []


def test_near_and_linear_far_callers_are_decode_checked():
    data = mz({0x300: b"\xe8" + rel(0x300, 0x400), 0x500: b"\x9a\x00\x04\x00\x10"})
    assert [c["at"] for c in P.near_callers(data, 0x400)] == [0x300]
    assert P.near_callers(data, 0x401) == []
    # 0x1000 * 16 + 0x40 ... use seg*16+off == 0x0A40 for a 9A at 0x500: seg 0x0A4, off 0x0
    data2 = mz({0x500: b"\x9a\x00\x00\xa4\x00"})
    hits = P.linear_far_callers(data2, 0xA40)
    assert [x["at"] for x in hits] == [0x500]
    assert P.linear_far_callers(data2, 0xA41) == []     # falsifier: a different linear address


# --------------------------------------------------------------------------
# Model check and closure
# --------------------------------------------------------------------------

def test_model_check_counts_ret_complete_at_delta_zero():
    seg, off = 0x0802, 0x0100
    f = 0x200 + seg * 16 + off
    data = bytearray(0x9000)
    data[f] = 0xC3                                      # ret
    sites = [(0, seg, off)]
    row = P.model_check(bytes(data), sites)["0x0802"]
    assert row["targets"] == 1 and row["delta0_ret_complete"] == 1 and row["delta0_decode_error"] == 0


def test_model_check_falsifier_decode_error_is_counted():
    seg, off = 0x0802, 0x0100
    f = 0x200 + seg * 16 + off
    data = bytearray(0x9000)
    data[f] = 0x0F                                      # unsupported escape byte here
    row = P.model_check(bytes(data), [(0, seg, off)])["0x0802"]
    assert row["delta0_ret_complete"] == 0 and row["delta0_decode_error"] == 1


def test_closure_reaches_int21_through_a_near_call():
    data = mz({0x300: b"\xe8" + rel(0x300, 0x320) + b"\xc3",
               0x320: b"\xb4\x3e\xcd\x21\xc3"})
    cl = P.closure(data, [(0x300, "root")], depth=2, budget=10)
    hits = [c for c in cl if c["int21_sites"]]
    assert hits and hits[0]["entry"] == 0x320 and hits[0]["depth"] == 1


# --------------------------------------------------------------------------
# Pins, refusal, output (synthetic install, allow-unpinned path)
# --------------------------------------------------------------------------

def test_pinned_row_refuses_mismatch_without_flag():
    with pytest.raises(P.ProbeError):
        P._pinned_row("START.EXE", b"x", P.PINNED_EXE["START.EXE"], allow_unpinned=False)
    row = P._pinned_row("START.EXE", b"x", P.PINNED_EXE["START.EXE"], allow_unpinned=True)
    assert row["pin_match"] is False


def test_main_refuses_unpinned_install_and_output_inside_install(tmp_path):
    inst = tmp_path / "inst"
    inst.mkdir()
    (inst / "START.EXE").write_bytes(mz())
    (inst / "GAME.OVR").write_bytes(b"FBOV" + b"\x00" * 300)
    out = tmp_path / "out"
    assert P.main(["--install", str(inst), "-o", str(out)]) == 2       # pins do not match
    assert not out.exists()
    assert P.main(["--install", str(inst), "-o", str(inst / "sub")]) == 2   # inside the install


def test_main_allow_unpinned_writes_deterministic_outputs(tmp_path):
    inst = tmp_path / "inst"
    inst.mkdir()
    (inst / "START.EXE").write_bytes(mz())
    (inst / "GAME.OVR").write_bytes(b"FBOV" + b"\x00" * 300)
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    code1 = P.main(["--install", str(inst), "-o", str(out1), "--allow-unpinned"])
    code2 = P.main(["--install", str(inst), "-o", str(out2), "--allow-unpinned"])
    assert code1 == code2 == 1                                          # diagnostic, not evidence
    j1 = (out1 / "por_8x8d_archive_chain_probe.json").read_bytes()
    j2 = (out2 / "por_8x8d_archive_chain_probe.json").read_bytes()
    assert j1 == j2
    doc = json.loads(j1)
    assert doc["playable"] is False and doc["mappings"] == [] and doc["binding_established"] is False
    assert len(doc["unresolved_edges"]) == 8
    text = j1.decode("utf-8")
    assert str(inst) not in text                                        # no absolute paths in output


# --------------------------------------------------------------------------
# Retail anchor (skipped unless the install is named)
# --------------------------------------------------------------------------

@needs_retail
def test_retail_anchor_pins_and_pieces():
    folder = P.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    ovr = (folder / "GAME.OVR").read_bytes()
    assert P._sha(exe) == P.PINNED_EXE["START.EXE"][1]
    assert P._sha(ovr) == P.PINNED_EXE["GAME.OVR"][1]
    pcs = {(r["offset"], r["kind"]): r for r in P.pieces(exe)}
    stem = [r for r in P.pieces(exe) if r["kind"] == "stem" and r["text"] == "8X8d1"][0]
    assert stem["pascal"] and stem["length_byte"] == 0x723A
    ext = [r for r in P.pieces(exe) if r["kind"] == "ext" and r["pascal"]]
    assert any(r["length_byte"] == 0x7240 for r in ext)
    assert pcs  # the scan returns rows


@needs_retail
def test_retail_anchor_start_0x7245_and_block_201():
    folder = P.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    L = P.routine(exe, 0x7245)
    assert L["status"] == "ret-complete" and L["instructions"] == 44 and L["end"] == 0x72A8
    assert [(p["at"], p["imm"]) for p in L["cs_pointer_pushes"]] == [(0x7250, 0x171), (0x725F, 0x177)]
    assert [(b["at"], b["imm"]) for b in L["byte_constants"]] == [(0x7269, 0xC9)]
    assert any(c["seg"] == 0x0802 and c["off"] == 0x0716 for c in L["far_calls"])
    base = P.base_check(exe, L["cs_pointer_pushes"], P.pieces(exe))
    assert base["candidates"][0]["cs_base"] == "0x070c9" and len(base["candidates"][0]["matched"]) == 2


@needs_retail
def test_retail_anchor_gameovr_0x32270_pointers_and_stub():
    folder = P.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    ovr = (folder / "GAME.OVR").read_bytes()
    R = P.routine(ovr, 0x32270)
    assert R["status"] == "ret-complete" and R["instructions"] == 106 and R["end"] == 0x3236F
    assert [p["imm"] for p in R["cs_pointer_pushes"]] == [0x0000, 0x0020, 0x0025, 0x0039]
    gctx = P.group_context(exe, ovr, 0x32270)
    assert gctx["body_fileofs"] == 0x32235 and gctx["entry_is_proc"] is True
    assert gctx["stub_matching_entry"]["start_file_offset"] == 0x42DE
    # the load call 0x0464:0x0111 is unconditional, and the slot test after it jumps to 0x32364
    assert (0x322F3, 0x0464, 0x0111) in [(c["at"], c["seg"], c["off"]) for c in R["far_calls"]]
    assert {"at": 0x3230B, "target": 0x32364} in R["conditional_jumps"]
    pref = P.base_check(ovr, R["cs_pointer_pushes"], P.pieces(ovr), preferred=0x32235)["preferred"]
    matched = {m["piece"] for m in pref["matched"]}
    assert matched == {"8x8d", "Unable to load 8x8D"}
    assert {u["other"] for u in pref["unmatched"]} == {"not-a-printable-pascal", "pascal '-'"}


@needs_retail
def test_retail_anchor_int21_inventory_and_overlay_header():
    folder = P.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    ovr = (folder / "GAME.OVR").read_bytes()
    inv = P.int21_inventory(exe)
    assert inv["count"] == 58 and inv["by_ah"]["0x3d"] == 1 and inv["by_ah"]["0x3f"] == 5
    assert [s["at"] for s in inv["sites"] if s["ah"] == 0x3D] == [0x0A8B6]
    assert P.int21_inventory(ovr)["count"] == 0
    assert ovr[:4] == b"FBOV"
    imms = {i["imm"] for i in P.immediates(exe, P.OVERLAY_HEADER_ROUTINE)}
    assert {"0x5a4d", "0x4246", "0x564f", "0x253f"} <= imms


@needs_retail
def test_retail_anchor_block_201_and_model_counts():
    folder = P.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    dax = (folder / "8X8D1.DAX").read_bytes()
    import por_map
    ents, _base = por_map.parse_dax(dax)
    assert [(e.index, e.block_id, e.raw_size) for e in ents][3] == (3, 201, 1416)
    rows = P.model_check(exe, P.far_call_sites(exe))
    assert rows["0x0af8"]["targets"] == 42 and rows["0x0af8"]["delta0_ret_complete"] == 30


@needs_retail
def test_retail_probe_is_deterministic_and_pins_hold(tmp_path):
    out1, out2 = tmp_path / "a", tmp_path / "b"
    assert P.main(["--install", RETAIL, "-o", str(out1)]) == 0
    assert P.main(["--install", RETAIL, "-o", str(out2)]) == 0
    assert (out1 / "por_8x8d_archive_chain_probe.json").read_bytes() == \
        (out2 / "por_8x8d_archive_chain_probe.json").read_bytes()
    doc = json.loads((out1 / "por_8x8d_archive_chain_probe.json").read_bytes())
    assert doc["source_unchanged"] is True and doc["binding_established"] is False
    assert all(p["pin_match"] for p in doc["pins"].values())
