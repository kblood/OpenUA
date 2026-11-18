"""Tests for tools/por_8x8d_dos_sites_probe.py (START.EXE DOS open/read sites, static).

Synthetic byte fixtures, hand-assembled, so each rule has a falsifier: a ret byte used as an
immediate is only a byte-ret basis (tier B), a site beyond a ret is not contained, an E8 target
that an anchored sweep covers without starting on is not graded as an entry, a CS pointer needs
the push cs / push reg pattern, the ASCIIZ-copy-then-open pattern needs the zero terminator, and a
9A literal needs to match the model target. The retail anchors run only when OPENUA_POR_INSTALL
names the local Pool of Radiance DOS install and are skipped otherwise. Nothing here writes outside
a temporary folder.
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
import por_8x8d_dos_sites_probe as D  # noqa: E402
import por_8x8d_archive_chain_probe as chain  # noqa: E402

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


PROLOGUE = b"\x55\x89\xe5"               # push bp; mov bp,sp
RET = b"\xc3"
MOV_AH_3D = b"\xb4\x3d"                  # mov ah,3Dh
INT21 = b"\xcd\x21"

# The open helper's shape as decoded in retail START.EXE 0x0A89E (lds, copy, NUL, lea, mov ah 3Dh, int)
ASCIIZ_OPEN = (b"\xc5\x76\x06"          # lds si,[bp+6]
               b"\xac\x8a\xc8\x32\xed"  # lodsb; mov cl,al; xor ch,ch
               b"\xf3\xa4"              # rep movsb
               b"\x32\xc0\xaa"          # xor al,al; stosb  (the NUL terminator)
               b"\x8d\x96\x7e\xff"      # lea dx,[bp-0x82]
               b"\x16\x1f"              # push ss; pop ds
               b"\x8a\x46\xfe"          # mov al,[bp-2]
               b"\xb4\x3d\xcd\x21"      # mov ah,3Dh; int 21h
               b"\xc3")                 # ret


# --------------------------------------------------------------------------
# Entry bases and tiers
# --------------------------------------------------------------------------

def test_prologue_and_byte_ret_bases():
    data = mz({0x300: PROLOGUE + RET, 0x320: b"\x90\x90" + RET + b"\xb8\x00\x00"})
    e8, far = {}, {}
    assert "prologue" in D.entry_bases(data, 0x300, e8, far)
    # 0x304 follows a ret byte at 0x303 (decodes as a ret), so it has the byte-ret basis
    assert D.entry_bases(data, 0x304, e8, far) == ["byte-ret"]
    assert D.tier_of(["byte-ret"]) == "B"
    assert D.tier_of(["prologue"]) == "A" and D.tier_of(["model"]) == "C"


def test_ret_byte_used_as_immediate_is_only_tier_b():
    # falsifier: b0 c3 is mov al,0xc3; the c3 byte is an immediate, but the byte-ret rule cannot tell,
    # so the entry after it (0x302) is tier B (never tier A) and its basis says so
    data = mz({0x300: b"\xb0\xc3" + b"\x90" + PROLOGUE + b"\x5d" + RET})
    assert D.entry_bases(data, 0x302, {}, {}) == ["byte-ret"]
    assert D.tier_of(D.entry_bases(data, 0x302, {}, {})) == "B"


def test_containing_needs_ret_complete_walk_that_contains_the_site():
    # 0x300 prologue; 0x303 mov ah,3Dh; 0x305 int 21h (the site); 0x307 pop bp; 0x308 ret
    data = mz({0x300: PROLOGUE + MOV_AH_3D + INT21 + b"\x5d" + RET})
    rows, stats = D.containing(data, 0x305, {}, {})
    assert [r["entry"] for r in rows] == [0x300] and rows[0]["tier"] == "A"
    assert stats["contains_site"] == 1 and stats["ret_complete"] >= 1
    # falsifier: an unsupported opcode before the ret makes the walk incomplete, so no containment
    bad = mz({0x300: PROLOGUE + MOV_AH_3D + INT21 + b"\x0f" + b"\x5d" + RET})
    assert D.containing(bad, 0x305, {}, {})[0] == []
    # falsifier: a site after the routine's ret is not contained by that routine
    after = mz({0x300: PROLOGUE + RET + MOV_AH_3D + INT21})              # int 21h at 0x306
    assert 0x300 not in [r["entry"] for r in D.containing(after, 0x306, {}, {})[0]]
    # falsifier: a site outside the image is reported as such, not walked
    assert D.containing(data, 0x5000, {}, {})[1].get("outside_image") is True


def test_pick_entry_prefers_tier_a_then_nearest():
    rows = [{"entry": 0x100, "tier": "B"}, {"entry": 0x200, "tier": "A"}, {"entry": 0x180, "tier": "A"}]
    assert D.pick_entry(rows)["entry"] == 0x200          # nearest tier-A entry
    assert D.pick_entry([{"entry": 0x100, "tier": "B"}])["entry"] == 0x100
    assert D.pick_entry([]) is None


# --------------------------------------------------------------------------
# E8 targets: anchored sweeps
# --------------------------------------------------------------------------

def _e8_fixture():
    # 0x300 prologue; 0x303 mov ah,3Dh; 0x305 int 21h (bytes 0x305-0x306); 0x307 call -> 0x306 (mid-int);
    # 0x30A call -> 0x307 (a true boundary, reached by the sweep from 0x300); 0x30D pop bp; 0x30E ret
    code = (PROLOGUE + MOV_AH_3D + INT21
            + b"\xe8" + rel(0x307, 0x306)
            + b"\xe8" + rel(0x30A, 0x307)
            + b"\x5d" + RET)
    return mz({0x300: code})


def test_e8_target_on_a_sweep_boundary_is_verified_and_mid_instruction_is_not():
    data = _e8_fixture()
    idx = D.near_call_index(data)
    assert 0x306 in idx and 0x307 in idx
    assert "e8-verified" in D.entry_bases(data, 0x307, idx, {})
    # falsifier: 0x306 is the second byte of cd 21, so the sweep covers it and never starts on it
    assert "e8-mid-insn" in D.entry_bases(data, 0x306, idx, {})
    assert "e8-verified" not in D.entry_bases(data, 0x306, idx, {})
    assert D.tier_of(D.entry_bases(data, 0x306, idx, {})) is None


def test_e8_target_without_an_earlier_anchor_is_unchecked():
    # falsifier: no prologue or ret byte before the target in the window, so it is not graded
    data = mz({0x300: b"\x90" * 0x10 + b"\xe8" + rel(0x310, 0x307) + b"\x90" * 6})
    idx = D.near_call_index(data)
    assert 0x307 in idx
    assert D._anchor_sweep_verdict(data, 0x307) == "no-anchor"
    assert "e8-unchecked" in D.entry_bases(data, 0x307, idx, {})


# --------------------------------------------------------------------------
# Caller context and CS pointers
# --------------------------------------------------------------------------

def _caller_fixture(extra=b"\x0e"):
    # 0x300 prologue; 0x303 mov di,0x171; 0x306 push cs (or extra); 0x307 push di; 0x308 call 0x320;
    # 0x30B pop bp; 0x30C ret.  The callee at 0x320 is a plain routine.
    code = (PROLOGUE + b"\xbf\x71\x01" + extra + b"\x57"
            + b"\xe8" + rel(0x308, 0x320) + b"\x5d" + RET)
    return mz({0x300: code, 0x320: PROLOGUE + b"\x5d" + RET})


def test_caller_context_reports_pre_call_and_cs_pointer():
    data = _caller_fixture()
    idx = D.near_call_index(data)
    ctx = D.caller_context(data, 0x308, idx, {})
    assert ctx["status"] == "contained" and ctx["routine_entry"] == 0x300 and ctx["tier"] == "A"
    assert ctx["cs_pointers"] == [{"at": 0x303, "imm": 0x171, "reg": "di"}]
    texts = [p["text"] for p in ctx["pre_call"]]
    assert any(t.startswith("push cs") for t in texts)


def test_cs_pointer_falsifier_needs_push_cs():
    data = _caller_fixture(extra=b"\x90")                   # nop in place of push cs
    ctx = D.caller_context(data, 0x308, D.near_call_index(data), {})
    assert ctx["cs_pointers"] == []


def test_caller_outside_any_ret_complete_routine_is_reported_not_dropped():
    data = mz({0x300: b"\x0f" * 4 + b"\xe8" + rel(0x304, 0x320) + b"\x90"})
    ctx = D.caller_context(data, 0x304, D.near_call_index(data), {})
    assert ctx["status"] == "caller-not-contained"


# --------------------------------------------------------------------------
# Routine facts: ASCIIZ copy then open
# --------------------------------------------------------------------------

def test_asciiz_copy_then_open_is_detected_from_decoded_pattern():
    data = mz({0x300: PROLOGUE + ASCIIZ_OPEN[:-1] + b"\x5d" + RET})
    site = data.index(INT21, 0x300)
    facts = D.node_facts(data, 0x300, {site: 0x3D})
    assert facts["asciiz_copy_then_open"] is True
    assert facts["rep_movsb"] and facts["zero_terminator_stosb"]
    assert facts["bp_displacement_counts"].get("6") == 1          # the [bp+6] name slot
    assert facts["lds_bp_operands"] and facts["lds_bp_operands"][0]["text"].startswith("lds")
    # falsifier: without the xor al,al / stosb terminator the copy is not an ASCIIZ copy
    no_nul = ASCIIZ_OPEN.replace(b"\x32\xc0\xaa", b"\x90\x90\x90")
    data2 = mz({0x300: PROLOGUE + no_nul[:-1] + b"\x5d" + RET})
    facts2 = D.node_facts(data2, 0x300, {data2.index(INT21, 0x300): 0x3D})
    assert facts2["asciiz_copy_then_open"] is False
    # falsifier: AH other than 3Dh at the int is not an open
    assert D.node_facts(data, 0x300, {site: 0x3F})["asciiz_copy_then_open"] is False


# --------------------------------------------------------------------------
# AH recovery and vector 3Fh installs
# --------------------------------------------------------------------------

def test_unknown_ah_walk_writer_and_falsifier():
    # pop ax (58) sits between the mov ah and the int: the nearest writer is "pop ax", not 3Dh
    data = mz({0x300: PROLOGUE + MOV_AH_3D + b"\x58" + INT21 + b"\x5d" + RET})
    inv = chain.int21_inventory(data)
    rows = D.unknown_ah_rows(data, inv, D.near_call_index(data), {})
    assert rows and rows[0]["ah_writer"]["kind"] == "other-writer"
    # a mov ah from memory is a non-immediate writer: its value is not guessed
    mem = mz({0x300: PROLOGUE + b"\x8a\x66\xfe" + INT21 + b"\x5d" + RET})
    rows2 = D.unknown_ah_rows(mem, chain.int21_inventory(mem), D.near_call_index(mem), {})
    assert rows2 and rows2[0]["ah_writer"]["kind"] == "non-immediate"
    assert rows2[0]["ah_writer"]["value"] is None


def test_vector_3f_install_recognised_only_for_al_3f():
    code = PROLOGUE + b"\xba\x10\x00" + b"\xb8\x3f\x25" + INT21 + b"\x5d" + RET
    data = mz({0x300: code})
    rows = D.vector_3f_rows(data, chain.int21_inventory(data), D.near_call_index(data), {})
    assert len(rows) == 1 and rows[0]["entry"] == "0x00300"
    assert any(p["text"].startswith("mov dx") for p in rows[0]["dx_setup_before"])
    # falsifier: vector 3Eh is not 3Fh
    other = mz({0x300: PROLOGUE + b"\xba\x10\x00" + b"\xb8\x3e\x25" + INT21 + b"\x5d" + RET})
    assert D.vector_3f_rows(other, chain.int21_inventory(other), D.near_call_index(other), {}) == []


# --------------------------------------------------------------------------
# 9A model: index and bounded delta sweep (hypothesis only)
# --------------------------------------------------------------------------

def test_far_index_and_delta_sweep_on_literal():
    # 9A off=0 seg=0x0020 -> literal 0x200; the model target for entry 0x400 is 0x200 + 0x200
    data = mz({0x500: b"\x9a\x00\x00\x20\x00"})
    far = D.far_model_index(data)
    assert 0x400 in far and far[0x400][0]["seg"] == 0x0020
    sites = D.far_sites(data)
    assert D.delta_sweep(0x400, sites)[0]["delta"] == 0
    # a literal 3 bytes off the model gives a hit with delta 3 (hypothesis, counted and labelled)
    data3 = mz({0x500: b"\x9a\x03\x00\x20\x00"})
    hit = D.delta_sweep(0x400, D.far_sites(data3))
    assert hit and hit[0]["delta"] == 3 and hit[0]["hypothesis"] is True
    # falsifier: a literal far outside the span is not a hit
    far_away = mz({0x500: b"\x9a\x00\x00\x00\x01"})
    assert D.delta_sweep(0x400, D.far_sites(far_away)) == []


# --------------------------------------------------------------------------
# Probe-level behaviour: refusals, determinism, no absolute paths
# --------------------------------------------------------------------------

def test_pin_mismatch_is_refused_without_flag():
    with pytest.raises(D.ProbeError):
        D._pin_row(D.EXE_NAME, b"x", allow_unpinned=False)
    row = D._pin_row(D.EXE_NAME, b"x", allow_unpinned=True)
    assert row["pin_match"] is False


def test_main_refuses_unpinned_install_and_output_inside_install(tmp_path):
    inst = tmp_path / "inst"
    inst.mkdir()
    (inst / "START.EXE").write_bytes(mz())
    (inst / "GAME.OVR").write_bytes(b"FBOV" + b"\x00" * 300)
    out = tmp_path / "out"
    assert D.main(["--install", str(inst), "-o", str(out)]) == 2       # pins do not match
    assert not out.exists()
    assert D.main(["--install", str(inst), "-o", str(inst / "sub")]) == 2   # inside the install


def test_main_allow_unpinned_writes_deterministic_outputs(tmp_path):
    inst = tmp_path / "inst"
    inst.mkdir()
    (inst / "START.EXE").write_bytes(mz({0x300: PROLOGUE + RET}))
    (inst / "GAME.OVR").write_bytes(b"FBOV" + b"\x00" * 300)
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    code1 = D.main(["--install", str(inst), "-o", str(out1), "--allow-unpinned"])
    code2 = D.main(["--install", str(inst), "-o", str(out2), "--allow-unpinned"])
    assert code1 == code2 == 1                                          # diagnostic, not evidence
    j1 = (out1 / "por_8x8d_dos_sites_probe.json").read_bytes()
    j2 = (out2 / "por_8x8d_dos_sites_probe.json").read_bytes()
    assert j1 == j2
    doc = json.loads(j1)
    assert doc["playable"] is False and doc["mappings"] == [] and doc["binding_established"] is False
    assert len(doc["unresolved_edges"]) == 7
    assert str(inst) not in j1.decode("utf-8")                          # no absolute paths in output
    assert (out1 / "por_8x8d_dos_sites_probe_report.md").is_file()
    # the synthetic image is too short for the retail sites: they are reported as outside the image
    assert doc["facts"]["requested_sites"]["0x0a8b6"]["containing_by_tier"] == {"A": 0, "B": 0, "C": 0}


# --------------------------------------------------------------------------
# Retail anchors (skipped unless the install is named)
# --------------------------------------------------------------------------

@needs_retail
def test_retail_pins_hold_and_source_unchanged(tmp_path):
    out = tmp_path / "r"
    assert D.main(["--install", RETAIL, "-o", str(out)]) == 0
    doc = json.loads((out / "por_8x8d_dos_sites_probe.json").read_bytes())
    assert doc["source_unchanged"] is True
    assert all(p["pin_match"] for p in doc["pins"].values())


@needs_retail
def test_retail_open_site_is_contained_by_the_0x0a89e_helper():
    folder = chain.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    idx = D.near_call_index(exe)
    rows, _ = D.containing(exe, 0x0A8B6, idx, D.far_model_index(exe))
    assert any(r["entry"] == 0x0A89E and r["tier"] == "A" for r in rows)
    # decode-verified E8 callers of 0x0A89E are exactly these three sites
    assert sorted(idx.get(0x0A89E, [])) == [0x0A806, 0x0A841, 0x0A895]
    facts = D.node_facts(exe, 0x0A89E, {0x0A8B6: 0x3D})
    assert facts["asciiz_copy_then_open"] is True and facts["int21_sites"] == ["0x0a8b6"]


@needs_retail
def test_retail_read_sites_have_containing_entries_and_uncalled_far_roots():
    folder = chain.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    ovr = (folder / "GAME.OVR").read_bytes()
    idx = D.near_call_index(exe)
    for site in D.READ_SITES:
        rows, _ = D.containing(exe, site, idx, D.far_model_index(exe))
        assert rows, "read 0x%05x has no containing entry" % site
    # the two far-returning read routines are uncalled by any decode-verified E8
    assert idx.get(0x0A97E, []) == [] and idx.get(0x0B360, []) == []
    # GAME.OVR has no INT 21h at all
    assert chain.int21_inventory(ovr)["count"] == 0


@needs_retail
def test_retail_vector_3f_install_and_counts(tmp_path):
    folder = chain.resolve_folder(Path(RETAIL))
    exe = (folder / "START.EXE").read_bytes()
    inv = chain.int21_inventory(exe)
    assert inv["count"] == 58 and inv["by_ah"]["0x3d"] == 1 and inv["by_ah"]["0x3f"] == 5
    rows = D.vector_3f_rows(exe, inv, D.near_call_index(exe), D.far_model_index(exe))
    assert any(r["at"] == "0x0a7f1" and r["entry"] == "0x0a728" for r in rows)
    out = tmp_path / "d"
    assert D.main(["--install", RETAIL, "-o", str(out)]) == 0
    doc = json.loads((out / "por_8x8d_dos_sites_probe.json").read_bytes())
    assert doc["facts"]["census_nodes"]["0x0a728"]["depth"] == 2
