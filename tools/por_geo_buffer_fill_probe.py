#!/usr/bin/env python3
"""Observe-only static probe: what fills the 1 KiB buffer at DGROUP 0x6A5C (PoR GAME.OVR).

The callee probe (tools/por_geo_callee_identity_probe.py) reads GAME.OVR:0x2EE71, which returns
ES:[ptr + 0x200 + 16*Y + X] for the far pointer ptr at DGROUP 0x6A5C. The pointer is stored at
GAME.OVR 0xE670 from the return of a call to 0x0AF8:0x023F with 0x400 pushed. This probe asks what
fills the buffer, and whether the fill is GEO block+2 (so that +0x200 is GEO plane 2).

Everything here is read from bytes. The probe:

1. Checks the pinned GAME.OVR and START.EXE (refuses any other bytes; there is no override).
2. Finds the allocation store and its enclosing function (prologue scan, decoder walk).
3. Takes the census of every literal reference to DGROUP 0x6A5C and 0x6A5E, and classifies each
   `les di,[0x6A5C]` by the ES-prefixed access that follows it (read or write, displacement).
4. Decodes the fill function: the status test after the loader call, and the four copy calls to
   0x0AF8:0x1685, by a small symbolic walk over the copy window. The walk fails closed on any
   opcode it does not model.
5. Finds the callers of the fill's overlay stub (far literal 03D5:0043, stub 7 candidate) and
   classifies the id byte each caller pushes.
6. Optionally tests the decoded pinned GEO blocks (tools/por_map.py) against RAM dumps. A positive
   control (START stub bytes, known to be in the pid34644 dump) shows the search works.

What it does NOT establish, and reports as unresolved: the identity and calling convention of
0x0AF8:0x1685 (copy direction), the identity and return value of the loader 0x0802:0x0716 (block
base), the meaning of the id byte, that any caller or the fill executes, and the live buffer
contents at any instant. It never claims plane 2 is bound to the callee's read.

Usage:
    python tools/por_geo_buffer_fill_probe.py [--install PATH/TO/POOLRAD] \
        [--dump data/work/por-live-memory-pid34644/ram-000000-100000.bin ...] \
        [-o data/work/por-geo-buffer-fill-probe]

Exit: 0 the probe ran (its verdict is `fill_established: false` by design); 2 a named refusal
(unpinned input, bad dump, output outside data/work).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_geo_callee_identity_probe as gcp  # noqa: E402
import por_map as pm  # noqa: E402

SCHEMA = "openua.por-geo-buffer-fill-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "buffer-fill-probe-only"
TOOL = "tools/por_geo_buffer_fill_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-buffer-fill-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMP = DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin"

OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME
PINS = om.PINS

PTR_OFF = 0x6A5C                 # DGROUP far pointer: offset word at +0, segment word at +2
PLANE_BYTES = 0x100
BUF_SIZE = 0x400
ALLOC_SIZE = 0x400
ALLOC_CALL = bytes.fromhex("9a 3f 02 f8 0a")     # call 0x0AF8:0x023F (allocator; retf 2 candidate)
COPY_CALL = bytes.fromhex("9a 85 16 f8 0a")     # call 0x0AF8:0x1685 (copy; convention unproved)
LOAD_CALL = bytes.fromhex("9a 16 07 02 08")     # call 0x0802:0x0716 (loader; unidentified)
LES_PTR = bytes.fromhex("c4 3e 5c 6a")          # les di,[0x6a5c]
STORE_AX = bytes.fromhex("a3 5c 6a")            # mov [0x6a5c],ax
STORE_DX = bytes.fromhex("89 16 5e 6a")         # mov [0x6a5e],dx
COPY_CTX = bytes.fromhex("c7 46 f8 02 00")      # mov word [bp-8],2 (copy cursor starts at block+2)
STUB_SEG = b"\xd5\x03"                          # far-call segment 0x03D5 (stub run segment)
STUB7_LIT_OFF = 0x0043                          # candidate literal for stub 7 (0x34 + 3*5, linear assumption)
STUB7_FILE = 0x3E11                             # START.EXE offset of stub 7 (from the callee probe)
STUB4_FILE = 0x3E02                            # stub the callee probe identified by live bytes
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
WINDOW = 16
POSITIVE_CONTROL_LEN = 16

NOT_ESTABLISHED = [
    "the identity and calling convention of 0x0AF8:0x1685: which pushed pointer is the source and which "
    "the destination is decided by the reading of the pushes, not by the callee's bytes",
    "the identity of the loader 0x0802:0x0716, and that the far pointer it writes to [bp-6] is a GEO block base",
    "that the loader's status word 0x402 is a byte count (1026, the Gen1 block size) rather than a code",
    "the meaning of the id byte the fill passes to the loader (its TOC block id, area number or other)",
    "that the fill function (GAME.OVR 0x2F9BE) runs, or that either caller runs, at any instant",
    "that the live buffer at DGROUP 0x6A5C holds any GEO block at any instant (no dump shows it)",
    "that plane 2 (buffer +0x200) is the byte the callee returns: only the copy geometry is decoded",
    "any segment-base model for the 0x0AF8 and 0x0802 selectors (the image mapping is a candidate only)",
]

Refusal = om.Refusal


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _positions(data: bytes, pat: bytes) -> list[int]:
    out, pos = [], data.find(pat)
    while pos != -1:
        out.append(pos)
        pos = data.find(pat, pos + 1)
    return out


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def _check_pins(ovr: bytes, exe: bytes) -> dict:
    return gcp.check_pins(ovr, exe, PINS)


# ---- allocation and pointer census ----------------------------------------------------

def allocation_facts(ovr: bytes) -> dict:
    """The store of the allocator result to 0x6A5C, and the ALLOC_SIZE push before the call."""
    stores = _positions(ovr, STORE_AX)
    rows = []
    for s in stores:
        pre = ovr[s - 9:s - 6]
        ok = (pre == bytes.fromhex("b8") + ALLOC_SIZE.to_bytes(2, "little")
              and ovr[s - 6] == 0x50 and ovr[s - 5:s] == ALLOC_CALL
              and ovr[s + 3:s + 7] == STORE_DX)
        rows.append({"store_at": s, "store_hex": "0x%X" % s, "allocator_call_at": s - 5,
                     "size_pushed": ALLOC_SIZE, "pattern_ok": ok,
                     "enclosing_entry": _entry_before(ovr, s)})
    return {"store_sites": rows, "store_count": len(stores)}


def _entry_before(ovr: bytes, site: int, span: int = 0x1000) -> Optional[int]:
    """Nearest prologue before `site` whose decoder walk covers `site`."""
    lo = max(0, site - span)
    for p in range(site - 1, lo - 1, -1):
        if ovr[p:p + 3] in PROLOGUES:
            w = lh.walk(ovr, p)
            if any(r["at"] == site for r in w["listing"]):
                return p
    return None


def pointer_census(ovr: bytes) -> dict:
    """Every literal reference to 0x6A5C / 0x6A5E, classified by the bytes before it."""
    rows = []
    for name, lit in (("6A5C", PTR_OFF.to_bytes(2, "little")), ("6A5E", (PTR_OFF + 2).to_bytes(2, "little"))):
        for pos in _positions(ovr, lit):
            before = ovr[max(0, pos - 2):pos]
            kind = "unclassified"
            if ovr[pos - 1:pos] == b"\xa3":
                kind = "store-ax"
            elif before == b"\x89\x16":
                kind = "store-dx"
            elif before == b"\xc4\x3e":
                kind = "les"
            rows.append({"slot": name, "at": pos, "at_hex": "0x%X" % pos, "kind": kind})
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    return {"sites": rows, "counts": counts}


# ---- les sites: enclosing function and the ES access that follows ---------------------

def _es_access(ovr: bytes, at: int) -> Optional[dict]:
    """Decode a `26 op modrm [disp]` ES access at `at` through [di] (read, write, or other).

    Only the [di] and [di+disp8/disp16] forms are decoded; any other base is reported as None."""
    if ovr[at:at + 1] != b"\x26":
        return None
    op = ovr[at + 1]
    modrm = ovr[at + 2]
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3 or rm != 5:
        return None                       # register operand, or not the [di] base
    if mod == 0:
        disp: Optional[int] = 0
    elif mod == 1:
        disp = ovr[at + 3]
    else:
        disp = _u16(ovr, at + 3)
    if op in (0x8A, 0x8B):
        kind = "read"
    elif op in (0x88, 0x89, 0xC6, 0xC7):
        kind = "write"
    else:
        kind = "other"
    return {"at": at, "op": op, "modrm": modrm, "disp": disp, "kind": kind}


def les_census(ovr: bytes) -> list[dict]:
    rows = []
    for site in _positions(ovr, LES_PTR):
        entry = _entry_before(ovr, site)
        row = {"les_at": site, "les_hex": "0x%X" % site, "entry": entry,
               "entry_hex": None if entry is None else "0x%X" % entry,
               "access": None, "pointer_passed": False}
        if entry is not None:
            w = lh.walk(ovr, entry)
            idx = next(i for i, r in enumerate(w["listing"]) if r["at"] == site)
            for r in w["listing"][idx + 1: idx + 8]:
                if r["bytes"] == "06":            # push es: the far pointer is passed on, not accessed
                    row["pointer_passed"] = True
                    break
                acc = _es_access(ovr, r["at"])
                if acc is not None:
                    row["access"] = {"kind": acc["kind"], "disp": acc["disp"]}
                    break
        rows.append(row)
    return rows


def function_role(ovr: bytes, entry: int, les_rows: list[dict]) -> dict:
    """Summarise one function that holds `les [0x6A5C]` sites: its retf, its first-bytes compares, and
    the ES accesses made through those sites only (an ES loaded from another pointer is not counted)."""
    w = lh.walk(ovr, entry)
    accesses = [{"les": r["les_hex"], "kind": r["access"]["kind"], "disp": r["access"]["disp"]}
                for r in les_rows if r["access"] is not None]
    kinds = sorted({(a["kind"], a["disp"]) for a in accesses}, key=lambda t: (t[0], t[1] or 0))
    head = ovr[entry:entry + 0x40]
    return {
        "entry": entry,
        "entry_hex": "0x%X" % entry,
        "walk_complete": w["complete"],
        "instruction_count": w["instruction_count"],
        "retf_imm": [r["imm"] for r in w["returns"]],
        "compares_in_first_0x40_bytes": {
            "bp+8 >= 0": b"\x80\x7e\x08\x00" in head,
            "bp+8 <= 15": b"\x80\x7e\x08\x0f" in head,
            "bp+10 >= 0": b"\x80\x7e\x0a\x00" in head,
            "bp+10 <= 15": b"\x80\x7e\x0a\x0f" in head,
        },
        "les_sites": [r["les_hex"] for r in les_rows],
        "accesses_through_les": accesses,
        "access_summary": [{"kind": k, "disp": None if d is None else "0x%X" % d} for k, d in kinds],
        "pointer_passed_on": any(r["pointer_passed"] for r in les_rows),
    }


# ---- fill: loader call, status gate, and the four copy calls --------------------------

def loader_facts(ovr: bytes, fill_entry: int) -> dict:
    """The loader call's argument pattern and the status test that follows it."""
    loads = [p for p in _positions(ovr, LOAD_CALL) if fill_entry <= p < fill_entry + 0x400]
    if len(loads) != 1:
        return {"found": len(loads), "ok": False}
    site = loads[0]
    args_ok = ovr[site - 14:site] == bytes.fromhex("8a 46 06 50 8d 7e fe 16 57 8d 7e fa 16 57")
    gate_at = site + 5
    gate = bytes.fromhex("83 7e fe 00 74 07 81 7e fe 02 04 74 2e")
    gate_ok = ovr[gate_at:gate_at + len(gate)] == gate
    # The gate's second jump (74 2e at gate_at+11) must land on the copy window's first byte.
    jump_target = gate_at + 13 + ovr[gate_at + 12] if gate_ok else None
    copy_start = _positions(ovr, COPY_CTX)
    return {
        "found": 1,
        "call_at": site,
        "call_hex": "0x%X" % site,
        "args_pattern_ok": args_ok,
        "args_meaning": {"id_pushed": "byte [bp+6] (fill argument)", "status_out": "[bp-2]",
                         "block_ptr_out": "[bp-6] (far pointer)"},
        "gate_at": "0x%X" % gate_at,
        "gate_ok": gate_ok,
        "gate_jump_target": None if jump_target is None else "0x%X" % jump_target,
        "gate_jump_lands_on_copy_window": bool(gate_ok and jump_target in copy_start),
        "status_value_tested": "0x402",
        "status_value_is_1026_bytes": 0x402 == 1026,
    }


def simulate_copies(ovr: bytes, start: int, copies: int = 4) -> dict:
    """Symbolic walk of the straight-line copy window. Fails closed on any unmodelled opcode."""
    st = {"bp8": None, "ax": None, "es": None, "di": None, "pushes": []}
    calls: list[dict] = []
    p = start
    budget = 200
    while len(calls) < copies and budget > 0:
        budget -= 1
        b = ovr[p:p + 6]
        if b[:3] == b"\xc7\x46\xf8":
            st["bp8"] = _u16(ovr, p + 3)
            p += 5
        elif b[:3] == b"\x81\x46\xf8":
            st["bp8"] = (st["bp8"] + _u16(ovr, p + 3)) & 0xFFFF
            p += 5
        elif b[:3] == b"\x8b\x46\xf8":
            st["ax"] = st["bp8"]
            p += 3
        elif b[:3] == b"\xc4\x7e\xfa":
            st["es"], st["di"] = "BLK", 0
            p += 3
        elif b[:4] == LES_PTR:
            st["es"], st["di"] = "BUF", 0
            p += 4
        elif b[:2] == b"\x03\xf8":
            if st["ax"] is None or st["di"] is None:
                return {"ok": False, "stopped_at": p, "reason": "add-di-ax-before-known-values"}
            st["di"] = (st["di"] + st["ax"]) & 0xFFFF
            p += 2
        elif b[:2] == b"\x81\xc7":
            if st["di"] is None:
                return {"ok": False, "stopped_at": p, "reason": "add-di-imm-before-les"}
            st["di"] = (st["di"] + _u16(ovr, p + 2)) & 0xFFFF
            p += 4
        elif b[:1] == b"\x06":
            st["pushes"].append(("es", st["es"]))
            p += 1
        elif b[:1] == b"\x57":
            st["pushes"].append(("di", st["di"]))
            p += 1
        elif b[:1] == b"\xb8":
            st["ax"] = _u16(ovr, p + 1)
            p += 3
        elif b[:1] == b"\x50":
            st["pushes"].append(("ax", st["ax"]))
            p += 1
        elif b[:5] == COPY_CALL:
            calls.append({"call_at": p, "pushes": list(st["pushes"])})
            st["pushes"] = []
            p += 5
        else:
            return {"ok": False, "stopped_at": p, "reason": "unmodelled-opcode-%s" % b[:1].hex()}
    if len(calls) != copies:
        return {"ok": False, "stopped_at": p, "reason": "copy-count-%d" % len(calls), "calls": calls}
    return {"ok": True, "calls": calls}


def copy_rows(sim: dict) -> list[dict]:
    rows = []
    for c in sim["calls"]:
        pu = c["pushes"]
        if len(pu) != 5:
            rows.append({"call_at": "0x%X" % c["call_at"], "ok": False, "reason": "push-count-%d" % len(pu)})
            continue
        # Pushed order: src (es, di), then dst (es, di), then count (ax). Left-to-right.
        (src_es, src_seg), (src_di, src_off), (dst_es, dst_seg), (dst_di, dst_off), (cnt, n) = pu
        ok = (src_es == "es" and src_seg == "BLK" and src_di == "di"
              and dst_es == "es" and dst_seg == "BUF" and dst_di == "di" and cnt == "ax")
        rows.append({
            "call_at": "0x%X" % c["call_at"],
            "ok": ok,
            "src": "BLK+0x%X" % src_off if ok else None,
            "dst": "BUF+0x%X" % dst_off if ok else None,
            "count": n if ok else None,
            "plane": dst_off // PLANE_BYTES if ok else None,
            "src_offset": src_off if ok else None,
            "dst_offset": dst_off if ok else None,
        })
    return rows


# ---- stub 7 callers and the id byte ----------------------------------------------------

def stub_literal_census(ovr: bytes) -> dict:
    by_off: dict[int, list[int]] = {}
    for m in re.finditer(rb"\x9a(..)\xd5\x03", ovr):
        off = m.group(1)[0] | (m.group(1)[1] << 8)
        by_off.setdefault(off, []).append(m.start())
    return {off: sites for off, sites in sorted(by_off.items())}


def caller_arg(ovr: bytes, site: int) -> dict:
    """Classify the byte pushed immediately before a far call to 03D5:0043."""
    if ovr[site - 4:site] == bytes.fromhex("8a 46 fd 50"):
        return {"source": "local [bp-3]", "pattern": "mov al,[bp-3]; push ax"}
    if ovr[site - 10:site - 6] == bytes.fromhex("c4 3e d2 49") and ovr[site - 6:site] == bytes.fromhex("26 8a 85 8a 01 50"):
        return {"source": "es:[49D2 far pointer + 0x18A]",
                "pattern": "les di,[0x49d2]; es mov al,[di+0x18a]; push ax",
                "note": "DGROUP far pointer 0x49D2 is not decoded further"}
    return {"source": "unclassified", "pattern": ovr[site - 10:site].hex(" ")}


# ---- dump observations (memory bytes at an unknown instant) --------------------------

def decoded_geo_blocks(install: Path) -> list[dict]:
    rows = []
    for n in range(1, 9):
        path = install / ("GEO%d.DAX" % n)
        if not path.exists():
            continue
        data = path.read_bytes()
        ents, base = pm.parse_dax(data)
        for e in ents:
            comp = data[base + e.data_offset: base + e.data_offset + e.comp_size]
            try:
                raw = pm.rle_decode(comp, e.raw_size)
            except Exception:  # noqa: BLE001 - a refused block is recorded, not decoded
                continue
            rows.append({"geo": n, "index": e.index, "raw": raw, "sha256": _sha(raw)})
    return rows


def window_search(dump: bytes, needle: bytes) -> list[int]:
    out, pos = [], dump.find(needle)
    while pos != -1 and len(out) < 64:
        out.append(pos)
        pos = dump.find(needle, pos + 1)
    return out


def dump_observations(dump_path: Path, start: bytes, blocks: list[dict]) -> dict:
    dump = dump_path.read_bytes()
    control = window_search(dump, start[:POSITIVE_CONTROL_LEN])
    hits = {"plane_windows_checked": 0, "plane_window_hits": []}
    for blk in blocks:
        raw = blk["raw"]
        for k in range(4):
            plane = raw[2 + PLANE_BYTES * k: 2 + PLANE_BYTES * (k + 1)]
            for s in range(0, PLANE_BYTES - WINDOW + 1, WINDOW):
                win = plane[s:s + WINDOW]
                if win.count(0) >= WINDOW - 2:
                    continue
                hits["plane_windows_checked"] += 1
                found = window_search(dump, win)
                if found:
                    hits["plane_window_hits"].append({"geo": blk["geo"], "index": blk["index"], "plane": k,
                                                      "offset": s, "dump_offsets": ["0x%X" % f for f in found[:4]]})
    return {
        "dump": str(dump_path.name),
        "dump_sha256": _sha(dump),
        "positive_control_hits": ["0x%X" % c for c in control],
        "positive_control_expected": "0x1C3E4 (the stub bytes the callee probe identifies by identity)",
        "geo_plane_windows_checked": hits["plane_windows_checked"],
        "geo_plane_window_hits": hits["plane_window_hits"],
        "reading": ("no decoded GEO plane window of 16 bytes occurs in this dump"
                    if not hits["plane_window_hits"] else "decoded GEO plane windows occur in this dump"),
    }


# ---- top-level probe -------------------------------------------------------------------

def analyse(ovr: bytes, exe: bytes, install_pins: dict) -> dict:
    alloc = allocation_facts(ovr)
    census = pointer_census(ovr)
    les = les_census(ovr)
    store = alloc["store_sites"][0] if alloc["store_sites"] else None
    entries = sorted({r["entry"] for r in les if r["entry"] is not None})
    roles = {("0x%X" % e): function_role(ovr, e, [r for r in les if r["entry"] == e]) for e in entries}
    fill_candidates = [r for r in les if r["pointer_passed"]]
    fill_entry = fill_candidates[0]["entry"] if fill_candidates else None
    loader = loader_facts(ovr, fill_entry) if fill_entry is not None else {"found": 0, "ok": False}
    sim = {"ok": False, "reason": "no-fill-entry"}
    if fill_entry is not None:
        ctx = _positions(ovr, COPY_CTX)
        ctx = [p for p in ctx if fill_entry <= p < fill_entry + 0x400]
        if ctx:
            sim = simulate_copies(ovr, ctx[0])
    rows = copy_rows(sim) if sim.get("ok") else []
    groups = gcp.all_groups(exe, ovr)
    grp = gcp.owner_group(groups, fill_entry) if fill_entry is not None else None
    stubs = stub_literal_census(ovr)
    callers = [{"site": s, "site_hex": "0x%X" % s, "entry": _entry_before(ovr, s),
                "arg": caller_arg(ovr, s)} for s in stubs.get(STUB7_LIT_OFF, [])]
    stub7 = exe[STUB7_FILE:STUB7_FILE + 5]
    return {
        "allocation": alloc,
        "store": store,
        "pointer_census": census,
        "les_sites": les,
        "function_roles": roles,
        "fill": {
            "entry": fill_entry,
            "entry_hex": None if fill_entry is None else "0x%X" % fill_entry,
            "owner_group_fileofs": None if grp is None else "0x%X" % grp["fileofs"],
            "owner_group_status": None if grp is None else grp.get("status"),
            "loader": loader,
            "copy_simulation_ok": sim.get("ok", False),
            "copy_simulation_reason": None if sim.get("ok") else sim.get("reason"),
            "copies": rows,
        },
        "stub7": {
            "file_offset": "0x%X" % STUB7_FILE,
            "bytes": stub7.hex(" "),
            "proc": "0x%04X" % (stub7[2] | (stub7[3] << 8)) if stub7[:2] == b"\xcd\x3f" else None,
            "trailer_byte": "0x%02X" % stub7[4] if len(stub7) == 5 else None,
            "trailer_well_formed": stub7[4] == 0x00 if len(stub7) == 5 else None,
            "literal_offset_candidate": "0x%04X" % STUB7_LIT_OFF,
            "literal_offset_basis": "candidate: 0x34 (stub 4, callee probe identity) + 3*5 (linear assumption)",
        },
        "callers": callers,
        "pins": install_pins,
    }


def unresolved_writers(doc: dict) -> list[dict]:
    fill = doc["fill"]
    out = []
    for c in fill["copies"]:
        out.append({"writer": c.get("call_at"), "writes": c.get("dst"),
                    "unresolved": "copy direction and source-pointer identity (0x0AF8:0x1685, 0x0802:0x0716)"})
    for r in doc["les_sites"]:
        if r["access"] and r["access"]["kind"] == "write":
            out.append({"writer": r["les_hex"], "writes": "plane disp %s" % (
                "0x%X" % r["access"]["disp"] if r["access"]["disp"] is not None else "?"),
                "unresolved": "mask-only plane-3 write: it changes two bits of an existing byte, no source byte"})
    return out


def probe(install: Path, out: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = _check_pins(ovr, exe)
    doc = analyse(ovr, exe, pins)
    blocks = decoded_geo_blocks(install)
    start = exe[STUB4_FILE:STUB4_FILE + POSITIVE_CONTROL_LEN]
    dumps = []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        dumps.append(dump_observations(dp, start, blocks))
    doc["writers"] = unresolved_writers(doc)
    doc.update({
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status_scope": STATUS_SCOPE,
        "playable": False,
        "fill_established": False,
        "plane2_binding": "not claimed",
        "geo_block_inputs": {"count": len(blocks), "sha256_per_block": {
            "GEO%d#%d" % (b["geo"], b["index"]): b["sha256"] for b in blocks}, "pinned": False},
        "dump_observations": dumps,
        "not_established": NOT_ESTABLISHED,
        "next_discriminating_observations": [
            "At the copy call (GAME.OVR 0x2FA70, 0x2FA92, 0x2FAB4, 0x2FAD6) in a live run, record the five pushed "
            "words and the 0x100 bytes at each side before and after. A dst that matches the src bytes falsifies "
            "the reading with dst pushed second, and a dst that equals the pushed src falsifies it the other way.",
            "At the return of the loader call (GAME.OVR 0x2FA17), record the status word at [bp-2] and the far "
            "pointer at [bp-6]. Status 0x402 and a pointer whose 1026 bytes decode to a pinned GEO block "
            "(tools/por_map.py) together support block+2; any other pointer falsifies it.",
            "Record the id byte the caller pushes (stub 7 literal 03D5:0043, sites 0x1A27 and 0x1FBC4) and the "
            "TOC block id it names. The id is not decoded past its source byte.",
            "Decode the resident routines 0x0AF8:0x1685 and 0x0802:0x0716 once their segment mapping is established "
            "(see docs/por-ecl-target-probe.md): the expected copy convention is retf 0x0A for a three-argument copy.",
            "Dump DGROUP 0x6A5C through 0x6A5E and the 1 KiB it names at a known point after an area is entered, "
            "then compare the four planes with the decoded GEO blocks. The two pinned dumps are of unknown instant.",
        ],
        "verdict": "fill not established; copy geometry decoded from bytes; source and direction unresolved",
    })
    return doc


def render_report(doc: dict) -> str:
    fill = doc["fill"]
    L = ["# Pool of Radiance: buffer fill at DGROUP 0x6A5C (observe-only)", "",
         "**Status: observe-only. `playable: false`. `fill_established: false`. `plane2_binding: not claimed`.**", "",
         "## Allocation", ""]
    for s in doc["allocation"]["store_sites"]:
        L.append("- store `%s`, allocator call at `0x%X` with %d pushed, pattern ok %s, enclosing entry %s" % (
            s["store_hex"], s["allocator_call_at"], s["size_pushed"], s["pattern_ok"],
            "0x%X" % s["enclosing_entry"] if s["enclosing_entry"] is not None else "none"))
    L += ["", "## Census of 0x6A5C / 0x6A5E references", ""]
    for k, v in sorted(doc["pointer_census"]["counts"].items()):
        L.append("- %s: %d" % (k, v))
    L += ["", "## Fill function", "",
          "- entry `%s`, owner group `%s` (%s)" % (fill["entry_hex"], fill["owner_group_fileofs"],
                                                  fill["owner_group_status"]),
          "- loader: %s" % json.dumps(fill["loader"], sort_keys=True),
          "- copy simulation ok: %s%s" % (fill["copy_simulation_ok"],
                                          "" if fill["copy_simulation_ok"] else " (%s)" % fill["copy_simulation_reason"]),
          "", "| call | ok | src | dst | count | plane |", "| --- | --- | --- | --- | --- | --- |"]
    for c in fill["copies"]:
        L.append("| %s | %s | %s | %s | %s | %s |" % (c["call_at"], c["ok"], c["src"], c["dst"], c["count"], c["plane"]))
    L += ["", "## Stub 7 callers (candidate literal 03D5:0043)", ""]
    for c in doc["callers"]:
        L.append("- `%s` in entry `%s`: %s" % (c["site_hex"], "0x%X" % c["entry"] if c["entry"] is not None else "none",
                                              c["arg"]["source"]))
    L += ["", "## Dumps (memory bytes, unknown instant)", ""]
    for d in doc["dump_observations"]:
        L.append("- %s: positive control hits %s; GEO plane windows checked %d, hits %d. %s" % (
            d["dump"], d["positive_control_hits"], d["geo_plane_windows_checked"],
            len(d["geo_plane_window_hits"]), d["reading"]))
    L += ["", "## Not established", ""] + ["- " + x for x in doc["not_established"]]
    L += ["", "## Next discriminating observations", ""] + ["%d. %s" % (i + 1, x) for i, x in
                                                          enumerate(doc["next_discriminating_observations"])]
    return "\n".join(L) + "\n"


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_buffer_fill_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_geo_buffer_fill_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only static probe of the 0x6A5C buffer fill.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL,
                    help="folder with the pinned GAME.OVR and START.EXE (default: data/work/por-geo-run/POOLRAD)")
    ap.add_argument("--dump", type=Path, action="append", default=None,
                    help="raw 1 MiB RAM dump(s) to test (repeatable)")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    dumps = args.dump if args.dump else [DEFAULT_DUMP]
    try:
        doc = probe(args.install, args.out, dumps)
    except (Refusal, FileNotFoundError, pm.PorMapError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s (fill_established=%s, copies ok=%s)" % (
        args.out, doc["fill_established"], doc["fill"]["copy_simulation_ok"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
