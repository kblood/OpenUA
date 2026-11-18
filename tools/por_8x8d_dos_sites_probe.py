#!/usr/bin/env python3
"""Pool of Radiance: START.EXE DOS open/read sites, non-prologue entry walk and caller census.

Status: STATIC-PROBE-ONLY. Read-only, playable: false, mappings: [], binding_established: false.

Question this probe narrows (it does not answer it): the single START.EXE INT 21h AH=3Dh site
(file 0x0A8B6) and the AH=3Fh sites (0x0A9B5, 0x0A9D6, 0x0B333, 0x0B374) are not contained by any
prologue-entered routine. Which routines contain them if entries without a prologue are allowed,
which decode-verified calls reach those entries, and does the code on the upward chain build or
name an 8X8D archive?

What it measures, from the retail bytes only (nothing is executed):

  * pinned hashes of START.EXE and GAME.OVR, before and after the run (source immutability);
  * a bounded entry search for every requested site: each offset in the window before the site
    is a candidate entry if it has a basis (see labels below); its ret-stopped linear walk must
    end at a ret and must contain the site as an instruction start;
  * an upward caller census from those entries (depth and node budget bounded): decode-verified
    E8 near callers (model-free), the pre-call instructions of each caller, and far-call (9A)
    callers under the image model (hypothesis only);
  * a pointer consistency check: CS pointers pushed before those calls, tested with the shared
    pieces-based base check (consistency only, not proof);
  * the AH value of each INT 21h site the shared predecessor rule could not resolve, taken from
    the nearest AH-writing instruction on the containing walk (walk-derived, labelled as such);
  * every decode-verified INT 21h with AH=25h and AL=3Fh (vector 3Fh installs) and the instructions
    that set DS:DX before them.

Evidence labels used in the output:
  decoded      an instruction decodes and lies on a ret-stopped walk from the entry shown
  e8-verified  the entry is the target of a decode-verified E8 near call (relative; no image model)
               and some linear sweep from an earlier prologue or byte-ret anchor has an instruction start there
  e8-mid-insn  an E8 target that such sweeps cover with an instruction but never start on: not graded as an entry
  e8-unchecked an E8 target with no earlier anchor in the window: not graded as an entry
  prologue     the entry bytes are a standard push bp / mov bp,sp prologue (byte pattern)
  byte-ret     the byte before the entry is a ret (C3/CB) or a ret imm16 (C2/CA) that decodes to the
               entry; the entry is NOT decode-synced to the code before it (weakest entry basis)
  model        depends on the far-call image model file = 0x200 + seg*16 + off, not validated
  consistency  a CS base places pointers on Pascal piece length bytes; not proof
  hypothesis   an interpretation the bytes do not establish

Tiers of a containing entry: A = prologue or e8-verified basis; B = byte-ret only; C = model only.

It binds no block to a PoR screen, no slot to a tile, and writes no mapping.

Usage
  python tools/por_8x8d_dos_sites_probe.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-8x8d-dos-sites-probe/retail [--allow-unpinned]

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_8x8d_dos_sites_probe.json        schema openua.por-8x8d-dos-sites-probe
  por_8x8d_dos_sites_probe_report.md   the readable summary

Exit codes
  0  every pin matched and the scan completed
  1  output written with a diagnostic (a pin did not match); with --allow-unpinned the output is
     not retail evidence
  2  named refusal: missing install files, an output folder that is not under data/ or is inside
     the install, a source that changed during the run, or a file not matching its pin
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Optional

import struct

import por_loadpieces_handler as h
import por_farcall_resolve as fr
import por_8x8d_archive_chain_probe as chain
from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-8x8d-dos-sites-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_8x8d_dos_sites_probe.py"
EXE_NAME = "START.EXE"
OVR_NAME = "GAME.OVR"
IMAGE_BASE = 0x200

PINNED = {EXE_NAME: fr.PINNED[EXE_NAME], OVR_NAME: fr.PINNED[OVR_NAME]}

WINDOW = 0x400                       # bytes before a site searched for entries
MAX_WALK = 800
MAX_DEPTH = 3                        # caller levels above the site's root routine
MAX_NODES = 40
PRE_CALL = 8                         # instructions shown before each caller's call
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")

OPEN_SITE = 0x0A8B6                  # INT 21h AH=3Dh (decode-verified, from the chain probe inventory)
READ_SITES = (0x0A9B5, 0x0A9D6, 0x0B333, 0x0B374)     # INT 21h AH=3Fh
VECTOR_AL = 0x3F                     # vector 3Fh (the VROOMM stub opcode is CD 3F)
ASCIIZ_OPEN_AH = 0x3D
ASCIIZ_READ_AH = 0x3F

PIECE_KINDS = ("stem", "ext", "message")


class ProbeError(PorSourceError):
    """A named refusal, or a source that cannot be read as pinned."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hx(v: Optional[int]) -> str:
    return "n/a" if v is None else "0x%05x" % v


def _pin_row(name: str, data: bytes, allow_unpinned: bool) -> dict:
    size, sha = PINNED[name]
    ok = len(data) == size and _sha(data) == sha
    if not ok and not allow_unpinned:
        raise ProbeError("%s does not match its pinned size and SHA-256" % name)
    return {"bytes": len(data), "sha256": _sha(data), "pin_match": ok}


# --------------------------------------------------------------------------
# Decode-verified call indexes (model-free for E8; model-conditional for 9A)
# --------------------------------------------------------------------------

def near_call_index(data: bytes) -> dict[int, list[int]]:
    """target file offset -> sites of decode-verified E8 near calls to it."""
    idx: dict[int, list[int]] = {}
    for i in range(len(data) - 2):
        if data[i] != 0xE8:
            continue
        ins, _err = _try_decode(data, i)
        if ins is not None and ins.flow == "call" and ins.target is not None:
            idx.setdefault(ins.target, []).append(i)
    return idx


def far_model_index(data: bytes) -> dict[int, list[dict]]:
    """model file offset (0x200 + seg*16 + off) -> decode-verified 9A sites. Model-conditional."""
    idx: dict[int, list[dict]] = {}
    for i in range(len(data) - 4):
        if data[i] != 0x9A:
            continue
        ins, _err = _try_decode(data, i)
        if ins is not None and ins.flow == "call_far" and ins.far:
            seg, off = ins.far
            tgt = IMAGE_BASE + seg * 16 + off
            idx.setdefault(tgt, []).append({"at": i, "seg": seg, "off": off})
    return idx


# --------------------------------------------------------------------------
# Entry candidates and the bounded walk
# --------------------------------------------------------------------------

# The shared decoder raises DecodeError for bad opcodes but IndexError for some invalid operand
# fields (e.g. mov sreg with reg 6 or 7). Walks start at arbitrary offsets here, so every failure
# is treated as a decode failure of this probe; the shared module itself is not modified.
_DECODE_FAILURES = (h.DecodeError, IndexError, ValueError, struct.error)


def _try_decode(data: bytes, p: int):
    try:
        return h.decode(data, p), None
    except _DECODE_FAILURES as exc:
        return None, type(exc).__name__


def _linear(data: bytes, off: int, limit: int) -> tuple[list, Optional[str]]:
    """h.linear with the decode-failure set above; stops at the first ret/retf."""
    out: list = []
    p = off
    while len(out) < limit:
        ins, err = _try_decode(data, p)
        if ins is None:
            return out, err
        out.append(ins)
        p = ins.end
        if ins.flow in ("ret", "retf"):
            break
    return out, None


def _ret_at(data: bytes, p: int, n: int) -> bool:
    """A ret/retf instruction of length n that starts at p and decodes to exactly the next byte."""
    ins, _err = _try_decode(data, p)
    return ins is not None and ins.flow in ("ret", "retf") and ins.length == n


def _anchor_sweep_verdict(data: bytes, p: int, window: int = WINDOW) -> str:
    """Is ``p`` an instruction boundary of some linear sweep from an earlier anchor?

    Anchors are prologue or byte-ret positions in the window before ``p``. Each sweep decodes
    linearly without stopping at rets. "sync" if any sweep has an instruction start at ``p``;
    "covered" if sweeps exist and none syncs but one has an instruction spanning ``p``;
    "no-anchor" otherwise. This is a consistency test, not proof of a boundary."""
    covered = False
    for a in range(max(0, p - window), p):
        is_anchor = data[a:a + 3] in PROLOGUES or (
            a >= 1 and data[a - 1] in (0xC3, 0xCB) and _ret_at(data, a - 1, 1))
        if not is_anchor:
            continue
        q = a
        status = None
        while q < p:
            ins, _err = _try_decode(data, q)
            if ins is None:
                status = "decode-error"
                break
            if ins.end > p:
                status = "covered"
                break
            q = ins.end
        if status is None and q == p:
            return "sync"
        if status == "covered":
            covered = True
    return "covered" if covered else "no-anchor"


def entry_bases(data: bytes, p: int, e8idx: dict, faridx: dict) -> list[str]:
    bases = []
    if not (0 <= p < len(data)):
        return bases
    if data[p:p + 3] in PROLOGUES:
        bases.append("prologue")
    if p in e8idx:
        verdict = _anchor_sweep_verdict(data, p)
        bases.append({"sync": "e8-verified", "covered": "e8-mid-insn", "no-anchor": "e8-unchecked"}[verdict])
    if p >= 1 and data[p - 1] in (0xC3, 0xCB) and _ret_at(data, p - 1, 1):
        bases.append("byte-ret")
    elif p >= 3 and data[p - 3] in (0xC2, 0xCA) and _ret_at(data, p - 3, 3):
        bases.append("byte-ret")
    if p in faridx:
        bases.append("model")
    return bases


def tier_of(bases: list[str]) -> Optional[str]:
    if "prologue" in bases or "e8-verified" in bases:
        return "A"
    if "byte-ret" in bases:
        return "B"
    if "model" in bases:
        return "C"
    return None


def containing(data: bytes, site: int, e8idx: dict, faridx: dict, window: int = WINDOW) -> tuple[list[dict], dict]:
    """Entries in the window whose ret-stopped walk ends at a ret and contains ``site``."""
    stats = {"candidates": 0, "walked": 0, "ret_complete": 0, "contains_site": 0, "decode_error": 0}
    rows = []
    if not (0 <= site < len(data)):
        stats["outside_image"] = True
        return rows, stats
    for p in range(max(0, site - window), site):
        bases = entry_bases(data, p, e8idx, faridx)
        if not bases:
            continue
        stats["candidates"] += 1
        ins, err = _linear(data, p, MAX_WALK)
        stats["walked"] += 1
        if err is not None:
            stats["decode_error"] += 1
            continue
        if not ins or ins[-1].flow not in ("ret", "retf"):
            continue
        stats["ret_complete"] += 1
        offs = [i.off for i in ins]
        if site not in offs:
            continue
        stats["contains_site"] += 1
        rows.append({"entry": p, "bases": bases, "tier": tier_of(bases),
                     "insns_to_site": offs.index(site), "end": ins[-1].end, "last_flow": ins[-1].flow})
    return rows, stats


def pick_entry(rows: list[dict]) -> Optional[dict]:
    """Tier A first, then B, then C; within a tier the entry nearest the site (heuristic)."""
    for tier in ("A", "B", "C"):
        cand = [r for r in rows if r["tier"] == tier]
        if cand:
            return max(cand, key=lambda r: r["entry"])
    return None


def _walk(data: bytes, entry: int) -> list:
    ins, _err = _linear(data, entry, MAX_WALK)
    return ins


# --------------------------------------------------------------------------
# Routine facts and the pre-call context of a caller
# --------------------------------------------------------------------------

def cs_pointers_in(pre: list) -> list[dict]:
    """``mov reg,imm16`` / ``push cs`` / ``push reg``: a CS-relative pointer pushed as an argument."""
    out = []
    for k in range(len(pre) - 2):
        a, b, c = pre[k], pre[k + 1], pre[k + 2]
        if a.name.startswith("mov ") and a.length == 3 and a.imm is not None and b.name == "push cs" \
                and c.name == "push " + a.name[4:]:
            out.append({"at": a.off, "imm": a.imm, "reg": a.name[4:]})
    return out


def caller_context(data: bytes, call_at: int, e8idx: dict, faridx: dict) -> dict:
    rows, _stats = containing(data, call_at, e8idx, faridx)
    pick = pick_entry(rows)
    if pick is None:
        return {"status": "caller-not-contained", "containing_rows": len(rows)}
    ins = _walk(data, pick["entry"])
    pre = [i for i in ins if i.end <= call_at][-PRE_CALL:]
    return {"status": "contained", "routine_entry": pick["entry"], "tier": pick["tier"],
            "bases": pick["bases"],
            "pre_call": [{"at": i.off, "text": i.text()} for i in pre],
            "cs_pointers": cs_pointers_in(pre)}


def node_facts(data: bytes, entry: int, ah_of: dict) -> dict:
    ins = _walk(data, entry)
    if ins:
        last = ins[-1]
        ret_complete = last.flow in ("ret", "retf")
    else:
        last, ret_complete = None, False
    rep_movsb = any(0xF3 in i.prefixes and i.name.startswith("movsb") for i in ins)
    zero_term = any(i.raw == b"\xaa" and k > 0 and ins[k - 1].raw == b"\x32\xc0"
                    for k, i in enumerate(ins))
    int21 = [i.off for i in ins if i.raw == b"\xcd\x21"]
    ahs = {"0x%05x" % a: ("0x%02x" % ah_of[a] if ah_of.get(a) is not None else "unknown") for a in int21}
    lds_bp = [{"at": i.off, "text": i.text()} for i in ins if i.name == "lds" and i.bp_disp is not None]
    return {
        "entry": "0x%05x" % entry,
        "instructions": len(ins),
        "ret_complete": ret_complete,
        "last_flow": last.flow if last else None,
        "end": "0x%05x" % last.end if last else None,
        "int21_sites": ["0x%05x" % a for a in int21],
        "int21_ah": ahs,
        "bp_displacement_counts": {"%d" % k: v for k, v in sorted(
            Counter(i.bp_disp for i in ins if i.bp_disp is not None).items())},
        "lds_bp_operands": lds_bp,
        "rep_movsb": rep_movsb,
        "zero_terminator_stosb": zero_term,
        "asciiz_copy_then_open": rep_movsb and zero_term and ("0x3d" in ahs.values()),
        "far_calls_decoded": sorted({"0x%04x:0x%04x" % (i.far[0], i.far[1]) for i in ins
                                     if i.flow == "call_far" and i.far}),
    }


# --------------------------------------------------------------------------
# Upward census (bounded)
# --------------------------------------------------------------------------

def far_sites(data: bytes) -> list[dict]:
    """Every decode-verified 9A site: (at, seg, off). Used by the model-conditional delta sweep."""
    out = []
    for i in range(len(data) - 4):
        if data[i] != 0x9A:
            continue
        ins, _err = _try_decode(data, i)
        if ins is not None and ins.flow == "call_far" and ins.far:
            out.append({"at": i, "seg": ins.far[0], "off": ins.far[1]})
    return out


DELTA_SPAN = 16


def delta_sweep(entry: int, sites: list[dict]) -> list[dict]:
    """9A sites whose literal ``seg*16+off`` equals ``entry - 0x200 + d`` for a small d.

    Hypothesis only: a hit at d != 0 would mean the image model is off by d for this entry.
    Counted and listed for roots with no decode-verified caller; nothing is bound from a hit."""
    out = []
    base = entry - IMAGE_BASE
    for c in sites:
        lit = c["seg"] * 16 + c["off"]
        d = lit - base
        if -DELTA_SPAN <= d <= DELTA_SPAN:
            out.append({"at": "0x%05x" % c["at"], "literal": "0x%04x:0x%04x" % (c["seg"], c["off"]),
                        "delta": d, "basis": "model-delta-sweep", "hypothesis": True})
    return out


def census(data: bytes, roots: list[int], e8idx: dict, faridx: dict, ah_of: dict,
           fsites: list[dict]) -> tuple[dict, bool]:
    nodes: dict[int, dict] = {}
    truncated = False
    q: deque = deque((r, 0) for r in roots)
    while q:
        entry, depth = q.popleft()
        if entry in nodes:
            continue
        if len(nodes) >= MAX_NODES:
            truncated = True
            break
        node = node_facts(data, entry, ah_of)
        node["depth"] = depth
        node["e8_callers"] = []
        for at in sorted(e8idx.get(entry, [])):
            ctx = caller_context(data, at, e8idx, faridx)
            row = {"at": "0x%05x" % at, "context": ctx}
            node["e8_callers"].append(row)
            if ctx["status"] == "contained" and depth < MAX_DEPTH:
                q.append((ctx["routine_entry"], depth + 1))
        node["model_far_callers"] = [
            {"at": "0x%05x" % c["at"], "literal": "0x%04x:0x%04x" % (c["seg"], c["off"]),
             "basis": "model", "hypothesis": True}
            for c in faridx.get(entry, [])]
        node["model_delta_sweep"] = (delta_sweep(entry, fsites)
                                     if not node["e8_callers"] and not node["model_far_callers"] else None)
        nodes[entry] = node
    return nodes, truncated


def _collect_pointers(nodes: dict) -> list[dict]:
    out = []
    for n in nodes.values():
        for row in n["e8_callers"]:
            ctx = row["context"]
            for p in ctx.get("cs_pointers", []):
                out.append({"imm": p["imm"], "at": p["at"], "caller": row["at"]})
    return out


# --------------------------------------------------------------------------
# AH recovery for sites the predecessor rule could not resolve
# --------------------------------------------------------------------------

def _ah_writer_kind(i) -> Optional[str]:
    """Classify an instruction as an AH writer: immediate, non-immediate, other, or not a writer.

    The shared decoder names 8Ah /r (mov r8, r/m8) plainly "mov", so a write to AH is recognised by
    the opcode and the ModRM reg field (4 = AH) rather than by the name."""
    if i.name in ("mov ah", "mov ax"):
        return "immediate" if i.imm is not None else "non-immediate"
    if i.op == 0x8A and i.modrm and i.modrm[1] == 4:
        return "non-immediate"
    if i.op == 0x8B and i.modrm and i.modrm[1] == 0:
        return "non-immediate"
    if i.name.startswith(("pop ax", "xchg", "lodsw", "in ", "call", "int")):
        return "other-writer"
    return None


def unknown_ah_rows(data: bytes, inv: dict, e8idx: dict, faridx: dict) -> list[dict]:
    rows = []
    for s in inv["sites"]:
        if s["ah"] is not None:
            continue
        a = s["at"]
        cont, _stats = containing(data, a, e8idx, faridx)
        pick = pick_entry(cont)
        row = {"at": "0x%05x" % a, "bytes_before": data[a - 6:a + 2].hex(" "), "entry": None}
        if pick is None:
            row["status"] = "no-containing-entry"
            rows.append(row)
            continue
        ins = _walk(data, pick["entry"])
        before = [i for i in ins if i.end <= a]
        writer, between = None, None
        for k in range(len(before) - 1, -1, -1):
            i = before[k]
            kind = _ah_writer_kind(i)
            if kind is None:
                continue
            if kind == "immediate":
                value = ("0x%02x" % (i.imm & 0xFF)) if i.name == "mov ah" else ("0x%02x" % ((i.imm >> 8) & 0xFF))
                writer = {"at": "0x%05x" % i.off, "text": i.text(), "value": value}
            else:
                # non-immediate or other writers: the value is not guessed
                writer = {"at": "0x%05x" % i.off, "text": i.text(), "value": None, "kind": kind}
            between = len(before) - 1 - k
            break
        row.update({"status": "walk-derived", "entry": "0x%05x" % pick["entry"], "tier": pick["tier"],
                    "ah_writer": writer, "instructions_between": between})
        rows.append(row)
    return rows


def vector_3f_rows(data: bytes, inv: dict, e8idx: dict, faridx: dict) -> list[dict]:
    out = []
    for s in inv["sites"]:
        if s["ah"] != 0x25:
            continue
        a = s["at"]
        # the predecessor rule guarantees mov ax,imm16 ends at the INT; recover AL
        if a < 3 or data[a - 3] != 0xB8 or data[a - 1] != 0x25 or data[a - 2] != VECTOR_AL:
            continue
        cont, _stats = containing(data, a, e8idx, faridx)
        pick = pick_entry(cont)
        pre = []
        if pick is not None:
            ins = _walk(data, pick["entry"])
            pre = [{"at": "0x%05x" % i.off, "text": i.text()} for i in ins if i.end <= a - 3][-4:]
        out.append({"at": "0x%05x" % a, "entry": ("0x%05x" % pick["entry"]) if pick else None,
                    "tier": pick["tier"] if pick else None, "dx_setup_before": pre})
    return out


# --------------------------------------------------------------------------
# Probe
# --------------------------------------------------------------------------

UNRESOLVED = [
    {"id": "D1", "edge": "routine containing the open (AH=3Dh, 0x0A8B6)",
     "status": "established-entry-by-decode",
     "why": "0x0A89E is a non-prologue entry (its bytes begin lds si,[bp+6]); it is the target of three "
            "decode-verified E8 calls and its ret-stopped walk ends at 0x0A8B8 and contains the INT 21h"},
    {"id": "D2", "edge": "the callers of the open helper 0x0A89E and of its callers",
     "status": "partly-established",
     "why": "E8 callers are decode-verified; the caller routines and what their BP frame holds are read from "
            "the census. Entries reached only by jumps, by INT 3Fh dispatch or by far calls are not counted"},
    {"id": "D3", "edge": "what the open helper opens: its Pascal name and mode",
     "status": "not-established",
     "why": "the helper reads the name from a frame slot [bp+6] (a far pointer) and the mode from [bp-2]; the "
            "frame belongs to an enclosing prologue routine whose callers are not established"},
    {"id": "D4", "edge": "the four AH=3Fh read sites",
     "status": "not-established",
     "why": "no read site is contained by a prologue-entered routine; the tier of each containing entry, and "
            "whether any has a decode-verified caller, is in the census. Whether they serve GAME.OVR "
            "(overlay/VROOMM) or a DAX file is not decided here"},
    {"id": "D5", "edge": "the 8 INT 21h sites with an AH the predecessor rule could not resolve",
     "status": "walk-derived",
     "why": "AH is taken from the nearest AH-writing instruction on the containing walk; a site with no "
            "containing entry, or a non-immediate writer, is reported as such and not guessed"},
    {"id": "D6", "edge": "far calls (9A) into the upward chain",
     "status": "model-conditional",
     "why": "the image model file = 0x200 + seg*16 + off is not validated (START.EXE has no relocations)"},
    {"id": "D7", "edge": "any 8X8D name on the upward chain",
     "status": "not-established",
     "why": "the pointer census lists CS pointers pushed before each caller's call; a base that places them on "
            "the 8X8D Pascal pieces is consistency only, and the pieces have no decoded consumer yet"},
]


def analyse(start: bytes, ovr: bytes) -> dict:
    e8idx = near_call_index(start)
    faridx = far_model_index(start)
    inv = chain.int21_inventory(start)
    ah_of = {s["at"]: s["ah"] for s in inv["sites"]}

    sites = {}
    roots: list[int] = []
    for label, s in [("open_3D", OPEN_SITE)] + [("read_3F", a) for a in READ_SITES]:
        rows, stats = containing(start, s, e8idx, faridx)
        pick = pick_entry(rows)
        tiers = Counter(r["tier"] for r in rows)
        sites["0x%05x" % s] = {
            "kind": label,
            "ah_by_predecessor": ("0x%02x" % ah_of[s]) if ah_of.get(s) is not None else None,
            "stats": stats,
            "containing_by_tier": {t: tiers.get(t, 0) for t in "ABC"},
            "containing": [{"entry": "0x%05x" % r["entry"], "tier": r["tier"], "bases": r["bases"],
                            "insns_to_site": r["insns_to_site"], "end": "0x%05x" % r["end"]}
                           for r in sorted(rows, key=lambda r: r["entry"])],
            "pick": ({"entry": "0x%05x" % pick["entry"], "tier": pick["tier"]} if pick else None),
        }
        # roots: every tier-A entry of the site, else the best tier-B/C entry
        tier_a = [r["entry"] for r in rows if r["tier"] == "A"]
        if tier_a:
            roots.extend(tier_a)
        elif pick is not None:
            roots.append(pick["entry"])
    roots = sorted(set(roots))

    nodes, truncated = census(start, roots, e8idx, faridx, ah_of, far_sites(start))
    ptrs = _collect_pointers(nodes)
    exe_pieces = chain.pieces(start)
    base = chain.base_check(start, [{"imm": p["imm"]} for p in ptrs], exe_pieces)
    piece_rows = [{"kind": r["kind"], "offset": "0x%05x" % r["offset"], "text": r["text"],
                   "pascal": r["pascal"], "length_byte": ("0x%05x" % r["length_byte"]) if r["length_byte"] is not None else None}
                  for r in exe_pieces]

    return {
        "int21_START_by_ah": inv["by_ah"],
        "int21_START_count": inv["count"],
        "int21_GAME_OVR_count": chain.int21_inventory(ovr)["count"],
        "requested_sites": sites,
        "census_roots": ["0x%05x" % r for r in roots],
        "census_nodes": {"0x%05x" % k: v for k, v in sorted(nodes.items())},
        "census_truncated": truncated,
        "unknown_ah_sites": unknown_ah_rows(start, inv, e8idx, faridx),
        "vector_3F_installs": vector_3f_rows(start, inv, e8idx, faridx),
        "pieces_START": piece_rows,
        "pointer_census": [{"imm": "0x%04x" % p["imm"], "at": "0x%05x" % p["at"], "caller": p["caller"]} for p in ptrs],
        "pointer_base_check": {
            "pointer_count": base["pointer_count"],
            "candidates": base["candidates"],
            "note": "consistency only: bases derived from the first pointer and each piece length byte",
        },
    }


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    folder = chain.resolve_folder(install)
    exe = (folder / EXE_NAME).read_bytes()
    ovr = (folder / OVR_NAME).read_bytes()
    pins = {EXE_NAME: _pin_row(EXE_NAME, exe, allow_unpinned),
            OVR_NAME: _pin_row(OVR_NAME, ovr, allow_unpinned)}
    if fr.mz_image_base(exe) != IMAGE_BASE:
        raise ProbeError("START.EXE header base is not 0x200 (model constant)")
    facts = analyse(exe, ovr)
    after = {EXE_NAME: _sha((folder / EXE_NAME).read_bytes()),
             OVR_NAME: _sha((folder / OVR_NAME).read_bytes())}
    unchanged = after[EXE_NAME] == pins[EXE_NAME]["sha256"] and after[OVR_NAME] == pins[OVR_NAME]["sha256"]
    if not unchanged:
        raise ProbeError("a pinned source changed during the run")
    all_pins = all(p["pin_match"] for p in pins.values())
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "playable": False,
        "mappings": [],
        "binding_established": False,
        "verdict": "bounded: the open and reads are located by decode; their use for 8X8D is not established",
        "pins": pins,
        "source_unchanged": unchanged,
        "facts": facts,
        "unresolved_edges": UNRESOLVED,
    }
    return doc, (0 if all_pins else 1)


def render_report(doc: dict) -> str:
    f = doc["facts"]
    a = []
    a.append("# PoR START.EXE DOS open/read sites: entry walk and caller census (observe-only)")
    a.append("")
    a.append("Status: `%s`. `playable: false`. `mappings: []`. `binding_established: false`." % doc["status"])
    a.append("Verdict: %s." % doc["verdict"])
    a.append("")
    a.append("## Pins")
    a.append("")
    for name, row in doc["pins"].items():
        a.append("- `%s`: %d bytes, sha256 `%s`, pin match %s" % (name, row["bytes"], row["sha256"], row["pin_match"]))
    a.append("- source unchanged after the run: %s" % doc["source_unchanged"])
    a.append("")
    a.append("## Requested sites")
    a.append("")
    for k, s in f["requested_sites"].items():
        a.append("- %s `%s` (predecessor AH %s): stats %s; containing by tier %s; pick %s" % (
            s["kind"], k, s["ah_by_predecessor"], json.dumps(s["stats"], sort_keys=True),
            json.dumps(s["containing_by_tier"], sort_keys=True), json.dumps(s["pick"], sort_keys=True)))
        for c in s["containing"]:
            a.append("  - entry %s tier %s bases %s, %d insns to site, ends %s" % (
                c["entry"], c["tier"], ",".join(c["bases"]), c["insns_to_site"], c["end"]))
    a.append("")
    a.append("## Upward census (roots: %s)" % ", ".join(f["census_roots"]))
    a.append("")
    if f["census_truncated"]:
        a.append("Census truncated at the node budget (%d)." % MAX_NODES)
        a.append("")
    for k, n in f["census_nodes"].items():
        a.append("### Node %s (depth %d)" % (k, n["depth"]))
        a.append("")
        a.append("- decoded: %d insns, ret_complete %s, ends %s (%s); INT 21h %s (AH %s)" % (
            n["instructions"], n["ret_complete"], n["end"], n["last_flow"], n["int21_sites"],
            json.dumps(n["int21_ah"], sort_keys=True)))
        a.append("- bp displacement counts %s; lds via bp %s" % (
            json.dumps(n["bp_displacement_counts"], sort_keys=True),
            "; ".join("%s %s" % (o["at"], o["text"]) for o in n["lds_bp_operands"]) or "none"))
        a.append("- ASCIIZ copy then open (decoded pattern): %s" % n["asciiz_copy_then_open"])
        for c in n["e8_callers"]:
            ctx = c["context"]
            if ctx["status"] == "contained":
                a.append("- e8-verified caller %s in routine %s (tier %s, bases %s); pre-call: %s" % (
                    c["at"], "0x%05x" % ctx["routine_entry"], ctx["tier"], ",".join(ctx["bases"]),
                    " ; ".join("%s %s" % (p["at"], p["text"]) for p in ctx["pre_call"])))
            else:
                a.append("- e8-verified caller %s: %s" % (c["at"], ctx["status"]))
        for m in n["model_far_callers"]:
            a.append("- model (hypothesis) 9A caller %s literal %s" % (m["at"], m["literal"]))
        if n.get("model_delta_sweep") is not None:
            a.append("- model delta sweep (+-%d, hypothesis only): %s" % (DELTA_SPAN, json.dumps(
                n["model_delta_sweep"], sort_keys=True) if n["model_delta_sweep"] else "no 9A literal within span"))
        if not n["e8_callers"] and not n["model_far_callers"]:
            a.append("- no decode-verified E8 or model 9A caller")
        a.append("")
    a.append("## AH of unresolved INT 21h sites (walk-derived)")
    a.append("")
    for r in f["unknown_ah_sites"]:
        a.append("- %s: %s; entry %s; writer %s" % (r["at"], r.get("status"), r.get("entry"),
                                                   json.dumps(r.get("ah_writer"), sort_keys=True)))
    a.append("")
    a.append("## Vector 3Fh installs (AH=25h, AL=3Fh)")
    a.append("")
    for v in f["vector_3F_installs"]:
        a.append("- %s in entry %s (tier %s): %s" % (v["at"], v["entry"], v["tier"],
                                                    " ; ".join("%s %s" % (p["at"], p["text"]) for p in v["dx_setup_before"])))
    a.append("")
    a.append("## Pointer census and base check (consistency only)")
    a.append("")
    a.append("- CS pointers pushed before census calls: %d" % f["pointer_base_check"]["pointer_count"])
    for c in f["pointer_base_check"]["candidates"][:4]:
        a.append("- base %s: matched %s; unmatched %d" % (
            c["cs_base"], json.dumps(c["matched"], sort_keys=True), len(c["unmatched"])))
    a.append("")
    a.append("## Unresolved edges")
    a.append("")
    for u in doc["unresolved_edges"]:
        a.append("- %s %s: %s. %s" % (u["id"], u["edge"], u["status"], u["why"]))
    a.append("")
    return "\n".join(a)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_8x8d_dos_sites_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_8x8d_dos_sites_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--install", required=True, type=Path)
    ap.add_argument("-o", "--out", required=True, type=Path)
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="analyse files that do not match their pins; output is not retail evidence")
    args = ap.parse_args(argv)
    try:
        folder = chain.resolve_folder(args.install)
        validate_output_dir(folder, args.out)
        doc, code = probe(args.install, args.out, args.allow_unpinned)
    except PorSourceError as exc:          # includes ProbeError
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s" % (args.out / "por_8x8d_dos_sites_probe.json"))
    return code


if __name__ == "__main__":
    sys.exit(main())
