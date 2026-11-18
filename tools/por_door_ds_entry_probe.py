#!/usr/bin/env python3
"""Pool of Radiance: static trace of the INT 3Fh dispatcher's far call through DS:[0x43F0].

Observe-only and diagnostic. Follows docs/por-door-indirect-probe.md and docs/por-door-caller-probe.md.
The question: does any byte-level caller or entry path establish AX, and hence DS, for the indirect far
call at START file 0x0AA40 (`callf [0x43F0]`), and can the far pointer it reads reach the door
writer/clearer stub at START file 0x0089C?

Chain under test (START.EXE, file offsets, decoded with tools/por_loadpieces_handler.py):
  0x0A9FC  INT 3Fh-shaped dispatcher: push bp ... reads the return CS:IP (les bx,[bp+2]), pushes the word
           there (the stub's proc word), ends with iret at 0x0AA4D.
  0x0AA07  B8 7C 0C        mov ax,0x0C7C        (decoded literal; MZ nreloc = 0, see below)
  0x0AA0A  8E D8           mov ds,ax
  0x0AA40  FF 1E F0 43     callf [0x43F0]       (far pointer read at DS:0x43F0)
  The only static initializer of DS:[0x43F0] found is routine A (entry 0x0A728, store at 0x0A7DE):
  `mov word [0x43F0],0x2E5` and `mov [0x43F2],cs`, guarded by a zero test. That store runs through the
  DS the caller passed in: the push cs / pop ds at 0x0A7EC comes after it.

Evidence classes, kept separate in the output:
  D  decoded: an instruction start reached by a walk (lh.walk or the image census below), with its
     operands read from the bytes. The only class that drives a verdict.
  R  raw: a byte pattern that is not a decoded instruction start. Counted and listed; never a caller,
     never a writer, never a verdict input.
  M  model: a file-to-linear skew used for arithmetic (see MODELS). Named, never promoted.
  X  doc: a runtime value quoted from another doc (DS 0x14A0, 12C6:02E6). Not re-derived here.

Address arithmetic. A far pointer seg:off in START addresses file offset seg*16+off+k for a uniform
skew k. The MZ image is paragraph-loaded, so k is 0 mod 16 whenever the image base is paragraph-aligned
(MZ header 0x200). Two named skews are checked (M0 k=0x200, M1 k=0x7E), and the skew residue that a
pointer offset would need to reach a target is reported (`required_skew`). A pointer offset and a
target differing in residue cannot meet under any single skew with residue 0.

Read-only. Refuses unpinned GAME.OVR or START.EXE (no override) and re-hashes both files after the run.
Writes only under data/work, outside the install folder.

Usage:
    python tools/por_door_ds_entry_probe.py --install PATH/TO/POOLRAD -o data/work/por-door-ds-entry-probe

Exit: 0 probe ran; 2 named refusal.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import deque
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_door_caller_probe as dc  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

SCHEMA = "openua.por-door-ds-entry-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_door_ds_entry_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-door-ds-entry-probe"

# ---- decoded anchors (START.EXE file offsets) ------------------------------------------------
DISPATCH = 0x0A9FC            # function entry (push bp; mov bp,sp)
MOV_AX_IMM = 0x0AA07          # B8 7C 0C
MOV_DS_AX = 0x0AA0A           # 8E D8
CALLF_PTR = 0x0AA40           # FF 1E F0 43
DS_LITERAL = 0x0C7C           # immediate of the mov ax at MOV_AX_IMM
PTR_OFF = 0x043F0             # DS-relative far pointer: offset word
PTR_SEG = 0x043F2             # DS-relative far pointer: segment word
ROUTINE_A_ENTRY = 0x0A728     # far-called (retf 4); its DS is the caller's
ROUTINE_A_GUARD = 0x0A7D5     # mov ax,[43F0] (read)
ROUTINE_A_STORE_OFF = 0x0A7DE  # C7 06 F0 43 E5 02  mov word [43F0],0x2E5
ROUTINE_A_STORE_SEG = 0x0A7E4  # 8C 0E F2 43        mov [43F2],cs
ROUTINE_A_PTR_VALUE = 0x02E5
ROUTINE_A_DX = 0x02E6         # DX of the INT 3Fh install in routine A (file 0x0A7E9)
ROUTINE_B_DX = 0x00D7         # DX of the INT 3Fh install in routine B (file 0x0ACF0 site)
ALIAS_8504_STORE = 0x0A7CB    # C7 06 04 85 68 02  mov word [8504],0x268
ALIAS_8504_VALUE = 0x0268
# X: runtime shift (linear - file) implied by the two quoted live INT 3Fh placements
# (12C6:02E6 -> file 0xA9FC, 131C:00D7 -> file 0xAD4D; docs/por-int3f-runtime-capture.md).
# Not re-derived here. Its residue is not 0, so it contradicts a paragraph-loaded image.
LIVE_QUOTED_SHIFT = 0x0854A
STUB1 = 0x0089C               # door writer/clearer stub (group 0x166CB, stub 1); C D 3F 6D 0D 00
STUB1_BYTES = bytes([0xCD, 0x3F, 0x6D, 0x0D, 0x00])
INT3F_INSTALL_TAIL = bytes([0xB8, 0x3F, 0x25, 0xCD, 0x21])  # mov ax,253Fh; int 21h

MODELS = {
    "M0": 0x200,   # zero-skew: file = hdr + seg*16 + off, hdr = MZ header size (paragraph aligned)
    "M1": 0x7E,    # dump-anchored (por-door-caller-probe.md): file = seg*16 + off + 0x7E
}

STORE_OPS = {0x88, 0x89, 0x8C, 0x8F, 0xA2, 0xA3}
DS_WRITE_NAMES = {0x1F: "pop ds", 0xC5: "lds"}

DOC_RUNTIME = {  # quoted from docs, not re-derived by this probe
    "int3f_live_vector": "12C6:02E6",
    "int3f_live_callee": "12C6:02E5 (retf, CB)",
    "ds_at_callf_live": "0x14A0 (14A0:43F0 = E5 02 C6 12)",
    "doc_label_routine_a_file": "0xA9FC",
}


class Refusal(Exception):
    pass


def u16(data: bytes, p: int) -> int:
    return struct.unpack_from("<H", data, p)[0]


def _dec(data: bytes, p: int) -> Optional[lh.Insn]:
    try:
        return lh.decode(data, p)
    except (lh.DecodeError, IndexError):
        return None


def _h(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%05X" % v


# ---- MZ header and relocation table ----------------------------------------------------------

def mz_facts(start: bytes) -> dict:
    if len(start) < 0x1C or start[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    cp, crlc, cparhdr, minalloc, maxalloc, ss, sp, csum, ip, cs, lfarlc = struct.unpack_from(
        "<HHHHHHHHHHH", start, 4)
    hdr = cparhdr * 16
    relocs = []
    for i in range(crlc):
        p = lfarlc + 4 * i
        if p + 4 > len(start):
            break
        ro, rs = struct.unpack_from("<HH", start, p)
        relocs.append({"fixup_word_image": rs * 16 + ro, "seg": rs, "off": ro})
    return {
        "hdr_bytes": hdr,
        "nreloc": crlc,
        "relocs": relocs,
        "entry_cs_ip": "%04X:%04X" % (cs, ip),
        "entry_file": hdr + cs * 16 + ip,
        "ss_sp": "%04X:%04X" % (ss, sp),
        "minalloc_paragraphs": minalloc,
        "maxalloc_paragraphs": maxalloc,
        "image_bytes": len(start) - hdr,
        "file_bytes": len(start),
    }


def reloc_covers(mz: dict, file_off: int, hdr: int) -> bool:
    """True if an MZ relocation fixup word covers the byte at file_off (image-relative fixup address)."""
    img = file_off - hdr
    return any(r["fixup_word_image"] in (img, img - 1) for r in mz["relocs"])


# ---- decoded census --------------------------------------------------------------------------

def closure(data: bytes, roots: list[int], lo: int, hi: int) -> dict[int, dict]:
    """Walk each root; follow near calls whose target is inside [lo, hi)."""
    fns: dict[int, dict] = {}
    q = deque(roots)
    while q:
        e = q.popleft()
        if e in fns or not (lo <= e < hi):
            continue
        w = lh.walk(data, e)
        fns[e] = w
        for c in w["near_calls"]:
            t = c["target"]
            if t is not None and lo <= t < hi and t not in fns:
                q.append(t)
    return fns


def image_census(data: bytes, entry: int, lo: int, hi: int) -> dict:
    """Closure from the entry point, then a Borland prologue sweep of the unreached prologues."""
    cl = closure(data, [entry], lo, hi)
    reached = {r["at"] for w in cl.values() for r in w["listing"]}
    sweep: dict[int, dict] = {}
    for p in range(lo, hi - 3):
        if data[p:p + 3] in dc.PROLOGUES and p not in reached:
            sweep[p] = lh.walk(data, p)
    walks = list(cl.values()) + list(sweep.values())
    insns = decode_listings(data, walks)
    cover: dict[int, int] = {}
    for s, ins in insns.items():
        for b in range(s, s + ins.length):
            cover[b] = s
    covered = sum(1 for b in range(lo, hi) if b in cover)
    return {
        "entry_file": entry,
        "walks_closure": len(cl),
        "walks_sweep": len(sweep),
        "walks_complete": sum(1 for w in walks if w["complete"]),
        "covered_bytes": covered,
        "image_bytes": hi - lo,
        "insns": insns,
        "cover": cover,
    }


def decode_listings(data: bytes, walks: list[dict]) -> dict[int, lh.Insn]:
    insns: dict[int, lh.Insn] = {}
    for w in walks:
        for r in w["listing"]:
            a = r["at"]
            if a not in insns:
                ins = _dec(data, a)
                if ins is not None:
                    insns[a] = ins
    return insns


def ds_write_kind(ins: lh.Insn) -> Optional[str]:
    if ins.op in DS_WRITE_NAMES:
        return DS_WRITE_NAMES[ins.op]
    if ins.op == 0x8E and ins.modrm and ins.modrm[1] == 3:
        return "mov ds, r/m16"
    return None


def access_class(ins: lh.Insn) -> str:
    """Coarse class of a memory operand's access. 'other' when the opcode is not in the table."""
    op = ins.op
    reg = ins.modrm[1] if ins.modrm else None
    if op in STORE_OPS:
        return "write"
    if op in (0xC6, 0xC7):
        return "write" if reg == 0 else "other"
    if op in (0x86, 0x87):
        return "rmw"
    if op < 0x40 and (op & 7) in (0, 1):
        return "read" if (op >> 3) == 7 else "rmw"
    if op < 0x40 and (op & 7) in (2, 3):
        return "read"
    if op in (0x80, 0x81, 0x83):
        return "read" if reg == 7 else "rmw"
    if op in (0xFE, 0xFF) and reg in (0, 1):
        return "rmw"
    if op == 0xFF and reg in (2, 3, 4, 5, 6):
        return "read"
    if op in (0xD0, 0xD1, 0xD2, 0xD3, 0xC0, 0xC1):
        return "rmw"
    if op in (0x84, 0x85, 0x8A, 0x8B, 0x8E, 0xA0, 0xA1, 0xC4, 0xC5, 0x3A, 0x3B, 0x38, 0x39):
        return "read"
    if op == 0x8D:
        return "address"
    if op in (0xF6, 0xF7):
        return "read" if reg in (0, 1) else "rmw"
    return "other"


def ds_writers(insns: dict[int, lh.Insn], starts) -> list[dict]:
    out = []
    for a in sorted(starts):
        ins = insns.get(a)
        if ins is None:
            continue
        k = ds_write_kind(ins)
        if k:
            out.append({"at": _h(a), "kind": k, "text": ins.text()})
    return out


# ---- chain facts (dispatcher -> AX -> DS -> callf) ---------------------------------------------

def chain_facts(data: bytes, insns: dict[int, lh.Insn], dispatch: int, mov_ax: int, mov_ds: int,
                callf: int, lit: int, ptr: int) -> dict:
    w = lh.walk(data, dispatch)
    body = [r["at"] for r in w["listing"]]
    body_set = set(body)
    ax = insns.get(mov_ax)
    ds = insns.get(mov_ds)
    cf = insns.get(callf)
    ax_ok = bool(ax and ax.op == 0xB8 and ax.imm == lit and ax.length == 3)
    ds_ok = bool(ds and ds.op == 0x8E and ds.modrm and ds.modrm[1] == 3 and ds.modrm[2] == 0)
    cf_ok = bool(cf and cf.flow == "indirect_callf" and cf.direct == ptr and cf.length == 4)
    branch_before_ds = [
        {"at": _h(a), "text": ins.text(), "flow": ins.flow}
        for a, ins in sorted(insns.items())
        if a in body_set and dispatch <= a < mov_ds and ins.flow != "seq"
    ]
    between = [a for a in body if mov_ds < a < callf]
    between_calls = []
    for a in sorted(between):
        ins = insns.get(a)
        if ins is None:
            continue
        if ins.flow in ("call", "call_far", "indirect_call", "indirect_callf"):
            between_calls.append({"at": _h(a), "flow": ins.flow, "text": ins.text(),
                                  "target": _h(ins.target) if ins.target is not None else None})
    return {
        "dispatch_walk_complete": w["complete"],
        "dispatch_walk_incomplete": w["incomplete"],
        "dispatch_instruction_count": w["instruction_count"],
        "mov_ax_imm": {"at": _h(mov_ax), "text": ax.text() if ax else None, "ok": ax_ok},
        "mov_ds_ax": {"at": _h(mov_ds), "text": ds.text() if ds else None, "ok": ds_ok},
        "callf": {"at": _h(callf), "text": cf.text() if cf else None, "ok": cf_ok},
        "branch_before_ds_load": branch_before_ds,
        "ds_writers_between_ds_and_callf": [r for r in ds_writers(insns, between)],
        "calls_between_ds_and_callf": between_calls,
        "_body": body_set,
    }


def edges_into(insns: dict[int, lh.Insn], body: set[int], lo: int, hi: int) -> dict:
    """Decoded edges from outside the dispatcher body into [lo, hi] (bypassing the AX/DS load)."""
    near = []
    far = []
    for a, ins in sorted(insns.items()):
        if a in body:
            continue
        if ins.flow in ("jcc", "jmp", "call") and ins.target is not None and lo <= ins.target <= hi:
            near.append({"from": _h(a), "to": _h(ins.target), "text": ins.text()})
        if ins.flow in ("call_far", "jmp_far") and ins.far is not None:
            seg, off = ins.far
            for name, k in MODELS.items():
                file_t = seg * 16 + off + k
                if lo <= file_t <= hi:
                    far.append({"from": _h(a), "seg": "0x%04X" % seg, "off": "0x%04X" % off,
                                "model": name, "file_target": _h(file_t)})
    return {"near_or_jump": near, "far_literal": far}


def ds_discipline(data: bytes, insns: dict[int, lh.Insn], starts: list[int],
                  before: Optional[int] = None) -> dict:
    """Bracket check for DS writes among `starts` (sorted by address; optionally only those < before).

    A DS write is `mov ds,r/m16` (8E /3), `lds` (C5), or a `pop ds` preceded by `push ss` (a temporary
    DS=SS switch). A plain `pop ds` is a restore. The function's DS is restored when every write has a
    `push ds` before it and a restore after it, and the push and restore counts match. This is an address-
    order check, not a path proof; it is reported as such.
    """
    seq = sorted(a for a in starts if before is None or a < before)
    pushes: list[int] = []
    restores: list[int] = []
    writers: list[int] = []
    texts: dict[int, str] = {}

    def get(p: int) -> Optional[lh.Insn]:
        # the caller's map may be the image census only; decode on a miss so callee closures are complete
        return insns.get(p) or _dec(data, p)

    for a in seq:
        ins = get(a)
        if ins is None:
            continue
        if ins.op == 0x1E:
            pushes.append(a)
        elif ins.op == 0x1F:
            prev = get(a - 1)
            if prev is not None and prev.op == 0x16:
                writers.append(a)
            else:
                restores.append(a)
        elif ds_write_kind(ins):
            writers.append(a)
        if a in writers:
            texts[a] = ins.text()
    bracketed = bool(writers) and len(pushes) == len(restores) and all(
        any(p < w for p in pushes) and any(r > w for r in restores) for w in writers)
    if not writers and not pushes and not restores:
        status = "none"
    elif bracketed:
        status = "bracketed"
    else:
        status = "open"
    return {"status": status, "pushes": [_h(x) for x in pushes], "restores": [_h(x) for x in restores],
            "writers": [{"at": _h(w), "text": texts[w]} for w in writers]}


def callee_audit(data: bytes, roots: list[int], lo: int, hi: int, insns_global: dict) -> dict:
    fns = closure(data, roots, lo, hi)
    rows = []
    open_edges: list[dict] = []
    for e, w in sorted(fns.items()):
        starts = [r["at"] for r in w["listing"]]
        dis = ds_discipline(data, insns_global, starts)
        row = {"entry": _h(e), "complete": w["complete"], "instructions": w["instruction_count"],
               "ds": dis["status"], "ds_writers": dis["writers"], "ds_pushes": dis["pushes"],
               "ds_restores": dis["restores"], "far_calls": [], "indirect": [], "direct_43f0_43f2": []}
        if not w["complete"]:
            open_edges.append({"function": _h(e), "kind": "walk-incomplete", "at": _h(e)})
        if dis["status"] == "open":
            open_edges.append({"function": _h(e), "kind": "ds-unbalanced", "writers": dis["writers"]})
        for r in w["listing"]:
            ins = insns_global.get(r["at"]) or _dec(data, r["at"])
            if ins is None:
                continue
            if ins.flow == "call_far":
                seg, off = ins.far
                row["far_calls"].append({"at": _h(r["at"]), "seg": "0x%04X" % seg, "off": "0x%04X" % off,
                                         "text": ins.text()})
                open_edges.append({"function": _h(e), "kind": "far-call", "at": _h(r["at"]),
                                   "text": ins.text()})
            if ins.flow.startswith("indirect"):
                row["indirect"].append({"at": _h(r["at"]), "flow": ins.flow, "text": ins.text()})
                open_edges.append({"function": _h(e), "kind": ins.flow, "at": _h(r["at"]),
                                   "text": ins.text()})
            if ins.direct in (PTR_OFF, PTR_SEG) and ins.modrm and ins.modrm[0] == 0:
                row["direct_43f0_43f2"].append({"at": _h(r["at"]), "class": access_class(ins),
                                                "text": ins.text()})
        rows.append(row)
    return {"functions": rows, "count": len(rows), "open_edges": open_edges,
            "free_of_open_edges": not open_edges}


# ---- DS:[43F0] / [43F2] references --------------------------------------------------------------

def direct_refs(insns: dict[int, lh.Insn], disps: set[int]) -> list[dict]:
    out = []
    for a, ins in sorted(insns.items()):
        if ins.direct in disps and ins.modrm and ins.modrm[0] == 0:
            out.append({"at": _h(a), "disp": "0x%04X" % ins.direct, "class": access_class(ins),
                        "text": ins.text(), "covered": "D"})
        elif 0xA0 <= ins.op <= 0xA3 and len(ins.raw) >= 3 and u16(ins.raw, 1) in disps:
            out.append({"at": _h(a), "disp": "0x%04X" % u16(ins.raw, 1),
                        "class": "write" if ins.op in (0xA2, 0xA3) else "read",
                        "text": ins.text(), "covered": "D"})
    return out


def raw_refs(data: bytes, disps: set[int], cover: Optional[dict[int, int]]) -> list[dict]:
    """Raw byte-pattern hits for a disp16 DS-direct operand or moffs. cover=None means no decode."""
    out = []
    for p in range(1, len(data) - 1):
        w = data[p] | (data[p + 1] << 8)
        if w not in disps:
            continue
        if p >= 2 and (data[p - 1] & 0xC7) == 0x06:
            site, op = p - 2, data[p - 2]
            kind = "modrm-disp16"
        elif 0xA0 <= data[p - 1] <= 0xA3:
            site, op = p - 1, data[p - 1]
            kind = "moffs"
        else:
            continue
        covered = None if cover is None else (site in cover or p in cover)
        out.append({"at": _h(site), "op": "0x%02X" % op, "kind": kind, "disp": "0x%04X" % w,
                    "covered_by_decode": covered, "raw": True})
    return out


def block_writers(insns: dict[int, lh.Insn]) -> dict:
    """Decoded string moves / stores whose destination is DS:DI (not resolved here)."""
    hits = []
    for a, ins in sorted(insns.items()):
        if ins.op in (0xA4, 0xA5, 0xAA, 0xAB):
            hits.append({"at": _h(a), "text": ins.text()})
    return {"count": len(hits), "sites": hits[:50]}


def int3f_installs(data: bytes) -> list[dict]:
    out = []
    p = 0
    while True:
        p = data.find(INT3F_INSTALL_TAIL, p)
        if p < 0:
            break
        dx = None
        for q in range(p - 3, max(p - 16, 0), -1):
            if data[q] == 0xBA:
                dx = u16(data, q + 1)
                break
        out.append({"at": _h(p), "dx": ("0x%04X" % dx) if dx is not None else None,
                    "required_skew_to_dispatch": (DISPATCH - dx) % 16 if dx is not None else None})
        p += 1
    return out


def far_literal_sites(data: bytes, targets: dict[str, int]) -> list[dict]:
    """Raw 9A (call far ptr16:16) sites whose literal lands on a named file target under each model."""
    out = []
    for p in range(len(data) - 4):
        if data[p] != 0x9A:
            continue
        off = u16(data, p + 1)
        seg = u16(data, p + 3)
        for name, k in MODELS.items():
            t = seg * 16 + off + k
            for tname, tfile in targets.items():
                if t == tfile:
                    out.append({"at": _h(p), "seg": "0x%04X" % seg, "off": "0x%04X" % off,
                                "model": name, "target": tname, "file_target": _h(t), "raw": True})
    return out


def near_raw_sites(data: bytes, targets: dict[str, int]) -> list[dict]:
    """Raw E8/E9 (near call/jmp rel16) sites whose computed in-segment target is a named file target."""
    out = []
    for p in range(len(data) - 3):
        if data[p] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<h", data, p + 1)[0]
        t = p + 3 + rel
        for tname, tfile in targets.items():
            if t == tfile:
                out.append({"at": _h(p), "op": "0x%02X" % data[p], "target": tname,
                            "file_target": _h(t), "raw": True})
    return out


# ---- residue arithmetic ------------------------------------------------------------------------

def required_skew(off: int, target: int) -> int:
    """Skew residue k (mod 16) a seg:off pointer needs to reach file `target` (file = seg*16+off+k)."""
    return (target - off) % 16


def reaches_under(off: int, target: int, k: int) -> bool:
    return (off + k - target) % 16 == 0


def residue_table(points: list[tuple[str, int, str]]) -> list[dict]:
    """points: (label, file offset, kind). Each row gives the mod-16 residue of the file offset."""
    return [{"label": lab, "file": _h(f), "residue_mod16": f % 16, "kind": kind} for lab, f, kind in points]


# ---- routine A (the only static initializer of DS:[43F0]) --------------------------------------

def routine_a_facts(data: bytes, insns: dict[int, lh.Insn]) -> dict:
    w = lh.walk(data, ROUTINE_A_ENTRY)
    starts = [r["at"] for r in w["listing"]]
    dis = ds_discipline(data, insns, starts, before=ROUTINE_A_STORE_OFF)
    store = insns.get(ROUTINE_A_STORE_OFF)
    seg_store = insns.get(ROUTINE_A_STORE_SEG)
    alias = insns.get(ALIAS_8504_STORE)
    return {
        "walk_complete": w["complete"],
        "ds_before_store": dis,
        "ds_at_store_equals_entry_ds": dis["status"] in ("none", "bracketed"),
        "store_off": {"at": _h(ROUTINE_A_STORE_OFF), "text": store.text() if store else None,
                      "imm": ("0x%04X" % store.imm) if store and store.imm is not None else None,
                      "ok": bool(store and store.op == 0xC7 and store.direct == PTR_OFF
                                 and store.imm == ROUTINE_A_PTR_VALUE)},
        "store_seg": {"at": _h(ROUTINE_A_STORE_SEG), "text": seg_store.text() if seg_store else None,
                      "ok": bool(seg_store and seg_store.op == 0x8C and seg_store.direct == PTR_SEG
                                 and seg_store.modrm and seg_store.modrm[1] == 1)},
        "alias_8504": {"at": _h(ALIAS_8504_STORE), "text": alias.text() if alias else None,
                       "value_off": "0x%04X" % ALIAS_8504_VALUE,
                       "residue_of_value": ALIAS_8504_VALUE % 16,
                       "residue_of_routine_a_entry": ROUTINE_A_ENTRY % 16},
    }


# ---- top-level analysis ------------------------------------------------------------------------

def analyse(ovr: bytes, start: bytes) -> dict:
    mz = mz_facts(start)
    hdr = mz["hdr_bytes"]
    lo, hi = hdr, len(start)
    entry = mz["entry_file"]
    census = image_census(start, entry, lo, hi)
    insns = census["insns"]
    cover = census["cover"]
    chain = chain_facts(start, insns, DISPATCH, MOV_AX_IMM, MOV_DS_AX, CALLF_PTR, DS_LITERAL, PTR_OFF)
    body = chain.pop("_body")
    bypass_edges = edges_into(insns, body, MOV_AX_IMM + 1, CALLF_PTR)
    entry_edges = edges_into(insns, body, DISPATCH, DISPATCH)
    callee_roots = sorted({int(c["target"], 16) for c in chain["calls_between_ds_and_callf"]
                           if c["target"] is not None and c["flow"] == "call"})
    callees = callee_audit(start, callee_roots, lo, hi, insns)

    refs_start = direct_refs(insns, {PTR_OFF, PTR_SEG})
    refs_start_raw = raw_refs(start, {PTR_OFF, PTR_SEG}, cover)
    refs_ovr_raw = raw_refs(ovr, {PTR_OFF, PTR_SEG}, None)
    raw_uncovered_start = [r for r in refs_start_raw if not r["covered_by_decode"]]
    disp_bytes = {"F0 43 in START": start.count(b"\xF0\x43"), "F0 43 in GAME.OVR": ovr.count(b"\xF0\x43"),
                  "F2 43 in START": start.count(b"\xF2\x43"), "F2 43 in GAME.OVR": ovr.count(b"\xF2\x43")}

    ra = routine_a_facts(start, insns)
    ra["decoded_callers"] = edges_into(insns, set(), ROUTINE_A_ENTRY, ROUTINE_A_ENTRY)
    targets = {"dispatch": DISPATCH, "stub1": STUB1, "routine_a_entry": ROUTINE_A_ENTRY}
    far_hits = far_literal_sites(start, targets) + far_literal_sites(ovr, {"stub1": STUB1})
    near_hits = near_raw_sites(start, {"dispatch": DISPATCH, "routine_a_entry": ROUTINE_A_ENTRY,
                                       "stub1": STUB1})
    installs = int3f_installs(start)

    points = [
        ("stub1 (door writer/clearer stub)", STUB1, "target"),
        ("dispatcher entry (callf host)", DISPATCH, "target"),
        ("callf [43F0] site", CALLF_PTR, "site"),
        ("routine A entry (far, retf 4)", ROUTINE_A_ENTRY, "target"),
        ("pointer offset written by routine A (0x2E5)", ROUTINE_A_PTR_VALUE, "pointer-offset"),
        ("INT 3Fh DX, routine A (0x2E6)", ROUTINE_A_DX, "pointer-offset"),
        ("INT 3Fh DX, routine B (0xD7)", ROUTINE_B_DX, "pointer-offset"),
        ("alias offset stored at [8504] (0x268)", ALIAS_8504_VALUE, "pointer-offset"),
    ]
    residues = residue_table(points)
    skews = {
        "pointer_0x2E5_to_stub1": required_skew(ROUTINE_A_PTR_VALUE, STUB1),
        "dx_0x2E6_to_dispatch": required_skew(ROUTINE_A_DX, DISPATCH),
        "dx_0x0D7_to_dispatch": required_skew(ROUTINE_B_DX, DISPATCH),
        "alias_0x268_to_routine_a_entry": required_skew(ALIAS_8504_VALUE, ROUTINE_A_ENTRY),
    }
    model_reach = {
        "pointer_0x2E5_to_stub1": {n: reaches_under(ROUTINE_A_PTR_VALUE, STUB1, k) for n, k in MODELS.items()},
        "dx_0x2E6_to_dispatch": {n: reaches_under(ROUTINE_A_DX, DISPATCH, k) for n, k in MODELS.items()},
        "dx_0x0D7_to_dispatch": {n: reaches_under(ROUTINE_B_DX, DISPATCH, k) for n, k in MODELS.items()},
    }
    live_k = -LIVE_QUOTED_SHIFT
    live_quoted = {
        "shift_linear_minus_file": "0x%05X" % LIVE_QUOTED_SHIFT,
        "k_mod16": live_k % 16,
        "source": "docs/por-int3f-runtime-capture.md (X, not re-derived)",
        "pointer_0x2E5_reaches_stub1": reaches_under(ROUTINE_A_PTR_VALUE, STUB1, live_k),
        "dx_0x2E6_reaches_dispatch": reaches_under(ROUTINE_A_DX, DISPATCH, live_k),
        "dx_0x0D7_reaches_dispatch": reaches_under(ROUTINE_B_DX, DISPATCH, live_k),
        "pointer_0x2E5_file_target_if_cs_is_12C6": _h(0x12C6 * 16 + ROUTINE_A_PTR_VALUE - LIVE_QUOTED_SHIFT),
    }
    ds_lin_image = DS_LITERAL * 16 + PTR_OFF

    bw = block_writers(insns)
    verdict = verdict_for(chain, bypass_edges, entry_edges, callees, ra, far_hits, near_hits, skews,
                          model_reach, refs_start, bw, disp_bytes)
    verdict["live_quoted_shift_reaches_stub1"] = live_quoted["pointer_0x2E5_reaches_stub1"]
    verdict["live_quoted_shift_places_int3f_handler_a_on_dispatcher"] = live_quoted["dx_0x2E6_reaches_dispatch"]
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "tool": TOOL,
        "mz": {k: v for k, v in mz.items() if k != "relocs"} | {"relocs": mz["relocs"]},
        "mz_relocation_covers_mov_ax_immediate": reloc_covers(mz, MOV_AX_IMM + 1, hdr),
        "census": {
            "entry_file": _h(entry),
            "walks_closure": census["walks_closure"],
            "walks_sweep": census["walks_sweep"],
            "walks_complete": census["walks_complete"],
            "covered_bytes": census["covered_bytes"],
            "image_bytes": census["image_bytes"],
            "covered_fraction": round(census["covered_bytes"] / census["image_bytes"], 4),
        },
        "chain": chain,
        "bypass_edges_into_ax_ds_load_to_callf": bypass_edges,
        "decoded_or_raw_callers_of_dispatcher_entry": entry_edges,
        "callee_audit_between_ds_and_callf": callees,
        "routine_a": ra,
        "ds_43f0_refs_decoded": refs_start,
        "ds_43f0_refs_raw_start_uncovered": raw_uncovered_start,
        "ds_43f0_refs_raw_start_all": len(refs_start_raw),
        "ds_43f0_refs_raw_ovr_count": len(refs_ovr_raw),
        "ds_43f0_refs_raw_ovr": refs_ovr_raw[:200],
        "disp16_byte_pair_counts": disp_bytes,
        "block_writers_decoded": bw,
        "far_literal_sites_raw": far_hits,
        "near_literal_sites_raw": near_hits,
        "int3f_installs_raw": installs,
        "residue_table": residues,
        "required_skew": skews,
        "model_reach": model_reach,
        "live_quoted_shift": live_quoted,
        "doc_runtime_quoted": DOC_RUNTIME,
        "dispatcher_ds_literal_static": "0x%04X" % DS_LITERAL,
        "ds_literal_runtime_x": DOC_RUNTIME["ds_at_callf_live"],
        "ds_base_image_offset_static": _h(ds_lin_image),
        "ds_base_image_beyond_file_bytes": ds_lin_image >= len(start) - hdr,
        "verdict": verdict,
        "limits": LIMITS,
    }


LIMITS = [
    "Static bytes only. No emulator, no dump, no runtime value is re-derived; DOC_RUNTIME rows are quoted.",
    "The file-to-linear skew is not fixed by the bytes. Residue results hold for a uniform skew (one k for all "
    "START segments). A per-segment non-paragraph base would break them.",
    "DS:[43F0] writers are found by direct-address decode and by raw byte pattern; base-indexed or "
    "block-copy writes are counted but not resolved.",
    "The callf [43F0] DS is 0x0C7C on the decoded path. The callee closure is audited, but far and indirect "
    "callees inside it are not resolved.",
    "GAME.OVR is raw-scanned only; overlay DS is not known, so its hits are unlabelled.",
]


def verdict_for(chain, bypass, entry_edges, callees, ra, far_hits, near_hits, skews, model_reach, refs,
                bw, disp_bytes) -> dict:
    ax_on_every_path = bool(chain["mov_ax_imm"]["ok"] and chain["mov_ds_ax"]["ok"]
                            and not chain["branch_before_ds_load"])
    no_bypass = not bypass["near_or_jump"] and not bypass["far_literal"]
    no_entry = not entry_edges["near_or_jump"] and not entry_edges["far_literal"]
    ptr_writers = [r for r in refs if r["class"] == "write" and r["disp"] == "0x43F0"]
    stub_reach_named = {n: model_reach["pointer_0x2E5_to_stub1"][n] for n in MODELS}
    direct_path_ds = not chain["ds_writers_between_ds_and_callf"]
    return {
        "ax_set_by_callee_mov_on_every_path_from_dispatch": ax_on_every_path,
        "caller_must_establish_ax": False if ax_on_every_path else "unresolved",
        "decoded_or_raw_jump_into_ax_ds_load_bypassing_it": not no_bypass,
        "decoded_or_raw_caller_of_dispatcher_entry": not no_entry,
        "ds_at_callf_static_literal": "0x%04X" % DS_LITERAL if ax_on_every_path else None,
        "ds_preserved_on_direct_decoded_path": direct_path_ds,
        "ds_preserved_through_decoded_callee_closure": callees["free_of_open_edges"],
        "ds_callee_closure_open_edges": callees["open_edges"],
        "ds_at_callf_status": (
            "0x0C7C on the decoded direct path; callee closure has %d open edge(s), so DS after the callees "
            "is not established" % len(callees["open_edges"])
            if not callees["free_of_open_edges"] else "0x0C7C; callee closure free of open edges"),
        "ptr_static_initializers": [{
            "at": _h(ROUTINE_A_STORE_OFF), "value_off": "0x%04X" % ROUTINE_A_PTR_VALUE,
            "segment_source": "cs of routine A (not established)",
            "ds_of_store": ("routine A entry DS (bracketed push ds/pop ds; status %s)" %
                            ra["ds_before_store"]["status"]),
            "guard": "stored only if [43F0] and [43F2] are zero"}],
        "ptr_writers_decoded_count": len(ptr_writers),
        "ptr_writer_block_copies_unresolved": bw["count"],
        "disp16_byte_pair_counts": disp_bytes,
        "ptr_literal_far_pairs_to_stub1_static": [h for h in far_hits if h["target"] == "stub1"],
        "required_uniform_skew_routine_a_pointer_to_stub1": skews["pointer_0x2E5_to_stub1"],
        "named_models_reach_stub1_via_routine_a_pointer": stub_reach_named,
        "dispatcher_reached_by_named_int3f_dx": {
            "dx_0x2E6_needs_skew": skews["dx_0x2E6_to_dispatch"],
            "dx_0x0D7_needs_skew": skews["dx_0x0D7_to_dispatch"],
        },
        "alias_8504_candidate": {
            "value_off": "0x%04X" % ALIAS_8504_VALUE,
            "skew_to_routine_a_entry": skews["alias_0x268_to_routine_a_entry"],
            "note": "callf [8504] sits in the callee closure (0xAAC0); it reaches routine A only if "
                    "CS of routine A is 0x0A2C under skew 0 (not established)",
        },
        "trigger_established": False,
        "stub1_reached_by_this_route": (
            "not shown. The only static initializer's offset cannot reach stub 1 under M0 or M1 (it would need "
            "uniform skew residue %d mod 16). Still open: that skew residue itself, the callee-closure open "
            "edges, and block copies with unresolved destinations"
            % skews["pointer_0x2E5_to_stub1"]),
        "routine_a_caller_ds": "not established: no decoded or raw far literal reaches routine A under M0/M1; "
                               "its DS at the store is its entry DS, which is the caller's",
        "playable": False,
    }


# ---- pins and run ------------------------------------------------------------------------------

def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def probe(install: Path, out: Optional[Path] = None) -> dict:
    ovr, start, pins = dc.load_pinned(install)
    if out is not None and _inside(out, install):
        raise Refusal("output folder is inside the install folder; refusing")
    doc = analyse(ovr, start)
    doc["pins"] = pins
    ovr2 = (install / fr.OVR_NAME).read_bytes()
    start2 = (install / fr.EXE_NAME).read_bytes()
    doc["pins_rechecked"] = {"unchanged": ovr2 == ovr and start2 == start}
    if not doc["pins_rechecked"]["unchanged"]:
        raise Refusal("a pinned file changed during the run; refusing to write output")
    return doc


def _fmt_rows(rows: list[dict], keys: list[str]) -> list[str]:
    out = ["| " + " | ".join(keys) + " |", "|" + "|".join("---" for _ in keys) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(k, "")) for k in keys) + " |")
    return out


def render_report(doc: dict) -> str:
    v = doc["verdict"]
    ch = doc["chain"]
    lines = [
        "# PoR door route: DS of callf [0x43F0] (static, observe-only)",
        "",
        "Status: %s. `playable: false`. Trigger established: **%s**." % (doc["status"], v["trigger_established"]),
        "",
        "## Pins",
        "",
    ]
    for name, p in doc["pins"].items():
        lines.append("- `%s` size %d, sha256 `%s`, pin match %s" % (name, p["size"], p["sha256"], p["pin_match"]))
    lines += [
        "- re-hashed after the run: unchanged = %s" % doc["pins_rechecked"]["unchanged"],
        "",
        "## Chain (class D decoded)",
        "",
        "- `mov ax,0x0C7C` at %s: %s, ok=%s" % (ch["mov_ax_imm"]["at"], ch["mov_ax_imm"]["text"],
                                               ch["mov_ax_imm"]["ok"]),
        "- `mov ds,ax` at %s: %s, ok=%s" % (ch["mov_ds_ax"]["at"], ch["mov_ds_ax"]["text"], ch["mov_ds_ax"]["ok"]),
        "- `callf` at %s: %s, ok=%s" % (ch["callf"]["at"], ch["callf"]["text"], ch["callf"]["ok"]),
        "- branches before the DS load: %d" % len(ch["branch_before_ds_load"]),
        "- calls between DS load and callf: %s" % ", ".join("%s %s" % (c["at"], c["text"])
                                                          for c in ch["calls_between_ds_and_callf"]),
        "- DS writers between DS load and callf: %d" % len(ch["ds_writers_between_ds_and_callf"]),
        "- decoded edges into the AX/DS load bypassing it: near/jump %d, far literal %d" % (
            len(doc["bypass_edges_into_ax_ds_load_to_callf"]["near_or_jump"]),
            len(doc["bypass_edges_into_ax_ds_load_to_callf"]["far_literal"])),
        "",
        "## Callee closure between DS load and callf (class D)",
        "",
        "- functions: %d; open edges (far call, indirect call, unbalanced DS write, incomplete walk): %d" % (
            doc["callee_audit_between_ds_and_callf"]["count"],
            len(doc["callee_audit_between_ds_and_callf"]["open_edges"])),
    ]
    for e in doc["callee_audit_between_ds_and_callf"]["open_edges"]:
        lines.append("  - %s at %s in fn %s: %s" % (e["kind"], e.get("at", "-"), e["function"], e.get("text", "")))
    lines += [
        "- decoded or raw callers of the dispatcher entry: %s" % (
            "none" if not (doc["decoded_or_raw_callers_of_dispatcher_entry"]["near_or_jump"]
                           or doc["decoded_or_raw_callers_of_dispatcher_entry"]["far_literal"]) else "present"),
        "- block copies in decoded START (destination unresolved): %d" % doc["block_writers_decoded"]["count"],
        "- F0 43 / F2 43 byte pairs: %s" % ", ".join("%s = %d" % kv for kv in doc["disp16_byte_pair_counts"].items()),
        "- alias [8504] = CS:0x268, stored by routine A at %s; a callf through it, if in the closure, is listed "
        "above as an indirect edge. CS of routine A is not established." % _h(ALIAS_8504_STORE),
        "",
        "## Routine A (only static initializer of DS:[43F0], class D)",
        "",
        "- store `mov word [43F0],0x2E5` at %s, ok=%s" % (doc["routine_a"]["store_off"]["at"],
                                                          doc["routine_a"]["store_off"]["ok"]),
        "- store `mov [43F2],cs` at %s, ok=%s" % (doc["routine_a"]["store_seg"]["at"],
                                                  doc["routine_a"]["store_seg"]["ok"]),
        "- DS discipline before the store: %s (pushes %s, restores %s)" % (
            doc["routine_a"]["ds_before_store"]["status"],
            ", ".join(doc["routine_a"]["ds_before_store"]["pushes"]),
            ", ".join(doc["routine_a"]["ds_before_store"]["restores"])),
        "",
        "## Residues (mod 16) and required uniform skew",
        "",
    ]
    lines += _fmt_rows(doc["residue_table"], ["label", "file", "residue_mod16", "kind"])
    lines += [""]
    for k, val in doc["required_skew"].items():
        lines.append("- `%s`: needs skew residue %d" % (k, val))
    lv = doc["live_quoted_shift"]
    lines.append("- X, quoted live shift %s (k mod 16 = %d): pointer 0x2E5 reaches stub 1 = %s; INT 3Fh DX 0x2E6 "
                 "reaches the dispatcher = %s; pointer file target if CS is 12C6 = %s" % (
                     lv["shift_linear_minus_file"], lv["k_mod16"], lv["pointer_0x2E5_reaches_stub1"],
                     lv["dx_0x2E6_reaches_dispatch"], lv["pointer_0x2E5_file_target_if_cs_is_12C6"]))
    lines += ["", "## Verdict", ""]
    for k in ("trigger_established", "stub1_reached_by_this_route", "ax_set_by_callee_mov_on_every_path_from_dispatch",
              "ds_preserved_on_direct_decoded_path", "ds_preserved_through_decoded_callee_closure",
              "routine_a_caller_ds"):
        lines.append("- `%s`: %s" % (k, v[k]))
    lines += ["", "## Limits", ""]
    lines += ["- " + s for s in doc["limits"]]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_door_ds_entry_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    (out / "por_door_ds_entry_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL,
                    help="folder holding the pinned GAME.OVR and START.EXE (read-only)")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT, help="output folder under data/work")
    args = ap.parse_args(argv)
    try:
        doc = probe(args.install, args.out)
    except (dc.Refusal, Refusal, ValueError, OSError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    v = doc["verdict"]
    print("ds-entry probe: dispatch walk complete=%s, mov ax ok=%s, mov ds ok=%s, callf ok=%s" % (
        doc["chain"]["dispatch_walk_complete"], doc["chain"]["mov_ax_imm"]["ok"],
        doc["chain"]["mov_ds_ax"]["ok"], doc["chain"]["callf"]["ok"]))
    print("trigger_established=%s; required uniform skew for routine A pointer to stub1 = %d (mod 16)" % (
        v["trigger_established"], v["required_uniform_skew_routine_a_pointer_to_stub1"]))
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
