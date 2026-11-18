#!/usr/bin/env python3
"""Pool of Radiance: bounded census of decoded accesses to the DS regions used by GAME.OVR 0x32392.

Status: STATIC-CENSUS-ONLY. Read-only, stdlib plus the existing PoR decoders,
playable: false, mappings: [], events_emitted: 0.

Question. docs/por-wall-32392-trace-probe.md records a DS word table at 0x2722, five far pointers
at DS:0x5E3A..0x5E4D, a secondary far pointer at DS:0x4A20 and an output far pointer at DS:0x5E4E.
Which decoded instructions in the pinned GAME.OVR and START.EXE reference those addresses, and are
the references reads or writes? Which decoded procedures write them, and which decoded near-call
paths reach those writers from a stub root?

Regions (half-open, DS-relative):
  W  0x2722..0x272B  word table, five words (class index * 2)
  F  0x5E3A..0x5E49  far-pointer table, five far pointers (class index * 4); 0x5E4A..0x5E4D is F[4]
  S  0x4A20..0x4A23  secondary far pointer
  Q  0x5E4E..0x5E51  output far pointer
The extents are the trace probe's stated extents, not re-derived here.

Method (what the bytes are allowed to say):
  * Code is walked, not swept. GAME.OVR units are the VROOMM groups that
    tools/por_farcall_resolve.scan_all accepts (well-formed) or lists as partial; each unit's roots
    are its well-formed stub targets. START.EXE units are (a) the MZ entry point and (b) the
    copied-image continuation that the entry's trampoline transfers to. Each root is decoded by
    cp.explore (recursive descent). Near calls are followed only inside the unit's own range.
    Far calls (9A) and indirect calls are recorded and not followed.
  * START.EXE's entry copies its first CX bytes (CX read from the walked `mov cx,[0x0006]`) to a new
    segment, then `push ax; mov ax,imm; push ax; retf` transfers there. The continuation is walked
    only inside the copied bytes [0, CX). Its DS is START's own image segment (`push cs; pop ds`),
    which is not shown to equal the overlay DGROUP; START matches carry that caveat.
  * Each memory operand is classified from decoder fields: direct (mod 00 rm 110, or moffs A0..A3),
    indexed ([di|si|bx|...+disp], not BP-based), or stack (BP-based). The opcode gives the access
    role: read, write, rmw (read-modify-write), address (LEA), far (4-byte pointer read), or
    indirect (indirect call/jump operand).
  * A DS direct operand matches a region when its byte range overlaps it. A DS indexed operand matches
    when its displacement lies inside a region. The indexed match is a NECESSARY condition only; the
    base register is not evaluated. ES-prefixed operands match as "es-*" candidates, never as DS.
  * The surface a disp-based match cannot see is counted, not hidden: writes through register-only
    bases, and string stores (stos/movs), which address ES:DI.
  * Writers are procedures with a write or rmw match. A near-call BFS from each unit's roots reports
    the decoded path to each writer, or that none was found.
  * Far calls: every GAME.OVR far call in the walked code is recorded. Its seg word is checked against
    the unit's fixup table. A fixup-listed seg word is loader-patched and is not a usable literal target.

What it does NOT establish: that any procedure executes, that a stub or far call reaches it at runtime,
the contents of any DS or ES table (runtime data), that a far pointer names WALLDEF or 8X8D data, or
which record is selected. Table binding and runtime execution stay unestablished.

Usage
  python tools/por_wall_32392_table_census.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-32392-table-census/retail

Output (deterministic, path-free, sorted keys, no timestamps):
  OUT/por_wall_32392_table_census.json   schema openua.por-wall-32392-table-census

Exit codes
  0  every walked unit decoded without an incomplete instruction or byte conflict, and the START continuation was found
  1  output written; at least one decode incomplete, byte conflict, or START continuation not found
  2  named refusal: missing or unpinned input, or output folder outside data/ or inside the install
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_loadpieces_handler as h  # noqa: E402
import por_wall_callee_probe as cp  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

SCHEMA = "openua.por-wall-32392-table-census"
SCHEMA_VERSION = 1
STATUS = "static-census-only"
TOOL = "tools/por_wall_32392_table_census.py"
OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME
ENTRY = 0x32392
MAX_INSNS = cp.DEFAULT_MAX_INSNS
SEG_NAME = {0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds"}
MEM_RE = re.compile(r"\[(bx\+si|bx\+di|bp\+si|bp\+di|si|di|bp|bx)([+-]\d+)?\]")
DS_REGIONS = (
    {"id": "W", "label": "word table, five words (class index * 2)", "lo": 0x2722, "hi": 0x272C},
    {"id": "F", "label": "far-pointer table, five far pointers (class index * 4)", "lo": 0x5E3A, "hi": 0x5E4E},
    {"id": "S", "label": "secondary far pointer (pushed by 0x32392)", "lo": 0x4A20, "hi": 0x4A24},
    {"id": "Q", "label": "output far pointer (les by 0x32392)", "lo": 0x5E4E, "hi": 0x5E52},
)
WRITE_ROLES = ("write", "rmw")
STRING_STORE_OPS = (0xA4, 0xA5, 0xAA, 0xAB)      # movsb, movsw, stosb, stosw (ES:DI destination)
COPY_LEN_CODE = b"\x8b\x0e\x06\x00"              # mov cx,[0x0006] (START entry copy length)
TRAMPOLINE = (0x50, 0xB8, 0x50, 0xCB)            # push ax; mov ax,imm16; push ax; retf
LIMITS = [
    "Procedures are GAME.OVR group stub targets and START.EXE's entry and copied-image continuation, "
    "plus near-call closures inside the same unit.",
    "Far calls (9A) are recorded, not followed. A fixup-listed seg word is loader-patched; a seg word that is not fixup-listed is still only a file literal, not a verified target.",
    "Indirect calls are recorded, not followed.",
    "Indexed matches are necessary conditions only: the base register is not evaluated.",
    "Register-only (no displacement) writes and string stores are counted as an unseen writer surface, not classified by region.",
    "START.EXE's DS is its own image segment after the entry trampoline; START matches are not shown to share GAME.OVR's DGROUP.",
    "DS is taken as the program data segment for GAME.OVR units; DS reassignment sites are reported, not corrected.",
    "Every unit is bounded to its own span: instructions that end beyond it are dropped and counted as leaves; roots outside the span are recorded, not walked.",
    "Table contents are runtime data and are not in GAME.OVR or START.EXE; table binding is not established.",
    "Runtime execution, reachability from 0x32392's callers, and the record selected are not established.",
]


class CensusError(Exception):
    """A named refusal. The CLI prints it and exits with 2."""


# ---------------------------------------------------------------------------
# Operand and access classification (pure functions over decoded instructions)
# ---------------------------------------------------------------------------

def access_of(ins: h.Insn) -> Optional[dict]:
    """Role and width of the memory operand of one decoded instruction, or None.

    Role is read, write, rmw, address (LEA, width 0), far (4-byte pointer read), or
    indirect (indirect call or jump operand).
    """
    op = ins.op
    reg = ins.modrm[1] if ins.modrm else None
    if 0xA0 <= op <= 0xA3:
        return {"role": "read" if op in (0xA0, 0xA1) else "write", "width": 1 if op in (0xA0, 0xA2) else 2}
    if op < 0x40 and (op & 7) < 4:
        byte = (op & 1) == 0
        if (op & 7) >= 2:
            role = "read"
        else:
            role = "read" if (op >> 3) == 7 else "rmw"
        return {"role": role, "width": 1 if byte else 2}
    if op in (0x80, 0x81, 0x82, 0x83):
        return {"role": "read" if reg == 7 else "rmw", "width": 1 if op in (0x80, 0x82) else 2}
    if op in (0x84, 0x85):
        return {"role": "read", "width": 1 if op == 0x84 else 2}
    if op in (0x86, 0x87):
        return {"role": "rmw", "width": 1 if op == 0x86 else 2}
    if op in (0x88, 0x89):
        return {"role": "write", "width": 1 if op == 0x88 else 2}
    if op in (0x8A, 0x8B):
        return {"role": "read", "width": 1 if op == 0x8A else 2}
    if op == 0x8C:
        return {"role": "write", "width": 2}
    if op == 0x8D:
        return {"role": "address", "width": 0}
    if op == 0x8E:
        return {"role": "read", "width": 2}
    if op == 0x8F:
        return {"role": "write", "width": 2}
    if op in (0xC4, 0xC5):
        return {"role": "far", "width": 4}
    if op == 0xC6:
        return {"role": "write", "width": 1}
    if op in (0xC0, 0xD0, 0xD2):
        return {"role": "rmw", "width": 1}
    if op in (0xC1, 0xD1, 0xD3):
        return {"role": "rmw", "width": 2}
    if op in (0xF6, 0xF7):
        role = "rmw" if reg in (2, 3) else "read"
        return {"role": role, "width": 1 if op == 0xF6 else 2}
    if op == 0xFE:
        return {"role": "rmw", "width": 1}
    if op == 0xFF:
        if reg in (0, 1):
            return {"role": "rmw", "width": 2}
        if reg == 2 or reg == 4:
            return {"role": "indirect", "width": 2}
        if reg == 3 or reg == 5:
            return {"role": "far" if reg == 3 else "indirect", "width": 4}
        if reg == 6:
            return {"role": "read", "width": 2}
    return None


def _seg_prefix(ins: h.Insn) -> Optional[str]:
    for p in ins.prefixes:
        if p in SEG_NAME:
            return SEG_NAME[p]
    return None


def operand(ins: h.Insn) -> Optional[dict]:
    """Where the memory operand points, and its access. None when there is no memory operand."""
    acc = access_of(ins)
    if acc is None:
        return None
    seg = _seg_prefix(ins)
    if 0xA0 <= ins.op <= 0xA3 or ins.direct is not None:
        return {"space": "direct", "segment": seg or "ds", "address": ins.direct, **acc}
    if ins.bp_disp is not None:
        return {"space": "stack", "segment": seg or "ss", "disp": ins.bp_disp, **acc}
    if ins.modrm is None or ins.modrm[0] == 3 or not ins.mem:
        return None
    m = MEM_RE.fullmatch(ins.mem)
    if m is None:
        return None
    base = m.group(1)
    has_disp = m.group(2) is not None
    disp = int(m.group(2)) if has_disp else 0
    if base in ("bp", "bp+si", "bp+di"):
        return {"space": "stack", "segment": seg or "ss", "base": base, "disp": disp, **acc}
    return {"space": "indexed", "segment": seg or "ds", "base": base, "disp": disp,
            "has_disp": has_disp, **acc}


def region_matches(opnd: dict) -> list[dict]:
    """Region hits for one operand. DS hits are direct-overlap or indexed-disp-in-region; ES hits
    carry an es- prefix. Other segments never match."""
    seg = opnd["segment"]
    if seg not in ("ds", "es"):
        return []
    out = []
    width = max(opnd["width"], 1)
    for r in DS_REGIONS:
        kind = None
        if opnd["space"] == "direct":
            a = opnd["address"]
            if a < r["hi"] and r["lo"] < a + width:
                kind = "direct-overlap"
        elif opnd["space"] == "indexed" and opnd.get("has_disp"):
            if r["lo"] <= opnd["disp"] < r["hi"]:
                kind = "indexed-disp-in-region"
        if kind is not None:
            out.append({"region": r["id"], "match": kind if seg == "ds" else "es-" + kind})
    return out


def ds_reassign(ins: h.Insn) -> Optional[str]:
    """DS-changing instruction kind, or None. The DS = DGROUP assumption breaks after it."""
    if ins.op == 0x8E and ins.modrm and ins.modrm[1] == 3:
        return "mov-ds"
    if ins.op == 0xC5:
        return "lds"
    if ins.op == 0x1F:
        return "pop-ds"
    return None


def find_continuations(insns: list[h.Insn], copy_len: Optional[int]) -> list[dict]:
    """Trampolines `push ax; mov ax,imm16; push ax; retf` in the walked entry code.

    The continuation is image offset imm16. It is reported only when copy_len is known and imm16 lies
    inside the copied bytes [0, copy_len)."""
    out = []
    for i in range(len(insns) - 3):
        a, b, c, d = insns[i], insns[i + 1], insns[i + 2], insns[i + 3]
        if (a.raw[:1] == b"\x50" and b.op == 0xB8 and c.raw[:1] == b"\x50" and d.op == 0xCB
                and b.end == c.off and c.end == d.off):
            imm = b.imm
            out.append({"at": a.off, "imm": imm, "copy_len": copy_len,
                        "inside_copy": copy_len is not None and imm < copy_len})
    return out


# ---------------------------------------------------------------------------
# Walking and census
# ---------------------------------------------------------------------------

def walk_procs(data: bytes, roots: list[int], lo: int, hi: int) -> dict:
    """Decode each root in [lo, hi) by recursive descent. Near calls are followed while the target stays
    in [lo, hi). An instruction that ends beyond hi is dropped with the edges it carries; those drops
    are counted as leaves, not walked."""
    procs: dict[int, dict] = {}
    outside: list[dict] = []
    q: deque = deque(r for r in roots if lo <= r < hi)
    seen = set(q)
    while q:
        e = q.popleft()
        if e in procs:
            continue
        ex = cp.explore(data, e, MAX_INSNS)
        kept = [i for i in ex["_insns"] if i.end <= hi]
        leaves = [{"at": i.off, "text": i.text()} for i in ex["_insns"] if i.end > hi]
        keep_at = {i.off for i in kept}
        ex["_insns"] = kept
        ex["near_calls"] = [c for c in ex["near_calls"] if c["at"] in keep_at]
        ex["far_calls"] = [c for c in ex["far_calls"] if c["at"] in keep_at]
        ex["indirect"] = [c for c in ex["indirect"] if c["at"] in keep_at]
        ex["leaves"] = leaves
        procs[e] = ex
        for c in ex["near_calls"]:
            t = c["target"]
            if t is not None and lo <= t < hi:
                if t not in seen:
                    seen.add(t)
                    q.append(t)
            else:
                outside.append({"from": e, "at": c["at"], "target": t, "text": c["text"]})
    return {"procs": procs, "outside_near_calls": outside}


def _covered(procs: dict) -> tuple[list[list[int]], int, int]:
    spans = []
    owner: dict[int, int] = {}
    conflicts = 0
    for ex in procs.values():
        for ins in ex["_insns"]:
            spans.append((ins.off, ins.end))
            for b in range(ins.off, ins.end):
                prev = owner.get(b)
                if prev is not None and prev != ins.off:
                    conflicts += 1
                owner[b] = ins.off
    merged = cp._merge(spans)
    return merged, sum(b - a for a, b in merged), conflicts


def _unwalked(lo: int, hi: int, merged: list[list[int]]) -> list[list[int]]:
    out, cur = [], lo
    for a, b in merged:
        if a > cur:
            out.append([cur, min(a, hi)])
        cur = max(cur, b)
    if cur < hi:
        out.append([cur, hi])
    return [r for r in out if r[1] > r[0] and r[0] >= lo]


def _bfs_path(adj: dict, root: int, target: int) -> Optional[list[int]]:
    parent: dict = {root: None}
    q: deque = deque([root])
    while q:
        n = q.popleft()
        if n == target:
            path, cur = [], n
            while cur is not None:
                path.append(cur)
                cur = parent[cur]
            return list(reversed(path))
        for m in sorted(adj.get(n, ())):
            if m not in parent:
                parent[m] = n
                q.append(m)
    return None


def census_file(data: bytes, file_name: str, units: list[dict]) -> dict:
    """Walk each unit and collect accesses, writers, far calls, reassignments and the write surface.

    unit keys: label, lo, hi, roots, header_offset, status, fixups (set of body offsets or None).
    """
    accesses: list[dict] = []
    reassign: list[dict] = []
    far_calls: list[dict] = []
    indirect: list[dict] = []
    surface: list[dict] = []
    unit_rows: list[dict] = []
    all_procs: dict[int, dict] = {}
    proc_unit: dict[int, int] = {}
    adj: dict[int, set] = {}
    unit_roots: dict[int, list[int]] = {}

    for ui, u in enumerate(units):
        walk = walk_procs(data, u["roots"], u["lo"], u["hi"])
        procs = walk["procs"]
        merged, covered, conflicts = _covered(procs)
        incomplete = [dict(proc=e, **inc) for e in sorted(procs) for inc in procs[e]["incomplete"]]
        for e in sorted(procs):
            for c in procs[e]["near_calls"]:
                if c["target"] is not None and u["lo"] <= c["target"] < u["hi"]:
                    adj.setdefault(e, set()).add(c["target"])
        for e in procs:
            all_procs[e] = procs[e]
            proc_unit[e] = ui
        unit_roots[ui] = [r for r in u["roots"] if u["lo"] <= r < u["hi"]]
        code_bytes = u["hi"] - u["lo"]
        unw = _unwalked(u["lo"], u["hi"], merged)
        fix = u.get("fixups")
        fix_in_unwalked = 0
        if fix:
            fix_in_unwalked = sum(1 for w in fix if any(a <= u["lo"] + w < b for a, b in unw))
        unit_rows.append({
            "label": u["label"], "header_offset": u.get("header_offset"), "status": u.get("status"),
            "fileofs": u["lo"], "span_end": u["hi"], "codesz": code_bytes,
            "roots": u["roots"], "walked_procs": len(procs),
            "instructions": sum(len(ex["_insns"]) for ex in procs.values()),
            "covered_bytes": covered, "unwalked_bytes": code_bytes - covered,
            "unwalked_ranges": unw, "unwalked_fixup_words": fix_in_unwalked,
            "byte_conflicts": conflicts, "decode_incomplete": incomplete,
            "roots_outside_span": [r for r in u["roots"] if not (u["lo"] <= r < u["hi"])],
            "leaves_span": sum(len(procs[e]["leaves"]) for e in procs),
            "outside_unit_near_calls": len(walk["outside_near_calls"]),
        })
        for e in sorted(procs):
            ex = procs[e]
            for ins in ex["_insns"]:
                ra = ds_reassign(ins)
                if ra:
                    reassign.append({"file": file_name, "unit": ui, "proc": e, "at": ins.off,
                                     "kind": ra, "bytes": ins.raw.hex(), "text": ins.text()})
                if ins.op in STRING_STORE_OPS:
                    surface.append({"file": file_name, "unit": ui, "proc": e, "at": ins.off,
                                    "kind": "string-store", "bytes": ins.raw.hex(), "text": ins.text()})
                opnd = operand(ins)
                if opnd is None:
                    continue
                if opnd["role"] in WRITE_ROLES and opnd["space"] == "indexed" and not opnd.get("has_disp"):
                    surface.append({"file": file_name, "unit": ui, "proc": e, "at": ins.off,
                                    "kind": "register-only-write", "segment": opnd["segment"],
                                    "bytes": ins.raw.hex(), "text": ins.text(), "role": opnd["role"]})
                for hit in region_matches(opnd):
                    rec = {"file": file_name, "unit": ui, "unit_label": u["label"], "proc": e,
                           "at": ins.off, "bytes": ins.raw.hex(), "text": ins.text(),
                           "role": opnd["role"], "width": opnd["width"], "space": opnd["space"],
                           "segment": opnd["segment"], "region": hit["region"], "match": hit["match"]}
                    for k in ("address", "base", "disp"):
                        if k in opnd:
                            rec[k] = opnd[k]
                    accesses.append(rec)
            for fc in ex["far_calls"]:
                seg_at = fc["at"] + 3 - u["lo"]
                fixed = None if fix is None else (seg_at in fix)
                far_calls.append({"file": file_name, "unit": ui, "caller_proc": e, "at": fc["at"],
                                  "bytes": fc["bytes"], "text": fc["text"], "seg": fc["seg"],
                                  "off": fc["off"], "seg_word_fixup_listed": fixed})
            for ic in ex["indirect"]:
                indirect.append({"file": file_name, "unit": ui, "caller_proc": e, "at": ic["at"],
                                 "kind": ic["kind"], "bytes": ic["bytes"], "text": ic["text"]})

    # Immediates equal to a region address: the usual way a register is loaded with a table base.
    # Necessary-condition candidates only; the immediate is not shown to reach the base register.
    imm_hits: list[dict] = []
    for ui, u in enumerate(units):
        for e in sorted(all_procs):
            if proc_unit.get(e) != ui:
                continue
            for ins in all_procs[e]["_insns"]:
                if ins.imm is None:
                    continue
                for r in DS_REGIONS:
                    if r["lo"] <= ins.imm < r["hi"]:
                        imm_hits.append({"file": file_name, "unit": ui, "proc": e, "at": ins.off,
                                         "text": ins.text(), "imm": ins.imm, "region": r["id"]})
    imm_procs = {(h_["file"], h_["proc"]) for h_ in imm_hits}
    surface_with_imm = [a for a in surface if a["kind"] == "register-only-write"
                        and (file_name, a["proc"]) in imm_procs]

    # Pointer hand-off: procedures that touch a region and then call out. A callee may receive a
    # region address or a pointer derived from one. Not followed; listed as a false-negative channel.
    region_procs = []
    touched = {}
    for rec in accesses:
        touched.setdefault((rec["file"], rec["proc"], rec["unit"]), set()).add(rec["region"])
    for (fname, e, ui), regs in sorted(touched.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        ex = all_procs[e]
        region_procs.append({
            "file": fname, "unit": ui, "proc": e, "regions": sorted(regs),
            "near_call_targets": sorted({c["target"] for c in ex["near_calls"] if c["target"] is not None}),
            "far_call_literals": [{"at": c["at"], "seg": c["seg"], "off": c["off"]} for c in ex["far_calls"]],
            "indirect_calls": [{"at": c["at"], "kind": c["kind"]} for c in ex["indirect"]],
            "register_only_writes": sum(1 for a in surface if a["kind"] == "register-only-write"
                                        and a["proc"] == e and a["file"] == fname),
        })

    writes_by_proc: dict[int, set] = {}
    for rec in accesses:
        if rec["role"] in WRITE_ROLES:
            writes_by_proc.setdefault(rec["proc"], set()).add(rec["region"])

    writer_rows = []
    for w in sorted(writes_by_proc):
        ui = proc_unit[w]
        reach = []
        for r in unit_roots[ui]:
            if r in all_procs:
                path = _bfs_path(adj, r, w)
                if path is not None:
                    reach.append({"root": r, "path": path})
        writer_rows.append({
            "file": file_name, "unit": ui, "proc": w,
            "regions_written": sorted(writes_by_proc[w]),
            "writes": [{"at": a["at"], "text": a["text"], "region": a["region"], "match": a["match"],
                        "role": a["role"], "width": a["width"]}
                       for a in accesses if a["proc"] == w and a["role"] in WRITE_ROLES],
            "reached_from_roots": reach,
            "root_path_status": "root-path-found" if reach else "no-root-path-within-walk",
        })
    return {
        "units": unit_rows,
        "accesses": sorted(accesses, key=lambda a: (a["proc"], a["at"])),
        "writers": writer_rows,
        "ds_reassign_sites": sorted(reassign, key=lambda a: (a["proc"], a["at"])),
        "write_surface": sorted(surface, key=lambda a: (a["proc"], a["at"])),
        "region_immediates": imm_hits,
        "region_access_procs": region_procs,
        "write_surface_in_region_immediate_procs": surface_with_imm,
        "far_calls": sorted(far_calls, key=lambda a: (a["caller_proc"], a["at"])),
        "indirect_calls": sorted(indirect, key=lambda a: (a["caller_proc"], a["at"])),
        "walked_proc_entries": sorted(all_procs),
        "writes_by_proc": {str(k): sorted(v) for k, v in sorted(writes_by_proc.items())},
    }


# ---------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------

def _ovr_units(ovr: bytes, groups: list[dict]) -> list[dict]:
    units = []
    for g in groups:
        roots = [g["fileofs"] + g["procs"][k] for k in range(g["stub_count"]) if g["stub_valid"][k]]
        units.append({"label": "group-0x%04X" % g["header_offset"], "lo": g["fileofs"],
                      "hi": g["fileofs"] + g["codesz"], "roots": roots,
                      "header_offset": g["header_offset"], "status": g["status"],
                      "fixups": fr.fixup_table(ovr, g)})
    return units


def _start_units(exe: bytes, hdr: int, entry: int) -> tuple[list[dict], dict]:
    """Unit 0: the MZ entry. Unit 1: the copied-image continuation, bounded by the walked CX."""
    entry_unit = {"label": "start-entry", "lo": hdr, "hi": len(exe), "roots": [entry],
                  "header_offset": None, "status": "mz-entry", "fixups": None}
    first = census_file(exe, EXE_NAME, [entry_unit])
    insns = []
    for e in first["walked_proc_entries"]:
        insns.extend(cp.explore(exe, e, MAX_INSNS)["_insns"])
    insns.sort(key=lambda i: i.off)
    copy_len = None
    for ins in insns:
        if ins.raw == COPY_LEN_CODE:
            copy_len = int.from_bytes(exe[hdr + 6:hdr + 8], "little")
            break
    conts = find_continuations(insns, copy_len)
    units = [entry_unit]
    for c in conts:
        if c["inside_copy"]:
            units.append({"label": "start-continuation-0x%04X" % c["imm"], "lo": hdr, "hi": hdr + copy_len,
                          "roots": [hdr + c["imm"]], "header_offset": None, "status": "copied-image",
                          "fixups": None})
    meta = {"copy_len": copy_len, "continuations": conts, "entry_insns": len(insns)}
    return units, meta


def analyse(ovr: bytes, exe: bytes) -> dict:
    scan = fr.scan_all(exe, ovr)
    groups = scan["groups"] + scan["partial_groups"]
    ovr_doc = census_file(ovr, OVR_NAME, _ovr_units(ovr, groups))

    hdr = fr.mz_image_base(exe)
    e_ip = int.from_bytes(exe[0x14:0x16], "little")
    e_cs = int.from_bytes(exe[0x16:0x18], "little")
    start_entry = hdr + e_cs * 16 + e_ip
    start_units, start_meta = _start_units(exe, hdr, start_entry)
    exe_doc = census_file(exe, EXE_NAME, start_units)

    owner = None
    for g in groups:
        for k in range(g["stub_count"]):
            if g["stub_valid"][k] and g["fileofs"] + g["procs"][k] == ENTRY:
                owner = {"group_header": g["header_offset"], "stub_index": k,
                         "stub_start": g["stub_start"] + fr.STUB_LEN * k, "fileofs": g["fileofs"],
                         "codesz": g["codesz"], "fixupsz": g["fixupsz"], "status": g["status"]}

    all_access = ovr_doc["accesses"] + exe_doc["accesses"]
    ovr_writes = [w for w in ovr_doc["writers"]]
    exe_writes = [w for w in exe_doc["writers"]]
    fc = ovr_doc["far_calls"]
    diags = []
    if any(r["decode_incomplete"] for r in ovr_doc["units"] + exe_doc["units"]):
        diags.append("decode-incomplete")
    if any(r["byte_conflicts"] for r in ovr_doc["units"] + exe_doc["units"]):
        diags.append("byte-conflicts-between-procedures")
    if not start_meta["continuations"]:
        diags.append("start-continuation-not-found")

    n_writers = len(ovr_writes) + len(exe_writes)
    rooted = sum(1 for w in ovr_writes + exe_writes if w["reached_from_roots"])
    verdict = {
        "answer": "writers-found-in-walked-code" if n_writers else "no-disp-carrying-writes-in-walked-code",
        "access_records": len(all_access),
        "write_or_rmw_records": sum(1 for a in all_access if a["role"] in WRITE_ROLES),
        "writer_procedures": n_writers,
        "writer_procedures_with_root_path": rooted,
        "write_surface_records": len(ovr_doc["write_surface"]) + len(exe_doc["write_surface"]),
        "far_call_sites": len(fc),
        "far_call_seg_fixup_listed": sum(1 for r in fc if r["seg_word_fixup_listed"]),
        "far_call_seg_not_fixup_listed": sum(1 for r in fc if r["seg_word_fixup_listed"] is False),
        "ds_reassign_sites": len(ovr_doc["ds_reassign_sites"]) + len(exe_doc["ds_reassign_sites"]),
        "region_immediate_sites": len(ovr_doc["region_immediates"]) + len(exe_doc["region_immediates"]),
        "region_access_procs": len(ovr_doc["region_access_procs"]) + len(exe_doc["region_access_procs"]),
        "region_access_procs_with_far_calls": sum(
            1 for r in ovr_doc["region_access_procs"] + exe_doc["region_access_procs"] if r["far_call_literals"]),
        "write_surface_in_region_immediate_procs": (len(ovr_doc["write_surface_in_region_immediate_procs"])
                                                    + len(exe_doc["write_surface_in_region_immediate_procs"])),
        "table_binding": "not-established",
        "runtime_execution": "not-established",
        "selection_reached": "not-established",
    }
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "mappings": [],
        "events_emitted": 0,
        "subject": {"entry": ENTRY, "owner_stub": owner,
                    "owner_placement_basis": "START.EXE descriptor scan (fr.scan_all); bytes only, not runtime"},
        "regions": [dict(r, hi_inclusive=r["hi"] - 1) for r in DS_REGIONS],
        "scan": {"groups_well_formed": len(scan["groups"]), "groups_partial": len(scan["partial_groups"]),
                 "notes": scan["notes"]},
        "start": {"header_bytes": hdr, "entry": start_entry, "copy_len": start_meta["copy_len"],
                  "continuations": start_meta["continuations"], "bytes": len(exe),
                  "units": exe_doc["units"], "walked_procs": exe_doc["walked_proc_entries"],
                  "ds_model": "START image segment after push cs; pop ds (not shown equal to DGROUP)"},
        "gameovr": {"units": ovr_doc["units"], "walked_proc_count": len(ovr_doc["walked_proc_entries"])},
        "accesses": {"gameovr": ovr_doc["accesses"], "start": exe_doc["accesses"]},
        "writers": {"gameovr": ovr_writes, "start": exe_writes},
        "write_surface": ovr_doc["write_surface"] + exe_doc["write_surface"],
        "region_immediates": {"gameovr": ovr_doc["region_immediates"], "start": exe_doc["region_immediates"]},
        "region_access_procs": {"gameovr": ovr_doc["region_access_procs"],
                                "start": exe_doc["region_access_procs"]},
        "write_surface_in_region_immediate_procs": (ovr_doc["write_surface_in_region_immediate_procs"]
                                                    + exe_doc["write_surface_in_region_immediate_procs"]),
        "far_calls": {"summary": {"sites": len(fc),
                                  "seg_fixup_listed": verdict["far_call_seg_fixup_listed"],
                                  "seg_not_fixup_listed": verdict["far_call_seg_not_fixup_listed"]},
                      "sites": fc},
        "indirect_calls": ovr_doc["indirect_calls"] + exe_doc["indirect_calls"],
        "ds_reassign_sites": ovr_doc["ds_reassign_sites"] + exe_doc["ds_reassign_sites"],
        "verdict": verdict,
        "limits": LIMITS,
        "diagnostics": diags,
    }


def read_pinned(install: Path, name: str) -> bytes:
    cands = [install / name, install / "POOLRAD" / name]
    path = next((c for c in cands if c.is_file()), None)
    if path is None:
        raise CensusError("%s not found in %s or its POOLRAD folder" % (name, install))
    data = path.read_bytes()
    size, sha = fr.PINNED[name]
    if len(data) != size or fr._sha(data) != sha:
        raise CensusError("%s does not match its pin (size %d); refusing unpinned input" % (name, len(data)))
    return data


def probe(install: Path, out: Path) -> tuple[dict, int]:
    try:
        validate_output_dir(install, out)
    except PorSourceError as exc:
        raise CensusError(str(exc)) from exc
    ovr = read_pinned(install, OVR_NAME)
    exe = read_pinned(install, EXE_NAME)
    doc = analyse(ovr, exe)
    doc["source"] = {"files": [{"name": OVR_NAME, "bytes": len(ovr), "pin": "pinned", "sha256": fr._sha(ovr)},
                               {"name": EXE_NAME, "bytes": len(exe), "pin": "pinned", "sha256": fr._sha(exe)}]}
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_32392_table_census.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc, (0 if not doc["diagnostics"] else 1)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--install", required=True, type=Path)
    ap.add_argument("-o", "--out", required=True, type=Path)
    a = ap.parse_args(argv)
    try:
        doc, code = probe(a.install.resolve(), a.out.resolve())
    except CensusError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    v = doc["verdict"]
    print("0x%05X: accesses %d (write/rmw %d), writers %d (rooted %d), write surface %d, "
          "far sites %d (fixup-listed %d, not fixup-listed %d), DS reassign %d, diagnostics %s, answer %s"
          % (ENTRY, v["access_records"], v["write_or_rmw_records"], v["writer_procedures"],
             v["writer_procedures_with_root_path"], v["write_surface_records"], v["far_call_sites"],
             v["far_call_seg_fixup_listed"], v["far_call_seg_not_fixup_listed"], v["ds_reassign_sites"],
             doc["diagnostics"] or "none", v["answer"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
