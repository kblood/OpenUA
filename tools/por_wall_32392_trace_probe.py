#!/usr/bin/env python3
"""Pool of Radiance: static trace of the GAME.OVR routine at 0x32392 (conditional placement).

Status: STATIC-PROBE-ONLY. Read-only, stdlib plus the existing PoR decoders,
playable: false, mappings: [], events_emitted: 0.

Context. docs/por-wall-far-target-probe.md maps the far call 0428:002A (one of the
owner's eight unfollowed far calls) to GAME.OVR 0x32392 ONLY under the sibling
consensus delta 0x1866 and the stub-run hypothesis (START stub 0x42E3). That mapping
is conditional and is not a runtime target. This tool does not re-measure it. It
decodes the bytes at 0x32392 and reports what they establish, whatever placement is
assumed.

Question. Does the bounded closure from 0x32392 (recursive descent, near calls
followed to --max-depth) (a) perform DOS file I/O inline, (b) reference a
WALLDEF / 8X8D / DAX literal, (c) index or select a table or record, and if so, which
DS/ES table bases and which scale does it use? Does any local slot get read before
it is written on some path?

Method (what the bytes are allowed to say):
  * The closure is produced by tools/por_wall_callee_probe.py traverse(); its decode
    rules, AH inference and string-token checks are reused unchanged.
  * Memory operands are classified from the decoder's fields: stack ([bp+d]), DS
    direct, indexed ([di|si|bx+d]), and the ES segment override (0x26 prefix).
  * LES/LDS are recorded as far-pointer loads. An ES-prefixed MUL/IMUL on a memory
    operand is recorded as an ES-scaled multiply site, with the straight-line
    instructions that follow it.
  * Uninitialised-local check: for each negative BP slot of each closure procedure,
    a breadth-first walk over the decoded flow (fall-through, both arms of Jcc,
    unconditional JMP; calls fall through and are assumed not to write the caller's
    frame) finds READS of that slot reachable on a path with no earlier WRITE. A
    write is a store opcode (88/89/8C/8F/C6/C7) with the same BP displacement.
    Exact displacement only; no aliasing between slots of different sizes.
  * Far (9A) and indirect calls are recorded and not followed; their segment words
    are loader values and their placement is the conditional part.

What it does NOT establish: placement or reachability of 0x32392, the delta, the
contents of any DS/ES table (those bytes are runtime data, not in GAME.OVR), the
identity of any far-call target, or which WALLDEF/8X8D record is selected.

Usage
  python tools/por_wall_32392_trace_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-32392-trace-probe/retail

Output (deterministic, path-free, sorted keys, no timestamps):
  OUT/por_wall_32392_trace_probe.json   schema openua.por-wall-32392-trace-probe

Exit codes
  0  entry prologue present and the near closure complete
  1  output written; a diagnostic (prologue absent, or near closure incomplete)
  2  named refusal: missing or unpinned GAME.OVR (without --allow-unpinned), or the
     output folder is inside the install
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from pathlib import Path
from typing import Optional

import por_loadpieces_handler as h
import por_wall_callee_probe as cp
import por_wall_owner_probe as ow

SCHEMA = "openua.por-wall-32392-trace-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_wall_32392_trace_probe.py"
OVR_NAME = ow.OVR_NAME

ENTRY = 0x32392
PROLOGUE = bytes([0x55, 0x89, 0xE5])          # push bp; mov bp,sp

# Conditional placement, recorded and never measured here (see the far-target probe doc).
GROUP_BODY = 0x32235                          # group 0x42C2 body in GAME.OVR (stub-run model)
BODY_OFFSET = ENTRY - GROUP_BODY              # 0x15D if the body model holds
SIBLING_DELTA = 0x1866                        # sibling consensus delta (not measured for the owner)
STUB_START = 0x42E3                           # START stub slot for far call 0428:002A

STRIDE_CONST = 156                            # 0x9C: the 0x2EB08 stride, presence check only
STORE_OPS = (0x88, 0x89, 0x8C, 0x8F, 0xC6, 0xC7)
CALL_FLOWS = ("seq", "call", "call_far", "indirect_call", "indirect_callf")
SEG_RE = re.compile(r"\[(bx\+si|bx\+di|bp\+si|bp\+di|si|di|bp|bx)([+-]\d+)?\]")
POST_MUL_WINDOW = 6

LIMITS = [
    "Placement of 0x32392 (delta 0x1866, stub 0x42E3) is conditional and not measured here.",
    "Near-call targets are taken as GAME.OVR file offsets (same-code-space assumption).",
    "Far (9A) and indirect calls are recorded, not followed; their targets are unresolved here.",
    "DS/ES table contents are runtime data and are not in GAME.OVR; table identity is not established.",
    "Which WALLDEF or 8X8D record (if any) is selected is not established.",
    "Uninitialised-local reads assume calls do not write the caller's frame; no pointer into the frame is checked.",
    "The uninitialised-local walk is path-insensitive: it lists structurally possible paths, not value-feasible ones. "
    "Its path through 0x323F3 (jb) is listed although the key range it needs is already taken by earlier arms.",
]


class TraceProbeError(Exception):
    """A named refusal. The CLI prints it and exits with 2."""


def _seg_of(ins: h.Insn) -> str:
    return "es" if 0x26 in ins.prefixes else "ds"


def _mem_of(ins: h.Insn) -> Optional[dict]:
    """Classify a memory operand. Returns None for register-only instructions."""
    if ins.bp_disp is not None:
        return {"space": "stack-bp", "disp": ins.bp_disp, "segment": "ss"}
    if ins.direct is not None:
        return {"space": "direct", "address": ins.direct, "segment": _seg_of(ins)}
    if ins.mem:
        m = SEG_RE.fullmatch(ins.mem)
        if m and m.group(1) in ("di", "si", "bx", "bx+si", "bx+di"):
            disp = int(m.group(2)) if m.group(2) else 0
            return {"space": "indexed", "base": m.group(1), "disp": disp, "segment": _seg_of(ins)}
    return None


def _site(ins: h.Insn, mem: dict) -> dict:
    out = {"at": ins.off, "op": ins.name, "bytes": ins.raw.hex(), "text": ins.text(),
           "segment": mem["segment"], "space": mem["space"]}
    for k in ("base", "disp", "address"):
        if k in mem:
            out[k] = mem[k]
    return out


def _slot_role(ins: h.Insn, slot: int) -> Optional[str]:
    if ins.bp_disp != slot:
        return None
    if ins.op == 0x8D:
        return "address"
    if ins.op in STORE_OPS:
        return "write"
    return "read"


def _path(parent: dict, node) -> list[int]:
    out = []
    cur = node
    while cur is not None:
        out.append(cur[0])
        cur = parent[cur]
    return list(reversed(out))


def uninit_reads(insns: list[h.Insn], entry: int, slot: int) -> list[dict]:
    """Reads of BP slot ``slot`` reachable from ``entry`` on a path with no earlier write."""
    by_off = {i.off: i for i in insns}
    start = (entry, False)
    parent: dict = {start: None}
    q: deque = deque([start])
    reads: dict[int, list[int]] = {}
    while q:
        node = q.popleft()
        addr, written = node
        ins = by_off.get(addr)
        if ins is None:
            continue
        role = _slot_role(ins, slot)
        if role == "read" and not written and addr not in reads:
            reads[addr] = _path(parent, node)
        nw = written or role == "write"
        if ins.flow in CALL_FLOWS:
            succs = [ins.end]
        elif ins.flow == "jcc" and ins.target is not None:
            succs = [ins.end, ins.target]
        elif ins.flow == "jmp" and ins.target is not None:
            succs = [ins.target]
        else:
            succs = []
        for s in succs:
            n2 = (s, nw)
            if n2 not in parent:
                parent[n2] = node
                q.append(n2)
    return [{"at": a, "path": reads[a]} for a in sorted(reads)]


def _post_mul(insns: list[h.Insn], idx: int) -> list[str]:
    return [i.text() for i in insns[idx + 1: idx + 1 + POST_MUL_WINDOW]]


def _scan_proc(data: bytes, entry: int, depth: int) -> dict:
    ex = cp.explore(data, entry, cp.DEFAULT_MAX_INSNS)
    insns = ex["_insns"]
    far_loads, indexed, es_mul, ds_direct, cmp_imm, imm156, slots = [], [], [], [], [], [], {}
    for idx, ins in enumerate(insns):
        if ins.bp_disp is not None and ins.bp_disp < 0:
            slots.setdefault(ins.bp_disp, {"writes": 0, "reads": 0, "address_taken": 0})
            role = _slot_role(ins, ins.bp_disp)
            key = {"write": "writes", "read": "reads", "address": "address_taken"}.get(role)
            if key:
                slots[ins.bp_disp][key] += 1
        mem = _mem_of(ins)
        if ins.op in (0xC4, 0xC5) and mem is not None:
            far_loads.append(_site(ins, mem))
        elif mem is not None and mem["space"] == "indexed":
            indexed.append(_site(ins, mem))
        if ins.op in (0xF6, 0xF7) and mem is not None and ins.modrm and ins.modrm[1] in (4, 5) \
                and _seg_of(ins) == "es":
            rec = _site(ins, mem)
            rec["post_mul_window"] = _post_mul(insns, idx)
            es_mul.append(rec)
        if mem is not None and mem["space"] == "direct" and _seg_of(ins) == "ds":
            ds_direct.append(_site(ins, mem))
        if ins.name == "cmp" and ins.imm is not None:
            cmp_imm.append({"at": ins.off, "imm": ins.imm, "text": ins.text()})
        if ins.imm == STRIDE_CONST:
            imm156.append({"at": ins.off, "bytes": ins.raw.hex(), "text": ins.text()})
    uninit = []
    for slot in sorted(slots):
        reads = uninit_reads(insns, entry, slot)
        if reads:
            uninit.append({"proc": entry, "slot_bp": slot, "reads": reads})
    return {
        "entry": entry, "depth": depth, "far_loads": far_loads, "indexed_accesses": indexed,
        "es_scaled_mul": es_mul, "ds_direct_accesses": ds_direct, "cmp_immediates": cmp_imm,
        "imm_156_sites": imm156, "bp_local_slots": {str(k): v for k, v in sorted(slots.items())},
        "uninit_local_reads": uninit,
    }


def analyse(data: bytes, entry: int = ENTRY) -> dict:
    """Trace the bounded closure from ``entry`` and report its access structure."""
    prologue_ok = data[entry:entry + 3] == PROLOGUE
    tr = cp.traverse(data, entry, cp.DEFAULT_MAX_DEPTH, cp.DEFAULT_MAX_PROCS, cp.DEFAULT_MAX_INSNS)
    v = tr["verdict"]
    scans = [_scan_proc(data, p["entry"], p["depth"]) for p in tr["procs"]]
    procs = []
    for p in tr["procs"]:
        procs.append({k: val for k, val in p.items() if not k.startswith("in_observed")})
    far_calls = [dict(proc=p["entry"], **f) for p in tr["procs"] for f in p["far_calls"]]
    int_sites = [dict(proc=p["entry"], **s) for p in tr["procs"] for s in p["ints"]]
    near_closure_complete = bool(v["closure_complete"])

    far_loads = [dict(proc=s["entry"], **x) for s in scans for x in s["far_loads"]]
    indexed = [dict(proc=s["entry"], **x) for s in scans for x in s["indexed_accesses"]]
    es_mul = [dict(proc=s["entry"], **x) for s in scans for x in s["es_scaled_mul"]]
    ds_direct = [dict(proc=s["entry"], **x) for s in scans for x in s["ds_direct_accesses"]]
    cmp_imm = [dict(proc=s["entry"], **x) for s in scans for x in s["cmp_immediates"]]
    imm156 = [dict(proc=s["entry"], **x) for s in scans for x in s["imm_156_sites"]]
    uninit = [u for s in scans for u in s["uninit_local_reads"]]

    far_table_loads = [x for x in far_loads if x["space"] in ("indexed", "direct")]
    shape_observed = bool(far_table_loads and es_mul)
    if not prologue_ok:
        answer = "entry-prologue-absent"
    elif shape_observed:
        answer = "far-table-record-index-observed; wall-binding-not-established"
    else:
        answer = "no-far-table-record-index-observed"

    diags = []
    if not prologue_ok:
        diags.append("entry-prologue-absent")
    if not near_closure_complete:
        diags.append("closure-near-incomplete")

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "mappings": [],
        "events_emitted": 0,
        "placement": {
            "status": "conditional-not-measured",
            "owner_delta_measured": False,
            "sibling_delta_assumed": SIBLING_DELTA,
            "stub_start": STUB_START,
            "group_body_offset": GROUP_BODY,
            "entry_body_offset": BODY_OFFSET,
            "basis": "docs/por-wall-far-target-probe.md (sibling consensus 0x1866, stub-run model); not re-measured",
            "dependence": [
                "0x32392 executes only if far call 0428:002A resolves through stub 0x42E3 under delta 0x1866",
                "near-call targets inside the closure are file offsets only under the body-at-file model",
                "all statements below are about the bytes at GAME.OVR 0x32392, not about execution",
            ],
        },
        "entry": {"offset": entry, "bytes": data[entry:entry + 8].hex(), "prologue_ok": prologue_ok},
        "closure": {
            "procs": procs,
            "procs_explored": len(procs),
            "instructions_decoded": v["instructions_decoded"],
            "near_closure_complete": near_closure_complete,
            "frontier_count": v["frontier_count"],
            "far_calls_not_followed": far_calls,
            "indirect_calls_not_followed": [dict(proc=p["entry"], **x) for p in tr["procs"] for x in p["indirect"]],
            "int_sites": int_sites,
            "dos_file_function_hits": v["dos_file_function_hits"],
            "int21_ah_unknown": v["int21_ah_unknown"],
            "string_token_candidates": v["string_token_candidates"],
            "string_token_file_offsets": tr["string_tokens"]["file_offsets"],
        },
        "access": {
            "far_pointer_loads": far_loads,
            "indexed_accesses": indexed,
            "es_scaled_multiplies": es_mul,
            "ds_direct_accesses": ds_direct,
            "compare_immediates": cmp_imm,
            "stride_constant_156_sites": imm156,
            "stride_constant": STRIDE_CONST,
        },
        "uninit_local_reads": uninit,
        "verdict": {
            "answer": answer,
            "far_table_load_sites": len(far_table_loads),
            "es_scaled_multiply_sites": len(es_mul),
            "dos_file_io_inline": len(v["dos_file_function_hits"]),
            "far_calls_unfollowed": len(far_calls),
            "wall_8x8d_dax_literal_refs": len(v["string_token_candidates"]),
            "stride_constant_156_sites": len(imm156),
            "uninit_local_read_sites": sum(len(u["reads"]) for u in uninit),
            "wall_binding": "not-established",
            "selection_reached": "not-established",
        },
        "limits": LIMITS,
        "diagnostics": diags,
    }


def probe(install: Path, out: Path, allow_unpinned: bool = False, entry: int = ENTRY) -> tuple[dict, int]:
    try:
        data, sha, pinned = ow.read_pinned_ovr(install, allow_unpinned)
    except ow.OwnerProbeError as exc:
        raise TraceProbeError(str(exc)) from exc
    doc = analyse(data, entry)
    doc["source"] = {"file": OVR_NAME, "bytes": len(data), "sha256": sha,
                     "pin": "pinned" if pinned else "unpinned"}
    if not pinned:
        doc["diagnostics"].append("unpinned-source")
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_32392_trace_probe.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc, (0 if not doc["diagnostics"] else 1)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--install", required=True, type=Path)
    ap.add_argument("-o", "--out", required=True, type=Path)
    ap.add_argument("--allow-unpinned", action="store_true")
    a = ap.parse_args(argv)
    try:
        install = a.install.resolve()
        out = a.out.resolve()
        if install == out or install in out.parents:
            raise TraceProbeError("output folder must not be inside the install")
        doc, code = probe(install, out, a.allow_unpinned)
    except TraceProbeError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    v = doc["verdict"]
    print("0x%05X: %d procs, %d insns, near-complete %s, far-unfollowed %d, DOS-IO %d, "
          "far-table loads %d, ES-scaled mul %d, uninit-read sites %d, tokens %d, answer %s, pin %s"
          % (ENTRY, doc["closure"]["procs_explored"], doc["closure"]["instructions_decoded"],
             doc["closure"]["near_closure_complete"], v["far_calls_unfollowed"], v["dos_file_io_inline"],
             v["far_table_load_sites"], v["es_scaled_multiply_sites"],
             sum(len(u["reads"]) for u in doc["uninit_local_reads"]), v["wall_8x8d_dax_literal_refs"],
             v["answer"], doc["source"]["pin"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
