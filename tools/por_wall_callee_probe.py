#!/usr/bin/env python3
"""Pool of Radiance: bounded call-edge probe from the GAME.OVR routine at 0x2EEF4.

Status: STATIC-PROBE-ONLY. Read-only, stdlib plus the existing PoR decoder,
playable: false, mappings: [], events_emitted: 0.

Question: starting from the layout-unique owner at GAME.OVR 0x2EEF4 (which ends
at the WALLDEF length byte 0x2F6AB), do the six direct near-call callees, and
the routines they reach by bounded direct near-call edges, perform a DOS file
function (INT 21h AH=3Ch create, 3Dh open, 3Eh close, 3Fh read, 40h write,
41h delete, 42h seek, 4Eh/4Fh find), touch a WALLDEF/8X8D/DAX string under the
stated literal models, or use a plausible record-index or stride selector?

Method (what the bytes are allowed to say):
  * Each procedure is decoded by recursive descent: fall-through, both arms of
    every conditional branch, and unconditional jumps are followed inside the
    procedure. A near CALL is recorded and its target is queued as a new
    procedure, but only while the call depth is within --max-depth. Far calls
    (9A) and indirect calls (FF /2, /3) are recorded and NOT followed: a far
    segment word is a loader value and no segment base is known here.
  * INT 21h AH is inferred only from a straight-line window: the nearest
    preceding MOV AH,imm8 or MOV AX,imm16 reached through instructions that do
    not write AX/AH (push, flag-only compare/test, memory-destination MOV that
    does not write a register). The window stops at any branch target and at
    any other writer. This is not dataflow; the result says which rule fired.
  * Stride / selector candidates are immediates and operations that could
    scale or index a record (IMUL with immediate, shifts, MUL/DIV). Presence is
    reported. No candidate is tied to an address or a WALLDEF record.
  * String tokens are located in the whole GAME.OVR. Two necessary-condition
    checks are reported: a branch target equal to a token's file offset, and an
    immediate, direct or far-offset operand equal to a token's low 16 bits. A
    match is a candidate only; the probe does not bind it.

It does not decode 0F-prefixed opcodes (they stop the walk and mark the
procedure incomplete), does not resolve far or indirect callees, and does not
establish runtime reachability or the caller of 0x2EEF4. Group 29 is named only
as the observed-load span (a runtime quote, not retail), labelled as hypothesis.

Usage
  python tools/por_wall_callee_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-callee-probe/retail

Output (deterministic, path-free, sorted keys, no timestamps):
  OUT/por_wall_callee_probe.json   schema openua.por-wall-callee-probe

Exit codes
  0  bounded closure complete, no diagnostic
  1  output written; closure incomplete, or a cross-check failed
  2  named refusal: missing or unpinned GAME.OVR (without --allow-unpinned),
     or output folder inside the install
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
import por_wall_owner_probe as ow

SCHEMA = "openua.por-wall-callee-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_wall_callee_probe.py"
OVR_NAME = ow.OVR_NAME
OWNER = ow.OWNER
LITERAL = ow.LITERAL

# The six owner callees (decoded from the owner's 39 near calls; checked in probe()).
EXPECTED_SEEDS = (0x2E8F7, 0x2EA6B, 0x2EB08, 0x2EC16, 0x2ED72, 0x2EEEA)

# Observed group-29 load (runtime quote, not retail). Labelled hypothesis wherever used.
GROUP29_SPAN = (0x2E8F7, 0x2E8F7 + 0x120B)

DOS_FILE_FUNCS = {
    0x3C: "create", 0x3D: "open", 0x3E: "close", 0x3F: "read", 0x40: "write",
    0x41: "delete", 0x42: "seek", 0x4E: "find-first", 0x4F: "find-next",
}
STRING_TOKENS = ("WALLDEF", "8X8D", "DAX")

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PROCS = 40
DEFAULT_MAX_INSNS = 1200
AH_LOOKBACK = 4

# Opcodes that never write AX or AH (used only inside the AH lookback window).
_PUSH_OPS = (0x06, 0x0E, 0x16, 0x1E) + tuple(range(0x50, 0x58))
_FLAGS_ONLY_OPS = (0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x84, 0x85, 0xA8, 0xA9)
_MOV_OTHER_REG8 = (0xB1, 0xB2, 0xB3, 0xB5, 0xB6, 0xB7)
_MOV_OTHER_REG16 = tuple(range(0xB9, 0xC0))


class CalleeProbeError(Exception):
    """A named refusal. The CLI prints it and exits with 2."""


def _neutral_before_int(i: h.Insn) -> bool:
    if i.op in _PUSH_OPS or i.op in _FLAGS_ONLY_OPS:
        return True
    if i.op in _MOV_OTHER_REG8 or i.op in _MOV_OTHER_REG16:
        return True
    if i.op in (0x88, 0x89) and i.modrm is not None and i.modrm[0] != 3:
        return True  # store to memory: writes no register
    return False


def _ah_before(at: int, by_end: dict, branch_targets: set) -> dict:
    """Straight-line AH inference for an INT at ``at``. See module docstring."""
    if at in branch_targets:
        return {"value": None, "reason": "int-is-branch-target", "source": None, "chain": []}
    cur = at
    chain: list[int] = []
    for _ in range(AH_LOOKBACK):
        pred = by_end.get(cur)
        if pred is None:
            return {"value": None, "reason": "no-straight-line-predecessor", "source": None, "chain": chain}
        chain.append(pred.off)
        if pred.op == 0xB4:  # MOV AH, imm8
            return {"value": pred.imm, "reason": "mov-ah-imm8", "source": pred.off, "chain": chain}
        if pred.op == 0xB8:  # MOV AX, imm16
            return {"value": (pred.imm >> 8) & 0xFF, "reason": "mov-ax-imm16", "source": pred.off, "chain": chain}
        if not _neutral_before_int(pred):
            return {"value": None, "reason": "intervening-unknown-writer", "source": None, "chain": chain,
                    "writer_text": pred.text()}
        if pred.off in branch_targets:
            return {"value": None, "reason": "join-point-before-int", "source": None, "chain": chain}
        cur = pred.off
    return {"value": None, "reason": "lookback-exhausted", "source": None, "chain": chain}


def _mov_imm_before(at: int, by_end: dict, branch_targets: set, mov_op: int) -> dict:
    """Straight-line value of the nearest preceding ``mov reg,imm`` (opcode ``mov_op``) that
    loads the register an operand names. Same window rules as _ah_before: stops at a branch
    target, at any other writer, or after AH_LOOKBACK predecessors."""
    if at in branch_targets:
        return {"value": None, "reason": "operand-is-branch-target", "source": None}
    cur = at
    for _ in range(AH_LOOKBACK):
        pred = by_end.get(cur)
        if pred is None:
            return {"value": None, "reason": "no-straight-line-predecessor", "source": None}
        if pred.op == mov_op:
            return {"value": pred.imm, "reason": "mov-imm-before-operand", "source": pred.off}
        if not _neutral_before_int(pred) or pred.op in (0xB8, 0xB0, 0xB4):
            return {"value": None, "reason": "intervening-unknown-writer", "source": None,
                    "writer_text": pred.text()}
        if pred.off in branch_targets:
            return {"value": None, "reason": "join-point-before-operand", "source": None}
        cur = pred.off
    return {"value": None, "reason": "lookback-exhausted", "source": None}


def explore(data: bytes, entry: int, max_insns: int) -> dict:
    """Recursive-descent decode of one procedure. Calls are recorded, not entered."""
    insns: dict[int, h.Insn] = {}
    owner_of: dict[int, int] = {}
    conflicts: list[dict] = []
    incomplete: list[dict] = []
    branch_targets: set[int] = set()
    work = [entry]
    while work:
        a = work.pop()
        if a in insns:
            continue
        if not (0 <= a < len(data)):
            incomplete.append({"code": "target-out-of-file", "at": a})
            continue
        if len(insns) >= max_insns:
            incomplete.append({"code": "insn-budget", "at": a})
            break
        try:
            ins = h.decode(data, a)
        except h.DecodeError as exc:
            incomplete.append({"code": exc.reason, "at": a})
            continue
        for b in range(ins.off, ins.end):
            prev = owner_of.get(b)
            if prev is not None and prev != ins.off:
                conflicts.append({"at": a, "overlaps": prev})
            owner_of[b] = ins.off
        insns[a] = ins
        f = ins.flow
        if f in ("seq", "call", "call_far", "indirect_call", "indirect_callf"):
            work.append(ins.end)
        elif f == "jcc" and ins.target is not None:
            work.append(ins.end)
            work.append(ins.target)
            branch_targets.add(ins.target)
        elif f == "jmp" and ins.target is not None:
            work.append(ins.target)
            branch_targets.add(ins.target)
        elif f in ("ret", "retf"):
            pass
        else:
            incomplete.append({"code": "flow-" + f, "at": a})

    ordered = [insns[k] for k in sorted(insns)]
    by_end = {i.end: i for i in ordered}

    near, far, indirect, ints, selectors, tokens = [], [], [], [], [], []
    direct: set[int] = set()
    for i in ordered:
        raw = i.raw.hex()
        if i.flow == "call":
            near.append({"at": i.off, "target": i.target, "bytes": raw, "text": i.text()})
        elif i.flow == "call_far":
            far.append({"at": i.off, "seg": i.far[0], "off": i.far[1], "bytes": raw, "text": i.text()})
        elif i.flow.startswith("indirect"):
            indirect.append({"at": i.off, "kind": i.flow, "bytes": raw, "text": i.text()})
        if i.op == 0xCD:
            ints.append({"at": i.off, "vector": i.imm, "bytes": raw,
                         "ah": _ah_before(i.off, by_end, branch_targets)})
        if i.op in (0x69, 0x6B):
            selectors.append({"at": i.off, "kind": "imul-imm", "imm": i.imm, "bytes": raw, "text": i.text()})
        elif i.op in (0xC0, 0xC1):
            selectors.append({"at": i.off, "kind": "shift-imm", "op": i.name, "imm": i.imm,
                              "bytes": raw, "text": i.text()})
        elif i.op in (0xD0, 0xD1, 0xD2, 0xD3):
            count = ({"value": 1, "reason": "implicit-count-1", "source": None} if i.op in (0xD0, 0xD1)
                     else _mov_imm_before(i.off, by_end, branch_targets, 0xB1))
            selectors.append({"at": i.off, "kind": "shift-1-or-cl", "op": i.name, "imm": None,
                              "count": count, "bytes": raw, "text": i.text()})
        elif i.op in (0xF6, 0xF7) and i.modrm is not None and i.modrm[1] in (4, 5, 6, 7):
            # Register operand: the straight-line mov into that register. Memory operand: none.
            operand = None
            if i.modrm[0] == 3:
                base = 0xB8 if i.op == 0xF7 else 0xB0
                operand = _mov_imm_before(i.off, by_end, branch_targets, base + i.modrm[2])
            selectors.append({"at": i.off, "kind": "mul-div", "op": i.name, "imm": None,
                              "operand": operand, "bytes": raw, "text": i.text()})
        if i.direct is not None:
            direct.add(i.direct)
    return {
        "entry": entry,
        "entry_bytes": data[entry:entry + 8].hex(),
        "instruction_count": len(ordered),
        "coverage_bytes": sum(i.length for i in ordered),
        "ranges": _merge([(i.off, i.end) for i in ordered]),
        "complete": not incomplete and not conflicts,
        "incomplete": incomplete,
        "overlap_conflicts": conflicts,
        "branch_targets": sorted(branch_targets),
        "near_calls": near,
        "far_calls": far,
        "indirect": indirect,
        "ints": ints,
        "direct_refs": sorted(direct),
        "selector_candidates": selectors,
        "_insns": ordered,  # internal; stripped before output
    }


def _merge(spans: list[tuple[int, int]]) -> list[list[int]]:
    out: list[list[int]] = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def _string_tokens(data: bytes) -> dict:
    """File offsets of each token (whole file), with its low 16 bits."""
    upper = data.upper()
    by_off: dict[int, str] = {}
    for tok in STRING_TOKENS:
        for m in re.finditer(re.escape(tok.encode("ascii")), upper):
            by_off[m.start()] = tok
    low16 = {}
    for off, tok in by_off.items():
        low16.setdefault(off & 0xFFFF, tok)
    return {"file_offsets": {"0x%05X" % k: v for k, v in sorted(by_off.items())},
            "_by_off": by_off, "_low16": low16}


def _proc_out(ex: dict, depth: int, tokens: dict) -> dict:
    by_off, low16 = tokens["_by_off"], tokens["_low16"]
    hits = []
    for i in ex["_insns"]:
        raw = i.raw.hex()
        if i.op != 0xCD:
            for label, val in (("imm", i.imm), ("direct", i.direct),
                               ("far-offset", i.far[1] if i.far else None)):
                if val is not None and val in low16:
                    hits.append({"at": i.off, "operand": label, "value": val, "model": "low16-segment-offset",
                                 "token": low16[val], "bytes": raw, "text": i.text()})
        if i.target is not None and i.target in by_off:
            hits.append({"at": i.off, "operand": "target", "value": i.target, "model": "file-offset",
                         "token": by_off[i.target], "bytes": raw, "text": i.text()})
    out = {k: v for k, v in ex.items() if not k.startswith("_")}
    out["depth"] = depth
    out["in_observed_group29_span_hypothesis"] = GROUP29_SPAN[0] <= ex["entry"] < GROUP29_SPAN[1]
    out["string_token_candidates"] = hits
    return out


def traverse(data: bytes, root: int, max_depth: int, max_procs: int, max_insns: int) -> dict:
    tokens = _string_tokens(data)
    procs: dict[int, dict] = {}
    edges: list[dict] = []
    frontier: list[dict] = []
    truncated = False
    queued = {root}
    q: deque = deque([(root, 0)])
    while q:
        entry, depth = q.popleft()
        if entry in procs:
            continue
        if len(procs) >= max_procs:
            truncated = True
            frontier.append({"entry": entry, "depth": depth, "reason": "proc-budget"})
            continue
        ex = explore(data, entry, max_insns)
        procs[entry] = {"depth": depth, "ex": ex}
        for c in ex["near_calls"]:
            t = c["target"]
            in_file = t is not None and 0 <= t < len(data)
            edges.append({"from": entry, "at": c["at"], "to": t, "callee_depth": depth + 1,
                          "bytes": c["bytes"], "text": c["text"], "in_file": in_file,
                          "callee_in_observed_group29_span_hypothesis":
                              bool(in_file and GROUP29_SPAN[0] <= t < GROUP29_SPAN[1])})
            if not in_file:
                continue
            if depth + 1 > max_depth:
                frontier.append({"entry": t, "depth": depth + 1, "reason": "depth-limit",
                                 "from": entry, "at": c["at"]})
                continue
            if t not in queued:
                queued.add(t)
                q.append((t, depth + 1))

    proc_list = [_proc_out(procs[e]["ex"], procs[e]["depth"], tokens) for e in sorted(procs)]
    edges.sort(key=lambda e: (e["from"], e["at"]))
    frontier.sort(key=lambda f: (f["entry"], f.get("at", -1)))
    verdict = _verdict(proc_list, frontier, truncated)
    return {
        "procs": proc_list,
        "call_edges": edges,
        "frontier": frontier,
        "verdict": verdict,
        "string_tokens": {"file_offsets": tokens["file_offsets"]},
        "proc_budget_truncated": truncated,
    }


def _verdict(procs: list[dict], frontier: list[dict], truncated: bool) -> dict:
    io_hits, int21_unknown, far_unfollowed, indirect_unfollowed = [], [], [], []
    incomplete, conflicts, selectors, token_hits = [], [], [], []
    for p in procs:
        for s in p["ints"]:
            if s["vector"] != 0x21:
                continue
            ah = s["ah"]["value"]
            rec = {"proc": p["entry"], "at": s["at"], "ah": ah, "ah_rule": s["ah"]["reason"],
                   "ah_source": s["ah"]["source"], "function": DOS_FILE_FUNCS.get(ah) if ah is not None else None,
                   "bytes": s["bytes"]}
            if ah is None:
                int21_unknown.append(rec)
            elif ah in DOS_FILE_FUNCS:
                io_hits.append(rec)
        far_unfollowed += [dict(proc=p["entry"], **f) for f in p["far_calls"]]
        indirect_unfollowed += [dict(proc=p["entry"], **f) for f in p["indirect"]]
        incomplete += [dict(proc=p["entry"], **x) for x in p["incomplete"]]
        conflicts += [dict(proc=p["entry"], **x) for x in p["overlap_conflicts"]]
        selectors += [dict(proc=p["entry"], **x) for x in p["selector_candidates"]]
        token_hits += [dict(proc=p["entry"], **x) for x in p["string_token_candidates"]]
    closure_complete = (not truncated and not frontier and not incomplete and not conflicts)
    if io_hits:
        answer = "dos-file-function-reached-in-bounds"
    elif closure_complete and not far_unfollowed and not indirect_unfollowed and not int21_unknown:
        answer = "no-dos-file-function-in-closure"
    else:
        answer = "no-dos-file-function-found-but-bounded-incomplete"
    return {
        "answer": answer,
        "closure_complete": closure_complete,
        "procs_explored": len(procs),
        "instructions_decoded": sum(p["instruction_count"] for p in procs),
        "dos_file_function_hits": io_hits,
        "int21_ah_unknown": int21_unknown,
        "far_calls_not_followed": far_unfollowed,
        "indirect_calls_not_followed": indirect_unfollowed,
        "incomplete": incomplete,
        "overlap_conflicts": conflicts,
        "frontier_count": len(frontier),
        "selector_candidate_count": len(selectors),
        "selector_candidates": selectors,
        "string_token_candidates": token_hits,
        "selection_reached": "not-established",
    }


UNRESOLVED = [
    "Far calls (9A) are recorded and not followed; their segment word is a loader value.",
    "Indirect calls (FF /2, /3) are recorded and not followed; no target table is parsed.",
    "0F-prefixed opcodes stop a procedure's walk and mark it incomplete.",
    "INT 21h AH is a straight-line inference (see the ah_rule per site), not dataflow.",
    "Selector candidates are presence only; none is tied to an address or a WALLDEF record.",
    "The caller set of 0x2EEF4 is not established by this probe (see the render and group-29 probes).",
    "Group-29 span membership is a hypothesis from one runtime quote, not a retail fact.",
]

LIMITS = [
    "Recursive descent from each entry, not a linear sweep: undecoded bytes are not reported.",
    "Near-call depth is bounded by --max-depth and the proc budget by --max-procs; see frontier.",
    "Per-procedure decode is bounded by --max-insns; a budget stop marks the procedure incomplete.",
    "A verdict of no-dos-file-function-in-closure means only the bounded, followed closure was searched.",
]


def analyse(data: bytes, root: int = OWNER, max_depth: int = DEFAULT_MAX_DEPTH,
            max_procs: int = DEFAULT_MAX_PROCS, max_insns: int = DEFAULT_MAX_INSNS) -> dict:
    """Bounded closure from ``root``. Pure function of the bytes and the parameters."""
    trav = traverse(data, root, max_depth, max_procs, max_insns)
    diagnostics = []
    if not trav["verdict"]["closure_complete"]:
        diagnostics.append("closure-incomplete")
    return {
        "root": root,
        "parameters": {"max_depth": max_depth, "max_procs": max_procs, "max_insns": max_insns},
        "limits": LIMITS,
        "unresolved_edges": UNRESOLVED,
        "diagnostics": diagnostics,
        **trav,
    }


def owner_cross_check(data: bytes) -> dict:
    """The owner's own linear walk (ow.analyse) must agree with the seeds and the recursive closure."""
    own = ow.analyse(data)
    targets = sorted({c["target"] for c in own.get("near_calls", []) if c["target"] is not None})
    diags = []
    if own.get("owner_end") != LITERAL:
        diags.append("owner-end-not-literal")
    if sorted(EXPECTED_SEEDS) != targets:
        diags.append("seed-targets-differ-from-owner-near-calls")
    return {
        "owner": OWNER,
        "owner_end": own.get("owner_end"),
        "literal": LITERAL,
        "instruction_count": own.get("instruction_count"),
        "near_call_count": len(own.get("near_calls", [])),
        "far_call_count": len(own.get("far_calls", [])),
        "interrupt_count": len(own.get("interrupts", [])),
        "near_call_targets": targets,
        "expected_seeds": sorted(EXPECTED_SEEDS),
        "seeds_match": sorted(EXPECTED_SEEDS) == targets,
        "diagnostics": diags,
    }


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    try:
        data, sha, pinned = ow.read_pinned_ovr(install, allow_unpinned)
    except ow.OwnerProbeError as exc:
        raise CalleeProbeError(str(exc)) from exc
    result = analyse(data)
    check = owner_cross_check(data)
    diags = list(result["diagnostics"])
    diags += ["owner-" + d for d in check["diagnostics"]]
    if not pinned:
        diags.append("unpinned-source")
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "mappings": [],
        "events_emitted": 0,
        "source": {"file": OVR_NAME, "bytes": len(data), "sha256": sha,
                   "pin": "pinned" if pinned else "unpinned"},
        "owner_cross_check": check,
        **result,
        "diagnostics": diags,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_callee_probe.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc, (0 if not diags else 1)


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
            raise CalleeProbeError("output folder must not be inside the install")
        doc, code = probe(install, out, a.allow_unpinned)
    except CalleeProbeError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    v = doc["verdict"]
    print("owner 0x%05X: %d procs, %d instructions, %d call edges, frontier %d, far %d, indirect %d, "
          "INT21 file hits %d, INT21 unknown AH %d, answer %s, pin %s"
          % (OWNER, v["procs_explored"], v["instructions_decoded"], len(doc["call_edges"]),
             v["frontier_count"], len(v["far_calls_not_followed"]), len(v["indirect_calls_not_followed"]),
             len(v["dos_file_function_hits"]), len(v["int21_ah_unknown"]), v["answer"],
             doc["source"]["pin"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
