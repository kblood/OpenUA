#!/usr/bin/env python3
"""Candidate ECL control-flow walk; diagnostic only, never a conversion.

The ordinary decoder stops at the first unsupported byte in linear order. This
probe follows the decoder's already-reported literal control-flow operands to
see whether another candidate code region lies beyond that stop. Both the
instruction framing and PoR vbase are conditional inputs; the output is never
labelled runtime-reachable or playable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import deque
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import por_ecl as pe


TOOL = "tools/por_ecl_cfg_probe.py"
SCHEMA = "openua.por-ecl-cfg-probe"
VERSION = 1
MAX_INSTRUCTIONS = 12000
CONDITIONAL_OPS = set(range(0x16, 0x1C))
UNCONDITIONAL_JUMPS = {0x01}
CALLS = {0x02}
MULTIWAY = {0x25, 0x26}
TERMINALS = {0x00, 0x13}


def _target_offset(vaddr: int, vbase: int) -> int:
    return (vaddr - vbase) & 0xFFFF


def _decode_one(block: bytes, start: int, framing: str) -> tuple[Optional[pe.Instruction], list[pe.Edge], Optional[str]]:
    if start < pe.ECL_HEADER_LEN or start >= len(block):
        return None, [], "start-outside-body"
    # Rebase this suffix at the decoder's normal stream origin. This reuses its
    # exact operand framing without copying or modifying the production decoder.
    shifted = block[:pe.ECL_HEADER_LEN] + block[start:]
    instructions, edges, stop = pe.walk_block(shifted, framing)
    if not instructions:
        return None, [], "%s:%s" % (stop.kind, stop.detail)
    first = instructions[0]
    delta = start - pe.ECL_HEADER_LEN
    first.offset += delta
    first.operands = [dict(x, offset=x["offset"] + delta) for x in first.operands]
    first.count_operands = [dict(x, offset=x["offset"] + delta) for x in first.count_operands]
    first_edges = []
    for edge in edges:
        if edge.source == pe.ECL_HEADER_LEN:
            edge.source += delta
            edge.operand_offset += delta
            first_edges.append(edge)
    return first, first_edges, None


def analyze_block(block: bytes, header: dict, framing: str = "spec-menus",
                  vbase: int = pe.POR_VBASE, max_instructions: int = MAX_INSTRUCTIONS) -> dict:
    """Return a bounded over-approximation of candidate decoded starts.

    Linear fallthrough and literal GOTO/GOSUB targets use the existing decoder's
    opcode table. Conditional opcodes 0x16..0x1B continue linearly as a
    candidate only and are recorded as unresolved condition-state points; no
    branch target is invented. ON_GOTO/ON_GOSUB follow literal targets and
    also retain fallthrough as an over-approximation.
    """
    if framing not in pe.FRAMINGS:
        raise pe.EclError("unknown framing %r" % framing)
    if max_instructions < 1:
        raise pe.EclError("max_instructions must be positive")
    starts = []
    invalid_roots = []
    for ptr in header["pointers"]:
        offset = _target_offset(ptr["vaddr"], vbase)
        if pe.ECL_HEADER_LEN <= offset < len(block):
            starts.append((offset, "header-slot-%d" % ptr["slot"]))
        else:
            invalid_roots.append({"slot": ptr["slot"], "vaddr": ptr["vaddr"], "offset": offset})
    queue = deque((offset, source) for offset, source in starts)
    queued = {offset for offset, _ in starts}
    instructions: dict[int, dict] = {}
    edges: list[dict] = []
    stops: list[dict] = []
    uncertainties: list[dict] = []
    interior_targets: list[dict] = []
    while queue and len(instructions) < max_instructions:
        offset, source = queue.popleft()
        if offset in instructions:
            continue
        containing = next((at for at, rec in instructions.items()
                           if at < offset < at + rec["length"]), None)
        if containing is not None:
            interior_targets.append({"target": offset, "inside_instruction": containing, "source": source})
            continue
        inst, inst_edges, error = _decode_one(block, offset, framing)
        if error:
            stops.append({"offset": offset, "source": source, "reason": error})
            continue
        assert inst is not None
        rec = {"offset": offset, "opcode": inst.opcode, "mnemonic": inst.mnemonic,
               "length": inst.length, "operands": inst.operands,
               "count_operands": inst.count_operands}
        instructions[offset] = rec
        if inst.opcode in CONDITIONAL_OPS:
            uncertainties.append({"offset": offset, "source": source,
                                  "reason": "conditional-branch-semantics-open"})
        if inst.opcode in TERMINALS:
            continue
        next_offset = offset + inst.length
        follows = inst.opcode not in UNCONDITIONAL_JUMPS
        if inst.opcode in UNCONDITIONAL_JUMPS | CALLS | MULTIWAY:
            for edge in inst_edges:
                target = None if edge.indirect or edge.target_vaddr is None else _target_offset(edge.target_vaddr, vbase)
                item = {"source": offset, "kind": edge.kind, "target_vaddr": edge.target_vaddr,
                        "target_offset": target, "indirect": edge.indirect,
                        "assumption": "decoder control-flow kind and conditional vbase"}
                edges.append(item)
                if target is not None and pe.ECL_HEADER_LEN <= target < len(block):
                    if target not in queued:
                        queue.append((target, "edge-from-%04x" % offset))
                        queued.add(target)
                elif target is not None:
                    stops.append({"offset": offset, "source": source,
                                  "reason": "edge-target-out-of-block", "target": target})
            if inst.opcode in CALLS | MULTIWAY:
                follows = True
        if follows and next_offset < len(block) and next_offset not in queued:
            queue.append((next_offset, "fallthrough-from-%04x" % offset))
            queued.add(next_offset)
    bounded = bool(queue)
    ordered = [instructions[k] for k in sorted(instructions)]
    return {
        "status": "candidate-control-flow-diagnostic",
        "playable": False,
        "runtime_reachability_established": False,
        "framing": framing,
        "vbase": vbase,
        "vbase_evidence": "conditional",
        "header_roots": [{"slot": slot, "offset": offset} for offset, slot in starts],
        "invalid_roots": invalid_roots,
        "candidate_instruction_count": len(ordered),
        "candidate_instructions": ordered,
        "candidate_edges": sorted(edges, key=lambda x: (x["source"], x["kind"], x["target_offset"] or -1)),
        "stops": sorted(stops, key=lambda x: (x["offset"], x["reason"])),
        "uncertainties": sorted(uncertainties, key=lambda x: (x["offset"], x["reason"])),
        "interior_targets": sorted(interior_targets, key=lambda x: x["target"]),
        "bounded_limit_hit": bounded,
        "not_established": [
            "that the conditional vbase 0x98FE is the runtime code base",
            "that spec-menus framing matches PoR at every menu",
            "that decoder control-flow kinds match PoR execution semantics",
            "conditional branch behavior for opcodes 0x16..0x1B",
            "runtime reachability, event meaning, or FRUA equivalence",
        ],
    }


def _out_dir(path: str, source_root: Path) -> Path:
    out = Path(path).resolve()
    src_root = source_root.resolve()
    if out == src_root or src_root in out.parents:
        raise pe.EclError("output must not be inside the source archive directory")
    repo = pe.REPO_ROOT.resolve()
    if (out == repo or repo in out.parents) and pe.DATA_DIR.resolve() not in (out, *out.parents):
        raise pe.EclError("output inside repository must be under data/")
    if out.exists() and any(out.iterdir()):
        raise pe.EclError("output directory must be new or empty")
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Candidate PoR ECL control-flow walk (diagnostic only)")
    ap.add_argument("--dax", help="explicit ECL DAX path")
    ap.add_argument("--install", help="PoR install folder")
    ap.add_argument("--ecl", type=int, help="ECL archive number 1..8 with --install")
    ap.add_argument("--block", type=int, help="unique block id")
    ap.add_argument("--index", type=int, help="TOC index")
    ap.add_argument("--framing", choices=pe.FRAMINGS, default="spec-menus")
    ap.add_argument("--max-instructions", type=int, default=MAX_INSTRUCTIONS)
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args(argv)
    try:
        source = pe.resolve_source(args.dax, args.install, args.ecl)
        data = source.read_bytes()
        before = hashlib.sha256(data).hexdigest()
        base = pe.decode_block(data, args.block, args.index, args.framing, None, por_vbase=True)
        result = analyze_block(base["block"], base["header"], args.framing,
                               pe.POR_VBASE, args.max_instructions)
        result.update({"schema": SCHEMA, "version": VERSION, "tool": TOOL,
                       "source_name": source.name, "source_sha256": before,
                       "toc_index": base["entry"].index, "block_id": base["entry"].block_id,
                       "block_length": len(base["block"]), "linear_walk": {
                           "instruction_count": len(base["instructions"]),
                           "stop_kind": base["stop"].kind, "stop_offset": base["stop"].offset,
                           "stop_opcode": base["stop"].opcode}})
        after = hashlib.sha256(source.read_bytes()).hexdigest()
        result["source_unchanged"] = before == after
        if before != after:
            raise pe.EclError("source archive changed during analysis")
        out = _out_dir(args.out, source.parent)
        out.mkdir(parents=True, exist_ok=True)
        (out / "por_ecl_cfg_probe.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (pe.EclError, OSError, ValueError) as exc:
        print("por_ecl_cfg_probe: error: %s" % exc, file=sys.stderr)
        return 2
    print("status=%s linear=%d candidate=%d edges=%d uncertainties=%d stops=%d playable=false" % (
        result["status"], result["linear_walk"]["instruction_count"],
        result["candidate_instruction_count"], len(result["candidate_edges"]),
        len(result["uncertainties"]), len(result["stops"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
