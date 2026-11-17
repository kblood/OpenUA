#!/usr/bin/env python3
"""Pool of Radiance: bounded decode of the GAME.OVR routine at 0x2EEF4.

Status: STATIC-PROBE-ONLY. Read-only, stdlib plus the existing PoR decoder,
playable: false, mappings: [].

Question: does the routine at GAME.OVR 0x2EEF4 (the layout-unique predecessor of
the WALLDEF literal at 0x2F6AB) itself establish a WALLDEF record selection, a
record stride or index, a DAX file or read path, or a wall slot -> art lookup?

What this decodes, from the pinned retail bytes only:
  * the ret-stopped walk from 0x2EEF4 (the same decoder as por_loadpieces_handler);
  * every instruction, its flow class and its byte range;
  * every direct near call, with its target, whether the target lies inside the
    routine, and the three instructions before it (argument pushes);
  * every interrupt, with the preceding AH/AL immediate, so a DOS file function
    (AH=3Dh open, 3Fh read, 42h seek) is visible if it is inline;
  * every immediate, direct (DS) and BP-relative operand, and every far call;
  * whether any operand equals the WALLDEF literal under the two offset models
    stated in the output (file offset, and the group-29 relative offset that the
    observed load places at 33E7:0000 -- a hypothesis, labelled as such).

It does not follow callees, does not infer a record index from a constant, and
binds no slot to an 8X8D tile. Unresolved edges are listed in the output.

Usage
  python tools/por_wall_owner_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-owner-probe

Exit codes: 0 clean; 1 written with a diagnostic (e.g. walk incomplete);
2 named refusal (missing or unpinned GAME.OVR, output inside the install).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

import por_loadpieces_handler as h

SCHEMA = "openua.por-wall-owner-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_wall_owner_probe.py"

OVR_NAME = "GAME.OVR"
OVR_SIZE = 206105
OVR_SHA = "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"

OWNER = 0x2EEF4
LITERAL = 0x2F6AB
RETF_AT = 0x2F6A8
MAX_WALK = 4000

# Group 29 (observed load, runtime-quoted, not retail): seek 0x2E8F7, read 0x120B.
GROUP29_SEEK = 0x2E8F7
GROUP29_LEN = 0x120B

PINNED_MARKER = "pinned"


class OwnerProbeError(Exception):
    """A named refusal. The CLI prints it and exits with 2."""


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_pinned_ovr(install: Path, allow_unpinned: bool = False) -> tuple[bytes, str, bool]:
    """Return (bytes, sha256, pinned). Refuses a missing or unpinned GAME.OVR unless allowed."""
    cand = None
    for c in (install, install / "POOLRAD"):
        if (c / OVR_NAME).is_file():
            cand = c / OVR_NAME
            break
    if cand is None:
        raise OwnerProbeError("no %s in %s or its POOLRAD folder" % (OVR_NAME, install))
    data = cand.read_bytes()
    sha = _sha(data)
    pinned = len(data) == OVR_SIZE and sha == OVR_SHA
    if not pinned and not allow_unpinned:
        raise OwnerProbeError("%s does not match its pin (use --allow-unpinned to probe anyway)" % OVR_NAME)
    return data, sha, pinned


def _in_owner(addr: Optional[int], owner_end: int) -> Optional[bool]:
    if addr is None:
        return None
    return OWNER <= addr < owner_end


def analyse(data: bytes, owner: int = OWNER, literal: int = LITERAL) -> dict:
    """Decode the ret-stopped walk from ``owner`` and report its control and data flows."""
    insns, err = h.linear(data, owner, MAX_WALK)
    if not insns:
        return {"status": "decode-failed", "reason": err}
    last = insns[-1]
    owner_end = last.end
    body_starts = {i.off for i in insns}
    idx_of = {i.off: n for n, i in enumerate(insns)}

    flows: dict[str, int] = {}
    for i in insns:
        flows[i.flow] = flows.get(i.flow, 0) + 1

    def before(n: int, k: int = 3) -> list[str]:
        return [insns[j].text() for j in range(max(0, n - k), n)]

    near_calls, far_calls, interrupts, indirect = [], [], [], []
    literal_refs, direct_refs, bp_refs, imm_refs = [], [], [], []
    lit_word = struct.pack("<H", literal & 0xFFFF)
    lit_word_hits = []
    for n, i in enumerate(insns):
        if i.flow == "call":
            near_calls.append({
                "at": i.off,
                "target": i.target,
                "target_inside_routine": _in_owner(i.target, owner_end),
                "target_on_boundary": i.target in body_starts if i.target is not None else None,
                "before": before(n),
            })
        elif i.flow == "call_far":
            far_calls.append({"at": i.off, "seg": i.far[0], "off": i.far[1]})
        elif i.flow.startswith("indirect"):
            indirect.append({"at": i.off, "kind": i.flow, "text": i.text()})
        if i.name.startswith("int"):
            interrupts.append({"at": i.off, "text": i.text(), "before": before(n)})
        if i.direct is not None:
            direct_refs.append({"at": i.off, "addr": i.direct, "text": i.text()})
        if i.bp_disp is not None:
            bp_refs.append({"at": i.off, "disp": i.bp_disp, "text": i.text()})
        if i.imm is not None and i.op not in (0xCD,):
            imm_refs.append({"at": i.off, "imm": i.imm, "text": i.text()})
        # literal under the file-offset model: an operand equal to the literal offset
        for label, val in (("target", i.target), ("direct", i.direct),
                           ("imm", None if i.op == 0xCD else i.imm)):
            if val is not None and val == literal:
                literal_refs.append({"at": i.off, "operand": label, "value": val, "text": i.text()})
        if i.far is not None and i.far[1] == (literal & 0xFFFF):
            literal_refs.append({"at": i.off, "operand": "far-offset", "value": i.far[1], "text": i.text()})
        if lit_word in i.raw:
            lit_word_hits.append({"at": i.off, "text": i.text()})

    # group-relative model (hypothesis): the literal's offset inside group 29's observed placement
    group_rel_literal = literal - GROUP29_SEEK
    group_rel_owner = owner - GROUP29_SEEK
    group_rel_hits = [r for r in imm_refs + direct_refs + near_calls
                      if (r.get("imm") == group_rel_literal or r.get("addr") == group_rel_literal
                          or r.get("target") == group_rel_literal)]

    diagnostics = []
    if last.flow not in ("ret", "retf"):
        diagnostics.append("walk-did-not-end-at-return")
    if last.end != literal:
        diagnostics.append("return-not-adjacent-to-literal")
    if err is not None:
        diagnostics.append("walk-decode-stopped")

    return {
        "owner": owner,
        "owner_end": owner_end,
        "literal": literal,
        "return": {"at": last.off, "flow": last.flow, "imm": last.imm, "text": last.text()},
        "instruction_count": len(insns),
        "flows": flows,
        "near_calls": near_calls,
        "far_calls": far_calls,
        "indirect": indirect,
        "interrupts": interrupts,
        "direct_refs": direct_refs,
        "bp_refs": bp_refs,
        "immediates": imm_refs,
        "literal_refs_file_offset_model": literal_refs,
        "literal_word_hits_raw_bytes": lit_word_hits,
        "hypothesis_group29_relative": {
            "label": "hypothesis: group 29 placed at 33E7:0000 by one observed load; not established",
            "group_rel_literal": group_rel_literal,
            "group_rel_owner": group_rel_owner,
            "hits": group_rel_hits,
        },
        "walk_error": err,
        "diagnostics": diagnostics,
        "listing": [{"at": i.off, "bytes": i.raw.hex(), "text": i.text(), "flow": i.flow} for i in insns],
    }


UNRESOLVED = [
    "Callees of the 39 near calls are not entered; their function is not identified here.",
    "A DOS function reached through a called helper is not visible in this routine's inline INT list.",
    "The routine's caller set is not established (see docs/por-wall-render-probe.md, group-29 probe).",
    "A record index or stride is not inferred from any immediate; no constant is tied to WALLDEF here.",
    "The group-29 relative model is a hypothesis taken from one runtime quote, not retail.",
]


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    data, sha, pinned = read_pinned_ovr(install, allow_unpinned)
    result = analyse(data)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "mappings": [],
        "events_emitted": 0,
        "source": {"file": OVR_NAME, "bytes": len(data), "sha256": sha,
                   "pin": PINNED_MARKER if pinned else "unpinned"},
        "answer": "not-established",
        "routine": result,
        "unresolved_edges": UNRESOLVED,
    }
    diag = 0 if (pinned and not result.get("diagnostics") and result.get("status") != "decode-failed") else 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_owner_probe.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc, diag


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
            raise OwnerProbeError("output folder must not be inside the install")
        doc, code = probe(install, out, a.allow_unpinned)
    except OwnerProbeError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    r = doc["routine"]
    print("owner 0x%05X: %s instructions, return %s at 0x%05X, near calls %d, far calls %d, INTs %d, "
          "literal refs (file model) %d, pin %s"
          % (r["owner"], r.get("instruction_count"), r.get("return", {}).get("flow"),
             r.get("return", {}).get("at", -1), len(r.get("near_calls", [])),
             len(r.get("far_calls", [])), len(r.get("interrupts", [])),
             len(r.get("literal_refs_file_offset_model", [])), doc["source"]["pin"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
