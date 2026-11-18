#!/usr/bin/env python3
"""Pool of Radiance: save-position vs GEO cell signature compatibility check.

Status: CANDIDATE-COMPATIBILITY-ONLY. Read-only, stdlib-only, playable: false,
runtime_established: false.

Question (narrow, falsifiable): for the two pinned retail saves, the candidate pose
(x, y) and the candidate facing name select one decoded GEO cell of the hypothesised
block GEO2.DAX TOC index 2 / block id 20. Does that cell's signature occur in any other
decoded GEO block (GEO1..GEO8.DAX), or is the hypothesised block the only one that
carries it?

Two signatures are tested, strongest first:
  full_cell    the four edge (slot, door) pairs N/E/S/W and the plane-2 descriptor.
               Independent of the facing name.
  facing_edge  the single edge the candidate facing name selects, and the descriptor.
               Conditional on the unverified facing names (north/east/south/west).

Both coordinate orderings are tested and reported: the primary hypothesis
(x = pose_x, y = pose_y, row 0 north) and the swapped order (x = pose_y, y = pose_x).
Neither is preferred here. Out-of-grid positions are reported as not-evaluable.

What it does NOT do: it does not turn a match into a game-area mapping, it does not say
the DOS runtime loaded the hypothesised block, and it does not transfer CoK or DoK
rules. A matched signature is compatibility evidence only, not a runtime binding.

Inputs are the two pinned saves (tools/por_save_state_probe.py) and the eight pinned GEO
archives (tools/por_area_evidence.GEO_PINS). Any missing, symlinked, size-changed,
hash-changed or malformed input is refused. Inputs that change during the run are refused.
Undecodable TOC blocks are counted and listed, and the search-complete flag records
whether any were skipped.

Usage
  python tools/por_save_geo_candidate_check.py --install "PATH/TO/POOLRAD" \\
      -o data/work/por-save-geo-candidate-check/retail

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths, no raw
save bytes):
  por_save_geo_candidate_check.json          schema openua.por-save-geo-candidate-check
  por_save_geo_candidate_check_report.md     the readable summary

Exit codes
  0  inputs pinned and matched; outputs written (verdicts are findings, not failures)
  2  named refusal, no output written
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Callable, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATA_DIR = REPO / "data"
sys.path.insert(0, str(HERE))

import por_save_state_probe as sp  # noqa: E402
import por_map as pm  # noqa: E402
from por_area_evidence import GEO_PINS  # noqa: E402

SCHEMA = "openua.por-save-geo-candidate-check"
SCHEMA_VERSION = 0
STATUS = "candidate-compatibility-only"
TOOL = "tools/por_save_geo_candidate_check.py"
INSTALL_ENV = sp.INSTALL_ENV
DEFAULT_INSTALL = sp.DEFAULT_INSTALL
SAVE_PINS = sp.SAVE_PINS
RECORDED = sp.RECORDED_OBSERVATIONS
GRID = pm.GRID_W

HYPOTHESIS = {"archive": "GEO2.DAX", "toc_index": 2, "block_id": 20}
HYPOTHESIS_STATUS = "same-suffix/same-id hypothesis (ECL member 20 -> GEO2.DAX block 20); not a binding"
FACING_EDGE = {"north": "N", "east": "E", "south": "S", "west": "W"}
ORDERINGS = (
    ("pose_xy", "x = pose_x, y = pose_y (row, 0 north)", "primary hypothesis"),
    ("pose_yx", "x = pose_y, y = pose_x", "alternate ordering, sensitivity only"),
)
SIGNATURES = (
    ("full_cell", "four edge (slot, door) pairs N/E/S/W and the plane-2 descriptor; "
                  "independent of the facing name"),
    ("facing_edge", "the one edge the candidate facing name selects, and the plane-2 "
                    "descriptor; conditional on the unverified facing names"),
)
QUESTION = (
    "Do the decoded GEO cell signatures at the two candidate save positions occur in any "
    "other decoded GEO block (GEO1..8.DAX), or is GEO2.DAX TOC index 2 / block id 20 the "
    "only block carrying them?"
)

LIMITATIONS = (
    "Save bytes: only six candidate bytes per pinned 13,137-byte save are read. No other "
    "save byte is decoded, and no save schema is claimed.",
    "Pose (x, y) and the facing name are candidate readings. The coordinate ordering and the "
    "facing mapping are both hypotheses, and both orderings are reported.",
    "GEO cells: the Gen1 layout is the one tools/por_map.py decodes. Only two cell values "
    "are PoR-checked in this repo; no other semantics are assumed.",
    "The join to GEO2.DAX block 20 is a same-suffix/same-id hypothesis. The check compares "
    "signatures and says nothing about which block the DOS runtime loaded.",
    "A match is compatibility evidence only. It is not a runtime binding, not a game-area "
    "mapping, and not a start state.",
    "No live DOS state is observed. Nothing was run, no emulator or codewheel was started, "
    "and no input was sent.",
    "Undecodable TOC blocks are skipped and listed. A uniqueness verdict covers decoded "
    "blocks only; search_complete is false when any block was skipped.",
    "Other coordinate conventions (flipped rows, 1-based indexing, other block-to-cell "
    "layouts) are not tested.",
    "Pins cover the two retail saves and the eight retail GEO archives only. Any other input "
    "is refused, not inspected.",
    "No CoK or DoK rules were transferred. Every field here is a PoR byte or a decoded PoR "
    "GEO cell.",
)
CLAIM_BOUNDARY = (
    "Compatibility check of candidate save positions against decoded GEO cell signatures. "
    "Not a runtime binding, not a game-area mapping, not a save schema, not a start state."
)


class CheckRefusal(Exception):
    """A named refusal. The CLI prints it and exits with 2, writing no output."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_pinned(folder: Path, name: str, size: int, sha: str) -> tuple[bytes, str]:
    """Read one pinned input. Refuses symlinks, missing files, size and hash mismatches."""
    path = folder / name
    if path.is_symlink():
        raise CheckRefusal("%s is a symbolic link; not read" % name)
    if not path.is_file():
        raise CheckRefusal("missing input %s" % name)
    data = path.read_bytes()
    if len(data) != size:
        raise CheckRefusal("%s size is %d, expected the pinned %d" % (name, len(data), size))
    digest = _sha(data)
    if digest != sha:
        raise CheckRefusal("%s sha256 does not match its pin; not inspected" % name)
    return data, digest


def decode_archive(name: str, data: bytes) -> dict:
    """Strictly parse one GEO DAX and decode each TOC block. A malformed container is a
    refusal. A block that does not decode as a Gen1 GEO block is recorded as skipped."""
    try:
        entries, base = pm.parse_dax(data)
    except pm.PorMapError as exc:
        raise CheckRefusal("%s: %s" % (name, exc)) from exc
    blocks, skipped = [], []
    for e in entries:
        start = base + e.data_offset
        comp = data[start:start + e.comp_size]
        try:
            cells = pm.decode_gen1_geo(pm.rle_decode(comp, e.raw_size))
        except pm.PorMapError as exc:
            skipped.append({"toc_index": e.index, "block_id": e.block_id, "reason": str(exc)})
            continue
        blocks.append({"archive": name, "toc_index": e.index, "block_id": e.block_id,
                       "cells": cells})
    return {"toc_entries": len(entries), "blocks": blocks, "skipped": skipped}


def _is_hypothesis_block(block: dict) -> bool:
    return (block["archive"], block["toc_index"], block["block_id"]) == (
        HYPOTHESIS["archive"], HYPOTHESIS["toc_index"], HYPOTHESIS["block_id"])


def _full_key(cell: dict) -> tuple:
    return (tuple(cell["edges"][k] for k in pm.EDGES), cell["planes"][2])


def _facing_key(cell: dict, edge: str) -> tuple:
    return (cell["edges"][edge], cell["planes"][2])


def _cell_view(block: dict, cell: dict) -> dict:
    return {
        "archive": block["archive"],
        "toc_index": block["toc_index"],
        "block_id": block["block_id"],
        "x": cell["x"],
        "y": cell["y"],
        "edges": {k: list(cell["edges"][k]) for k in pm.EDGES},
        "descriptor": cell["planes"][2],
    }


def _not_evaluable(basis: str, reason: str) -> dict:
    return {"basis": basis, "evaluable": False, "reason": reason, "verdict": "not-evaluable",
            "match_count": 0, "same_position_match_count": 0, "distinct_blocks": [],
            "matches": []}


def _verdict(matches: list[dict]) -> str:
    n = len(matches)
    hyp = [m for m in matches if m["hypothesised_block"]]
    other = [m for m in matches if not m["hypothesised_block"]]
    if n == 0:
        return "no-match"
    if n == 1 and hyp:
        return "unique-to-hypothesised-block"
    if n == 1:
        return "unique-to-other-block"
    if not other:
        return "repeats-only-within-hypothesised-block"
    return "non-unique-across-blocks"


def _search(blocks: list[dict], x: int, y: int, basis: str, target: tuple,
            keyfn: Callable[[dict], tuple], include_cells: bool) -> dict:
    matches = []
    for b in blocks:
        for c in b["cells"]:
            if keyfn(c) == target:
                matches.append({
                    "archive": b["archive"],
                    "toc_index": b["toc_index"],
                    "block_id": b["block_id"],
                    "x": c["x"],
                    "y": c["y"],
                    "same_position": (c["x"], c["y"]) == (x, y),
                    "hypothesised_block": _is_hypothesis_block(b),
                })
    per_block: dict[tuple, int] = {}
    for m in matches:
        key = (m["archive"], m["toc_index"], m["block_id"])
        per_block[key] = per_block.get(key, 0) + 1
    distinct = [{"archive": a, "toc_index": t, "block_id": i, "cell_matches": n}
                for (a, t, i), n in sorted(per_block.items())]
    return {
        "basis": basis,
        "evaluable": True,
        "reason": None,
        "verdict": _verdict(matches),
        "match_count": len(matches),
        "same_position_match_count": sum(1 for m in matches if m["same_position"]),
        "candidate_block_match_count": sum(1 for m in matches if m["hypothesised_block"]),
        "distinct_blocks": distinct,
        "matches": matches if include_cells else [],
        "matches_listed": include_cells,
    }


def _candidate_block(blocks: list[dict]) -> Optional[dict]:
    for b in blocks:
        if _is_hypothesis_block(b):
            return b
    return None


def _evaluate(save_name: str, fields: dict, blocks: list[dict], ordering_id: str) -> dict:
    px = fields["pose_x"]["value"]
    py = fields["pose_y"]["value"]
    x, y = (px, py) if ordering_id == "pose_xy" else (py, px)
    facing = fields["facing_raw"]
    fname = facing["candidate_name"]
    fedge = FACING_EDGE.get(fname)
    in_bounds = 0 <= x < GRID and 0 <= y < GRID
    row = {
        "save": save_name,
        "ordering": ordering_id,
        "x": x,
        "y": y,
        "in_bounds": in_bounds,
        "facing_raw": facing["value"],
        "facing_candidate": fname,
        "facing_edge_candidate": fedge,
    }
    hyp = _candidate_block(blocks)
    if not in_bounds:
        reason = "candidate position is outside the 16 x 16 grid"
    elif hyp is None:
        reason = "hypothesised block GEO2.DAX TOC index 2 / block id 20 was not decoded"
    else:
        reason = None
    if reason is not None:
        row["candidate_cell"] = None
        row["signatures"] = {
            "full_cell": _not_evaluable(SIGNATURES[0][1], reason),
            "facing_edge": _not_evaluable(SIGNATURES[1][1], reason),
        }
        return row
    cell = hyp["cells"][y * GRID + x]
    row["candidate_cell"] = _cell_view(hyp, cell)
    full_target = _full_key(cell)
    sigs = {
        "full_cell": _search(blocks, x, y, SIGNATURES[0][1], full_target, _full_key,
                             include_cells=True),
    }
    if fedge is None:
        sigs["facing_edge"] = _not_evaluable(
            SIGNATURES[1][1], "facing raw %d has no candidate edge name" % facing["value"])
    else:
        sigs["facing_edge"] = _search(
            blocks, x, y, SIGNATURES[1][1], _facing_key(cell, fedge),
            lambda c, e=fedge: _facing_key(c, e), include_cells=False)
    row["signatures"] = sigs
    return row


def _archive_row(name: str, size: int, sha: str, dec: dict) -> dict:
    return {
        "name": name,
        "size": size,
        "sha256": sha,
        "pin": "matched",
        "toc_entries": dec["toc_entries"],
        "decoded_blocks": len(dec["blocks"]),
        "skipped_blocks": dec["skipped"],
    }


def check(install: Path, out: Path, save_pins: dict = SAVE_PINS, geo_pins: dict = GEO_PINS,
          data_root: Path = DATA_DIR, recorded: Optional[dict] = RECORDED) -> dict:
    if not install.is_dir():
        raise CheckRefusal("install folder not found")
    try:
        sp.check_output(out, install, data_root)
    except sp.ProbeRefusal as exc:
        raise CheckRefusal(str(exc)) from exc

    save_inputs = {}
    for name, (size, sha) in sorted(save_pins.items()):
        save_inputs[name] = (size, sha) + _read_pinned(install, name, size, sha)
    geo_inputs = {}
    for name, (size, sha) in sorted(geo_pins.items()):
        geo_inputs[name] = (size, sha) + _read_pinned(install, name, size, sha)

    archives = []
    all_blocks: list[dict] = []
    for name in sorted(geo_inputs):
        size, sha, data, digest = geo_inputs[name]
        dec = decode_archive(name, data)
        archives.append(_archive_row(name, size, digest, dec))
        all_blocks.extend(dec["blocks"])

    saves_out = []
    save_fields: dict[str, dict] = {}
    for name in sorted(save_inputs):
        size, sha, data, digest = save_inputs[name]
        rec = recorded.get(name) if recorded is not None else None
        obs = sp.observe_save(data, name, digest, rec)
        save_fields[name] = obs["fields"]
        saves_out.append({
            "name": name,
            "size": size,
            "sha256": digest,
            "pin": "matched",
            "fields": {fid: {"offset": f["offset"], "offset_hex": f["offset_hex"],
                             "value": f["value"], "role": f["role"],
                             "candidate_name": f.get("candidate_name"),
                             "matches_recorded_observation": f.get("matches_recorded_observation")}
                       for fid, f in obs["fields"].items()},
        })

    # Re-hash every input: a change during the run is refused, not reported as a result.
    for name, (size, sha) in list(save_pins.items()) + list(geo_pins.items()):
        if _sha((install / name).read_bytes()) != sha:
            raise CheckRefusal("%s changed during the run; nothing written" % name)

    candidates = []
    for name in sorted(save_fields):
        for oid, _, _ in ORDERINGS:
            candidates.append(_evaluate(name, save_fields[name], all_blocks, oid))

    id20 = [{"archive": b["archive"], "toc_index": b["toc_index"]}
            for b in all_blocks if b["block_id"] == HYPOTHESIS["block_id"]]
    search_complete = all(not a["skipped_blocks"] for a in archives)

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "playable": False,
        "runtime_established": False,
        "runtime_binding_claimed": False,
        "question": QUESTION,
        "hypothesis": dict(HYPOTHESIS, status=HYPOTHESIS_STATUS),
        "orderings": [{"id": oid, "description": d, "role": r} for oid, d, r in ORDERINGS],
        "signatures": [{"id": sid, "basis": b} for sid, b in SIGNATURES],
        "inputs": {"saves": saves_out, "archives": archives},
        "search_scope": {
            "archives": len(archives),
            "toc_entries": sum(a["toc_entries"] for a in archives),
            "decoded_blocks": len(all_blocks),
            "skipped_blocks": sum(len(a["skipped_blocks"]) for a in archives),
            "search_complete": search_complete,
        },
        "block_id_20_occurrences": id20,
        "candidates": candidates,
        "install_unchanged": True,
        "limitations": list(LIMITATIONS),
        "claim_boundary": CLAIM_BOUNDARY,
    }


def _edge_text(edges: dict) -> str:
    return ", ".join("%s (%d,%d)" % (k, edges[k][0], edges[k][1]) for k in pm.EDGES)


def render_report(doc: dict) -> str:
    L = [
        "# Pool of Radiance: save position vs GEO cell signature check",
        "",
        "Status: `%s`. `playable: false`. `runtime_established: false`. "
        "`runtime_binding_claimed: false`." % doc["status"],
        "",
        "## Question",
        "",
        doc["question"],
        "",
        "## 1. Directly observed saved bytes",
        "",
        "Six candidate bytes per pinned save. Values are observed; field roles are candidates.",
        "",
        "| Save | Field | Offset | Value | Matches recorded GoldBox reading |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for s in doc["inputs"]["saves"]:
        for fid, f in s["fields"].items():
            rec = f["matches_recorded_observation"]
            L.append("| %s | %s | %d (%s) | %d | %s |" % (
                s["name"], fid, f["offset"], f["offset_hex"], f["value"],
                "n/a" if rec is None else str(rec)))
    L += ["", "Facing candidate names (`0 north / 2 east / 4 south / 6 west`) are an unverified mapping.", ""]

    L += [
        "## 2. Decoded GEO cell bytes",
        "",
        "Cell (x, y) is read from the hypothesised block with row 0 north, as in "
        "`tools/por_map.py`. Edges are `(slot, door)`. Descriptor is plane 2, raw.",
        "",
    ]
    for c in doc["candidates"]:
        L.append("### %s, ordering `%s`" % (c["save"], c["ordering"]))
        L.append("")
        L.append("- Candidate position: x=%d, y=%d (in bounds: %s). Facing raw %d, candidate name `%s`, "
                 "candidate edge `%s`." % (c["x"], c["y"], c["in_bounds"], c["facing_raw"],
                                           c["facing_candidate"], c["facing_edge_candidate"]))
        cc = c["candidate_cell"]
        if cc is None:
            L.append("- Candidate cell: not available (see the signatures table).")
        else:
            L.append("- Candidate cell in `%s` TOC %d / block %d: %s; descriptor `0x%02X`."
                     % (cc["archive"], cc["toc_index"], cc["block_id"],
                        _edge_text(cc["edges"]), cc["descriptor"]))
        L.append("")

    L += [
        "## 3. Candidate join",
        "",
        "Hypothesised block: `%s` TOC index %d, block id %d. Status: %s." % (
            doc["hypothesis"]["archive"], doc["hypothesis"]["toc_index"],
            doc["hypothesis"]["block_id"], doc["hypothesis"]["status"]),
        "",
        "The join is a hypothesis. Matching a signature is compatibility evidence only, not a "
        "runtime binding. The check does not show which block the DOS game loaded.",
        "",
        "Block id %d occurs at: %s." % (doc["hypothesis"]["block_id"],
            ", ".join("%s TOC %d" % (o["archive"], o["toc_index"])
                      for o in doc["block_id_20_occurrences"]) or "nowhere"),
        "",
        "## 4. Search results",
        "",
        "| Save | Ordering | Signature | Matches | Same position | In hypothesised block | Distinct blocks | Verdict |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for c in doc["candidates"]:
        for sid, _ in SIGNATURES:
            s = c["signatures"][sid]
            L.append("| %s | %s | %s | %d | %d | %d | %d | `%s` |" % (
                c["save"], c["ordering"], sid, s["match_count"], s["same_position_match_count"],
                s.get("candidate_block_match_count", 0), len(s["distinct_blocks"]), s["verdict"]))
    L.append("")
    for c in doc["candidates"]:
        for sid, _ in SIGNATURES:
            s = c["signatures"][sid]
            if not s["evaluable"]:
                L.append("- %s / `%s` / %s: not evaluable: %s." % (c["save"], c["ordering"], sid, s["reason"]))
            elif s["distinct_blocks"]:
                blocks = "; ".join("%s TOC %d (id %d): %d" % (b["archive"], b["toc_index"],
                                                              b["block_id"], b["cell_matches"])
                                   for b in s["distinct_blocks"])
                L.append("- %s / `%s` / %s distinct blocks: %s." % (c["save"], c["ordering"], sid, blocks))
    L += ["", "## 5. Inputs and scope", ""]
    L += [
        "| Archive | Size | SHA-256 | TOC entries | Decoded | Skipped |",
        "| --- | ---: | --- | ---: | ---: | --- |",
    ]
    for a in doc["inputs"]["archives"]:
        skipped = ", ".join("TOC %d (id %d)" % (k["toc_index"], k["block_id"])
                            for k in a["skipped_blocks"]) or "none"
        L.append("| %s | %d | `%s` | %d | %d | %s |" % (
            a["name"], a["size"], a["sha256"], a["toc_entries"], a["decoded_blocks"], skipped))
    sc = doc["search_scope"]
    L += ["", "Search scope: %d archives, %d TOC entries, %d decoded blocks, %d skipped. "
              "`search_complete: %s`." % (sc["archives"], sc["toc_entries"], sc["decoded_blocks"],
                                          sc["skipped_blocks"], sc["search_complete"]),
          "", "Install unchanged during run: `%s`." % doc["install_unchanged"], ""]
    L += ["## 6. Hypothesis and claim limits", ""]
    L += ["- %s" % item for item in doc["limitations"]]
    L += ["", "## Claim boundary", "", doc["claim_boundary"], ""]
    return "\n".join(L)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_save_geo_candidate_check.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_save_geo_candidate_check_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", help="PoR install folder (default: $%s or %s)"
                    % (INSTALL_ENV, DEFAULT_INSTALL))
    ap.add_argument("-o", "--output", required=True,
                    help="output folder, explicitly under data/ (relative paths are from the repo root)")
    args = ap.parse_args(argv)
    install = Path(args.install or os.environ.get(INSTALL_ENV) or DEFAULT_INSTALL)
    out = Path(args.output)
    if not out.is_absolute():
        out = (REPO / out).resolve()
    try:
        doc = check(install, out)
    except CheckRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, out)
    sc = doc["search_scope"]
    print("saves: %d; archives: %d; decoded blocks: %d; skipped: %d; search_complete %s"
          % (len(doc["inputs"]["saves"]), sc["archives"], sc["decoded_blocks"],
             sc["skipped_blocks"], sc["search_complete"]))
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
