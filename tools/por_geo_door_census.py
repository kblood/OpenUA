#!/usr/bin/env python3
"""Pool of Radiance GEO door-flag census (static, read-only).

Status: CENSUS-ONLY. This tool counts what the retail door flags (plane 3,
2 bits per edge) look like across every 1026-byte Gen1 GEO block of one
install. It does NOT decide what a flag does in play, does NOT change the
edge mapping in tools/por_map.py, and claims no playable module. Its counts
can show whether a value is common, rare, one-sided or agreed across a shared
edge. They cannot show that a value passes or blocks the party. See
docs/por-geo-door-semantics.md for the evidence gaps.

Reads the install's GEO*.DAX files (in the folder or its POOLRAD subfolder)
strictly read-only. It sha256-pins each file before and after the scan and
refuses to write a report if any file changed. It writes only to an explicit
output folder, which must lie outside the install (see por_convert).

Usage
  python3 tools/por_geo_door_census.py --install "G:/Games/Pool of Radiance" \\
      -o data/work/por-geo-door-census

Stdlib only. Decodes with tools/por_map.py so the census and the converter
read blocks identically.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from por_convert import PorSourceError, validate_output_dir
import por_map as pm

SCHEMA = "openua.por-geo-door-census"
SCHEMA_VERSION = 1
STATUS = "census-only"
TOOL = "tools/por_geo_door_census.py"
GEO_NAME_RE = re.compile(r"GEO(\d+)\.DAX", re.IGNORECASE)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pair_key(a: int, b: int) -> str:
    lo, hi = sorted((a, b))
    return "%d-%d" % (lo, hi)


def census_cells(blocks: list[list[dict]]) -> dict:
    """Count door values over a list of decoded blocks (each a list of cell
    records from pm.decode_gen1_geo).

    edge_door        every edge, by door value 0..3
    edge_door_slot0  edges whose wall slot is 0, by door value
    edge_door_wall   edges whose wall slot is nonzero, by door value
    shared_both_walls  shared interior edges where both sides have a nonzero
                       slot, keyed by the sorted pair of door values
    shared_some_open   shared interior edges where at least one side has
                       slot 0, keyed the same way
    slot_mismatch      shared interior edges whose two stored slots differ,
                       keyed the same way (context for one-sidedness)
    """
    edge_door: Counter = Counter()
    edge_door_slot0: Counter = Counter()
    edge_door_wall: Counter = Counter()
    shared_both: Counter = Counter()
    shared_some_open: Counter = Counter()
    slot_mismatch: Counter = Counter()
    for cells in blocks:
        by = {(c["x"], c["y"]): c for c in cells}
        for c in cells:
            for k in pm.EDGES:
                slot, door = c["edges"][k]
                edge_door[door] += 1
                (edge_door_slot0 if slot == 0 else edge_door_wall)[door] += 1
        for (x, y), c in by.items():
            pairs = []
            if x + 1 < pm.GRID_W:
                pairs.append((c["edges"]["E"], by[(x + 1, y)]["edges"]["W"]))
            if y + 1 < pm.GRID_H:
                pairs.append((c["edges"]["S"], by[(x, y + 1)]["edges"]["N"]))
            for (sa, da), (sb, db) in pairs:
                key = pair_key(da, db)
                (shared_both if (sa and sb) else shared_some_open)[key] += 1
                if sa != sb:
                    slot_mismatch[key] += 1
    agree_both = sum(v for k, v in shared_both.items() if k.split("-")[0] == k.split("-")[1])
    agree_open = sum(v for k, v in shared_some_open.items() if k.split("-")[0] == k.split("-")[1])
    return {
        "cells": sum(len(c) for c in blocks),
        "edge_door": _sorted_counts(edge_door),
        "edge_door_slot0": _sorted_counts(edge_door_slot0),
        "edge_door_wall": _sorted_counts(edge_door_wall),
        "shared_both_walls": _sorted_pairs(shared_both),
        "shared_some_open": _sorted_pairs(shared_some_open),
        "slot_mismatch": _sorted_pairs(slot_mismatch),
        "shared_both_walls_total": sum(shared_both.values()),
        "shared_both_walls_door_agree": agree_both,
        "shared_some_open_total": sum(shared_some_open.values()),
        "shared_some_open_door_agree": agree_open,
    }


def _sorted_counts(c: Counter) -> dict:
    return {str(k): c[k] for k in sorted(c)}


def _sorted_pairs(c: Counter) -> dict:
    return {k: c[k] for k in sorted(c)}


def find_geo_files(install: Path) -> list[Path]:
    """GEO<n>.DAX directly in install or in its POOLRAD subfolder, matched
    case-insensitively, sorted by number. A duplicate name is an error."""
    found: dict[str, Path] = {}
    for folder in (install, install / "POOLRAD"):
        if not folder.is_dir():
            continue
        with os.scandir(folder) as it:
            for entry in it:
                if not entry.is_file() or not GEO_NAME_RE.fullmatch(entry.name):
                    continue
                key = entry.name.upper()
                if key in found:
                    raise pm.PorMapError("%s appears twice: %s and %s"
                                         % (key, found[key], entry.path))
                found[key] = Path(entry.path)
    if not found:
        raise pm.PorMapError("no GEO<n>.DAX under %s (or its POOLRAD subfolder)" % install)
    return [found[k] for k in sorted(found, key=lambda n: int(GEO_NAME_RE.fullmatch(n).group(1)))]


def scan(install: Path) -> dict:
    """Pin, decode and re-pin every GEO file. Read-only."""
    files = find_geo_files(install)
    before = {f.name: _sha(f.read_bytes()) for f in files}

    blocks: list[list[dict]] = []
    per_file = []
    skipped = []
    errors = []
    for f in files:
        data = f.read_bytes()
        try:
            entries, base = pm.parse_dax(data)
        except pm.PorMapError as exc:
            errors.append("%s: %s" % (f.name, exc))
            continue
        used = 0
        for te in entries:
            if te.raw_size != pm.GEO_BLOCK_RAW:
                skipped.append({"file": f.name, "toc_index": te.index,
                                "block_id": te.block_id, "raw_size": te.raw_size})
                continue
            start = base + te.data_offset
            comp = data[start:start + te.comp_size]
            try:
                raw = pm.rle_decode(comp, te.raw_size)
                cells = pm.decode_gen1_geo(raw)
            except pm.PorMapError as exc:
                errors.append("%s block %d (toc %d): %s"
                              % (f.name, te.block_id, te.index, exc))
                continue
            blocks.append(cells)
            used += 1
        per_file.append({"file": f.name, "sha256": before[f.name],
                         "bytes": len(data), "toc_entries": len(entries),
                         "geo_blocks_decoded": used})

    after = {f.name: _sha(f.read_bytes()) for f in files}
    if after != before:
        raise pm.PorMapError("install changed during the census; no report written")

    return {
        "pins": {"before": before, "after": after, "unchanged": True},
        "files": per_file,
        "blocks_decoded": len(blocks),
        "skipped_non_geo_blocks": skipped,
        "errors": errors,
        "census": census_cells(blocks),
    }


def render_md(result: dict) -> str:
    c = result["census"]
    lines = [
        "# Pool of Radiance GEO door-flag census (CENSUS-ONLY)",
        "",
        "**Status: CENSUS-ONLY.** Counts door-flag values only. It does not show what a",
        "flag does in play and changes no mapping. See `docs/por-geo-door-semantics.md`.",
        "",
        "## Pins (read-only; unchanged across the scan)",
        "",
        "| file | sha256 | bytes | TOC entries | GEO blocks decoded |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in result["files"]:
        lines.append("| %s | `%s` | %d | %d | %d |" % (f["file"], f["sha256"], f["bytes"],
                                                      f["toc_entries"], f["geo_blocks_decoded"]))
    lines += [
        "",
        "## Door values over all edges",
        "",
        "- all edges: %s" % _fmt(c["edge_door"]),
        "- slot 0 (no wall graphic): %s" % _fmt(c["edge_door_slot0"]),
        "- slot nonzero (wall): %s" % _fmt(c["edge_door_wall"]),
        "",
        "## Shared interior edges (door pair, sorted)",
        "",
        "- both sides have a wall slot: %s" % _fmt(c["shared_both_walls"]),
        "  - total %d, door values agree %d"
        % (c["shared_both_walls_total"], c["shared_both_walls_door_agree"]),
        "- at least one side slot 0: %s" % _fmt(c["shared_some_open"]),
        "  - total %d, door values agree %d"
        % (c["shared_some_open_total"], c["shared_some_open_door_agree"]),
        "- stored slots differ: %s" % _fmt(c["slot_mismatch"]),
        "",
        "## Refusals and skips",
        "",
        "- non-1026-byte TOC entries skipped: %d" % len(result["skipped_non_geo_blocks"]),
        "- errors: %d" % len(result["errors"]),
    ]
    lines += ["- %s" % e for e in result["errors"]]
    lines.append("")
    return "\n".join(lines)


def _fmt(d: dict) -> str:
    return ", ".join("%s: %s" % (k, v) for k, v in d.items()) or "none"


def write_report(result: dict, out: Path) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    j = out / "por_geo_door_census.json"
    m = out / "por_geo_door_census.md"
    doc = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS,
           "tool": TOOL, "playable": False, **result}
    j.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    m.write_text(render_md(result), encoding="utf-8")
    return j, m


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Read-only census of Pool of Radiance GEO door flags (census-only).")
    ap.add_argument("--install", required=True, type=Path,
                    help="explicit PoR DOS folder (or its POOLRAD subfolder)")
    ap.add_argument("-o", "--out", required=True, type=Path,
                    help="output folder, outside the install")
    args = ap.parse_args(argv)
    try:
        out = validate_output_dir(args.install, args.out)
        result = scan(args.install)
        j, m = write_report(result, out)
    except (pm.PorMapError, PorSourceError) as exc:
        print("por_geo_door_census: error: %s" % exc, file=sys.stderr)
        return 2
    print("por_geo_door_census: wrote %s and %s" % (j, m))
    return 0


if __name__ == "__main__":
    sys.exit(main())
