#!/usr/bin/env python3
"""Pool of Radiance GEO plane-2 observer: descriptive census and unresolved
hypotheses for the per-cell descriptor byte. OBSERVE-ONLY.

Status: this tool emits NOTHING. It has no cell-event, zone or flag output and
it does not assign any meaning to plane 2. It exists because the consumer of
the Gen1 GEO plane-2 byte (kept raw by tools/por_map.py, zeroed by
build_openua_geo) is not established by PoR-specific evidence; see
docs/por-geo-descriptor-probe.md. The tool records what the bytes look like and
which candidate readings are still open, with the observation that would
falsify each one.

What it does
  * Opens each GEO<n>.DAX strictly read-only (``"rb"``) through tools/por_map.py
    (parse_dax, rle_decode, decode_gen1_geo). Never writes to the install.
  * For every block that decodes to a valid 1026-byte Gen1 GEO block, records
    counts over the 256 plane-2 bytes: nonzero, bit 7 set, distinct raw values,
    distinct low-7 values, and how many nonzero cells lie on an all-open
    (no wall slot on any edge) versus a walled cell. Also a SHA-256 of the
    plane-2 slice and of the whole decoded block, so a reader can pin the bytes.
  * Checks a fixed list of cell values that earlier notes recorded, each tagged
    with its source tier. Greybox (GoldBox) entries are never treated as PoR
    evidence; they are reported as agreeing or disagreeing with the retail bytes
    and that is all.
  * Writes a deterministic JSON and a Markdown report to an output folder that is
    outside the install (and outside the repository unless under data/).

Usage
  python tools/por_geo_plane2_observe.py --install "G:/Games/Pool of Radiance/POOLRAD" \\
      -o data/work/por-geo-plane2-observe

Stdlib only, plus tools/por_map.py and tools/por_convert.py (read-only use).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

from por_convert import PorSourceError, validate_output_dir
import por_map as pm

SCHEMA = "openua.por-geo-plane2-observe"
SCHEMA_VERSION = 1
STATUS = "observe-only"

# (GEO archive, DAX block id, x, y, documented raw plane-2 value, source tier, note)
# Tier "retail-recorded" = an earlier OpenUA run on the retail install recorded it.
# Tier "goldbox-por-cross-check" = Pool-specific GoldBox route notes.
# They are consistent with PoR bytes but do not prove DOS dataflow or OpenUA binding.
ANCHORS = [
    (2, 20, 1, 5, 0x8E, "retail-recorded",
     "docs/por-converter.md: GEO2#20 (1,5) = 0x8e"),
    (8, 29, 7, 8, 0x02, "retail-recorded",
     "docs/por-converter.md: GEO8#29 (7,8) & 0x7f = 2"),
    (8, 29, 7, 7, 0x01, "retail-recorded",
     "docs/por-converter.md: GEO8#29 (7,7) & 0x7f = 1"),
    (1, 18, 14, 8, 0x86, "goldbox-por-cross-check",
     "GoldBox pool-natural-encounter-route.md: GEO1#18 (14,8) raw 0x86"),
    (2, 20, 13, 10, 0x83, "goldbox-por-cross-check",
     "GoldBox pool-natural-encounter-route.md: GEO2#20 (13,10) 0x83"),
]

# Candidate readings of the plane-2 byte. None is established. Each lists the
# observation that would falsify it. The tool does not test them: a test needs a
# runtime capture or a decoded consumer, neither of which exists here.
HYPOTHESES = [
    {"id": "H1", "reading": "raw plane-2 byte is the event/dispatch key for the cell",
     "falsifier": "a decoded consumer that reads buffer offset 514 + y*16 + x and "
                  "returns a different value, or a runtime capture where the value "
                  "written to DGROUP 0x6AB1 differs from plane 2 at the party cell",
     "settles_with": "decoded callee of the far call at seg 0x03D5 off 0x0034, or a "
                     "runtime capture of the 0x3A51-family store"},
    {"id": "H2", "reading": "low seven bits (plane2 & 0x7F) are the event/dispatch key",
     "falsifier": "the same as H1, plus a consumer that uses bit 7 in the lookup",
     "settles_with": "the same consumer decode as H1; ECL getter masks with 0x7F "
                     "(GAME.OVR:0x837A..0x840E) but the caller's use is unseen"},
    {"id": "H3", "reading": "bit 7 is a separate flag and low bits are an identifier",
     "falsifier": "a consumer that ignores bit 7, or a runtime capture where bit 7 "
                  "changes without the low bits changing",
     "settles_with": "a consumer decode, or paired runtime captures"},
    {"id": "H4", "reading": "nonzero plane 2 marks cells that carry a zone or backdrop",
     "falsifier": "a non-zero plane-2 value on an all-open cell that has no zone, or a "
                  "zone on a cell whose plane-2 byte is zero",
     "settles_with": "a zone table decode, or a runtime capture of zone state per cell"},
    {"id": "H5", "reading": "plane 2 is independent of the wall planes",
     "falsifier": "a repeatable cell-wise relation between plane-2 values and wall-edge "
                  "tuples across the decoded blocks",
     "settles_with": "a cell-wise cross-tabulation of plane-2 values against wall-edge "
                     "tuples; correlation alone would not establish semantics"},
]

NOT_CLAIMED = [
    "no cell-event, zone, flag or backdrop mapping is emitted",
    "no meaning is assigned to any plane-2 value or bit",
    "the consumer of plane 2 is not identified; hypotheses H1-H5 are untested",
    "the GoldBox route notes are PoR-specific external cross-checks only; they do not prove "
    "native DOS dataflow or OpenUA event binding",
    "counts describe the bytes; they say nothing about reachability in play",
    "no runtime capture, no DOSBox/GameLink, no emulator, no install write",
]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def observe_block(raw: bytes, cells: list[dict]) -> dict:
    p2 = [c["planes"][2] for c in cells]
    nz = [c for c in cells if c["planes"][2]]
    all_open = [c for c in nz if all(c["edges"][k][0] == 0 for k in "NESW")]
    return {
        "cells": len(cells),
        "plane2_nonzero": len(nz),
        "plane2_bit7_set": sum(1 for v in p2 if v & 0x80),
        "plane2_distinct_raw": len(set(p2)),
        "plane2_distinct_low7": len(set(v & 0x7F for v in p2)),
        "nonzero_on_all_open_cells": len(all_open),
        "nonzero_on_walled_cells": len(nz) - len(all_open),
        "plane2_sha256": _sha(bytes(p2)),
        "block_sha256": _sha(raw),
    }


def census(install: Path, geos: list[int]) -> tuple[list[dict], dict]:
    """Return (per-block records, pins). Never raises for a malformed block: it is
    recorded as ``error`` so the rest of the census still runs."""
    records: list[dict] = []
    pins: dict = {}
    # Block ids may repeat in a DAX. Preserve all matches so an anchor never
    # silently binds to the last duplicate; ambiguity is an observation too.
    lookup: dict[tuple[int, int], list[tuple[int, list[dict]]]] = {}
    for n in geos:
        dax = pm.resolve_geo(install, n)
        data = dax.read_bytes()
        pins["GEO%d.DAX" % n] = {"bytes": len(data), "sha256": _sha(data)}
        entries, base = pm.parse_dax(data)
        for e in entries:
            rec = {"geo": n, "toc_index": e.index, "block_id": e.block_id}
            try:
                comp = data[base + e.data_offset:base + e.data_offset + e.comp_size]
                raw = pm.rle_decode(comp, e.raw_size)
                cells = pm.decode_gen1_geo(raw)
            except pm.PorMapError as exc:
                rec["error"] = str(exc)
                records.append(rec)
                continue
            rec.update(observe_block(raw, cells))
            records.append(rec)
            lookup.setdefault((n, e.block_id), []).append((e.index, cells))
    anchors = []
    for geo, bid, x, y, want, tier, note in ANCHORS:
        matches = lookup.get((geo, bid), [])
        if not matches:
            anchors.append({"geo": geo, "block_id": bid, "x": x, "y": y,
                            "tier": tier, "note": note, "status": "block-not-found"})
            continue
        if len(matches) != 1:
            candidates = [{"toc_index": idx,
                           "observed": cells[y * pm.GRID_W + x]["planes"][2]}
                          for idx, cells in matches]
            anchors.append({"geo": geo, "block_id": bid, "x": x, "y": y,
                            "documented": want, "tier": tier, "note": note,
                            "status": "ambiguous-block-id", "candidates": candidates})
            continue
        toc_index, cells = matches[0]
        got = cells[y * pm.GRID_W + x]["planes"][2]
        anchors.append({"geo": geo, "block_id": bid, "x": x, "y": y,
                        "toc_index": toc_index, "documented": want,
                        "observed": got, "tier": tier,
                        "note": note,
                        "status": "agrees" if got == want else "disagrees"})
    return records, {"files": pins, "anchors": anchors}


def build_result(install: Path, geos: list[int]) -> dict:
    records, extra = census(install, geos)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "emitted": [],
        "mappings": [],
        "install_folder": "PoR install (path not recorded)",
        "geos": geos,
        "pins": extra["files"],
        "blocks": records,
        "anchors": extra["anchors"],
        "hypotheses": HYPOTHESES,
        "not_claimed": NOT_CLAIMED,
    }


def render_report(res: dict) -> str:
    lines = ["# PoR GEO plane-2 observation (observe-only)", "",
             "**Status: observe-only. `emitted: []`, `mappings: []`.** No meaning is assigned "
             "to plane 2. See the hypotheses below; none is tested here.", "",
             "## Blocks", "",
             "| GEO | TOC idx | block id | nonzero | bit7 | distinct raw | distinct low7 | "
             "nonzero on open cells | nonzero on walled cells | plane2 sha256 (12) |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for b in res["blocks"]:
        if "error" in b:
            lines.append("| %d | %d | %d | error: %s | | | | | | |"
                         % (b["geo"], b["toc_index"], b["block_id"], b["error"]))
            continue
        lines.append("| %d | %d | %d | %d | %d | %d | %d | %d | %d | %s |" % (
            b["geo"], b["toc_index"], b["block_id"], b["plane2_nonzero"],
            b["plane2_bit7_set"], b["plane2_distinct_raw"], b["plane2_distinct_low7"],
            b["nonzero_on_all_open_cells"], b["nonzero_on_walled_cells"],
            b["plane2_sha256"][:12]))
    lines += ["", "## Anchors (cross-checks, not evidence of a rule)", "",
              "| GEO | block | cell | documented | observed | tier | status |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for a in res["anchors"]:
        if a.get("status") == "ambiguous-block-id":
            candidates = ", ".join("idx %d: 0x%02X" %
                                    (c["toc_index"], c["observed"])
                                    for c in a["candidates"])
            lines.append("| %d | %d | (%d,%d) | 0x%02X | %s | %s | %s |" % (
                a["geo"], a["block_id"], a["x"], a["y"], a["documented"],
                candidates, a["tier"], a["status"]))
            continue
        if "observed" not in a:
            lines.append("| %d | %d | (%d,%d) | | | %s | %s |" % (
                a["geo"], a["block_id"], a["x"], a["y"], a["tier"], a["status"]))
            continue
        lines.append("| %d | %d | (%d,%d) | 0x%02X | 0x%02X | %s | %s |" % (
            a["geo"], a["block_id"], a["x"], a["y"], a["documented"], a["observed"],
            a["tier"], a["status"]))
    lines += ["", "## Unresolved hypotheses (not tested)", ""]
    for h in res["hypotheses"]:
        lines.append("- **%s** %s. Falsifier: %s. Settles with: %s."
                     % (h["id"], h["reading"], h["falsifier"], h["settles_with"]))
    lines += ["", "## Not claimed", ""] + ["- " + s for s in res["not_claimed"]] + [""]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Observe PoR GEO plane-2 bytes (observe-only; emits nothing).")
    ap.add_argument("--install", required=True, type=Path,
                    help="PoR DOS folder (or its POOLRAD subfolder); read-only")
    ap.add_argument("--geo", type=int, action="append", choices=range(1, 9),
                    help="GEO number; repeatable; default 1..8")
    ap.add_argument("-o", "--out", required=True, type=Path,
                    help="output folder (outside the install)")
    args = ap.parse_args(argv)
    geos = sorted(set(args.geo)) if args.geo else list(range(1, 9))
    try:
        out = validate_output_dir(args.install, args.out)
        res = build_result(args.install, geos)
    except (pm.PorMapError, PorSourceError) as exc:
        print("por_geo_plane2_observe: error: %s" % exc, file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_plane2_observe.json").write_text(
        json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_geo_plane2_observe.md").write_text(render_report(res), encoding="utf-8")
    print("por_geo_plane2_observe: wrote %s (observe-only, emitted=0)" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
