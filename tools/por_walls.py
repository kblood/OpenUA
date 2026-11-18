#!/usr/bin/env python3
"""Pool of Radiance dungeon wall census, slice 4: GEO wall slots x WALLDEF
block inventory x 8X8D inventory, with explicit per-slot binding status.

Status: CENSUS-ONLY. This tool does NOT bind any PoR wall slot to OpenUA art.
It reads an explicit, user-supplied PoR DOS install read-only and writes
machine-readable evidence:

  * every GEO<n>.DAX block (1026-byte Gen1 GEO, via por_map.decode_gen1_geo):
    edge-slot histogram (slot 0..15 over all four edges of every cell);
  * every WALLDEF<n>.DAX block: record count (780 bytes = one 5 x 156 record)
    and per-row min/max/distinct statistics. No tile bytes are written;
  * every 8X8D<n>.DAX block: TOC inventory only (tile banks are not decoded);
  * per area, a cross-reference of used slots against the WALLDEF archive and
    the documented "WALLDEF block B -> 8X8D blocks B*10+k" pairing candidates.

Binding policy (see docs/por-converter.md, "Slice 4"):
  * The Gen1 slot -> WALLDEF row/wallset arithmetic is recorded as an INDEX
    (row = (slot-1) % 5, wallset = (slot-1) // 5), taken from GoldBox's CoK
    evidence. It is not an art binding.
  * The WALLDEF block id that fills a wallset is NOT in the GEO data. In the
    Gen1 family it arrives through ECL LOAD_PIECES (0x37), which slice 3 does
    not decode for PoR. Every slot is therefore emitted with
    ``binding: null`` and ``binding_status: "unresolved"``.
  * OpenUA draws wall groups from its own FRUA wall sets (src/engine/boot.c,
    wall_slot_for_edge); no PoR tile -> FRUA art conversion exists.

Usage
  python3 tools/por_walls.py --install PATH/TO/POOLRAD -o data/por-walls/pool
  python3 tools/por_walls.py --install PATH/TO/POOLRAD -o OUT --area 2

Outputs in OUT (both deterministic, no timestamps, no absolute source paths):
  por_walls.json        schema openua.por-walls, version 1, playable: false
  por_walls_report.md   human-readable census and unresolved list

Exit codes: 0 census complete with no decode errors; 1 census written but at
least one archive or block failed to decode (see its "diagnostics"); 2 named
refusal (bad install folder, refused output location, bad argument).

The source is opened "rb" and never written. Stdlib only, plus the PoR DAX
helpers in tools/por_map.py and the output guard in tools/por_convert.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from por_convert import PorSourceError, validate_output_dir
from por_map import (PorMapError, decode_gen1_geo, parse_dax, rle_decode,
                     GEO_BLOCK_RAW)

SCHEMA = "openua.por-walls"
SCHEMA_VERSION = 1
STATUS = "census-only"
TOOL = "tools/por_walls.py"

WALLDEF_RECORD = 780          # 5 rows x 156 columns, GoldBox firstperson-wall-geometry-cok.md
WALLDEF_ROWS = 5
WALLDEF_COLS = 156
SLOT_MAX = 15
AREAS = tuple(range(1, 9))
FAMILIES = ("GEO", "WALLDEF", "8X8D")
DEFAULT_AREAS = AREAS

# Stable reason codes attached to every unresolved slot (machine-readable).
REASON_BLOCK_ID = "walldef-block-id-not-in-geo"
REASON_TILE_ART = "pool-slot-to-tile-art-unverified"
REASON_OPENUA_ART = "openua-draws-frua-wallsets"
SLOT_REASONS = (REASON_BLOCK_ID, REASON_TILE_ART, REASON_OPENUA_ART)

UNSUPPORTED = [
    {"code": "no-art-binding",
     "message": "No PoR wall slot is bound to an OpenUA texture group or FRUA "
                "art. Every slot is emitted as unresolved."},
    {"code": "walldef-block-id-source",
     "message": "The WALLDEF block id that fills each wallset is not stored in "
                "GEO. In the Gen1 family it is set by ECL LOAD_PIECES, which is "
                "not decoded for PoR (see docs/por-ecl-decoder.md)."},
    {"code": "tile-bank-not-decoded",
     "message": "8X8D tile banks are inventoried by TOC only. Tile pixels are not "
                "decoded, so no tile is compared with any art."},
    {"code": "no-events-text-monsters-items",
     "message": "Only the dungeon wall census is produced. Nothing is emitted for "
                "events, text, monsters, items, or campaign logic."},
]

_CLAIMS = [
    ("GEO block: 1026 bytes, size field 1024, four planes, slot = low/high nibble",
     "documented Gen1 decode; validated on GEO2#20 and GEO8#29 (por_map --expect)"),
    ("slot -> (row, wallset) arithmetic: row=(slot-1)%5, wallset=(slot-1)//5",
     "CoK/COAB source via GoldBox docs; not checked against PoR art"),
    ("WALLDEF record = 780 bytes = 5 x 156",
     "CoK/COAB source; PoR block sizes are all multiples of 780 (census)"),
    ("WALLDEF block B with k records pairs with 8X8D B*10+1..B*10+k (k>1), or 8X8D B (k=1)",
     "CoK/COAB LoadWalldef rule; candidates only, not verified for PoR"),
    ("slot -> OpenUA group/facet index", "OpenUA boot.c wall_slot_for_edge; an index, not art"),
    ("slot -> PoR art, slot -> OpenUA texture group", "NOT ESTABLISHED; every slot is unresolved"),
]


class WallCensusError(PorMapError):
    """A named error for a single archive or block. The census continues."""


# --------------------------------------------------------------------------
# Locating archives (read-only; no symlinks followed)
# --------------------------------------------------------------------------

def resolve_archive(install: Path, stem: str, n: int) -> Optional[Path]:
    """Find ``<stem><n>.DAX`` directly in ``install`` or its POOLRAD subfolder,
    case-insensitively. Returns None when absent. Ambiguity is an error."""
    want = ("%s%d.DAX" % (stem, n)).upper()
    found: list[Path] = []
    for folder in (install, install / "POOLRAD"):
        if not folder.is_dir():
            continue
        with os.scandir(folder) as it:
            for entry in it:
                if entry.name.upper() == want and entry.is_file(follow_symlinks=False):
                    found.append(Path(entry.path))
    if len(found) > 1:
        raise PorMapError("%s is ambiguous: found in more than one folder" % want)
    return found[0] if found else None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _block_bytes(data: bytes, base: int, entry) -> bytes:
    start = base + entry.data_offset
    return data[start:start + entry.comp_size]


# --------------------------------------------------------------------------
# Per-archive census
# --------------------------------------------------------------------------

def census_geo(path: Path) -> dict:
    """Edge-slot histogram for every Gen1 GEO block in an archive."""
    data = path.read_bytes()
    entries, base = parse_dax(data)
    blocks = []
    for e in entries:
        rec = {"toc_index": e.index, "block_id": e.block_id,
               "raw_size": e.raw_size, "comp_size": e.comp_size}
        try:
            raw = rle_decode(_block_bytes(data, base, e), e.raw_size)
            if len(raw) != GEO_BLOCK_RAW:
                raise WallCensusError("GEO block decodes to %d bytes, expected %d"
                                      % (len(raw), GEO_BLOCK_RAW))
            cells = decode_gen1_geo(raw)
        except PorMapError as exc:
            rec["status"] = "error"
            rec["message"] = str(exc)
            blocks.append(rec)
            continue
        counts = Counter()
        for cell in cells:
            for slot, _door in cell["edges"].values():
                counts[slot] += 1
        rec["status"] = "ok"
        rec["decoded_sha256"] = _sha(raw)
        rec["edge_slot_counts"] = {str(s): counts.get(s, 0) for s in range(SLOT_MAX + 1)}
        rec["slots_used"] = [s for s in range(1, SLOT_MAX + 1) if counts.get(s, 0)]
        rec["wallsets_used"] = sorted({(s - 1) // 5 for s in rec["slots_used"]})
        blocks.append(rec)
    return {"file": path.name, "sha256": _sha(data), "bytes": len(data),
            "toc_entries": len(entries), "blocks": blocks}


def _walldef_rows(seg_record: bytes) -> list[dict]:
    rows = []
    for r in range(WALLDEF_ROWS):
        seg = seg_record[r * WALLDEF_COLS:(r + 1) * WALLDEF_COLS]
        rows.append({"row": r, "min": min(seg), "max": max(seg),
                     "distinct": len(set(seg))})
    return rows


def census_walldef(path: Path) -> dict:
    """Record counts and per-row statistics for each WALLDEF block. No tile
    bytes are kept in the output; only counts, ranges and hashes."""
    data = path.read_bytes()
    entries, base = parse_dax(data)
    blocks = []
    for e in entries:
        rec = {"toc_index": e.index, "block_id": e.block_id,
               "raw_size": e.raw_size, "comp_size": e.comp_size}
        try:
            raw = rle_decode(_block_bytes(data, base, e), e.raw_size)
            if len(raw) % WALLDEF_RECORD:
                raise WallCensusError("WALLDEF block %d is %d bytes, not a multiple of %d"
                                      % (e.block_id, len(raw), WALLDEF_RECORD))
        except PorMapError as exc:
            rec["status"] = "error"
            rec["message"] = str(exc)
            blocks.append(rec)
            continue
        records = []
        for i in range(len(raw) // WALLDEF_RECORD):
            seg = raw[i * WALLDEF_RECORD:(i + 1) * WALLDEF_RECORD]
            records.append({"record": i, "rows": _walldef_rows(seg)})
        rec["status"] = "ok"
        rec["decoded_sha256"] = _sha(raw)
        rec["records"] = len(records)
        rec["record_stats"] = records
        blocks.append(rec)
    return {"file": path.name, "sha256": _sha(data), "bytes": len(data),
            "toc_entries": len(entries), "blocks": blocks}


def inventory_8x8d(path: Path) -> dict:
    """TOC-only inventory. Tile banks are not decoded here."""
    data = path.read_bytes()
    entries, _base = parse_dax(data)
    blocks = [{"toc_index": e.index, "block_id": e.block_id,
               "raw_size": e.raw_size, "comp_size": e.comp_size,
               "status": "not-decoded"} for e in entries]
    return {"file": path.name, "sha256": _sha(data), "bytes": len(data),
            "toc_entries": len(entries), "blocks": blocks}


# --------------------------------------------------------------------------
# Cross-reference per area
# --------------------------------------------------------------------------

def slot_index(slot: int) -> dict:
    """Index arithmetic only. Not an art binding."""
    return {"walldef_row": (slot - 1) % 5, "walldef_wallset": (slot - 1) // 5,
            "openua_group": (slot - 1) // 5, "openua_facet": (slot - 1) % 5}


def cross_reference(area: int, geo: Optional[dict], wd: Optional[dict],
                    x8: Optional[dict]) -> dict:
    out = {"area": area,
           "geo_file": geo["file"] if geo else None,
           "walldef_file": wd["file"] if wd else None,
           "8x8d_file": x8["file"] if x8 else None}

    totals: Counter = Counter()
    blocks_using: Counter = Counter()
    if geo:
        for b in geo["blocks"]:
            if b.get("status") != "ok":
                continue
            for s, c in b["edge_slot_counts"].items():
                if int(s) >= 1 and c:
                    totals[int(s)] += c
                    blocks_using[int(s)] += 1
    slots = []
    for s in range(1, SLOT_MAX + 1):
        if not totals[s]:
            continue
        rec = {"slot": s, "edges": totals[s], "geo_blocks_using": blocks_using[s]}
        rec.update(slot_index(s))
        rec["binding"] = None
        rec["binding_status"] = "unresolved"
        rec["unresolved_reasons"] = list(SLOT_REASONS)
        slots.append(rec)
    out["slots"] = slots

    wd_ok = []
    if wd:
        wd_ok = [b for b in wd["blocks"] if b.get("status") == "ok"]
    out["walldef_block_ids"] = [b["block_id"] for b in wd_ok]

    ids8 = set()
    if x8:
        ids8 = {b["block_id"] for b in x8["blocks"]}
    pairing = []
    for b in wd_ok:
        k = b["records"]
        cands = ([b["block_id"] * 10 + j for j in range(1, k + 1)] if k > 1
                 else [b["block_id"]])
        present = [c for c in cands if c in ids8]
        pairing.append({"walldef_block": b["block_id"], "records": k,
                        "candidate_8x8d_ids": cands,
                        "present_8x8d_ids": present,
                        "all_present": len(present) == len(cands),
                        "evidence": "CoK/COAB LoadWalldef rule; not verified for PoR"})
    out["pairing_candidates"] = pairing

    missing = []
    if geo is None:
        missing.append("GEO%d.DAX" % area)
    if wd is None:
        missing.append("WALLDEF%d.DAX" % area)
    if x8 is None:
        missing.append("8X8D%d.DAX" % area)
    out["missing_archives"] = missing
    return out


# --------------------------------------------------------------------------
# Whole census
# --------------------------------------------------------------------------

def _census_family(install: Path, family: str, n: int) -> tuple[Optional[dict], Optional[str]]:
    """Return (archive census or None, error message or None). A container
    that fails to parse yields (None, message): it is reported as a diagnostic
    and treated as absent for cross-referencing."""
    path = resolve_archive(install, family, n)
    if path is None:
        return None, None
    try:
        if family == "GEO":
            return census_geo(path), None
        if family == "WALLDEF":
            return census_walldef(path), None
        return inventory_8x8d(path), None
    except PorMapError as exc:
        return None, "%s: %s" % (path.name, exc)


def census(install: Path, out: Path, areas: tuple[int, ...] = DEFAULT_AREAS) -> dict:
    if not install.is_dir():
        raise PorSourceError("install folder not found")
    out = validate_output_dir(install, out)

    archives: dict[str, dict[int, dict]] = {}
    diagnostics: list[dict] = []
    absent: list[dict] = []
    per_area: list[dict] = []
    for n in areas:
        archives[n] = {}
        for fam in FAMILIES:
            if resolve_archive(install, fam, n) is None:
                absent.append({"area": n, "family": fam, "file": "%s%d.DAX" % (fam, n)})
            census_obj, err = _census_family(install, fam, n)
            if census_obj is not None:
                archives[n][fam] = census_obj
            if err is not None:
                diagnostics.append({"code": "archive-container-error", "area": n,
                                    "family": fam, "message": err})
            if census_obj is not None:
                for b in census_obj.get("blocks", []):
                    if b.get("status") == "error":
                        diagnostics.append({"code": "block-error", "area": n,
                                            "family": fam, "file": census_obj["file"],
                                            "block_id": b["block_id"],
                                            "toc_index": b["toc_index"],
                                            "message": b["message"]})

    global_slots: Counter = Counter()
    for n in areas:
        xref = cross_reference(n, archives[n].get("GEO"),
                               archives[n].get("WALLDEF"),
                               archives[n].get("8X8D"))
        per_area.append(xref)
        for s in xref["slots"]:
            global_slots[s["slot"]] += s["edges"]

    summary = {
        "areas_requested": list(areas),
        "archives_present": sum(len(archives[n]) for n in areas),
        "archives_absent": len(absent),
        "geo_blocks_ok": sum(1 for n in areas if "GEO" in archives[n]
                             for b in archives[n]["GEO"]["blocks"] if b.get("status") == "ok"),
        "geo_blocks_error": sum(1 for n in areas if "GEO" in archives[n]
                                for b in archives[n]["GEO"]["blocks"] if b.get("status") == "error"),
        "walldef_blocks_ok": sum(1 for n in areas if "WALLDEF" in archives[n]
                                 for b in archives[n]["WALLDEF"]["blocks"] if b.get("status") == "ok"),
        "walldef_records": sum(b.get("records", 0) for n in areas if "WALLDEF" in archives[n]
                               for b in archives[n]["WALLDEF"]["blocks"] if b.get("status") == "ok"),
        "slots_used_total_edges": {str(s): global_slots[s] for s in sorted(global_slots)},
        "slots_bound": 0,
        "slots_unresolved": sum(len(a["slots"]) for a in per_area),
    }

    # Archive provenance: file name, sha256, byte count, TOC size. No paths.
    provenance = []
    for n in areas:
        for fam in FAMILIES:
            obj = archives[n].get(fam)
            if obj is None:
                continue
            provenance.append({"area": n, "family": fam, "file": obj["file"],
                               "sha256": obj["sha256"], "bytes": obj["bytes"],
                               "toc_entries": obj["toc_entries"],
                               "status": obj.get("status", "ok")})

    norm = {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "tool": TOOL,
        "binding_policy": ("No PoR wall slot is bound to OpenUA art. Each slot is "
                           "unresolved; the index arithmetic is recorded only."),
        "claims": [{"claim": c, "evidence": e} for c, e in _CLAIMS],
        "provenance": provenance,
        "absent": absent,
        "per_area": per_area,
        "summary": summary,
        "diagnostics": diagnostics,
        "unsupported": UNSUPPORTED,
        "_archives": archives,
    }
    return {"norm": norm, "out": out}


def _render_report(norm: dict) -> str:
    s = norm["summary"]
    lines = [
        "# Pool of Radiance wall census (slice 4)",
        "",
        "**CENSUS-ONLY. `playable: false`.** No PoR wall slot is bound to OpenUA art.",
        "Every slot below is UNRESOLVED. Nothing here is a playable conversion.",
        "",
        "## Summary",
        "",
        "| Item | Value |",
        "| --- | --- |",
        "| archives present | %d |" % s["archives_present"],
        "| archives absent | %d |" % s["archives_absent"],
        "| GEO blocks ok / error | %d / %d |" % (s["geo_blocks_ok"], s["geo_blocks_error"]),
        "| WALLDEF blocks ok | %d (%d records) |" % (s["walldef_blocks_ok"], s["walldef_records"]),
        "| slots bound | %d |" % s["slots_bound"],
        "| slot rows unresolved | %d |" % s["slots_unresolved"],
        "",
        "## Archives",
        "",
        "| Area | Family | File | SHA-256 | Bytes | TOC entries | Status |",
        "| --- | --- | --- | --- | --: | --: | --- |",
    ]
    for p in norm["provenance"]:
        lines.append("| %d | %s | %s | `%s` | %d | %d | %s |"
                     % (p["area"], p["family"], p["file"], p["sha256"],
                        p["bytes"], p["toc_entries"], p["status"]))
    if norm["absent"]:
        lines += ["", "Absent: " + ", ".join(a["file"] for a in norm["absent"])]

    lines += ["", "## Slot cross-reference (per area)", "",
              "| Area | Slot | Edges | GEO blocks | WALLDEF row | WALLDEF wallset | "
              "OpenUA group/facet (index only) | Binding |",
              "| --: | --: | --: | --: | --: | --: | --- | --- |"]
    for a in norm["per_area"]:
        for r in a["slots"]:
            lines.append("| %d | %d | %d | %d | %d | %d | %d / %d | %s (%s) |"
                         % (a["area"], r["slot"], r["edges"], r["geo_blocks_using"],
                            r["walldef_row"], r["walldef_wallset"],
                            r["openua_group"], r["openua_facet"],
                            "none", r["binding_status"]))

    lines += ["", "## WALLDEF blocks and 8X8D pairing candidates", "",
              "Pairing is the CoK/COAB rule (B*10+k), recorded as a candidate only.", ""]
    for a in norm["per_area"]:
        wd = norm["_archives"].get(a["area"], {}).get("WALLDEF")
        if wd is None:
            continue
        lines.append("### Area %d (%s)" % (a["area"], wd["file"]))
        lines += ["", "| WALLDEF block | Records | Candidate 8X8D ids | Present | All present |",
                  "| --: | --: | --- | --- | --- |"]
        for p in a["pairing_candidates"]:
            lines.append("| %d | %d | %s | %s | %s |"
                         % (p["walldef_block"], p["records"],
                            ", ".join(str(c) for c in p["candidate_8x8d_ids"]),
                            ", ".join(str(c) for c in p["present_8x8d_ids"]) or "-",
                            "yes" if p["all_present"] else "no"))
        lines.append("")

    if norm["diagnostics"]:
        lines += ["## Diagnostics", ""]
        for d in norm["diagnostics"]:
            lines.append("- area %s %s: %s" % (d.get("area"), d.get("file", d.get("family")),
                                                d["message"]))
        lines.append("")

    lines += ["## Claims and evidence", "", "| Claim | Evidence |", "| --- | --- |"]
    for c in norm["claims"]:
        lines.append("| %s | %s |" % (c["claim"], c["evidence"]))
    lines += ["", "## Unsupported and unresolved", ""]
    for u in norm["unsupported"]:
        lines.append("- `%s`: %s" % (u["code"], u["message"]))
    lines += ["", "## Next evidence needed", "",
              "- The WALLDEF block id per wallset for each PoR area. This needs a "
              "decoded PoR ECL LOAD_PIECES (0x37) operand table.",
              "- A PoR screen-to-tile reference, so that a WALLDEF tile id can be "
              "checked against the art it draws.",
              "- A PoR 8X8D tile-bank decode, checked against that reference.",
              "- Only then a per-slot OpenUA texture group. The data does not yet "
              "establish one.", ""]
    return "\n".join(lines)


def write_outputs(result: dict) -> None:
    norm, out = result["norm"], result["out"]
    out.mkdir(parents=True, exist_ok=True)
    # The per-archive table is an internal aid; keep the JSON free of it.
    public = {k: v for k, v in norm.items() if not k.startswith("_")}
    (out / "por_walls.json").write_text(
        json.dumps(public, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_walls_report.md").write_text(_render_report(norm), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance wall census: GEO slots x WALLDEF x 8X8D (slice 4).")
    ap.add_argument("--install", type=Path, required=True,
                    help="explicit PoR DOS folder (or its POOLRAD subfolder); read-only")
    ap.add_argument("-o", "--out", type=Path, required=True,
                    help="output folder (outside the source; under data/ in the repo)")
    ap.add_argument("--area", type=int, choices=AREAS, action="append",
                    help="limit to one area (repeatable); default all 1..8")
    args = ap.parse_args(argv)
    areas = tuple(sorted(set(args.area))) if args.area else DEFAULT_AREAS
    try:
        result = census(args.install, args.out, areas)
    except (PorMapError, PorSourceError) as exc:
        print("por_walls: error: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(result)
    norm = result["norm"]
    print("por_walls: wrote %s and %s" % (result["out"] / "por_walls.json",
                                         result["out"] / "por_walls_report.md"))
    print("por_walls: CENSUS-ONLY, playable: false; %d slot rows, all unresolved"
          % norm["summary"]["slots_unresolved"])
    for d in norm["diagnostics"]:
        print("por_walls: diagnostic: %s" % d["message"], file=sys.stderr)
    return 1 if norm["diagnostics"] else 0


if __name__ == "__main__":
    sys.exit(main())
