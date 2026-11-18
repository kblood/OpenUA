#!/usr/bin/env python3
"""Pool of Radiance -> OpenUA map converter, slice 2: one GEO block -> a
map-only FRUA design.

Status: MAP-ONLY. This tool reads one Gen1 GEO block out of an explicit
user-supplied DAX file, validates it, writes a normalized map (JSON) and a
human report, and optionally assembles a local ``<NAME>.DSN`` design folder
whose single area carries that block's walls. It emits NO events, text,
monsters, items, art bindings or campaign logic. The design is a geometry
artifact until it has been loaded and walked in OpenUA (see
docs/por-converter.md, "What is not claimed").

What it does
  * Opens the source DAX strictly read-only (``"rb"``); the source is never
    written, renamed or deleted.
  * Parses the DAX container: 2-byte TOC size, 9-byte TOC entries, a
    contiguous data chain that closes exactly at EOF. Anything else is
    malformed and refused.
  * Decodes one block with the signed-byte RLE (exact raw size or refusal).
  * Validates the Gen1 GEO block: raw size 1026, size field 1024, 16 x 16
    grid, four 256-byte planes (see ``decode_gen1_geo``).
  * Maps each Gen1 edge (wall slot, door flag) to an OpenUA wall byte
    (``map_edge``) and every loss into the report.
  * Optionally checks documented PoR facts against the decoded block
    (``--expect``), and writes a deterministic JSON + Markdown report.

Usage
  python3 tools/por_map.py --dax PATH/GEO1.DAX --list
  python3 tools/por_map.py --dax PATH/GEO1.DAX --block 18 -o data/por/geo1-18
  python3 tools/por_map.py --install "D:/PoR/POOLRAD" --geo 1 --index 0 -o OUT \\
        --entry 3,5 --facing north --area 5 --name PORMAP

``--entry X,Y`` is the party start as (column, row), with row 0 north, the
same convention as tools/find_geo_path.py. It is required before a ``.DSN``
is written. Refuses an output folder inside the source folder, and inside the
repository unless it is under ``data/``.

Stdlib only. Uses tools/geo.py and tools/dsn.py (OpenUA's own writers) for the
FRUA side, and the output guard from tools/por_convert.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from collections import deque
from pathlib import Path
from typing import Optional

from dsn import ART_BLOCK, Design
from geo import Geo
from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-map"
SCHEMA_VERSION = 1
STATUS = "map-only"
TOOL = "tools/por_map.py"

GRID_W = 16
GRID_H = 16
PLANE_BYTES = GRID_W * GRID_H            # 256
GEO_BLOCK_RAW = 2 + 4 * PLANE_BYTES      # 1026
GEO_SIZE_FIELD = 1024                    # uint16 LE at raw[0:2]
DAX_TOC_ENTRY = 9                        # u8 id, u32 offset, u16 raw, u16 comp

# Edge order is the OpenUA order (dsn.py / geo.py): 0=N 1=E 2=S 3=W.
EDGES = ("N", "E", "S", "W")
# GEO entry facings are the engine's 3-bit compass direction codes. The
# runtime normalizes 0 to 8; the cardinal headings are therefore N=0, E=2,
# S=4, W=6 (odd values are diagonals). See jt297's direction-table comments
# and jt210's `(dir & 6) >> 1` edge selection in src/engine/boot.c.
FACINGS = {"north": 0, "east": 2, "south": 4, "west": 6}
DSN_NAME_RE = re.compile(r"[A-Z0-9_]{1,8}")
DEFAULT_AREA = 5     # same start-area convention as dsn.demo_design()
DEFAULT_NAME = "PORMAP"


class PorMapError(Exception):
    """A source, validation or argument problem. The message says which."""


# --------------------------------------------------------------------------
# DAX container and RLE
# --------------------------------------------------------------------------

class TocEntry:
    __slots__ = ("index", "block_id", "data_offset", "raw_size", "comp_size")

    def __init__(self, index, block_id, data_offset, raw_size, comp_size):
        self.index = index
        self.block_id = block_id
        self.data_offset = data_offset
        self.raw_size = raw_size
        self.comp_size = comp_size


def parse_dax(data: bytes) -> tuple[list[TocEntry], int]:
    """Return (TOC entries, data-section base). Raises on any malformation:
    a TOC that is not a positive multiple of 9, a TOC past EOF, a data chain
    that is not contiguous from offset 0, or a data section that does not end
    exactly at EOF (truncated or trailing bytes)."""
    if len(data) < 2:
        raise PorMapError("DAX truncated: no TOC size word")
    toc_bytes = struct.unpack_from("<H", data, 0)[0]
    if toc_bytes == 0 or toc_bytes % DAX_TOC_ENTRY:
        raise PorMapError("DAX TOC size %d is not a positive multiple of %d"
                          % (toc_bytes, DAX_TOC_ENTRY))
    base = 2 + toc_bytes
    if base > len(data):
        raise PorMapError("DAX truncated: TOC runs past end of file")
    entries = []
    for i in range(toc_bytes // DAX_TOC_ENTRY):
        bid, off, raw, comp = struct.unpack_from("<BIHH", data, 2 + DAX_TOC_ENTRY * i)
        entries.append(TocEntry(i, bid, off, raw, comp))
    expect = 0
    for e in entries:
        if e.data_offset != expect:
            raise PorMapError("DAX entry %d data_offset %d, expected %d "
                              "(chain must be contiguous from 0)"
                              % (e.index, e.data_offset, expect))
        expect += e.comp_size
    if base + expect != len(data):
        raise PorMapError("DAX data section is %d bytes but the TOC accounts "
                          "for %d (truncated or trailing bytes)"
                          % (len(data) - base, expect))
    return entries, base


def rle_decode(comp: bytes, raw_size: int) -> bytes:
    """Signed-byte RLE: control c < 0x80 copies c+1 literal bytes; c >= 0x80
    repeats the next byte 256-c times. The output must be exactly raw_size."""
    out = bytearray()
    i = 0
    n = len(comp)
    while i < n:
        c = comp[i]
        i += 1
        if c < 0x80:
            count = c + 1
            if i + count > n:
                raise PorMapError("RLE literal run overruns its block")
            out += comp[i:i + count]
            i += count
        else:
            if i >= n:
                raise PorMapError("RLE repeat run has no value byte")
            out += bytes((comp[i],)) * (256 - c)
            i += 1
        if len(out) > raw_size:
            raise PorMapError("RLE output exceeds the TOC raw size %d" % raw_size)
    if len(out) != raw_size:
        raise PorMapError("RLE output is %d bytes, TOC raw size is %d"
                          % (len(out), raw_size))
    return bytes(out)


def select_block(entries: list[TocEntry], block_id: Optional[int],
                 index: Optional[int]) -> TocEntry:
    """Pick one TOC entry. Block ids can repeat in principle, so an ambiguous
    id is refused and the caller must name a TOC index."""
    if index is not None:
        if not 0 <= index < len(entries):
            raise PorMapError("TOC index %d out of range 0..%d"
                              % (index, len(entries) - 1))
        e = entries[index]
        if block_id is not None and e.block_id != block_id:
            raise PorMapError("TOC index %d holds block %d, not %d"
                              % (index, e.block_id, block_id))
        return e
    if block_id is None:
        raise PorMapError("name a block with --block ID or a TOC index with --index")
    matches = [e for e in entries if e.block_id == block_id]
    if not matches:
        raise PorMapError("no block id %d in this DAX" % block_id)
    if len(matches) > 1:
        raise PorMapError("block id %d appears %d times; choose one with --index"
                          % (block_id, len(matches)))
    return matches[0]


# --------------------------------------------------------------------------
# Gen1 GEO block decode
# --------------------------------------------------------------------------

def decode_gen1_geo(raw: bytes) -> list[dict]:
    """Decode a 1026-byte Gen1 GEO block into 256 cell records, row-major
    (index = y * 16 + x, y 0 = north).

    Layout (the Gen1 model used by tools/find_geo_path.py; not established
    as PoR compass semantics):
      raw[0:2]      uint16 LE data size, must be 1024
      plane 0       Gen1 model: N in high nibble, E in low nibble
      plane 1       Gen1 model: S in high nibble, W in low nibble
      plane 2       per-cell descriptor (event/backdrop byte; kept raw)
      plane 3       Gen1 model: four 2-bit edge fields; PoR code confirms
                    direction-code bit pairs but not their compass labels
    Each wall is (slot 0..15, door 0..3). Slot 0 means no wall graphic.
    """
    if len(raw) != GEO_BLOCK_RAW:
        raise PorMapError("Gen1 GEO block must be %d bytes, got %d"
                          % (GEO_BLOCK_RAW, len(raw)))
    size_field = struct.unpack_from("<H", raw, 0)[0]
    if size_field != GEO_SIZE_FIELD:
        raise PorMapError("Gen1 GEO size field is %d, expected %d"
                          % (size_field, GEO_SIZE_FIELD))
    planes = [raw[2 + k * PLANE_BYTES: 2 + (k + 1) * PLANE_BYTES] for k in range(4)]
    cells = []
    for y in range(GRID_H):
        for x in range(GRID_W):
            i = y * GRID_W + x
            p0, p1, p2, p3 = planes[0][i], planes[1][i], planes[2][i], planes[3][i]
            # Compass labels and packed-field order follow the Gen1 decoder
            # model. PoR's static writer/reader probe establishes direction
            # codes 0/2/4/6 -> pairs 0/1/2/3, but does not name those headings.
            edges = {
                "N": (p0 >> 4, p3 & 3),
                "E": (p0 & 15, (p3 >> 2) & 3),
                "S": (p1 >> 4, (p3 >> 4) & 3),
                "W": (p1 & 15, (p3 >> 6) & 3),
            }
            cells.append({"x": x, "y": y, "index": i,
                          "planes": [p0, p1, p2, p3], "edges": edges})
    return cells


# --------------------------------------------------------------------------
# Edge mapping: Gen1 (slot, door) -> OpenUA wall byte (passability << 4 | group)
# --------------------------------------------------------------------------

# OpenUA passability nibble (dsn.py): 0 open, 1 secret door (passable, engine
# says "A SECRET DOOR!"), 14 solid wall, 15 Blocked-menu edge. The PoR DOS
# runtime trace records one flag-2 edge where Bash opened the way; the runtime
# GEO-byte-to-reader link and a general flag rule remain unestablished. Flag 3
# remains a CoK-derived hypothesis. The low nibble is the wall texture group;
# Gen1 slot is used unchanged (also unverified).
MAP_RULES = {
    "open": "ASSUMPTION: slot 0: no wall, passable whatever the door byte says",
    "solid": "ASSUMPTION: wall, no door flag: solid wall (14)",
    "auto-door": "ASSUMPTION: wall + door 1 maps to passable secret-door (1)",
    "locked": "one PoR DOS runtime route: wall + flag 2 stopped the party until a successful Bash; encoded as Blocked-menu edge (15); general flag-2 rule unproven",
    "door3-unresolved": "no PoR runtime observation: wall + door 3 is a CoK/other-title Bash/Knock hypothesis; encoded as Blocked-menu edge (15) provisionally",
}

# Per-rule provenance, emitted with the normalized map. `basis` is where the
# rule's meaning comes from; `por_runtime` is what the PoR DOS runtime showed.
# Only `locked` has a PoR runtime observation, and that is one route. No rule
# has its GEO-reader binding proven, and none sets por_door_rule_proven.
RULE_EVIDENCE = {
    "open": {"basis": "assumption", "por_runtime": "none",
             "status": "assumption-unverified",
             "geo_reader_binding": "unproven", "general_rule_proven": False},
    "solid": {"basis": "assumption", "por_runtime": "none",
              "status": "assumption-unverified",
              "geo_reader_binding": "unproven", "general_rule_proven": False},
    "auto-door": {"basis": "assumption", "por_runtime": "none",
                  "status": "assumption-unverified",
                  "geo_reader_binding": "unproven", "general_rule_proven": False},
    "locked": {"basis": "por-runtime-single-route",
               "por_runtime": ("GEO2 block 20 (14,10) west, flag 2: LOCKED. BASH PICK "
                               "EXIT; one Pick failed; Bash succeeded; party moved to (13,10)"),
               "status": "supported-single-route",
               "geo_reader_binding": "unproven", "general_rule_proven": False},
    "door3-unresolved": {"basis": "other-title-hypothesis (CoK)",
                         "por_runtime": "none",
                         "status": "provisional",
                         "geo_reader_binding": "unproven", "general_rule_proven": False},
}

EDGE_MAPPING_EVIDENCE = {
    "status": "single-por-runtime-case; general-mapping-unverified",
    "source_boundary": "PoR DOS runtime supports interaction-gated crossing for one flag-2 edge; GEO field binding and general semantics remain open; flag 3 is CoK-only hypothesis",
    "por_door_rule_proven": False,
    "wall_art_binding_proven": False,
    "por_runtime_observation": {
        "source": "GoldBox read-only reference: docs/engine/research/gen1-dosbox-runtime-trace.md, PoR DOS runtime sections dated 2026-07-22",
        "case": "GEO2.DAX block 20, cell (14,10), west, wall slot 10, observed plane-3 flag 2",
        "outcome": "LOCKED. BASH PICK EXIT; Pick failed in one attempt; Bash succeeded, party crossed to (13,10), and the original persisted the opened edge",
        "scope": "one native route observation; not a full proof that every stored flag-2 byte feeds this runtime edge reader",
    },
    "rules": RULE_EVIDENCE,
}


# OPT-IN CANDIDATE ONLY. The default encodes door flag 2 as passability 15 (the
# Blocked-menu edge). This candidate encodes flag 2 as passability 2 instead,
# which the engine routes to the same Blocked menu but skips the
# passability-15-only FORCE refusal. It is never applied unless a caller asks
# for it (``--candidate-flag2-passable``); it is not the default and is not a
# verified PoR rule.
CANDIDATE_FLAG2_PASSABILITY = 2


def map_edge(slot: int, door: int,
             flag2_passability: Optional[int] = None) -> tuple[int, str]:
    """Return (OpenUA wall byte, rule name) for one Gen1 edge.

    ``flag2_passability`` is None for the default conversion (flag 2 -> 15).
    Only an explicit opt-in candidate sets it; the rule name stays "locked"
    so the default rule counts and evidence labels do not change."""
    if slot == 0:
        return 0x00, "open"
    if door == 0:
        return (14 << 4) | slot, "solid"
    if door == 1:
        return (1 << 4) | slot, "auto-door"
    if door == 2:
        p = 15 if flag2_passability is None else flag2_passability
        return (p << 4) | slot, "locked"
    return (15 << 4) | slot, "door3-unresolved"


def _passable_unconditionally(slot: int, door: int) -> bool:
    # Current conversion policy: slot 0 is open, door 1 is provisionally
    # mapped to passable, door 2 is interaction-gated in the PoR runtime case,
    # and door 3 remains provisionally mapped to a Blocked-menu edge.
    return slot == 0 or door == 1


def entry_reachable(cells: list[dict], x0: int, y0: int) -> set[tuple[int, int]]:
    """Cells reachable from (x0, y0) over unconditionally passable edges."""
    by_xy = {(c["x"], c["y"]): c for c in cells}
    seen = {(x0, y0)}
    queue = deque([(x0, y0)])
    delta = {"N": (0, -1), "E": (1, 0), "S": (0, 1), "W": (-1, 0)}
    while queue:
        x, y = queue.popleft()
        for k in EDGES:
            slot, door = by_xy[(x, y)]["edges"][k]
            if not _passable_unconditionally(slot, door):
                continue
            dx, dy = delta[k]
            nxt = (x + dx, y + dy)
            if nxt in by_xy and nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def shared_edge_stats(cells: list[dict]) -> dict:
    """Diagnostic only, never a rejection. Counts shared interior edges whose
    two stored slots agree: S(x,y) vs N(x,y+1) and E(x,y) vs W(x+1,y). Earlier
    GoldBox research reported a high but not total agreement, so a mismatch
    is recorded, not treated as corruption."""
    by_xy = {(c["x"], c["y"]): c for c in cells}
    total = matched = 0
    for (x, y), c in by_xy.items():
        if y + 1 < GRID_H:
            total += 1
            matched += c["edges"]["S"][0] == by_xy[(x, y + 1)]["edges"]["N"][0]
        if x + 1 < GRID_W:
            total += 1
            matched += c["edges"]["E"][0] == by_xy[(x + 1, y)]["edges"]["W"][0]
    return {"shared_edges": total, "slot_agree": matched,
            "slot_disagree": total - matched}


# --------------------------------------------------------------------------
# Normalized map, OpenUA design, reports
# --------------------------------------------------------------------------

def parse_point(text: str) -> tuple[int, int]:
    try:
        x, y = (int(p.strip(), 0) for p in text.split(",", 1))
    except ValueError as exc:
        raise PorMapError("expected X,Y, got %r" % text) from exc
    for v in (x, y):
        if not 0 <= v < GRID_W:
            raise PorMapError("cell coordinate %d out of range 0..%d" % (v, GRID_W - 1))
    return x, y


def parse_expectation(text: str) -> dict:
    """``X,Y=VALUE[/MASK]``: check plane 2 (the descriptor byte) of cell (X,Y).
    VALUE and MASK accept 0x hex. The check passes when
    (plane2 & MASK) == (VALUE & MASK). MASK defaults to 0xFF."""
    m = re.fullmatch(r"\s*(\S+?)\s*=\s*(\S+?)(?:/(\S+))?\s*", text)
    if not m:
        raise PorMapError("expectation must be X,Y=VALUE[/MASK], got %r" % text)
    x, y = parse_point(m.group(1))
    try:
        value = int(m.group(2), 0)
        mask = int(m.group(3), 0) if m.group(3) else 0xFF
    except ValueError as exc:
        raise PorMapError("bad number in expectation %r" % text) from exc
    if not (0 <= value <= 0xFF and 0 <= mask <= 0xFF):
        raise PorMapError("expectation values must fit one byte: %r" % text)
    return {"x": x, "y": y, "value": value, "mask": mask}


def build_openua_geo(cells: list[dict], entry: Optional[tuple[int, int, int]],
                     flag2_passability: Optional[int] = None) -> Geo:
    """A 16 x 16 OpenUA area built with OpenUA's own geo.py. Cell (x,y) is
    addressed as cell(col=x, row=y); the wall bytes come from map_edge. Source
    edges and OpenUA's runtime selector are ordered N/E/S/W, so write them in
    that order. The plane-2 descriptor and zone bits are left at zero (not
    mapped). ``flag2_passability`` is the opt-in candidate (None = default)."""
    g = Geo.blank(GRID_W, GRID_H)
    g.hdr[4:14] = ART_BLOCK          # the known-good art binding dsn.py uses
    for c in cells:
        walls = tuple(map_edge(*c["edges"][k], flag2_passability=flag2_passability)[0]
                      for k in ("N", "E", "S", "W"))
        g.set_cell(c["x"], c["y"], walls=walls)
    if entry is not None:
        ex, ey, facing = entry
        g.set_entry_point(0, row=ey, col=ex, facing=facing)
    return g


def build_normalized(source: dict, cells: list[dict], expectations: list[dict],
                     entry: Optional[tuple[int, int, int]], emitted: dict) -> dict:
    rule_counts = {k: 0 for k in MAP_RULES}
    for c in cells:
        for k in EDGES:
            rule_counts[map_edge(*c["edges"][k])[1]] += 1
    descriptor_nonzero = sum(1 for c in cells if c["planes"][2])
    fully_closed = sum(1 for c in cells
                       if all(not _passable_unconditionally(*c["edges"][k])
                              for k in EDGES))
    diagnostics = {
        "cells": len(cells),
        "edge_rules": rule_counts,
        "descriptor_nonzero_cells": descriptor_nonzero,
        "cells_with_no_unconditional_exit": fully_closed,
        "shared_edge_slots": shared_edge_stats(cells),
    }
    if entry is not None:
        ex, ey, _ = entry
        reach = entry_reachable(cells, ex, ey)
        diagnostics["entry_reachable_cells"] = len(reach)
    cells_out = []
    for c in cells:
        cells_out.append({
            "x": c["x"], "y": c["y"], "index": c["index"],
            "planes": c["planes"],
            "edges": {k: {"slot": c["edges"][k][0], "door": c["edges"][k][1]}
                      for k in EDGES},
        })
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "tool": TOOL,
        "source": source,
        "grid": {"width": GRID_W, "height": GRID_H,
                 "cell_index": "y * 16 + x", "row_0": "north"},
        "cells": cells_out,
        "diagnostics": diagnostics,
        "edge_mapping_evidence": EDGE_MAPPING_EVIDENCE,
        "expectations": expectations,
        "openua": emitted,
    }


def render_report(norm: dict, warnings: list[str], unsupported: list[str]) -> str:
    s = norm["source"]
    d = norm["diagnostics"]
    lines = [
        "# Pool of Radiance map conversion report (MAP-ONLY)",
        "",
        "**Status: MAP-ONLY. Not a playable module claim.** This output carries one",
        "Gen1 GEO block's walls. It includes only OpenUA's generic area ART_BLOCK",
        "binding, not PoR art. It has no events, text, monsters, items or campaign",
        "logic. Runtime loading in OpenUA is not verified by this tool.",
        "",
        "**Evidence boundary:** emitted door passability and wall-slot texture",
        "choices remain provisional overall. One PoR DOS runtime route supports",
        "interaction-gated crossing for a flag-2 edge; its general GEO-to-runtime",
        "binding is open. Flag 3 is a CoK-only hypothesis, and wall art is unverified.",
        "See the converter documentation for the evidence boundary.",
        "",
        "## Source (read-only)",
        "",
        "| field | value |",
        "| --- | --- |",
        "| file | `%s` |" % s["file"],
        "| file sha256 | `%s` |" % s["sha256"],
        "| file bytes | %d |" % s["bytes"],
        "| TOC index | %d |" % s["toc_index"],
        "| block id | %d |" % s["block_id"],
        "| raw size | %d |" % s["raw_size"],
        "| compressed size | %d |" % s["comp_size"],
        "| decoded sha256 | `%s` |" % s["decoded_sha256"],
        "| grid | 16 x 16, row 0 north |",
        "",
        "## Edge mapping (Gen1 slot/door -> OpenUA wall byte)",
        "",
    ]
    for k, text in MAP_RULES.items():
        lines.append("- **%s** [%s]: %s (%d edges)"
                     % (k, RULE_EVIDENCE[k]["status"], text, d["edge_rules"][k]))
    lines += [
        "",
        "## Diagnostics",
        "",
        "- cells: %d" % d["cells"],
        "- cells with no unconditional exit: %d" % d["cells_with_no_unconditional_exit"],
        "- descriptor (plane 2) nonzero cells: %d (not mapped)"
        % d["descriptor_nonzero_cells"],
        "- shared interior edges: %d, slots agree %d, disagree %d"
        % (d["shared_edge_slots"]["shared_edges"],
           d["shared_edge_slots"]["slot_agree"],
           d["shared_edge_slots"]["slot_disagree"]),
    ]
    if "entry_reachable_cells" in d:
        lines.append("- cells reachable from entry over unconditional edges: %d"
                     % d["entry_reachable_cells"])
    lines += ["", "## Expectations (documented PoR facts)", ""]
    if norm["expectations"]:
        for e in norm["expectations"]:
            lines.append("- cell (%d,%d) plane 2 & 0x%02X == 0x%02X: %s (actual 0x%02X)"
                         % (e["x"], e["y"], e["mask"], e["value"] & e["mask"],
                            "PASS" if e["ok"] else "FAIL", e["actual"]))
    else:
        lines.append("- none supplied")
    lines += ["", "## Warnings", ""]
    lines += ["- %s" % w for w in warnings] or ["- none"]
    lines += ["", "## Unsupported and lost (not in the design)", ""]
    lines += ["- %s" % u for u in unsupported]
    lines += ["", "## OpenUA design", ""]
    o = norm["openua"]
    if o["emitted"]:
        lines += [
            "- folder: `%s`" % o["folder"],
            "- start area %d (GEO%03d.DAT), start entry 1" % (o["area"], o["area"]),
            "- entry cell (x=%d, y=%d), facing %s" % (o["entry"]["x"], o["entry"]["y"],
                                                     o["entry"]["facing"]),
            "- title: `%s`" % o["title"],
        ]
    else:
        lines.append("- not emitted: no `--entry` given (a .DSN needs an explicit start)")
    lines.append("")
    return "\n".join(lines)


UNSUPPORTED_MAP_ONLY = [
    "ECL scripts and every event: no event records written (ENCR is empty)",
    "text / strings: STRG is empty; no PoR text is copied",
    "monsters and encounters: no combat groups, no MON references",
    "items, treasure, shops, temples, training, inns: none",
    "plane 2 descriptor (search/event dispatch key, backdrop/zone): kept in por_map.json only",
    "zones and cell flags: zero",
    "wall art: HDR art block copied from OpenUA dsn.py (known-good), not PoR WALLDEF",
    "door semantics: flag 2 has one PoR DOS runtime route (Bash opened it), but the GEO-reader binding and the general flag-2 rule are unproven; flag 3 is a CoK/other-title hypothesis; both currently encode to the OpenUA Blocked-menu edge (15)",
    "Gen1 wall slot used as the OpenUA texture group unchanged (unverified)",
    "party and economy: GAME001 defaults (XP, gold) from dsn.Design, not PoR",
    "campaign: one area only, no transitions to other areas",
    "validation: OpenUA runtime load/walk was not run",
]


# --------------------------------------------------------------------------
# Drivers
# --------------------------------------------------------------------------

def resolve_geo(install: Path, n: int) -> Path:
    """Find GEO<n>.DAX directly in install or in its POOLRAD subfolder (the
    GOG layout), case-insensitively. Ambiguity is an error."""
    want = "GEO%d.DAX" % n
    found = []
    for folder in (install, install / "POOLRAD"):
        if not folder.is_dir():
            continue
        with os.scandir(folder) as it:
            for entry in it:
                if entry.name.upper() == want and entry.is_file():
                    found.append(Path(entry.path))
    if not found:
        raise PorMapError("no %s under %s (or its POOLRAD subfolder)" % (want, install))
    if len(found) > 1:
        raise PorMapError("%s is ambiguous: %s" % (want, ", ".join(map(str, found))))
    return found[0]


def _read_source(path: Path) -> bytes:
    if not path.is_file():
        raise PorMapError("source DAX not found: %s" % path.name)
    return path.read_bytes()


def list_toc(path: Path) -> str:
    data = _read_source(path)
    entries, _base = parse_dax(data)
    rows = ["index  block_id  data_offset  raw_size  comp_size"]
    for e in entries:
        rows.append("%5d  %8d  %11d  %8d  %9d"
                    % (e.index, e.block_id, e.data_offset, e.raw_size, e.comp_size))
    return "\n".join(rows) + "\n"


def convert(dax_path: Path, out: Path, *, block_id: Optional[int],
            index: Optional[int], expect: list[dict],
            entry: Optional[tuple[int, int, int]], area: int, name: str,
            title: Optional[str],
            flag2_passability: Optional[int] = None) -> dict:
    """Run the whole slice. Returns the normalized map. Writes files only to
    ``out``. The source file is read once and never written.

    ``flag2_passability`` is an OPT-IN candidate (see CANDIDATE_FLAG2_PASSABILITY).
    None, the default, leaves every output byte as it was before the option
    existed."""
    if flag2_passability is not None and not (0 <= flag2_passability <= 15):
        raise PorMapError("candidate flag-2 passability must be 0..15")
    src_dir = dax_path.parent
    out = validate_output_dir(src_dir, out)
    data = _read_source(dax_path)
    entries, base = parse_dax(data)
    te = select_block(entries, block_id, index)
    start = base + te.data_offset
    comp = data[start:start + te.comp_size]
    raw = rle_decode(comp, te.raw_size)
    cells = decode_gen1_geo(raw)

    expectations = []
    for ex in expect:
        if not (0 <= ex["x"] < GRID_W and 0 <= ex["y"] < GRID_H):
            raise PorMapError("expectation cell out of range")
        actual = cells[ex["y"] * GRID_W + ex["x"]]["planes"][2]
        ok = (actual & ex["mask"]) == (ex["value"] & ex["mask"])
        expectations.append({"x": ex["x"], "y": ex["y"], "plane": 2,
                             "mask": ex["mask"], "value": ex["value"],
                             "actual": actual, "ok": ok})

    if entry is not None and not (1 <= area <= 999):
        raise PorMapError("area must be 1..999")
    source = {
        "file": dax_path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "toc_entries": len(entries),
        "toc_index": te.index,
        "block_id": te.block_id,
        "raw_size": te.raw_size,
        "comp_size": te.comp_size,
        "data_size_field": GEO_SIZE_FIELD,
        "decoded_sha256": hashlib.sha256(raw).hexdigest(),
    }
    warnings = []
    emitted = {"emitted": False}
    folder_abs = None
    if entry is not None:
        if not DSN_NAME_RE.fullmatch(name):
            raise PorMapError("design name must be 1..8 of A-Z, 0-9, _")
        ex_, ey_, facing = entry
        if all(not _passable_unconditionally(*cells[ey_ * GRID_W + ex_]["edges"][k])
               for k in EDGES):
            warnings.append("entry cell (%d,%d) has no unconditional exit" % (ex_, ey_))
        g_title = (title or ("PoR map-only %s #%d" % (dax_path.name, te.block_id)))[:31]
        emitted = {"emitted": True, "design": name, "folder": None,
                   "area": area, "title": g_title,
                   "entry": {"x": ex_, "y": ey_, "facing": facing_name(facing)}}
    if any(not e["ok"] for e in expectations):
        warnings.append("one or more expectations FAILED (see Expectations)")
    if flag2_passability is not None:
        warnings.append("OPT-IN CANDIDATE: door flag 2 encoded as passability %d "
                        "(default is 15); not the default conversion"
                        % flag2_passability)

    out.mkdir(parents=True, exist_ok=True)
    if entry is not None:
        geo = build_openua_geo(cells, entry, flag2_passability=flag2_passability)
        d = Design(name, title=emitted["title"])
        d.start_area = area
        d.start_entry = 1
        d.add_area(area, geo)
        folder_abs = Path(d.write(str(out)))
        emitted["folder"] = folder_abs.relative_to(out).as_posix()

    norm = build_normalized(source, cells, expectations, entry, emitted)
    report = render_report(norm, warnings, UNSUPPORTED_MAP_ONLY)
    if flag2_passability is not None:
        norm["candidate"] = {
            "opt_in": True,
            "default": False,
            "rule": "locked",
            "flag2_passability": flag2_passability,
            "default_flag2_passability": 15,
            "status": "opt-in candidate; not verified; not promoted to default",
        }
        report += ("\n## OPT-IN CANDIDATE (not the default)\n\n"
                   "Door flag 2 is encoded as passability %d instead of 15. "
                   "This output is for a bounded runtime experiment only.\n"
                   % flag2_passability)
    # Deterministic output: sorted JSON keys, no timestamps.
    (out / "por_map.json").write_text(
        json.dumps(norm, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_map_report.md").write_text(report, encoding="utf-8")
    return {"norm": norm, "warnings": warnings, "folder": folder_abs}


def facing_name(f: int) -> str:
    return {v: k for k, v in FACINGS.items()}[f]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance GEO block -> OpenUA map-only design (slice 2).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--dax", type=Path, help="explicit GEO DAX file (read-only)")
    src.add_argument("--install", type=Path,
                     help="explicit PoR DOS folder (or its POOLRAD subfolder); needs --geo")
    ap.add_argument("--geo", type=int, help="with --install: the GEO file number, e.g. 1")
    ap.add_argument("--block", type=int, help="block id inside the DAX")
    ap.add_argument("--index", type=int, help="TOC index (use when a block id repeats)")
    ap.add_argument("--list", action="store_true", help="print the TOC and exit")
    ap.add_argument("--expect", action="append", default=[], metavar="X,Y=VALUE[/MASK]",
                    help="check a documented plane-2 value; repeatable")
    ap.add_argument("-o", "--out", type=Path, help="output folder (outside the source)")
    ap.add_argument("--entry", metavar="X,Y", help="party start cell, column,row (0..15)")
    ap.add_argument("--facing", choices=sorted(FACINGS), default="north")
    ap.add_argument("--area", type=int, default=DEFAULT_AREA)
    ap.add_argument("--name", default=DEFAULT_NAME, help="design name, 1..8 chars")
    ap.add_argument("--title", default=None, help="GAME001 title (31 bytes max)")
    ap.add_argument("--candidate-flag2-passable", type=int, default=None, metavar="N",
                    help="OPT-IN CANDIDATE ONLY (default: off): encode door flag 2 "
                         "as OpenUA passability N (0..15) instead of 15. Not the "
                         "default; never applied unless given.")
    args = ap.parse_args(argv)
    try:
        if args.dax is not None:
            dax = args.dax
        else:
            if args.geo is None:
                raise PorMapError("--geo N is required with --install")
            dax = resolve_geo(args.install, args.geo)
        if args.list:
            sys.stdout.write(list_toc(dax))
            return 0
        if args.out is None:
            raise PorMapError("-o/--out is required")
        expect = [parse_expectation(t) for t in args.expect]
        entry = None
        if args.entry is not None:
            x, y = parse_point(args.entry)
            entry = (x, y, FACINGS[args.facing])
        result = convert(dax, args.out, block_id=args.block, index=args.index,
                         expect=expect, entry=entry, area=args.area,
                         name=args.name.upper(), title=args.title,
                         flag2_passability=args.candidate_flag2_passable)
    except (PorMapError, PorSourceError) as exc:
        print("por_map: error: %s" % exc, file=sys.stderr)
        return 2
    norm = result["norm"]
    print("por_map: wrote %s and %s" % (args.out / "por_map.json",
                                       args.out / "por_map_report.md"))
    if result["folder"] is not None:
        print("por_map: design folder %s (MAP-ONLY, not a playable claim)"
              % result["folder"])
    for w in result["warnings"]:
        print("por_map: warning: %s" % w, file=sys.stderr)
    failed = any(not e["ok"] for e in norm["expectations"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
