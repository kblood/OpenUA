#!/usr/bin/env python3
"""Pool of Radiance -> OpenUA: one repeatable run over a user-supplied install.

Status: MAP-ONLY PIPELINE. ``playable: false``. Nothing here runs the game,
verifies wall art, or proves that an emitted design loads or walks in OpenUA.
With ``--with-ecl-text`` the run also carries the ECL string census and its
retail-codec diagnostic (``diagnostic-unaccepted``, ``playable: false``). That
output is diagnosis only: no string is accepted, merged into a DSN or STRG, or
claimed as a runtime match.

What one run does (every stage is read-only on the install)
  1. FINGERPRINT. Hash GEO1..GEO8.DAX, GAME.OVR and START.EXE. With
     ``--with-ecl-text`` also ECL1..ECL8.DAX, which are then required. The same
     hashes are taken again at the end; a change is a refusal (exit 2), not a
     warning.
  2. BLOCKS. Decode every TOC block of every GEO archive with
     ``por_map.convert`` (normalized map + report only, no design). A block that
     the decoder refuses is recorded as ``refused`` with its reason; the run goes
     on, so one bad block cannot hide the others.
  3. DESIGNS. For each entry in an explicit ``--plan`` file, emit a map-only
     ``NAME.DSN`` and read each GEO back with OpenUA's own ``geo.Geo.parse``. The
     check is byte round-trip plus the entry point. A flat entry is one area, via
     ``por_map.convert``. A grouped entry (``areas``) is MULTI-AREA map-only: one
     ``NAME.DSN`` folder holding several GEO files, written by ``dsn.Design``. It
     is all or nothing: if any area is refused, no folder is written. This is a
     container check, not a gameplay check.
     Each emitted ``NAME.DSN`` folder also gets the loader-equivalent host checks
     of ``tools/por_dsn_load_smoke.py`` (``validate_folder``, read-only). A design
     is ``ok`` only if its round-trip checks AND the loader verdict pass. A loader
     failure fails the design (exit 1); the folder is still published, as for a
     round-trip failure. A GEO area above the engine's 0..255 range fails the
     ``geo-addressable`` check. Nothing here runs the engine: ``runtime_loaded``
     and ``engine_executed`` stay false.
  3b. ECL TEXT (optional, ``--with-ecl-text``). Run the ECL string census
     (``tools/por_ecl_strings.py``) into ``ecl-census/`` and the unaccepted 6-bit
     diagnostic (``tools/por_ecl_text_diagnostic.py``) over that census into
     ``ecl-text-diagnostic/``. Both are written under OUT only. A census with
     diagnostics (exit 1) makes the run degraded, not refused; the diagnostic
     still runs over the frames that were found.
  4. MANIFEST. Write ``por_pipeline.json`` and ``por_pipeline_report.md``. The
     output holds hashes, counts and statuses only. It has no absolute paths and
     no timestamps, so two runs over the same install are byte-identical. Without
     ``--with-ecl-text`` the manifest is exactly the map-only one (no ``ecl_text``
     key), so existing outputs are unchanged.
  5. PUBLISH. Stages 2-4 write into a fresh staging folder beside OUT (same
     parent). The install is fingerprinted once more just before publishing; if
     it differs, nothing is published. Otherwise each owned entry of OUT
     (``maps``, ``designs``, ``ecl-census``, ``ecl-text-diagnostic``,
     ``por_pipeline.json``, ``por_pipeline_report.md``) is renamed aside and the
     staged one is renamed in. Any other file or folder in OUT is left alone. A
     failed rename is rolled back, and the staging folder is removed. A
     refusal leaves OUT as it was, and no run leaves a staging folder behind.

Plan file (explicit; nothing is guessed). Entry coordinates are not recovered
from the install. Each entry must come from evidence or be marked a test position.

A flat row is one map-only design with one area (the v0 form, unchanged):

    {"schema": "openua.por-pipeline-plan", "version": 0,
     "designs": [{"name": "PORMAP", "geo": 2, "index": 2, "area": 5,
                  "entry": [13, 8], "facing": "east", "title": "test entry"}]}

A grouped row (MULTI-AREA, map-only) puts several areas in one ``NAME.DSN``
folder. Every field is required except ``title``; nothing defaults:

    {"name": "TWOAREA", "title": "two areas", "start_area": 5, "start_entry": 1,
     "areas": [{"geo": 2, "index": 2, "area": 5, "entry": [13, 8], "facing": "east"},
               {"geo": 3, "index": 0, "area": 6, "entry": [1, 2], "facing": "south"}]}

Rules for a grouped row: ``areas`` is a non-empty list; each area number is
1..999 and unique in the design; each (geo, index) pair is used once per design;
``start_area`` must be one of the area numbers. ``start_entry`` must be 1: each
generated area has one entry point, GEO table index 0, placed at that area's
``entry``. GAME001 byte 49 is 1-based, so 1 names that point. Unknown keys and
flat fields on a grouped row are refused. A flat row and a grouped row can share
one plan. Design names are unique across both forms.

Usage
  python3 tools/por_pipeline.py --install "G:/Games/Pool of Radiance" \
      -o data/work/por-pipeline/retail [--plan plan.json] [--with-ecl-text]

Output folder: must be outside the install and, inside this repository, under
``data/`` (git-ignored). Stdlib plus the repo's own tools only.

Exit codes
  0  every block decoded, every planned design round-tripped, install unchanged
     (and, with --with-ecl-text, the ECL census exited 0)
  1  the run completed but at least one block was refused, a design failed its
     round-trip, or the ECL census reported diagnostics (the manifest is still
     written and is the result)
  2  refusal: missing or ambiguous install member (including any ECL1..8.DAX
     when --with-ecl-text is given), bad plan, refused output location, or the
     install changed during the run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Optional

import por_dsn_load_smoke as pls
import por_ecl as pe
import por_ecl_strings as ps
import por_ecl_text_diagnostic as ptd
import por_map as pm
from dsn import Design
from geo import Geo, GeoError
from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-pipeline"
SCHEMA_VERSION = 0
PLAN_SCHEMA = "openua.por-pipeline-plan"
PLAN_VERSION = 0
STATUS = "map-only-pipeline"

GEO_NUMBERS = tuple(range(1, 9))
FINGERPRINT_EXTRA = ("GAME.OVR", "START.EXE")
DEFAULT_TITLE = "PoR map-only"
GROUP_KIND = "multi-area-map-only"   # a grouped design: several areas, one DSN folder
GROUP_SCOPE = "multi-area map-only"  # label used in the report; never "full-game"

ECL_ARCHIVES = tuple("%s%d.DAX" % (ps.ARCHIVE_STEM, n) for n in ps.ARCHIVES)
ECL_CENSUS_DIR = "ecl-census"
ECL_DIAG_DIR = "ecl-text-diagnostic"
ECL_CENSUS_JSON = "por_ecl_strings.json"
ECL_CENSUS_MD = "por_ecl_strings_report.md"
ECL_STATUS = "diagnostic-unaccepted"

# Output staging. A run builds everything in a fresh folder beside OUT (same
# parent, so the same volume), and publishes by renaming only the entries the
# pipeline owns. Anything else already in OUT is never touched.
STAGE_PREFIX = ".por-pipeline-staging-"
REPLACED_DIR = ".replaced"          # inside the staging folder: old owned entries
OWNED_OUTPUTS = ("maps", "designs", ECL_CENSUS_DIR, ECL_DIAG_DIR,
                 "por_pipeline.json", "por_pipeline_report.md")

UNSUPPORTED = [
    "No FRUA art binding: walls use the dsn.py ART_BLOCK; PoR wall art is unresolved.",
    "Door mapping: one cited PoR DOS route reports a flag-2 locked door and successful Bash crossing; the GEO-to-reader binding and general flag-2 rule remain unproven. Flag 3 is a CoK/other-title hypothesis; flags 2 and 3 currently map to OpenUA passability 15.",
    "No events, text, monsters, items, shops or campaign logic.",
    "Entry points come from the plan only; none are recovered from the install.",
    "No runtime check: nothing here boots OpenUA or walks the emitted design.",
    "Loader-equivalent checks (tools/por_dsn_load_smoke.py) are host readings of the "
    "emitted bytes. The engine loader is not run, and no runtime load is claimed.",
]

ECL_UNSUPPORTED = list(ptd.NOT_CLAIMED) + [
    "The ECL stage writes only under the ecl-census and ecl-text-diagnostic folders; "
    "it writes no DSN, no design and no FRUA STRG resource.",
    "String frames come from the census walks; an incomplete walk is never read as "
    "an absence of strings.",
]


class PorPipelineError(Exception):
    """A named refusal. The CLI prints it and exits with 2."""


# --------------------------------------------------------------------------
# Install access (read-only)
# --------------------------------------------------------------------------

def locate_member(install: Path, name: str) -> Path:
    """Find ``name`` directly in the install or in its POOLRAD subfolder (GOG
    layout), case-insensitively. Missing or ambiguous is a refusal."""
    want = name.upper()
    found = []
    for folder in (install, install / "POOLRAD"):
        if not folder.is_dir():
            continue
        with os.scandir(folder) as it:
            for entry in it:
                if entry.name.upper() == want and entry.is_file():
                    found.append(Path(entry.path))
    if not found:
        raise PorPipelineError("no %s under %s (or its POOLRAD subfolder)"
                               % (name, install.name or install))
    if len(found) > 1:
        raise PorPipelineError("%s is ambiguous (%d copies)" % (name, len(found)))
    return found[0]


def fingerprint(install: Path, extra: tuple = ()) -> dict:
    """SHA-256 and size of every member the run depends on, keyed by name.
    ``extra`` adds members (the ECL archives when --with-ecl-text is given)."""
    names = ["GEO%d.DAX" % n for n in GEO_NUMBERS] + list(FINGERPRINT_EXTRA) + list(extra)
    out = {}
    for name in names:
        path = locate_member(install, name)
        data = path.read_bytes()
        out[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return out


# --------------------------------------------------------------------------
# Plan
# --------------------------------------------------------------------------

def load_plan(path: Optional[Path]) -> tuple[list[dict], Optional[str]]:
    """Return (designs, plan sha256). No plan means no designs, not a default."""
    if path is None:
        return [], None
    try:
        raw = path.read_bytes()
        plan = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise PorPipelineError("plan unreadable or not JSON: %s" % exc)
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise PorPipelineError("plan schema must be %r" % PLAN_SCHEMA)
    if plan.get("version") != PLAN_VERSION:
        raise PorPipelineError("plan version must be %d" % PLAN_VERSION)
    designs = plan.get("designs")
    if not isinstance(designs, list):
        raise PorPipelineError("plan.designs must be a list")
    seen = set()
    rows = []
    for i, d in enumerate(designs):
        where = "plan.designs[%d]" % i
        if not isinstance(d, dict):
            raise PorPipelineError("%s must be an object" % where)
        name = d.get("name")
        if not isinstance(name, str) or not pm.DSN_NAME_RE.fullmatch(name):
            raise PorPipelineError("%s.name must be 1..8 of A-Z 0-9 _" % where)
        if name in seen:
            raise PorPipelineError("%s.name %r repeats" % (where, name))
        seen.add(name)
        if "areas" in d:
            rows.append(_load_group(where, d, name))
        else:
            rows.append(_load_flat(where, d, name))
    return rows, hashlib.sha256(raw).hexdigest()


def _load_flat(where: str, d: dict, name: str) -> dict:
    """One map-only design row: one GEO block, one area (the original v0 form)."""
    geo = d.get("geo")
    if not isinstance(geo, int) or not (1 <= geo <= 8):
        raise PorPipelineError("%s.geo must be 1..8" % where)
    index = d.get("index")
    if not isinstance(index, int) or index < 0:
        raise PorPipelineError("%s.index must be a TOC index >= 0" % where)
    area = d.get("area", pm.DEFAULT_AREA)
    if not isinstance(area, int) or not (1 <= area <= 999):
        raise PorPipelineError("%s.area must be 1..999" % where)
    entry = d.get("entry")
    if (not isinstance(entry, list) or len(entry) != 2
            or not all(isinstance(v, int) and 0 <= v <= 15 for v in entry)):
        raise PorPipelineError("%s.entry must be [x, y] with 0..15" % where)
    facing = d.get("facing", "north")
    if facing not in pm.FACINGS:
        raise PorPipelineError("%s.facing must be one of %s"
                               % (where, ", ".join(sorted(pm.FACINGS))))
    title = d.get("title", DEFAULT_TITLE)
    if not isinstance(title, str):
        raise PorPipelineError("%s.title must be a string" % where)
    return {"name": name, "geo": geo, "index": index, "area": area,
            "entry": (entry[0], entry[1]), "facing": facing, "title": title}


GROUP_KEYS = frozenset({"name", "title", "start_area", "start_entry", "areas"})
AREA_KEYS = frozenset({"geo", "index", "area", "entry", "facing"})


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _load_group(where: str, d: dict, name: str) -> dict:
    """One MULTI-AREA, map-only design: several GEO blocks, one .DSN folder.

    Entry policy: every area gets exactly one entry point, GEO table index 0, at
    the ``entry`` [x, y] and ``facing`` given for that area. So ``start_entry``
    is 1-based (GAME001 byte 49) and must be 1. Nothing defaults: ``area``,
    ``entry``, ``facing``, ``start_area`` and ``start_entry`` must all be named.
    """
    mixed = sorted(AREA_KEYS & set(d))
    if mixed:
        raise PorPipelineError("%s mixes a grouped 'areas' list with flat field(s) %s; "
                               "put those fields on each area" % (where, ", ".join(mixed)))
    unknown = sorted(set(d) - GROUP_KEYS)
    if unknown:
        raise PorPipelineError("%s has unknown key(s) %s" % (where, ", ".join(unknown)))
    title = d.get("title", DEFAULT_TITLE)
    if not isinstance(title, str):
        raise PorPipelineError("%s.title must be a string" % where)
    if "start_area" not in d:
        raise PorPipelineError("%s is missing start_area" % where)
    start_area = d["start_area"]
    if not _is_int(start_area) or not (1 <= start_area <= 999):
        raise PorPipelineError("%s.start_area must be 1..999" % where)
    if "start_entry" not in d:
        raise PorPipelineError("%s is missing start_entry" % where)
    if not _is_int(d["start_entry"]) or d["start_entry"] != 1:
        raise PorPipelineError("%s.start_entry must be 1: each area has one entry point "
                               "(GEO table index 0), and GAME001 byte 49 is 1-based"
                               % where)
    areas_in = d["areas"]
    if not isinstance(areas_in, list) or not areas_in:
        raise PorPipelineError("%s.areas must be a non-empty list" % where)

    areas = []
    area_nums = set()
    blocks = set()
    for j, a in enumerate(areas_in):
        awhere = "%s.areas[%d]" % (where, j)
        if not isinstance(a, dict):
            raise PorPipelineError("%s must be an object" % awhere)
        unknown = sorted(set(a) - AREA_KEYS)
        if unknown:
            raise PorPipelineError("%s has unknown key(s) %s" % (awhere, ", ".join(unknown)))
        missing = sorted(AREA_KEYS - set(a))
        if missing:
            raise PorPipelineError("%s is missing %s (nothing is defaulted in a group)"
                                   % (awhere, ", ".join(missing)))
        geo = a["geo"]
        if not _is_int(geo) or not (1 <= geo <= 8):
            raise PorPipelineError("%s.geo must be 1..8" % awhere)
        index = a["index"]
        if not _is_int(index) or index < 0:
            raise PorPipelineError("%s.index must be a TOC index >= 0" % awhere)
        area = a["area"]
        if not _is_int(area) or not (1 <= area <= 999):
            raise PorPipelineError("%s.area must be 1..999" % awhere)
        entry = a["entry"]
        if (not isinstance(entry, list) or len(entry) != 2
                or not all(_is_int(v) and 0 <= v <= 15 for v in entry)):
            raise PorPipelineError("%s.entry must be [x, y] with 0..15" % awhere)
        facing = a["facing"]
        if not isinstance(facing, str) or facing not in pm.FACINGS:
            raise PorPipelineError("%s.facing must be one of %s"
                                   % (awhere, ", ".join(sorted(pm.FACINGS))))
        if area in area_nums:
            raise PorPipelineError("%s.area %d repeats within design %r"
                                   % (awhere, area, name))
        area_nums.add(area)
        if (geo, index) in blocks:
            raise PorPipelineError("%s: GEO%d index %d is used twice in design %r "
                                   "(ambiguous)" % (awhere, geo, index, name))
        blocks.add((geo, index))
        areas.append({"geo": geo, "index": index, "area": area,
                      "entry": (entry[0], entry[1]), "facing": facing})
    if start_area not in area_nums:
        raise PorPipelineError("%s.start_area %d is not one of the design's areas %s"
                               % (where, start_area, sorted(area_nums)))
    return {"name": name, "kind": GROUP_KIND, "title": title,
            "start_area": start_area, "start_entry": 1, "areas": areas}


# --------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------

def stage_blocks(install: Path, out: Path) -> list[dict]:
    """Decode every TOC block of every GEO archive. Refusals are recorded."""
    rows = []
    for n in GEO_NUMBERS:
        dax = locate_member(install, "GEO%d.DAX" % n)
        entries, _base = pm.parse_dax(dax.read_bytes())
        for te in entries:
            row = {"geo": n, "index": te.index, "block_id": te.block_id,
                   "raw_size": te.raw_size}
            folder = out / "maps" / ("geo%d-i%02d-b%03d" % (n, te.index, te.block_id))
            try:
                res = pm.convert(dax, folder, block_id=None, index=te.index,
                                 expect=[], entry=None, area=pm.DEFAULT_AREA,
                                 name=pm.DEFAULT_NAME, title=None)
                row["status"] = "decoded"
                row["decoded_sha256"] = res["norm"]["source"]["decoded_sha256"]
                row["warnings"] = len(res["warnings"])
            except (pm.PorMapError, PorSourceError) as exc:
                row["status"] = "refused"
                row["reason"] = str(exc)
            rows.append(row)
    return rows


def stage_designs(install: Path, out: Path, designs: list[dict]) -> list[dict]:
    """Emit each planned map-only design and read it back with OpenUA's loader.

    A flat row is one area through ``por_map.convert`` (unchanged). A grouped row
    (``kind == GROUP_KIND``) is one DSN folder with several areas; see
    ``stage_group_design``.
    """
    rows = []
    for d in designs:
        if d.get("kind") == GROUP_KIND:
            rows.append(stage_group_design(install, out, d))
            continue
        row = {"name": d["name"], "geo": d["geo"], "index": d["index"],
               "area": d["area"], "entry": {"x": d["entry"][0], "y": d["entry"][1],
                                            "facing": d["facing"]}}
        dax = locate_member(install, "GEO%d.DAX" % d["geo"])
        folder = out / "designs" / d["name"]
        facing = pm.FACINGS[d["facing"]]
        try:
            pm.convert(dax, folder, block_id=None, index=d["index"], expect=[],
                       entry=(d["entry"][0], d["entry"][1], facing),
                       area=d["area"], name=d["name"], title=d["title"])
        except (pm.PorMapError, PorSourceError) as exc:
            row["status"] = "refused"
            row["reason"] = str(exc)
            rows.append(row)
            continue
        dsn_dir = d["name"] + ".DSN"          # dsn.Design appends the suffix
        dsn = folder / dsn_dir / ("GEO%03d.DAT" % d["area"])
        row["file"] = "%s/GEO%03d.DAT" % (dsn_dir, d["area"])
        row["checks"] = _round_trip(dsn, d["entry"], facing)
        row["loader_equivalent"] = _loader_check(folder / dsn_dir, [d["area"]])
        row["status"] = _design_status(row["checks"], row["loader_equivalent"])
        rows.append(row)
    return rows


def _decode_area(install: Path, a: dict) -> tuple[dict, Geo]:
    """Decode one planned area's TOC block into an OpenUA Geo with its entry point.

    Mirrors the decode in ``por_map.convert`` but writes nothing, so a grouped
    design can be checked in full before any folder is created. Raises the
    decoder's own refusal types.
    """
    dax = locate_member(install, "GEO%d.DAX" % a["geo"])
    data = dax.read_bytes()
    entries, base = pm.parse_dax(data)
    te = pm.select_block(entries, None, a["index"])
    start = base + te.data_offset
    raw = pm.rle_decode(data[start:start + te.comp_size], te.raw_size)
    cells = pm.decode_gen1_geo(raw)
    x, y = a["entry"]
    geo = pm.build_openua_geo(cells, (x, y, pm.FACINGS[a["facing"]]))
    src = {"block_id": te.block_id, "raw_size": te.raw_size,
           "decoded_sha256": hashlib.sha256(raw).hexdigest()}
    return src, geo


def stage_group_design(install: Path, out: Path, d: dict) -> dict:
    """One MULTI-AREA map-only design: every area's GEO in one ``NAME.DSN`` folder.

    All areas are decoded first. If any area is refused, the design is refused and
    no folder is written. Otherwise one ``dsn.Design`` gets every area and writes
    the folder (GAME001.DAT plus GEO<NNN>.DAT per area). Each emitted GEO is read
    back with ``geo.Geo.parse`` and compared with its in-memory build; GAME001 is
    checked for the start area and start entry. Still playable=false.
    """
    name = d["name"]
    row = {"name": name, "kind": GROUP_KIND, "scope": GROUP_SCOPE, "playable": False,
           "title": d["title"], "start_area": d["start_area"],
           "start_entry": d["start_entry"], "areas": []}
    built = []
    refused = []
    for a in d["areas"]:
        arow = {"area": a["area"], "geo": a["geo"], "index": a["index"],
                "entry": {"x": a["entry"][0], "y": a["entry"][1],
                          "facing": a["facing"]}}
        row["areas"].append(arow)
        try:
            src, geo = _decode_area(install, a)
        except (pm.PorMapError, PorSourceError, GeoError) as exc:
            arow["status"] = "refused"
            arow["reason"] = str(exc)
            refused.append(a["area"])
            continue
        arow.update(src)
        arow["status"] = "decoded"      # overwritten to ok/failed once the DSN is checked
        built.append((a, geo, arow))
    if refused:
        row["status"] = "refused"
        row["reason"] = "%d of %d areas refused (area %s)" % (
            len(refused), len(d["areas"]), ", ".join(str(n) for n in refused))
        return row

    ds = Design(name, title=d["title"][:31])
    ds.start_area = d["start_area"]
    ds.start_entry = d["start_entry"]
    for a, geo, _arow in built:
        ds.add_area(a["area"], geo)
    folder = out / "designs" / name
    ds_folder = Path(ds.write(str(folder)))      # <folder>/<NAME>.DSN
    rel_dir = "designs/%s/%s" % (name, ds.name)

    game = (ds_folder / "GAME001.DAT").read_bytes()
    expected = sorted(["GAME001.DAT"] + ["GEO%03d.DAT" % a["area"] for a, _g, _r in built])
    design_checks = {
        "files_exact": sorted(os.listdir(ds_folder)) == expected,
        "game001_bytes_match": game == ds.game001(),
        "game001_start_area": game[48] == d["start_area"],   # GAME001 byte 48
        "game001_start_entry": game[49] == d["start_entry"],  # GAME001 byte 49
    }
    rels = ["%s/GAME001.DAT" % rel_dir]
    for a, geo, arow in built:
        fname = "GEO%03d.DAT" % a["area"]
        path = ds_folder / fname
        checks = _round_trip(path, a["entry"], pm.FACINGS[a["facing"]])
        checks["file_equals_built"] = path.read_bytes() == geo.build()
        arow["file"] = "%s/%s" % (rel_dir, fname)
        arow["checks"] = checks
        arow["status"] = "ok" if all(checks.values()) else "failed"
        rels.append(arow["file"])

    row["folder"] = rel_dir
    row["checks"] = design_checks
    # The fields dsn.Design sets for every design. They are the writer's own
    # defaults, not values recovered from the Pool of Radiance install.
    row["game001_writer_defaults"] = {"xp": ds.xp, "platinum": ds.platinum,
                                      "gems": ds.gems, "jewelry": ds.jewelry,
                                      "equipment": ds.equipment}
    row["files"] = _out_files(out, rels)
    row["loader_equivalent"] = _loader_check(ds_folder, [a["area"] for a in d["areas"]])
    areas_ok = all(r.get("status") == "ok" for r in row["areas"])
    row["status"] = "ok" if (all(design_checks.values()) and areas_ok
                             and row["loader_equivalent"]["verdict"] == "pass") else "failed"
    return row


def _round_trip(dsn: Path, entry: tuple, facing: int) -> dict:
    """Container round-trip and entry point, through OpenUA's own geo.py."""
    checks = {"parses": False, "byte_round_trip": False, "entry_point": False}
    raw = dsn.read_bytes()
    try:
        geo = Geo.parse(raw)
    except (GeoError, ValueError):
        return checks
    checks["parses"] = True
    checks["byte_round_trip"] = geo.build() == raw
    checks["entry_point"] = geo.entry_point(0) == (entry[1], entry[0], facing)
    return checks


def _loader_check(dsn_folder: Path, areas: list) -> dict:
    """Loader-equivalent host checks on one emitted ``NAME.DSN`` folder.

    Delegates to ``por_dsn_load_smoke.validate_folder``; no engine rule is copied
    here. ``verdict`` is ``pass`` only when every check passed on these bytes. A
    ``fail`` lists the failing check ids in ``failed``. Any GEO area above the
    engine's 0..255 range is a failing ``geo-addressable`` check, so it cannot
    pass. ``areas_above_engine_range`` names those areas explicitly, because
    GAME001 byte 48 keeps only the low byte of the start area, so the validator's
    ``start-geo-present`` check can fail for the wrong-looking reason. ``areas``
    are the design's area numbers. ``runtime_loaded`` and ``engine_executed`` are
    false by construction: this stage never runs the engine.
    """
    above = sorted(a for a in areas if a > pls.ENGINE_MAX_AREA)
    base = {"engine_area_max": pls.ENGINE_MAX_AREA, "areas_above_engine_range": above,
            "runtime_loaded": False, "engine_executed": False}
    try:
        rep = pls.validate_folder(dsn_folder)
    except pls.SmokeRefusal as exc:
        return dict(base, verdict="refused", reason=str(exc), failed=[],
                    start_area=None, start_entry=None, checks=[])
    checks = [{"id": c["id"], "status": c["status"], "detail": c["detail"],
               "source": c["source"]} for c in rep["checks"]]
    return dict(base, verdict=rep["verdict"],
                failed=[c["id"] for c in checks if c["status"] == "fail"],
                start_area=rep["start_area"], start_entry=rep["start_entry"],
                checks=checks)


def _design_status(checks: dict, loader: dict) -> str:
    """A design is ``ok`` only when its round-trip checks AND its loader-equivalent
    verdict pass. A loader failure is a design failure, not a warning."""
    return "ok" if (all(checks.values()) and loader["verdict"] == "pass") else "failed"


def _loader_cell(d: dict) -> str:
    """Report-table text for one design's loader-equivalent verdict."""
    le = d.get("loader_equivalent")
    if le is None:
        return "not checked"
    if le["verdict"] == "pass":
        return "pass"
    parts = [le["verdict"]]
    if le["areas_above_engine_range"]:
        parts.append("areas above engine range 0..%d: %s" % (
            le["engine_area_max"], ", ".join(str(a) for a in le["areas_above_engine_range"])))
    if le["failed"]:
        parts.append(", ".join(le["failed"]))
    return "; ".join(parts)


def _out_files(out: Path, rels: list[str]) -> list[dict]:
    """Path (relative to OUT, POSIX), size and SHA-256 of each written file."""
    rows = []
    for rel in rels:
        data = (out / rel).read_bytes()
        rows.append({"path": rel, "bytes": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()})
    return rows


def stage_ecl_text(install: Path, out: Path) -> dict:
    """ECL census, then the unaccepted 6-bit diagnostic over that census.

    Both write under OUT only. Read-only on the install (the census opens its
    archives "rb"). Returns the manifest section; never claims a decoded string
    as accepted text.
    """
    census_dir = out / ECL_CENSUS_DIR
    diag_dir = out / ECL_DIAG_DIR
    try:
        result, census_code = ps.census(install, census_dir)
        ps.write_outputs(result, census_dir)
    except (ps.StringCensusError, pe.EclError, pm.PorMapError) as exc:
        raise PorPipelineError("ECL census refused: %s" % exc)
    try:
        doc = ptd.run(census_dir / ECL_CENSUS_JSON, diag_dir)
    except ptd.DiagnosticError as exc:
        raise PorPipelineError("ECL text diagnostic refused: %s" % exc)

    per = result["summary"]["per_framing"]
    census_rel = ["%s/%s" % (ECL_CENSUS_DIR, ECL_CENSUS_JSON),
                  "%s/%s" % (ECL_CENSUS_DIR, ECL_CENSUS_MD)]
    diag_rel = ["%s/%s" % (ECL_DIAG_DIR, ptd.OUT_JSON),
                "%s/%s" % (ECL_DIAG_DIR, ptd.OUT_MD)]
    frames = doc["frames"]
    return {
        "status": ECL_STATUS,
        "playable": False,
        "census": {
            "dir": ECL_CENSUS_DIR,
            "status": result["status"],
            "exit": census_code,
            "archives_present": result["summary"]["archives_present"],
            "blocks_ok": result["summary"]["blocks_ok"],
            "string_frames_by_framing": {fr: per[fr]["string_frames"]
                                         for fr in ps.FRAMINGS},
            "skipped_frames": len(result["skipped_frames"]),
            "diagnostics": len(result["diagnostics"]),
            "files": _out_files(out, census_rel),
        },
        "diagnostic": {
            "dir": ECL_DIAG_DIR,
            "status": doc["status"],
            "frames_total": doc["summary"]["frames_total"],
            "chars_decoded_total": doc["summary"]["chars_decoded_total"],
            "zero_values_skipped_total": doc["summary"]["zero_values_skipped_total"],
            "accepted_frames": sum(1 for f in frames if f["accepted"]),
            "files": _out_files(out, diag_rel),
        },
        "unresolved": ptd.unresolved_summary(),
        "unsupported": list(ECL_UNSUPPORTED),
    }


# --------------------------------------------------------------------------
# Manifest and report
# --------------------------------------------------------------------------

def _summary(blocks: list[dict], designs: list[dict]) -> dict:
    decoded = sum(1 for b in blocks if b["status"] == "decoded")
    ok = sum(1 for d in designs if d["status"] == "ok")
    loader_pass = sum(1 for d in designs
                      if d.get("loader_equivalent", {}).get("verdict") == "pass")
    return {
        "blocks_total": len(blocks),
        "blocks_decoded": decoded,
        "blocks_refused": len(blocks) - decoded,
        "designs_planned": len(designs),
        "designs_ok": ok,
        "designs_failed": len(designs) - ok,
        "designs_loader_passed": loader_pass,
    }


def render_report(manifest: dict) -> str:
    s = manifest["summary"]
    lines = [
        "# Pool of Radiance pipeline run (MAP-ONLY)", "",
        "**`playable: false`.** Container checks only; no runtime check.", "",
        "| Item | Count |", "| --- | ---: |",
        "| GEO blocks decoded | %d / %d |" % (s["blocks_decoded"], s["blocks_total"]),
        "| Planned designs round-tripped | %d / %d |" % (s["designs_ok"], s["designs_planned"]),
        "| Loader-equivalent host checks passed (engine NOT run) | %d / %d |"
        % (s["designs_loader_passed"], s["designs_planned"]),
        "| Install unchanged during run | %s |" % ("yes" if manifest["install"]["unchanged"] else "NO"),
        "", "## Blocks", "",
        "| GEO | TOC index | block id | status | note |", "| ---: | ---: | ---: | --- | --- |",
    ]
    for b in manifest["blocks"]:
        note = b.get("reason", "") or ("warnings %d" % b.get("warnings", 0))
        lines.append("| %d | %d | %d | %s | %s |" % (b["geo"], b["index"], b["block_id"],
                                                    b["status"], note))
    flat = [d for d in manifest["designs"] if d.get("kind") != GROUP_KIND]
    grouped = [d for d in manifest["designs"] if d.get("kind") == GROUP_KIND]
    if flat:
        lines += ["", "## Designs", "",
                  "| name | GEO | index | area | entry (x,y,facing) | status | loader-equivalent |",
                  "| --- | ---: | ---: | ---: | --- | --- | --- |"]
        for d in flat:
            e = d["entry"]
            lines.append("| %s | %d | %d | %d | %d,%d,%s | %s | %s |"
                         % (d["name"], d["geo"], d["index"], d["area"],
                            e["x"], e["y"], e["facing"], d["status"], _loader_cell(d)))
    for d in grouped:
        lines += _render_group(d)
    if "ecl_text" in manifest:
        lines += _render_ecl(manifest["ecl_text"])
    lines += ["", "## Not claimed", ""]
    lines += ["- " + u for u in UNSUPPORTED]
    return "\n".join(lines) + "\n"


def _render_group(d: dict) -> list[str]:
    """One grouped design: a header row, then one row per area."""
    lines = ["", "## Multi-area design %s (%s; playable=false)" % (d["name"], GROUP_SCOPE),
             "", "| name | areas | start area | start entry | status | loader-equivalent |",
             "| --- | ---: | ---: | ---: | --- | --- |",
             "| %s | %d | %d | %d | %s | %s |" % (d["name"], len(d["areas"]), d["start_area"],
                                                  d["start_entry"], d["status"],
                                                  _loader_cell(d))]
    if "reason" in d:
        lines += ["", "Refused: %s" % d["reason"]]
    lines += ["", "| area | GEO | index | entry (x,y,facing) | status |",
              "| ---: | ---: | ---: | --- | --- |"]
    for a in d["areas"]:
        e = a["entry"]
        lines.append("| %d | %d | %d | %d,%d,%s | %s |"
                     % (a["area"], a["geo"], a["index"], e["x"], e["y"], e["facing"],
                        a["status"]))
    return lines


def _render_ecl(e: dict) -> list[str]:
    c, d = e["census"], e["diagnostic"]
    sbf = c["string_frames_by_framing"]
    lines = ["", "## ECL text (optional; diagnostic-unaccepted)", "",
             "**Status: %s. `playable: false`.** The census frames are decoded with the "
             "retail-verified 6-bit codec for diagnosis only. No string is accepted, "
             "merged into a DSN or STRG, or shown as Pool of Radiance text." % e["status"],
             "",
             "| Item | Value |", "| --- | ---: |",
             "| ECL archives present | %d / 8 |" % c["archives_present"],
             "| Census exit (0 clean, 1 diagnostics) | %d |" % c["exit"],
             "| String frames by framing | %s |" % ", ".join(
                 "%s %d" % (k, sbf[k]) for k in sorted(sbf)),
             "| Skipped or ambiguous walks | %d |" % c["skipped_frames"],
             "| Census diagnostics | %d |" % c["diagnostics"],
             "| Diagnostic frames | %d |" % d["frames_total"],
             "| Frames accepted | %d |" % d["accepted_frames"],
             "", "Unresolved:", ""]
    lines += ["- `%s` (%s): %s" % (u["code"], u["scope"], u["message"])
              for u in e["unresolved"]]
    lines += ["", "Outputs: `%s/`, `%s/` (hashes in `por_pipeline.json`)."
              % (c["dir"], d["dir"]), "", "ECL not claimed:", ""]
    lines += ["- " + u for u in e["unsupported"]]
    return lines


def _move(src: Path, dst: Path) -> None:
    """One rename within OUT's parent. A seam for the rollback tests."""
    os.rename(src, dst)


def _make_dirs(path: Path) -> list[Path]:
    """Create ``path`` and any missing ancestors. Returns the folders this call
    created, in creation order, so a failed run can remove only those."""
    missing = []
    p = path
    while not p.exists() and p.parent != p:
        missing.append(p)
        p = p.parent
    made = []
    for m in reversed(missing):
        m.mkdir()
        made.append(m)
    return made


def _rmdir_if_empty(path: Path) -> None:
    try:
        os.rmdir(path)
    except OSError:
        pass


def _discard_staging(staging: Path, parent: Path) -> None:
    """Remove the one staging folder this run created, and nothing else."""
    if staging.parent != parent or not staging.name.startswith(STAGE_PREFIX):
        raise PorPipelineError("refusing to remove an unexpected staging path")
    shutil.rmtree(staging)


def _publish(staging: Path, out: Path, created: list[Path]) -> None:
    """Replace the owned outputs in OUT with the staged ones.

    For each owned name: an existing OUT entry is renamed into the staging
    folder (``REPLACED_DIR``), then the staged entry is renamed into OUT. Any
    rename failure reverses every rename already made, so OUT ends as it began.
    Only the owned names are touched; unrelated OUT entries are never moved.
    A rollback that itself fails keeps the replaced entries in the staging
    folder and marks the error ``keep_staging`` so the caller does not delete
    them.
    """
    old = staging / REPLACED_DIR
    moved_old: list[str] = []
    moved_new: list[str] = []
    try:
        if not out.is_dir():
            out.mkdir()
            created.append(out)
        old.mkdir()
        for name in OWNED_OUTPUTS:
            if os.path.lexists(out / name):
                _move(out / name, old / name)
                moved_old.append(name)
            if os.path.lexists(staging / name):
                _move(staging / name, out / name)
                moved_new.append(name)
    except OSError as exc:
        try:
            for name in reversed(moved_new):
                _move(out / name, staging / name)
            for name in reversed(moved_old):
                _move(old / name, out / name)
        except OSError as rb:
            err = PorPipelineError(
                "publish failed (%s) and rollback failed (%s); the previous output is "
                "kept in %s" % (exc, rb, old))
            err.keep_staging = True
            raise err from exc
        raise PorPipelineError("could not publish output (%s); previous output restored"
                               % exc) from exc


def run(install: Path, out: Path, plan: Optional[Path], *,
        with_ecl_text: bool = False) -> tuple[dict, int]:
    """Run every stage into a staging folder beside OUT, then publish.

    The install is fingerprinted before the stages and again after them. A
    change is a refusal, and nothing is published. On any failure only the
    staging folder and the directories this call created are removed.
    """
    if not install.is_dir():
        raise PorPipelineError("install folder not found")
    out = Path(out)
    # validate_output_dir returns a resolved path. Use it so the staging parent
    # and tempfile.mkdtemp() agree on absolute vs relative paths. In Python
    # 3.12+, mkdtemp(dir=<relative path>) returns an absolute path on every
    # platform, and the staging cleanup guard intentionally rejects a path
    # whose parent differs from the relative parent. Without this assignment a
    # successful relative-path run can publish all output and then fail while
    # cleaning its staging folder.
    out = validate_output_dir(install, out)
    poolrad = install / "POOLRAD"
    if poolrad.is_dir():
        validate_output_dir(poolrad, out)
    if out.name == "":
        raise PorPipelineError("output folder needs a name (not a drive root)")
    if out.exists() and not out.is_dir():
        raise PorPipelineError("output path exists and is not a folder")
    designs_plan, plan_sha = load_plan(plan)
    extra = ECL_ARCHIVES if with_ecl_text else ()

    before = fingerprint(install, extra)
    parent = out.parent
    created: list[Path] = []
    staging: Optional[Path] = None
    try:
        created.extend(_make_dirs(parent))
        staging = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=str(parent)))
        blocks = stage_blocks(install, staging)
        designs = stage_designs(install, staging, designs_plan)
        ecl = stage_ecl_text(install, staging) if with_ecl_text else None

        manifest = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "status": STATUS,
            "playable": False,
            "install": {"members": before, "unchanged": True},
            "plan": {"sha256": plan_sha, "designs": len(designs_plan)},
            "blocks": blocks,
            "designs": designs,
            "summary": _summary(blocks, designs),
            "unsupported": UNSUPPORTED,
        }
        if ecl is not None:
            manifest["ecl_text"] = ecl
        (staging / "por_pipeline.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (staging / "por_pipeline_report.md").write_text(
            render_report(manifest), encoding="utf-8")

        # Last look at the install, immediately before anything is published.
        if fingerprint(install, extra) != before:
            raise PorPipelineError("install changed during the run; output discarded")
        _publish(staging, out, created)
    except BaseException as exc:
        if staging is not None and not getattr(exc, "keep_staging", False):
            _discard_staging(staging, parent)
        for d in reversed(created):
            _rmdir_if_empty(d)
        raise

    try:
        _discard_staging(staging, parent)   # now holds only the replaced entries
    except OSError as exc:
        warnings.warn("published, but staging folder %s could not be removed: %s"
                      % (staging.name, exc))

    s = manifest["summary"]
    clean = (s["blocks_refused"] == 0 and s["designs_failed"] == 0
             and (ecl is None or ecl["census"]["exit"] == 0))
    return manifest, 0 if clean else 1


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance install -> OpenUA map-only pipeline (one run).")
    ap.add_argument("--install", type=Path, required=True,
                    help="PoR DOS install folder (or the folder above POOLRAD)")
    ap.add_argument("-o", "--out", type=Path, required=True,
                    help="output folder (outside the install; under data/ in-repo)")
    ap.add_argument("--plan", type=Path, default=None,
                    help="explicit design plan JSON (see the module docstring)")
    ap.add_argument("--with-ecl-text", action="store_true",
                    help="also run the ECL string census and the unaccepted 6-bit "
                         "diagnostic over ECL1..8.DAX (requires all eight)")
    args = ap.parse_args(argv)
    try:
        manifest, code = run(args.install, args.out, args.plan,
                             with_ecl_text=args.with_ecl_text)
    except (PorPipelineError, PorSourceError, pm.PorMapError, GeoError) as exc:
        print("por_pipeline: error: %s" % exc, file=sys.stderr)
        return 2
    s = manifest["summary"]
    print("por_pipeline: blocks decoded %d/%d; designs ok %d/%d; loader-equivalent pass %d/%d "
          "(MAP-ONLY, engine not run, not a playable claim)"
          % (s["blocks_decoded"], s["blocks_total"], s["designs_ok"], s["designs_planned"],
             s["designs_loader_passed"], s["designs_planned"]))
    if "ecl_text" in manifest:
        e = manifest["ecl_text"]
        print("por_pipeline: ECL text %s, playable=false; census exit %d, %d string frames, "
              "%d diagnostic frames (none accepted)"
              % (e["status"], e["census"]["exit"], sum(e["census"]["string_frames_by_framing"].values()),
                 e["diagnostic"]["frames_total"]))
    print("por_pipeline: wrote %s and %s" % (args.out / "por_pipeline.json",
                                           args.out / "por_pipeline_report.md"))
    return code


if __name__ == "__main__":
    sys.exit(main())
