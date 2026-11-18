#!/usr/bin/env python3
"""OpenUA design-folder load smoke: the engine loader's checks, run on the host.

Input is one generated design folder (`<NAME>.DSN/`, as written by tools/dsn.py
`Design.write`, or by any tool that writes the same layout). The folder is read
only; nothing in it is modified and no file is created inside it.

What this establishes, and only this
  Every check below is a host-side reading of the bytes that the engine's
  loader tests before it accepts a GEO or GAME record. Each check names the
  engine routine it mirrors. A `pass` verdict means: these loader-equivalent
  checks passed on these bytes. It does NOT mean the engine loaded the design.

What this does NOT establish
  The engine loader is 68k code in the Atari build (src/engine/boot.c: jt198 ->
  L720a -> L7226, jt127, jt361). It runs only inside an emulator or on hardware.
  This tool does not run it, does not launch an emulator, and does not claim
  runtime loading. See LIMITATIONS in the report, and docs/por-dsn-load-smoke.md.

Checks (each row of the report's `checks` list)
  design-folder-name     the folder is `*.DSN` (engine design picker, boot.c)
  game001-present        GAME001.DAT exists                         (boot.c jt361)
  game001-start-bytes    GAME001.DAT has bytes 48 and 49            (boot.c jt361)
  start-area-nonzero     start area byte 48 is 1 or more            (writer convention, tools/dsn.py)
  geo-files-present      at least one GEO<NNN>.DAT                   (boot.c jt198)
  start-geo-present      GEO<start>.DAT exists                       (boot.c jt198; missing -> jt69)
  geo-addressable:F      area number <= 255                          (boot.c jt127: (unsigned char) num)
  geo-size:F             exactly GEO_SIZE (12962) bytes              (boot.c jt198: out must equal 12962)
  geo-parse:F            geo.Geo.parse accepts the container         (boot.c L7226 structure, tools/geo.py)

Reuse, not copies: the container parse is `geo.Geo.parse`; the 12962-byte size is
`geo.GEO_SIZE`. This tool adds only the exact-size rule, the file-presence rules
and the reporting around them.

Usage
  python3 tools/por_dsn_load_smoke.py <path\\to\\NAME.DSN> [--report out.json]

  --report writes the JSON report (sorted keys, no timestamps, no absolute paths,
  so the same folder gives byte-identical output). The report file must be outside
  the design folder; a report inside it is refused.

Exit codes
  0  every loader-equivalent check passed
  1  at least one check failed (the report lists which, and why)
  2  refusal: not a directory, or the report would be written inside the folder
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

from geo import GEO_SIZE, Geo, GeoError

SCHEMA = "openua.por-dsn-load-smoke"
SCHEMA_VERSION = 0

# jt127 (boot.c) passes the area number as (unsigned char) num, so only areas
# 0..255 can be addressed. tools/dsn.py allows 1..999, so this can be exceeded.
ENGINE_MAX_AREA = 255

# GAME001.DAT: byte 48 = start area, byte 49 = start entry (1-based). The engine
# reads both on Play (boot.c jt361 reads the whole record; gh[48], gh[49]).
GAME_NAME = "GAME001.DAT"
GAME_START_OFF = 48
GAME_ENTRY_OFF = 49

GEO_NAME_RE = re.compile(r"^GEO(\d{3})\.DAT$", re.IGNORECASE)

LIMITATIONS = [
    "The engine loader is 68k code in the Atari build; this tool does not run it "
    "and does not launch an emulator or DOSBox. No runtime load is claimed.",
    "Checks are reading-equivalents of the loader's tests, not the loader itself; "
    "a pass shows the bytes pass these tests, not that the engine accepts them.",
    "Not checked: start.dat (the design name the engine resolves), GEO event and "
    "string contents, monster and item references, art resolution, and the start "
    "entry (byte 49) against the area's entry-point table.",
    "Not checked: the GAME001.DAT record length. The engine reads whatever length "
    "the file has (boot.c jt361); only bytes 48 and 49 are required here.",
    "Stricter than the engine on one point: L7226 accepts a GEO whose first long "
    "is not FORM/CAT/LIST as raw legacy data. geo.Geo.parse refuses it, and so does "
    "this tool.",
]


class SmokeRefusal(Exception):
    """A refusal: the input cannot be checked, nothing is judged."""


def _check(checks: list, cid: str, ok: bool, detail: str, source: str) -> None:
    checks.append({
        "id": cid,
        "status": "pass" if ok else "fail",
        "detail": detail,
        "source": source,
    })


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_folder(folder: Path) -> dict:
    """Run every loader-equivalent check on one design folder. Read-only."""
    if not folder.is_dir():
        raise SmokeRefusal("not a directory: %s" % folder.name)

    # Read every file once; all checks use these bytes. Names are matched
    # case-insensitively, as GEMDOS does; the actual on-disk name is kept.
    blobs: dict[str, bytes] = {}
    for name in sorted(os.listdir(folder)):
        path = folder / name
        if path.is_file():
            blobs[name] = path.read_bytes()
    by_upper = {name.upper(): name for name in blobs}

    checks: list = []
    _check(checks, "design-folder-name",
           folder.name.upper().endswith(".DSN"),
           "folder %r is %s" % (folder.name,
                                "*.DSN" if folder.name.upper().endswith(".DSN")
                                else "not *.DSN"),
           "boot.c design picker enumerates *.DSN folders")

    # GAME001.DAT: start area and entry.
    start = None
    entry = None
    game = by_upper.get(GAME_NAME)
    if game is None:
        _check(checks, "game001-present", False, "GAME001.DAT missing",
               "boot.c jt361 reads GAME001 at boot")
    else:
        _check(checks, "game001-present", True, "GAME001.DAT present",
               "boot.c jt361 reads GAME001 at boot")
        raw = blobs[game]
        has_bytes = len(raw) > GAME_ENTRY_OFF
        _check(checks, "game001-start-bytes", has_bytes,
               "GAME001.DAT is %d bytes; bytes 48-49 %s"
               % (len(raw), "present" if has_bytes else "missing"),
               "boot.c jt361 / Play reads gh[48] and gh[49]")
        if has_bytes:
            start = raw[GAME_START_OFF]
            entry = raw[GAME_ENTRY_OFF]
            _check(checks, "start-area-nonzero", start >= 1,
                   "start area = %d" % start,
                   "writer convention: tools/dsn.py areas are 1..999")

    # GEO files: name, number, exact size, container parse.
    geo_files = []
    for name in sorted(blobs):
        m = GEO_NAME_RE.match(name)
        if m:
            geo_files.append((int(m.group(1)), name))
    _check(checks, "geo-files-present", bool(geo_files),
           "%d GEO file(s) found" % len(geo_files),
           "boot.c jt198 loads GEO<NNN>.DAT")

    nums = {num for num, _ in geo_files}
    if start is not None:
        start_name = "GEO%03d.DAT" % start
        _check(checks, "start-geo-present", start in nums,
               "%s %s" % (start_name,
                          "present" if start in nums else "missing"),
               "boot.c jt198: missing file -> read count 0 -> jt69 fatal")

    for num, name in geo_files:
        _check(checks, "geo-addressable:%s" % name, num <= ENGINE_MAX_AREA,
               "area %d %s the engine's 0..255 range"
               % (num, "within" if num <= ENGINE_MAX_AREA else "above"),
               "boot.c jt127 passes (unsigned char) num")
        data = blobs[name]
        size_ok = len(data) == GEO_SIZE
        _check(checks, "geo-size:%s" % name, size_ok,
               "%d bytes; engine requires exactly %d" % (len(data), GEO_SIZE),
               "boot.c jt198: read count must equal 12962")
        if size_ok:
            try:
                Geo.parse(data)
                _check(checks, "geo-parse:%s" % name, True,
                       "geo.Geo.parse accepts the container",
                       "boot.c L7226 structure; tools/geo.py Geo.parse")
            except GeoError as exc:
                _check(checks, "geo-parse:%s" % name, False, str(exc),
                       "boot.c L7226 structure; tools/geo.py Geo.parse")
        else:
            _check(checks, "geo-parse:%s" % name, False,
                   "not parsed: size check failed",
                   "boot.c L7226 structure; tools/geo.py Geo.parse")

    verdict = "pass" if all(c["status"] == "pass" for c in checks) else "fail"
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "design_folder": folder.name,
        "verdict": verdict,
        "start_area": start,
        "start_entry": entry,
        "files": {name: {"bytes": len(blobs[name]), "sha256": _sha256(blobs[name])}
                  for name in sorted(blobs)},
        "checks": checks,
        "runtime_loaded": False,
        "engine_executed": False,
        "limitations": LIMITATIONS,
    }


def _inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
        return True
    except ValueError:
        return False


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Loader-equivalent host checks on one generated .DSN folder. "
                    "Does not run the engine.")
    ap.add_argument("folder", help="the design folder (NAME.DSN)")
    ap.add_argument("--report", metavar="PATH",
                    help="also write the JSON report here (must be outside the folder)")
    args = ap.parse_args(argv)

    folder = Path(args.folder)
    try:
        if args.report and _inside(Path(args.report), folder):
            raise SmokeRefusal("--report must be outside the design folder")
        report = validate_folder(folder)
    except SmokeRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2

    for c in report["checks"]:
        print("  %-4s  %-28s  %s" % (c["status"].upper(), c["id"], c["detail"]))
    print("verdict: %s (loader-equivalent host checks; engine NOT run, "
          "no runtime load claimed)" % report["verdict"])

    if args.report:
        Path(args.report).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
