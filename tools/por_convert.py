#!/usr/bin/env python3
"""Pool of Radiance -> FRUA converter, slice 1: read-only source inventory.

Status: SOURCE INVENTORY + NORMALIZED-IR SKELETON ONLY. This tool does not
produce a FRUA design, a GEO/GAME/STRG/MONST file or anything the engine can
load. Its output says so in every file it writes (``"playable": false``).

What it does
  * Reads a user-supplied Pool of Radiance source folder strictly read-only.
    Every source file is opened ``"rb"``; nothing under the source is written,
    renamed or deleted, and symlinks are recorded but never followed.
  * Hashes and classifies every file (BMP, the Game.dat title header, text,
    item records, unknown), parses only the headers it can verify, and records
    what it did not decode.
  * Writes two deterministic files into an explicit output folder:
    ``por_ir.json`` (versioned intermediate skeleton with provenance) and
    ``por_report.md`` (human-readable status, unsupported list, loss list).

What it refuses
  * An output folder inside the source folder (or the source itself).
  * An output folder inside this repository unless it is under ``data/``,
    the git-ignored game-data folder. Generated output must never land in
    tracked source.
  * A source folder missing a required member (see REQUIRED_MEMBERS).

Usage
  python3 tools/por_convert.py SOURCE_DIR -o OUT_DIR

Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCHEMA = "openua.por-source-ir"
SCHEMA_VERSION = 0
STATUS = "source-inventory-only"
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"

# Members the slice needs to see before it will report on a source folder.
# Matching is case-insensitive on the file name, at the top level of the source.
REQUIRED_MEMBERS = ("Game.dat", "Levels.txt", "World.bmp")

# BMP pixel formats this slice recognises. Pixels are never decoded here.
BMP_BPP_OK = (1, 4, 8, 16, 24, 32)
BMP_COMPRESSION_NAMES = {0: "BI_RGB", 1: "BI_RLE8", 2: "BI_RLE4", 3: "BI_BITFIELDS"}


class PorSourceError(Exception):
    """A named, user-facing failure. The CLI prints it and exits with 2."""


@dataclass
class FileRecord:
    path: str                       # POSIX-style, relative to the source root
    kind: str                       # bmp | game-dat | text | item | symlink | unknown
    size: int = 0
    sha256: Optional[str] = None
    status: str = "inventoried"     # what the slice did with it
    details: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    def as_json(self) -> dict:
        out = {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
            "status": self.status,
            "details": self.details,
        }
        if self.warnings:
            out["warnings"] = self.warnings
        return out


# --------------------------------------------------------------------------
# Format probes. Each returns a details dict and may add warnings; none of
# them interpret game semantics.
# --------------------------------------------------------------------------

def probe_bmp(data: bytes, file_size: int) -> tuple[dict, list]:
    """Read the BITMAPFILEHEADER and BITMAPINFOHEADER. Pixels are not read."""
    warnings: list = []
    if len(data) < 54 or data[:2] != b"BM":
        raise PorSourceError("bmp probe: missing BM signature or truncated header")
    declared_size = struct.unpack_from("<I", data, 2)[0]
    pix_off = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    if dib_size < 40:
        raise PorSourceError(f"bmp probe: unsupported DIB header size {dib_size}")
    width, height = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    comp = struct.unpack_from("<I", data, 30)[0]
    if width <= 0 or height == 0:
        raise PorSourceError(f"bmp probe: bad dimensions {width}x{height}")
    if pix_off >= file_size:
        raise PorSourceError("bmp probe: pixel offset past end of file")
    if bpp not in BMP_BPP_OK:
        warnings.append(f"unusual bits-per-pixel {bpp}")
    if declared_size != file_size:
        warnings.append(
            f"BMP header declares {declared_size} bytes, file is {file_size}")
    details = {
        "width": width,
        "height": abs(height),
        "top_down": height < 0,
        "bits_per_pixel": bpp,
        "compression": BMP_COMPRESSION_NAMES.get(comp, f"unknown({comp})"),
        "pixel_offset": pix_off,
        "decoded": False,
    }
    return details, warnings


def probe_game_dat(data: bytes) -> tuple[dict, list]:
    """Read the leading title string of Game.dat. The rest is not decoded.

    The observed layout is two prefix bytes followed by a NUL-terminated ASCII
    title. The meaning of the prefix bytes is not established, so they are only
    recorded as hex.
    """
    warnings: list = []
    if len(data) < 3:
        raise PorSourceError("game-dat probe: file too short for a header")
    end = data.find(b"\x00", 2, 2 + 64)
    if end < 0:
        warnings.append("title is not NUL-terminated within 64 bytes")
        end = min(len(data), 2 + 64)
    raw = data[2:end]
    title = raw.decode("ascii", errors="replace")
    if not raw or any(b < 0x20 or b > 0x7E for b in raw):
        warnings.append("title contains non-printable bytes")
    details = {
        "prefix_hex": data[:2].hex(),
        "title": title,
        "body_decoded": False,
    }
    return details, warnings


def probe_text(data: bytes) -> dict:
    """Count lines and note the line ending. Text content is not kept."""
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    if crlf and lf:
        ending = "mixed"
    elif crlf:
        ending = "crlf"
    elif lf:
        ending = "lf"
    else:
        ending = "none"
    return {
        "lines": len(data.splitlines()),
        "line_ending": ending,
        "content_kept": False,
    }


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------

def _classify(rel_posix: str) -> str:
    name = rel_posix.rsplit("/", 1)[-1].lower()
    if name.endswith(".bmp"):
        return "bmp"
    if name == "game.dat" and "/" not in rel_posix:
        return "game-dat"
    if name.endswith(".txt"):
        return "text"
    if name.endswith(".itm") and rel_posix.lower().startswith("items/"):
        return "item"
    return "unknown"


def inventory_source(source: Path) -> list[FileRecord]:
    """Walk the source tree read-only and return a sorted list of records."""
    source = Path(source)
    if not source.is_dir():
        raise PorSourceError(f"source is not a directory: {source}")
    records: list[FileRecord] = []
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(source).as_posix()
            if full.is_symlink():
                records.append(FileRecord(path=rel, kind="symlink",
                                          status="skipped-symlink-not-followed"))
                continue
            if not full.is_file():
                continue
            kind = _classify(rel)
            # One read per file: hash and probe from the same bytes.
            data = full.read_bytes()
            rec = FileRecord(path=rel, kind=kind, size=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
            try:
                if kind == "bmp":
                    rec.details, rec.warnings = probe_bmp(data, len(data))
                    rec.status = "header-read"
                elif kind == "game-dat":
                    rec.details, rec.warnings = probe_game_dat(data)
                    rec.status = "title-read"
                elif kind == "text":
                    rec.details = probe_text(data)
                    rec.status = "inventoried"
                elif kind == "item":
                    rec.status = "inventoried"
                else:
                    rec.status = "unrecognised"
            except PorSourceError as exc:
                rec.status = "probe-failed"
                rec.warnings.append(str(exc))
            records.append(rec)
    return records


def check_required(records: list[FileRecord]) -> list[str]:
    """Return the required members that are missing (case-insensitive)."""
    top = {r.path.lower() for r in records if "/" not in r.path}
    return [m for m in REQUIRED_MEMBERS if m.lower() not in top]


# --------------------------------------------------------------------------
# Output-folder safety
# --------------------------------------------------------------------------

def validate_output_dir(source: Path, out: Path) -> Path:
    """Refuse output locations that could overwrite or pollute tracked data."""
    src = Path(source).resolve()
    dst = Path(out).resolve()
    if dst == src or dst.is_relative_to(src):
        raise PorSourceError(
            "output folder must not be inside the source folder")
    repo = REPO_ROOT.resolve()
    if dst.is_relative_to(repo) and not dst.is_relative_to(DATA_DIR.resolve()):
        raise PorSourceError(
            "output folder inside the repository must be under data/ "
            "(git-ignored); choose another location")
    return dst


# --------------------------------------------------------------------------
# Normalized intermediate skeleton and report
# --------------------------------------------------------------------------

UNSUPPORTED = [
    {"code": "no-design-output",
     "message": "No FRUA design (GAME001.DAT, GEO*.DAT, STRG*.DAT, MONST*.DAT) "
                "is written. This slice produces source inventory only."},
    {"code": "game-dat-body",
     "message": "Game.dat is recognised only by its title header. The body "
                "is not decoded."},
    {"code": "world-map-raster",
     "message": "World.bmp is a raster image; its pixels are not decoded. "
                "It is not a cell grid and must not be used as one."},
    {"code": "levels-text",
     "message": "Levels.txt is inventoried; class/level tables are not parsed."},
    {"code": "item-records",
     "message": "Item files are inventoried; item fields are not decoded."},
    {"code": "ecl-scripts",
     "message": "No ECL script is decoded. ECL is not translated to FRUA "
                "events and must not be replaced with empty or guessed events."},
    {"code": "monsters-encounters",
     "message": "Monster and encounter records are not decoded."},
    {"code": "art-assets",
     "message": "Bitmap art is not converted. FRUA art needs a separate "
                "measured path (see docs/converter-howto.md)."},
]

LOSS_NOTES = [
    "Nothing from the source is written into the output except hashes, sizes, "
    "header-level fields (BMP dimensions, Game.dat title) and line counts.",
    "FRUA limits that any future area translation must respect: at most 576 "
    "cells per area (w*h <= 576), 100 events per area, fixed 7168-byte STRG "
    "chunk (docs/geo-format.md).",
    "Provenance is not verified against a retail DOS release. The source is a "
    "decoded workspace layout; its origin and rights status are the user's to "
    "establish.",
]


def build_ir(source: Path, records: list[FileRecord]) -> dict:
    missing = check_required(records)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "source": {
            "label": Path(source).name,
            "required_members": list(REQUIRED_MEMBERS),
            "missing_members": missing,
            "file_count": len(records),
            "files": [r.as_json() for r in records],
        },
        "areas": [],
        "unsupported": UNSUPPORTED,
        "loss": LOSS_NOTES,
    }


def render_report(ir: dict) -> str:
    lines = [
        "# Pool of Radiance -> FRUA: source inventory report",
        "",
        f"**Status: `{ir['status']}`. This is NOT a playable FRUA module.**",
        "",
        "This report describes what the converter read from the source folder. "
        "It emits no design files, so it cannot be loaded by OpenUA or FRUA.",
        "",
        "## Source",
        "",
        f"- Label: `{ir['source']['label']}`",
        f"- Files inventoried: {ir['source']['file_count']}",
        f"- Missing required members: "
        f"{', '.join(ir['source']['missing_members']) or 'none'}",
        "",
        "## Files",
        "",
        "| Path | Kind | Size | Status | Notes |",
        "|---|---|---:|---|---|",
    ]
    for f in ir["source"]["files"]:
        d = f["details"]
        notes = []
        if f["kind"] == "bmp" and d:
            notes.append(f"{d['width']}x{d['height']} {d['bits_per_pixel']}bpp")
        if f["kind"] == "game-dat" and d:
            notes.append(f"title `{d['title']}`")
        if f["kind"] == "text" and d:
            notes.append(f"{d['lines']} lines")
        notes.extend(f.get("warnings", []))
        # A pipe in a source name would split the Markdown table; escape it.
        cell = lambda s: str(s).replace("|", "\\|")
        lines.append(
            f"| `{cell(f['path'])}` | {f['kind']} | {f['size']} | {f['status']} | "
            f"{cell('; '.join(notes))} |")
    lines += ["", "## Not converted (unsupported)", ""]
    lines += [f"- **{u['code']}**: {u['message']}" for u in ir["unsupported"]]
    lines += ["", "## Loss and limits", ""]
    lines += [f"- {n}" for n in ir["loss"]]
    lines += [
        "",
        "## Next blockers",
        "",
        "1. Decode the source map geometry to cell-level data, with a verified "
        "mapping from the source's cell model to FRUA's (not yet established).",
        "2. Decode ECL control flow and the mapping to FRUA event types.",
        "3. Decode monster, encounter and item records against a known layout.",
        "4. Establish the source's edition and provenance (retail DOS, or a "
        "derived workspace).",
        "5. Runtime validation in FRUA or OpenUA is not possible until a "
        "playable output exists.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(ir: dict, out: Path) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    ir_path = out / "por_ir.json"
    report_path = out / "por_report.md"
    ir_path.write_text(json.dumps(ir, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8", newline="\n")
    report_path.write_text(render_report(ir), encoding="utf-8", newline="\n")
    return ir_path, report_path


def convert(source: Path, out: Path) -> dict:
    """Run the slice end to end. Returns the IR dict."""
    source = Path(source)
    dst = validate_output_dir(source, out)
    records = inventory_source(source)
    missing = check_required(records)
    if missing:
        raise PorSourceError(
            "source is missing required member(s): " + ", ".join(missing))
    failed = [r.path for r in records
              if r.status == "probe-failed"
              and r.path.lower() in {m.lower() for m in REQUIRED_MEMBERS}]
    if failed:
        raise PorSourceError(
            "required member(s) failed validation: " + ", ".join(failed))
    ir = build_ir(source, records)
    write_outputs(ir, dst)
    return ir


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance source inventory (slice 1; not a playable conversion).")
    ap.add_argument("source", help="user-supplied PoR source folder (read-only)")
    ap.add_argument("-o", "--out", required=True,
                    help="output folder (outside the source; under data/ if inside the repo)")
    args = ap.parse_args(argv)
    try:
        convert(Path(args.source), Path(args.out))
    except PorSourceError as exc:
        print(f"por_convert: error: {exc}", file=sys.stderr)
        return 2
    print(f"por_convert: wrote {Path(args.out) / 'por_ir.json'} and "
          f"{Path(args.out) / 'por_report.md'}")
    print(f"por_convert: status {STATUS}; NOT a playable FRUA module")
    return 0


if __name__ == "__main__":
    sys.exit(main())
