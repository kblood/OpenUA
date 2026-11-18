#!/usr/bin/env python3
"""Pool of Radiance: scan pinned saves for exact decoded GEO payloads.

Read-only diagnostic. Exact byte matches are compatibility evidence only; this
probe cannot bind a GEO block to a save, game area, or runtime load.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATA_DIR = REPO / "data"
sys.path.insert(0, str(HERE))

import por_map as pm  # noqa: E402
from por_area_evidence import GEO_PINS  # noqa: E402
from por_save_state_probe import DEFAULT_INSTALL, INSTALL_ENV, SAVE_PINS  # noqa: E402

SCHEMA = "openua.por-save-geo-payload-probe"
SCHEMA_VERSION = 0
TOOL = "tools/por_save_geo_payload_probe.py"
WINDOW_LENGTHS = (64, 128, 192, 256)
MIN_DISTINCT_BYTES = 8
LIMITATIONS = [
    "A byte match does not establish that DOS loaded the matched block, nor does it map a block to a game area.",
    "The scan covers only the two pinned saves and the eight pinned GEO archives.",
    "Plane and window offsets use the decoded Gen1 GEO layout from tools/por_map.py; this probe assigns no plane semantics.",
    "Informative windows require at least eight distinct byte values. This is a reporting filter, not a game-format rule.",
    "No save schema, runtime state, or save-to-area relation is inferred.",
]


class ProbeRefusal(Exception):
    """Input, pin, format, or output-path refusal."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _all_offsets(data: bytes, needle: bytes) -> list[int]:
    if not needle:
        return []
    out = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def _offset_fields(offsets: list[int]) -> dict:
    """Keep common repetitive matches compact while preserving their exact count."""
    return {
        "save_offset_count": len(offsets),
        "save_offsets": offsets[:16],
        "save_offsets_truncated": len(offsets) > 16,
    }


def scan_save(save: bytes, blocks: list[dict]) -> dict:
    """Return exact full-block/plane matches and high-diversity plane windows.

    Every row contains offsets and byte statistics only, never the matched bytes.
    Windows are searched at every start wholly inside each of the four 256-byte
    planes; the two-byte map header is excluded.
    """
    full = []
    planes = []
    informative = {n: [] for n in WINDOW_LENGTHS}
    for block in blocks:
        raw = block["raw"]
        if len(raw) < 2 + 4 * 256:
            raise ProbeRefusal("decoded GEO block is shorter than its four planes")
        offsets = _all_offsets(save, raw)
        if offsets:
            full.append({
                "archive": block["archive"], "toc_index": block["toc_index"],
                "block_id": block["block_id"], **_offset_fields(offsets),
                "matched_length": len(raw),
            })
        for plane in range(4):
            lo = 2 + plane * 256
            data = raw[lo:lo + 256]
            offsets = _all_offsets(save, data)
            if offsets:
                planes.append({
                    "archive": block["archive"], "toc_index": block["toc_index"],
                    "block_id": block["block_id"], "plane_index": plane,
                    "raw_offset": lo, **_offset_fields(offsets),
                    "length": len(data), "distinct_byte_count": len(set(data)),
                    "nonzero_byte_count": sum(value != 0 for value in data),
                })
            for length in WINDOW_LENGTHS:
                for start in range(lo, lo + 257 - length):
                    window = raw[start:start + length]
                    distinct = len(set(window))
                    if distinct < MIN_DISTINCT_BYTES:
                        continue
                    offsets = _all_offsets(save, window)
                    if offsets:
                        informative[length].append({
                            "archive": block["archive"], "toc_index": block["toc_index"],
                            "block_id": block["block_id"], "plane_index": plane,
                            "raw_offset": start, **_offset_fields(offsets),
                            "length": length, "distinct_byte_count": distinct,
                        })
    windows = {}
    for length, rows in informative.items():
        windows[str(length)] = {
            "minimum_distinct_bytes": MIN_DISTINCT_BYTES,
            "matching_window_count": len(rows),
            "distinct_block_count": len({(r["archive"], r["toc_index"]) for r in rows}),
            "matches": rows,
        }
    return {
        "full_block_match_count": len(full),
        "full_block_matches": full,
        "exact_plane_match_count": len(planes),
        "exact_plane_matches": planes,
        "informative_windows": windows,
    }


def _read_pinned(install: Path, pins: dict, kind: str) -> tuple[dict, dict[str, bytes]]:
    rows = []
    data_by_name = {}
    for name, (expected_size, expected_hash) in sorted(pins.items()):
        path = install / name
        if path.is_symlink():
            raise ProbeRefusal("%s input is a symlink: %s" % (kind, name))
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ProbeRefusal("cannot read %s input %s: %s" % (kind, name, exc))
        digest = _sha(data)
        if len(data) != expected_size:
            raise ProbeRefusal("%s input %s has size %d, expected %d"
                               % (kind, name, len(data), expected_size))
        if digest != expected_hash:
            raise ProbeRefusal("%s input %s SHA-256 mismatch" % (kind, name))
        rows.append({"name": name, "size": len(data), "sha256": digest, "pin": "matched"})
        data_by_name[name] = data
    return {"files": rows}, data_by_name


def build_report(install: Path, out: Optional[Path] = None,
                 save_pins: Optional[dict] = None,
                 geo_pins: Optional[dict] = None) -> dict:
    install = Path(install)
    if install.is_symlink():
        raise ProbeRefusal("install folder is a symlink")
    install = install.resolve()
    if not install.is_dir():
        raise ProbeRefusal("install folder is missing or not a directory")
    if out is not None:
        out = out.resolve()
        data_root = DATA_DIR.resolve()
        if out == data_root or not _within(out, data_root):
            raise ProbeRefusal("output must be a child of data/")
        if _within(out, install) or _within(install, out):
            raise ProbeRefusal("output must not contain or be inside the install")

    save_pins = SAVE_PINS if save_pins is None else save_pins
    geo_pins = GEO_PINS if geo_pins is None else geo_pins
    save_meta, save_data = _read_pinned(install, save_pins, "save")
    geo_meta, geo_data = _read_pinned(install, geo_pins, "GEO archive")
    blocks = []
    archive_rows = []
    try:
        for name in sorted(geo_data):
            data = geo_data[name]
            entries, base = pm.parse_dax(data)
            decoded = 0
            for entry in entries:
                comp = data[base + entry.data_offset:base + entry.data_offset + entry.comp_size]
                raw = pm.rle_decode(comp, entry.raw_size)
                if len(raw) != 2 + 4 * 256:
                    raise ProbeRefusal("%s TOC %d decodes to %d bytes, expected 1026"
                                       % (name, entry.index, len(raw)))
                blocks.append({
                    "archive": name, "toc_index": entry.index,
                    "block_id": entry.block_id, "raw": raw,
                })
                decoded += 1
            archive_rows.append({
                "name": name, "toc_entry_count": len(entries),
                "decoded_block_count": decoded,
            })
    except (pm.PorMapError, IndexError, struct.error) as exc:  # type: ignore[name-defined]
        raise ProbeRefusal("invalid GEO archive: %s" % exc)

    findings = []
    for name in sorted(save_data):
        findings.append({"save": name, **scan_save(save_data[name], blocks)})

    # Re-hash every input after decoding and scanning to reject a moving install.
    for name, (size, digest) in list(save_pins.items()) + list(geo_pins.items()):
        path = install / name
        if path.is_symlink() or not path.is_file():
            raise ProbeRefusal("%s changed during the run" % name)
        current = path.read_bytes()
        if len(current) != size or _sha(current) != digest:
            raise ProbeRefusal("%s changed during the run" % name)

    all_no_blocks = all(item["full_block_match_count"] == 0 for item in findings)
    status = "no-full-block-payload-match" if all_no_blocks else "exact-payload-match-found-unbound"
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "tool": TOOL,
        "playable": False,
        "runtime_established": False,
        "runtime_binding_claimed": False,
        "claim_boundary": "Exact save/GEO byte matches only; no runtime or area binding.",
        "inputs": {"saves": save_meta["files"], "archives": geo_meta["files"],
                   "decoded_archives": archive_rows},
        "search_scope": {
            "save_count": len(findings), "archive_count": len(archive_rows),
            "decoded_block_count": len(blocks), "full_block_length": 1026,
            "plane_length": 256, "plane_count_per_block": 4,
            "informative_window_lengths": list(WINDOW_LENGTHS),
            "minimum_distinct_bytes_per_window": MIN_DISTINCT_BYTES,
        },
        "save_findings": findings,
        "install_unchanged": True,
        "limitations": list(LIMITATIONS),
    }


def render_report(doc: dict) -> str:
    lines = [
        "# PoR pinned-save to decoded-GEO payload scan",
        "",
        "Status: %s. playable: false. runtime binding: not established." % doc["status"],
        "",
        "## Scope",
        "",
        "%d pinned saves, %d pinned GEO archives, %d decoded blocks. Full block: %d bytes; "
        "%d planes of %d bytes. Informative windows: lengths %s with at least %d distinct "
        "byte values." % (
            doc["search_scope"]["save_count"], doc["search_scope"]["archive_count"],
            doc["search_scope"]["decoded_block_count"], doc["search_scope"]["full_block_length"],
            doc["search_scope"]["plane_count_per_block"], doc["search_scope"]["plane_length"],
            ", ".join(map(str, doc["search_scope"]["informative_window_lengths"])),
            doc["search_scope"]["minimum_distinct_bytes_per_window"]),
        "",
        "## Results",
        "",
        "| Save | Full block matches | Exact plane matches | 64-byte windows | 128-byte windows | 192-byte windows | 256-byte windows |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for finding in doc["save_findings"]:
        w = finding["informative_windows"]
        lines.append("| %s | %d | %d | %d | %d | %d | %d |" % (
            finding["save"], finding["full_block_match_count"],
            finding["exact_plane_match_count"], *(w[str(n)]["matching_window_count"]
                                                   for n in WINDOW_LENGTHS)))
    lines += ["", "### Exact plane matches", ""]
    for finding in doc["save_findings"]:
        if not finding["exact_plane_matches"]:
            lines.append("- %s: none." % finding["save"])
        for match in finding["exact_plane_matches"]:
            lines.append("- %s: %s TOC %d / block id %d, plane %d, save offset %d; "
                         "%d overlapping exact occurrences; %d distinct byte value(s), "
                         "%d nonzero byte(s)." % (
                finding["save"], match["archive"], match["toc_index"], match["block_id"],
                match["plane_index"], match["save_offsets"][0], match["save_offset_count"],
                match["distinct_byte_count"], match["nonzero_byte_count"]))
    lines += ["", "### Exact informative windows", ""]
    for finding in doc["save_findings"]:
        for length in WINDOW_LENGTHS:
            row = finding["informative_windows"][str(length)]
            lines.append("- %s, %d bytes: %d matching windows across %d blocks." % (
                finding["save"], length, row["matching_window_count"],
                row["distinct_block_count"]))
    lines += [
        "",
        "Exact plane and window matches are byte observations. All-zero matches are listed "
        "separately from the informative-window filter; they do not identify an area.",
        "",
        "## Inputs",
        "",
        "| File | Size | SHA-256 |",
        "| --- | ---: | --- |",
    ]
    for row in doc["inputs"]["saves"] + doc["inputs"]["archives"]:
        lines.append("| %s | %d | %s |" % (row["name"], row["size"], row["sha256"]))
    lines += ["", "Install unchanged during scan: %s." % doc["install_unchanged"],
              "", "## Limits", ""]
    lines += ["- %s" % item for item in doc["limitations"]]
    lines += ["", doc["claim_boundary"], ""]
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_save_geo_payload_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_save_geo_payload_probe_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--install", help="PoR install folder (default: $%s or %s)"
                        % (INSTALL_ENV, DEFAULT_INSTALL))
    parser.add_argument("-o", "--output", required=True,
                        help="output folder, explicitly under data/ (relative to repo root)")
    args = parser.parse_args(argv)
    install = Path(args.install or os.environ.get(INSTALL_ENV) or DEFAULT_INSTALL)
    out = Path(args.output)
    if not out.is_absolute():
        out = REPO / out
    try:
        doc = build_report(install, out)
    except ProbeRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, out.resolve())
    counts = [f"{row['save']}: {row['full_block_match_count']} blocks, "
              f"{row['exact_plane_match_count']} planes"
              for row in doc["save_findings"]]
    print("%s; %d decoded blocks; %s" % (
        doc["status"], doc["search_scope"]["decoded_block_count"], "; ".join(counts)))
    print("wrote %s" % out.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
