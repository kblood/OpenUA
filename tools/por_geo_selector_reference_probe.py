#!/usr/bin/env python3
"""Bounded decoded-reference census for PoR GEO filename selector globals.

The probe pins retail START.EXE and GAME.OVR, finds candidate VROOMM descriptors,
walks 8086 prologue roots inside each code body with the repository decoder, and
reports decoded direct references to DGROUP 0x49D6/0x49D8/0x5376. Raw/unwalked
bytes, runtime values, and semantic meanings are not promoted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import por_loadpieces_handler as decoder  # noqa: E402
import por_overlay_group_map as group_map  # noqa: E402

SCHEMA = "openua.por-geo-selector-reference-probe"
VERSION = 1
TOOL = "tools/por_geo_selector_reference_probe.py"
DEFAULT_INSTALL = Path(r"G:\Games\Pool of Radiance\POOLRAD")
DEFAULT_OUT = ROOT / "data" / "work" / "por-geo-selector-reference-probe"
TARGETS = (0x49D6, 0x49D8, 0x5376)
PROLOGUE = b"\x55\x89\xE5"


class Refusal(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify_reference(raw_hex: str, text: str) -> str:
    raw = bytes.fromhex(raw_hex)
    normalized = text.lower()
    if "[0x49d6]" in normalized and normalized.startswith("les"):
        return "far-pointer-read"
    if "[0x49d6]" in normalized or "[0x49d8]" in normalized:
        if raw[0] in (0xA2, 0xA3, 0xC6, 0xC7, 0x88, 0x89, 0x8C):
            return "write"
        return "read-or-compare"
    if "[0x5376]" in normalized:
        if raw[0] in (0xA2, 0xC6, 0xC7, 0x88, 0x89):
            return "write"
        return "read-or-compare"
    return "other"


def address_constant(raw_hex: str) -> Optional[int]:
    """Return a MOV r16,imm16 value; it names an address but is not a memory access."""
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if len(raw) == 3 and raw[0] in range(0xB8, 0xC0):
        value = int.from_bytes(raw[1:3], "little")
        return value if value in TARGETS else None
    return None


def _candidate_groups(exe: bytes, ovr: bytes) -> list[dict]:
    groups = []
    for pos in range(0, len(exe) - group_map.DESC_MIN + 1):
        if exe[pos:pos + 4] != group_map.DESC_MAGIC:
            continue
        try:
            group = group_map.parse_descriptor(exe, ovr, pos)
        except group_map.Refusal:
            continue
        groups.append(group)
    return groups


def analyze(ovr: bytes, exe: bytes) -> dict:
    group_map.check_pin("GAME.OVR", ovr, group_map.PINS)
    group_map.check_pin("START.EXE", exe, group_map.PINS)
    groups = _candidate_groups(exe, ovr)
    roots = 0
    complete_walks = 0
    refs: dict[int, dict] = {}
    address_constants: dict[int, dict] = {}
    for group in groups:
        lo = group["fileofs"]
        hi = lo + group["codesz"]
        for entry in range(lo, hi - len(PROLOGUE) + 1):
            if ovr[entry:entry + len(PROLOGUE)] != PROLOGUE:
                continue
            roots += 1
            result = decoder.walk(ovr, entry)
            complete_walks += int(bool(result["complete"]))
            for ins in result["listing"]:
                address = None
                m = re.search(r"\[0x([0-9a-f]+)\]", ins["text"].lower())
                if m:
                    address = int(m.group(1), 16)
                if address in TARGETS:
                    row = {
                        "site": "0x%05X" % ins["at"],
                        "bytes": ins["bytes"],
                        "instruction": ins["text"],
                        "target": "0x%04X" % address,
                        "access": classify_reference(ins["bytes"], ins["text"]),
                        "group_file_offset": "0x%05X" % group["fileofs"],
                        "walk_entry": "0x%05X" % entry,
                    }
                    refs[ins["at"]] = row
                # `mov di,imm16` names an address but does not itself read/write it.
                value = address_constant(ins["bytes"])
                if value is not None:
                    address_constants[ins["at"]] = {
                        "site": "0x%05X" % ins["at"],
                        "bytes": ins["bytes"],
                        "instruction": ins["text"],
                        "target": "0x%04X" % value,
                        "meaning": "address-immediate; memory access occurs only if later instructions use it",
                        "group_file_offset": "0x%05X" % group["fileofs"],
                        "walk_entry": "0x%05X" % entry,
                    }
    references = sorted(refs.values(), key=lambda row: (row["target"], row["site"]))
    constants = sorted(address_constants.values(), key=lambda row: row["site"])
    per_target = {}
    for target in TARGETS:
        rows = [r for r in references if int(r["target"], 16) == target]
        per_target["0x%04X" % target] = {
            "decoded_sites": len(rows),
            "far_pointer_reads": sum(r["access"] == "far-pointer-read" for r in rows),
            "writes": sum(r["access"] == "write" for r in rows),
            "read_or_compare": sum(r["access"] == "read-or-compare" for r in rows),
            "sites": rows,
        }
    return {
        "schema": SCHEMA,
        "schema_version": VERSION,
        "tool": TOOL,
        "playable": False,
        "status": "bounded-static-decoded-reference-census",
        "pins": {
            "GAME.OVR": {"size": len(ovr), "sha256": sha(ovr), "match": True},
            "START.EXE": {"size": len(exe), "sha256": sha(exe), "match": True},
        },
        "coverage": {
            "candidate_descriptors": len(groups),
            "prologue_roots": roots,
            "complete_walks": complete_walks,
            "walks_incomplete": roots - complete_walks,
            "method": "scan pinned GAME.OVR group bodies for 55 89 E5 roots, then follow decoder branch/fallthrough paths; calls are not entered",
            "not_exhaustive": True,
        },
        "targets": per_target,
        "address_constants": constants,
        "conclusion": {
            "selector_writer_chain_at_0x1FBA7": "one dynamic write among multiple decoded 0x5376 assignments",
            "0x49D6_role": "far-pointer slot is read in many decoded routines and initialized in one decoded allocation routine; field meaning unresolved",
            "archive_or_area_mapping": "not_established",
            "runtime_values_or_execution": "not_established",
        },
    }


def render_report(report: dict) -> str:
    lines = [
        "# PoR GEO selector reference census", "",
        "**Static diagnostic only. `playable: false`; archive and area mappings remain unresolved.**", "",
        "## Coverage", "",
        "- Candidate descriptors: %d; decoded prologue roots: %d; complete walks: %d; incomplete: %d." % (
            report["coverage"]["candidate_descriptors"], report["coverage"]["prologue_roots"],
            report["coverage"]["complete_walks"], report["coverage"]["walks_incomplete"]),
        "- Calls are recorded by the decoder but not followed. Bytes outside the walked paths may contain references.",
        "- This is not an exhaustive whole-image reference proof.", "",
        "## Decoded direct references", "",
        "| DGROUP target | Sites | Far-pointer reads | Writes | Read/compare |",
        "|---|---:|---:|---:|---:|",
    ]
    for target, row in report["targets"].items():
        lines.append("| `%s` | %d | %d | %d | %d |" % (
            target, row["decoded_sites"], row["far_pointer_reads"], row["writes"], row["read_or_compare"]))
    lines += [
        "", "The references classify instruction behavior only. The `0x49D6` slot is reused and its `+0x624` field is not identified as an archive selector by these bytes.",
        "The `0x5376` byte has decoded constant assignments as well as the dynamic assignment at GAME.OVR `0x1FBB0`; neither the values nor the call paths identify a GEO archive.",
        "", "## Address constants", "",
    ]
    if report["address_constants"]:
        lines += ["| Site | Bytes | Target | Meaning |", "|---|---|---|---|"]
        for row in report["address_constants"]:
            lines.append("| `%s` | `%s` | `%s` | %s |" % (
                row["site"], row["bytes"], row["target"], row["meaning"]))
    else:
        lines.append("No decoded address-immediate references to these globals were found in the bounded walks.")
    lines += [
        "", "## Limits", "",
        "- A `55 89 E5` byte pattern is a candidate procedure entry, not proof of a live entry.",
        "- The census follows branch/fallthrough paths from candidate roots; it does not follow calls or indirect control flow.",
        "- It does not inspect runtime DGROUP contents, infer an archive number, map any GEO block, or establish gameplay reachability.",
        "- `playable: false`; no converter behavior is changed.", "",
    ]
    return "\n".join(lines)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    parser.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if not _inside(out, ROOT / "data"):
        print("refused: output must be under repository data/", file=sys.stderr)
        return 2
    try:
        paths = {name: args.install / name for name in group_map.PINS}
        if not all(path.is_file() for path in paths.values()):
            raise Refusal("missing pinned START.EXE or GAME.OVR")
        before = {name: path.read_bytes() for name, path in paths.items()}
        report = analyze(before["GAME.OVR"], before["START.EXE"])
        after = {name: path.read_bytes() for name, path in paths.items()}
        if any(sha(after[name]) != sha(before[name]) for name in before):
            raise Refusal("pinned inputs changed during probe")
        for name in report["pins"]:
            report["pins"][name]["unchanged_after"] = True
        out.mkdir(parents=True, exist_ok=True)
        (out / "por_geo_selector_reference_probe.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out / "por_geo_selector_reference_probe.md").write_text(render_report(report), encoding="utf-8")
        print("wrote %s (decoded selector reference census; playable=false)" % out)
        return 0
    except (OSError, Refusal, group_map.Refusal) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
