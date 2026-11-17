#!/usr/bin/env python3
"""Static, observe-only trace of PoR START's GEO-loader open path.

This probe pins START.EXE and decodes the 0x8624 routine plus its path-check/open helpers. It
records the strongest file-byte contract (including the DOS AH=3Dh open and the path buffer
address) while leaving the actual archive name unresolved when runtime DS/table/argument values
are not known. It does not run DOSBox or identify a GEO archive or block.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import sys
from pathlib import Path
from typing import Optional

SCHEMA = "openua.por-geo-loader-open-probe"
VERSION = 1
TOOL = "tools/por_geo_loader_open_probe.py"
ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-geo-loader-open-probe"
START_NAME = "START.EXE"
START_PIN = {"size": 65231,
             "sha256": "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"}

# Resident code offsets; module-helper placement is conditional on the established 0x0AF8 base.
OPEN_ROUTINE = 0x8624
PATH_CHECK = 0x82B4
PATH_BUILD = 0x8342
PATH_ERROR = 0x81EA
MODULE_BASE = 0xAC76
OPEN_WRAPPER = MODULE_BASE + 0x1410
OPEN_SETUP = bytes.fromhex("a0 2c 44 b4 3d 33 d2 eb 06")
OPEN_INT = bytes.fromhex("1e 8d 55 30 06 1f 33 c9 cd 21 1f")
NAME_INDEX_CHAIN = bytes.fromhex("a0 76 53 30 e4 ba 1e 00 f7 e2 8b f8 81 c7 14 26 1e 57 9a 0b 0b f8 0a")


class Refusal(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _at(data: bytes, pos: int, expected: bytes) -> bool:
    return data[pos:pos + len(expected)] == expected


def inspect_open_call_contract(data: bytes) -> dict:
    """Byte-only classification of the DOS open wrapper; its FCB path contents are not decoded."""
    path_guard = _at(data, 0xC0BD, bytes.fromhex("26 80 7d 30 00 74 12"))
    setup = _at(data, OPEN_WRAPPER, OPEN_SETUP)
    open_sequence = _at(data, 0xC0C4, OPEN_INT)
    return {
        "setup_matches": setup,
        "path_guard_matches": path_guard,
        "open_sequence_matches": open_sequence,
        "all_match": setup and path_guard and open_sequence,
        "path_offset": 0x30 if path_guard and open_sequence else None,
        "dos_ah": 0x3D if setup and open_sequence else None,
    }


def _near_call(data: bytes, at: int) -> Optional[int]:
    if at < 0 or at + 3 > len(data) or data[at] != 0xE8:
        return None
    disp = int.from_bytes(data[at + 1:at + 3], "little", signed=True)
    return at + 3 + disp


def _far_call(data: bytes, at: int) -> Optional[str]:
    if at < 0 or at + 5 > len(data) or data[at] != 0x9A:
        return None
    off = int.from_bytes(data[at + 1:at + 3], "little")
    seg = int.from_bytes(data[at + 3:at + 5], "little")
    return "%04X:%04X" % (seg, off)


def inspect_start(start: bytes) -> dict:
    """Inspect the known offsets. Returns byte facts; paths and archive identity remain hypotheses."""
    if len(start) != START_PIN["size"] or sha(start) != START_PIN["sha256"]:
        raise Refusal("START.EXE does not match the pinned PoR file")

    # The byte chain in 0x8624 selects one Pascal string by a DS byte index and 30-byte stride.
    selector_ok = _at(start, 0x8671, NAME_INDEX_CHAIN)
    # Wrapper 0x1410 leaves AH=3Dh live, then opens the NUL-terminated path at ES:DI+0x30.
    contract = inspect_open_call_contract(start)
    setup_ok = contract["setup_matches"]
    path_guard_ok = contract["path_guard_matches"]
    path_sequence_ok = contract["open_sequence_matches"]
    open_site = 0xC0C4
    direct_edges = {
        "8624_to_82b4": _near_call(start, 0x86B0),
        "82b4_to_8342": _near_call(start, 0x82E6),
        "82b4_to_81ea": _near_call(start, 0x8301),
        "8624_open_wrapper": _far_call(start, 0x86E4),
        "82b4_open_wrapper": _far_call(start, 0x0832E),
        "8342_open_wrapper": _far_call(start, 0x08376),
    }
    edge_matches = direct_edges == {
        "8624_to_82b4": PATH_CHECK,
        "82b4_to_8342": PATH_BUILD,
        "82b4_to_81ea": PATH_ERROR,
        "8624_open_wrapper": "0AF8:1410",
        "82b4_open_wrapper": "0AF8:1410",
        "8342_open_wrapper": "0AF8:1410",
    }

    return {
        "schema": SCHEMA,
        "schema_version": VERSION,
        "tool": TOOL,
        "playable": False,
        "pins": {START_NAME: {"size": len(start), "sha256": sha(start), "match": True}},
        "routine_sites": {
            "open_routine_8624": {"file_offset": "0x08624", "entry_bytes": start[0x8624:0x862B].hex(" "),
                                   "return_bytes": start[0x873B:0x873E].hex(" ")},
            "path_check_82b4": {"file_offset": "0x082B4", "entry_bytes": start[0x82B4:0x82BB].hex(" "),
                                "return_bytes": start[0x833F:0x8342].hex(" ")},
            "path_build_8342": {"file_offset": "0x08342", "entry_bytes": start[0x8342:0x834A].hex(" "),
                                "return_bytes": start[0x83A7:0x83AD].hex(" ")},
            "path_error_81ea": {"file_offset": "0x081EA", "entry_bytes": start[0x81EA:0x81F3].hex(" "),
                                "return_bytes": start[0x8241:0x8244].hex(" ")},
            "module_open_wrapper": {"file_offset_if_base_0xac76": "0x%05X" % OPEN_WRAPPER,
                                    "entry_bytes": start[OPEN_WRAPPER:OPEN_WRAPPER + len(OPEN_SETUP)].hex(" "),
                                    "return_bytes": start[0xC0E7:0xC0EB].hex(" ")},
        },
        "path_selector": {
            "file_offset": "0x08671",
            "bytes": start[0x8671:0x8688].hex(" "),
            "chain_matches": selector_ok,
            "index_source": "DS:[0x5376] low byte",
            "stride": 0x1E,
            "table_displacement": 0x2614,
            "selected_source": "DS:[0x2614 + index*0x1E]",
            "copy_helper": "0x0AF8:0x0B0B (Pascal-string copy; helper identity conditional on module base)",
            "selected_string_value": "not_established",
            "runtime_DS": "not_established_for_0x8624_context",
        },
        "open_contract": {
            "wrapper_file_offset_if_module_base_0xac76": "0x%05X" % OPEN_WRAPPER,
            "module_base_conditional": "0x0AF8 -> START.EXE file 0x0AC76, per the copy-helper probe",
            "setup_bytes": start[OPEN_WRAPPER:OPEN_WRAPPER + len(OPEN_SETUP)].hex(" "),
            "setup_matches": setup_ok,
            "path_guard_bytes": start[0xC0BD:0xC0C4].hex(" "),
            "path_guard_matches": path_guard_ok,
            "open_call_sequence_bytes": start[open_site:open_site + len(OPEN_INT)].hex(" "),
            "open_call_sequence_matches": path_sequence_ok,
            "dos_function": "INT 21h AH=3Dh (open), file-byte path",
            "path_pointer": "ES:DI+0x30 at wrapper entry" if contract["path_offset"] == 0x30 else "not_established",
            "path_format": "NUL-terminated string required by DOS AH=3Dh",
            "access_mode_AL_source": "DS:[0x442C] at wrapper entry; live value not established here",
            "path_bytes": "not_established",
        },
        "routine_call_edges": {
            "direct_targets": {k: ("0x%05X" % v if isinstance(v, int) else v) if v is not None else None
                               for k, v in direct_edges.items()},
            "expected_edges_match": edge_matches,
        },
        "verdict": {
            "open_abi": "byte-confirmed" if contract["all_match"]
            else "incomplete",
            "path_construction": "partial: selects a DS table string, but its value and the runtime DS are unknown",
            "archive": "not_established",
            "requested_block": "not_established",
            "geo_block_identity": "not_established",
            "playable": False,
        },
        "not_established": [
            "the runtime DS table at 0x2614 and the selected row index at DS:0x5376",
            "the bytes passed to the open wrapper at ES:DI+0x30 in a running loader call",
            "whether the selected filename is GEO1.DAX through GEO8.DAX",
            "the requested id byte, TOC record, seek base, archive handle, or decoded GEO output",
            "the runtime segment translation and relocation of the direct DS operands in these routines",
            "whether the decoded 0x8624 routine is entered by the map loader in gameplay",
        ],
        "all_byte_checks_match": selector_ok and contract["all_match"],
    }


def probe(install: Path) -> dict:
    file = install / START_NAME
    if not file.is_file():
        raise Refusal("missing START.EXE")
    start = file.read_bytes()
    result = inspect_start(start)
    after = file.read_bytes()
    if len(after) != len(start) or sha(after) != sha(start):
        raise Refusal("START.EXE changed during probe")
    result["pins"][START_NAME]["unchanged_after"] = True
    result["input_unchanged"] = True
    return result


def render_report(doc: dict) -> str:
    p = doc["path_selector"]
    o = doc["open_contract"]
    v = doc["verdict"]
    lines = [
        "# Pool of Radiance GEO loader open path (static, observe-only)", "",
        "**Status: `playable: false`. Archive and requested block remain unresolved.**", "",
        "## What the bytes establish", "",
        "- The path builder at START `0x8624` selects a Pascal string from `DS:[0x2614 + index*0x1E]`, where the low byte of `DS:[0x5376]` supplies the index.",
        "- Conditional on the known module placement, wrapper `0x0AF8:0x1410` sets AH to 3Dh and calls INT 21h with DX pointing at `ES:DI+0x30`.",
        "- DOS AH=3Dh opens a NUL-terminated path. The code bytes establish the pointer location and operation, not the path contents.",
        "- The wrapper gets its access-mode AL from `DS:[0x442C]`; this probe does not fix that live value.", "",
        "## Evidence values", "",
        "- START file pin: `%s` (%d bytes), unchanged after the read." % (doc["pins"][START_NAME]["sha256"], doc["pins"][START_NAME]["size"]),
        "- Selector bytes at `0x8671`: `%s`; match: `%s`." % (p["bytes"], p["chain_matches"]),
        "- Open wrapper bytes: `%s`; match: `%s`." % (o["open_call_sequence_bytes"], o["open_call_sequence_matches"]),
        "- Selected instruction spans match: `%s`; direct call edges match: `%s`." %
        (doc["all_byte_checks_match"], doc["routine_call_edges"]["expected_edges_match"]), "",
        "## Not established", "",
    ]
    lines.extend("- " + item for item in doc["not_established"])
    lines += ["", "## Verdict", "", "- Open ABI: `%s`." % v["open_abi"],
              "- Path construction: %s." % v["path_construction"],
              "- Archive: `%s`; requested block: `%s`; GEO block identity: `%s`." %
              (v["archive"], v["requested_block"], v["geo_block_identity"]), ""]
    return "\n".join(lines)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static PoR GEO-loader open-path probe")
    parser.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    parser.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if not _inside(args.out, DATA_WORK) or _inside(args.out, args.install):
        print("refused: output must be under data/work and outside the install", file=sys.stderr)
        return 2
    try:
        doc = probe(args.install)
    except (Refusal, OSError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "por_geo_loader_open_probe.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (args.out / "por_geo_loader_open_probe.md").write_text(render_report(doc), encoding="utf-8")
    print("wrote %s (open_abi=%s, archive=%s, playable=false)" %
          (args.out, doc["verdict"]["open_abi"], doc["verdict"]["archive"]))
    return 0 if doc["all_byte_checks_match"] and doc["routine_call_edges"]["expected_edges_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
