#!/usr/bin/env python3
"""Check the ECL 0x21 handler's 03D5:003E targets against START stub 6 in RAM dumps.

This is memory-byte evidence only. It does not claim that any far call executed.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import por_overlay_group_map as pogm  # noqa: E402
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

SCHEMA = "openua.por-ecl-21-stub6-dump-probe"
TOOL = "tools/por_ecl_21_stub6_dump_probe.py"
ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-ecl-21-stub6-dump-probe"
DEFAULT_DUMPS = [DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                 DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin"]

HANDLER_DESC = 0x03C3
HANDLER_FILE = 0x0D46
HANDLER_BASE = 0x45C40
CALL_SITES = (0x1A77, 0x1A9E, 0x1AAA, 0x1AD6)
CALL_BYTES = bytes.fromhex("9a 3e 00 d5 03")
RAW_SEG = 0x03D5
CALL_OFF = 0x003E
LIVE_SEG = 0x1C3B
LIVE_TARGET = 0x1C3EE

OWNER_DESC = 0x3DD7
OWNER_FILE = 0x2E8F7
OWNER_CODESZ = 0x120B
STUB_RUN = 0x3DEE
STUB_STRIDE = 5
STUB_INDEX = 6
STUB_FILE = STUB_RUN + STUB_STRIDE * STUB_INDEX
STUB_BYTES = bytes.fromhex("cd 3f 08 0e 00")
PROC_OFF = 0x0E08
PROC_FILE = OWNER_FILE + PROC_OFF
PROC_PROLOGUE = bytes.fromhex("55 89 e5")

KNOWN_DUMPS = {
    "f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895": "por-live-memory-pid34644",
    "3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa": "por-wheel-live-capture",
}


class Refusal(Exception):
    pass


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def analyze(ovr: bytes, exe: bytes, dumps: list[tuple[str, bytes]], *, pins: dict = pogm.PINS) -> dict:
    pogm.check_pin("GAME.OVR", ovr, pins)
    pogm.check_pin("START.EXE", exe, pins)
    if not dumps:
        raise Refusal("no RAM dump given")

    handler = pogm.parse_descriptor(exe, ovr, HANDLER_DESC)
    fixups = pogm.read_fixups(ovr, handler)
    owner = pogm.parse_descriptor(exe, ovr, OWNER_DESC)
    file_checks = {
        "handler_descriptor_fileofs": handler["fileofs"] == HANDLER_FILE,
        "handler_descriptor_codesz": handler["codesz"] == 0x350D,
        "four_static_far_call_sites": all(ovr[s:s + 5] == CALL_BYTES for s in CALL_SITES),
        "all_four_segment_words_fixup_listed": all(s - HANDLER_FILE + 3 in fixups for s in CALL_SITES),
        "owner_descriptor_fileofs": owner["fileofs"] == OWNER_FILE,
        "owner_descriptor_codesz": owner["codesz"] == OWNER_CODESZ,
        "stub6_location_matches_run": STUB_FILE == 0x3E0C and exe[STUB_FILE:STUB_FILE + 5] == STUB_BYTES,
        "stub6_proc_word": u16(exe, STUB_FILE + 2) == PROC_OFF,
        "proc_inside_owner": PROC_OFF < owner["codesz"],
        "proc_file_has_prologue": ovr[PROC_FILE:PROC_FILE + 3] == PROC_PROLOGUE,
    }

    rows = []
    for label, raw in dumps:
        base = pogm.resolve_dump_base(label, len(raw), None)
        dump = pogm.Dump(raw, base)
        code = ovr[HANDLER_FILE:HANDLER_FILE + handler["codesz"]]
        mapped = pogm.map_group(handler, code, fixups, dump)
        row = {"label": label, "sha256": pogm.sha256(raw),
               "known_dump": KNOWN_DUMPS.get(pogm.sha256(raw)),
               "group_status": mapped["status"], "group_base": mapped["base_linear"],
               "checks": {}}
        checks = row["checks"]
        calls = []
        if mapped["status"] == "unique" and mapped["base_linear"] == HANDLER_BASE:
            for site in CALL_SITES:
                linear = HANDLER_BASE + site - HANDLER_FILE
                live = dump.read(linear, 5)
                seg, off = u16(live, 3), u16(live, 1)
                target = seg * 16 + off
                target_bytes = dump.read(target, 5) if dump.covers(target, 5) else b""
                calls.append({"site": site, "linear": linear, "bytes": live.hex(" "),
                              "call_prefix_matches_static": live[:3] == CALL_BYTES[:3],
                              "live_segment": seg, "live_offset": off,
                              "target_linear": target, "target_bytes": target_bytes.hex(" "),
                              "target_matches_stub6": target_bytes == STUB_BYTES})
            checks.update({
                "group_unique_at_expected_base": True,
                "all_four_live_calls_match_static_offsets": all(c["call_prefix_matches_static"]
                    and c["live_offset"] == CALL_OFF for c in calls),
                "all_four_live_segments_equal_1c3b": all(c["live_segment"] == LIVE_SEG for c in calls),
                "all_four_targets_equal_1c3ee": all(c["target_linear"] == LIVE_TARGET for c in calls),
                "all_four_targets_match_exact_stub6": all(c["target_matches_stub6"] for c in calls),
            })
        else:
            checks["group_unique_at_expected_base"] = False
        row["calls"] = calls
        row["status"] = "ok" if checks and all(checks.values()) else "diagnostic"
        rows.append(row)

    return {
        "schema": SCHEMA, "schema_version": 1, "tool": TOOL,
        "status_scope": "memory-byte-stub6-cross-check-only", "playable": False,
        "status": "ok" if all(file_checks.values()) and all(r["status"] == "ok" for r in rows) else "diagnostic",
        "execution_established": False,
        "input_pins": {"GAME.OVR": {"size": len(ovr), "sha256": pogm.sha256(ovr)},
                       "START.EXE": {"size": len(exe), "sha256": pogm.sha256(exe)}},
        "file_side": {"checks": file_checks,
                      "call_sites": list(CALL_SITES),
                      "stub": {"start_file": STUB_RUN, "index": STUB_INDEX, "file": STUB_FILE,
                               "bytes": STUB_BYTES.hex(" "), "proc_offset": PROC_OFF,
                               "proc_file": PROC_FILE, "proc_prologue": PROC_PROLOGUE.hex(" ")}},
        "dumps": rows,
        "not_established": ["that any of the four far calls executed",
                            "that the ECL 0x21 arm or its handler is runtime-reachable",
                            "that the mapped stub's INT 3Fh dispatch reached the GEO procedure",
                            "the call arguments' meaning or a GEO archive/block mapping"],
    }


def _output_dir(install: Path, out: Path) -> Path:
    try:
        resolved = validate_output_dir(install, out)
    except PorSourceError as exc:
        raise Refusal(str(exc))
    if DATA_WORK.resolve() not in resolved.parents:
        raise Refusal("output must be under data/work")
    return resolved


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install", type=Path, default=None)
    ap.add_argument("--dump", type=Path, action="append", default=[])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    try:
        install = pogm.find_install(args.install)
        out = _output_dir(install, args.out)
        ovr = (install / "GAME.OVR").read_bytes()
        exe = (install / "START.EXE").read_bytes()
        dumps = args.dump or DEFAULT_DUMPS
        inputs = [(f"{p.parent.name}/{p.name}", p.read_bytes()) for p in dumps]
        report = analyze(ovr, exe, inputs)
        out.mkdir(parents=True, exist_ok=True)
        (out / "por_ecl_21_stub6_dump_probe.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (Refusal, pogm.Refusal) as exc:
        print("REFUSED: " + str(exc), file=sys.stderr)
        return 2
    print("status=%s dumps=%s" % (report["status"],
          [(row["known_dump"], row["status"]) for row in report["dumps"]]))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
