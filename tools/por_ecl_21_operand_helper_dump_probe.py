#!/usr/bin/env python3
"""Trace the ECL 0x21 handler's 002B:0025 call through pinned RAM dumps.

Status: MEMORY-BYTE-CROSS-CHECK-ONLY. This identifies a byte path in two saved
memory images; it does not claim that the call executed. Inputs are PoR-pinned
GAME.OVR/START.EXE plus raw linear RAM dumps. No emulator is started and no
input file is modified.
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
import por_loadpieces_handler as dec  # noqa: E402
import por_overlay_group_map as pogm  # noqa: E402
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

SCHEMA = "openua.por-ecl-21-operand-helper-dump-probe"
TOOL = "tools/por_ecl_21_operand_helper_dump_probe.py"
ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-ecl-21-operand-helper-dump-probe"
DEFAULT_DUMPS = [DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                 DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin"]

# GAME.OVR handler group and the 002B:0025 far-call site in opcode-21 handler.
GROUP_DESC = 0x3C3
GROUP_FILE = 0x0D46
GROUP_BASE = 0x45C40
HANDLER_CALL = 0x19DA
RAW_SEG = 0x002B
HELPER_OFF = 0x0025
LIVE_SEG = 0x1891
LIVE_CALL = 0x468D4
THUNK_LINEAR = 0x18935
THUNK = bytes.fromhex("ea 36 01 cc 40")  # jmp far 40CC:0136
HELPER_LINEAR = 0x40DF6
HELPER_FILE = 0x7609
HELPER_END = 0x7689
HELPER_LEN = HELPER_END - HELPER_FILE
HELPER_RET = bytes.fromhex("ca 02 00")
HELPER_ARRAYS = (0x7085, 0x7045, 0x7005)
HELPER_EXPECTED_SHA256 = "0dd25983c54922e1ebe6f9f1b693f32c6a1c2b69199ddf110fc7d040134ec42b"
KNOWN_DUMPS = {
    "f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895": "por-live-memory-pid34644",
    "3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa": "por-wheel-live-capture",
}


class Refusal(Exception):
    pass


def u16(b: bytes, at: int) -> int:
    return struct.unpack_from("<H", b, at)[0]


def analyze(ovr: bytes, exe: bytes, dumps: list[tuple[str, bytes]], *, pins: dict = pogm.PINS) -> dict:
    pogm.check_pin("GAME.OVR", ovr, pins)
    pogm.check_pin("START.EXE", exe, pins)
    if not dumps:
        raise Refusal("no RAM dump given")
    group = pogm.parse_descriptor(exe, ovr, GROUP_DESC)
    fixups = pogm.read_fixups(ovr, group)
    site_body = HANDLER_CALL - group["fileofs"]
    helper, decode_error = dec.linear(ovr, HELPER_FILE, 300)
    helper_bytes = ovr[HELPER_FILE:HELPER_END]
    helper_complete = (decode_error is None and helper and helper[-1].off + helper[-1].length == HELPER_END
                       and helper[-1].flow == "retf" and helper[-1].imm == 2)
    file_checks = {
        "handler_group_file_offset": group["fileofs"] == GROUP_FILE,
        "handler_call_is_002b_0025": ovr[HANDLER_CALL:HANDLER_CALL + 5] == bytes.fromhex("9a 25 00 2b 00"),
        "handler_call_segment_fixup_listed": site_body + 3 in fixups,
        "helper_linear_decode_complete_to_retf2": bool(helper_complete),
        "helper_operand_is_bp_plus_6": ovr[HELPER_FILE:HELPER_FILE + 3] == bytes.fromhex("55 89 e5")
            and ovr[HELPER_FILE + 6:HELPER_FILE + 9] == bytes.fromhex("8a 46 06"),
        "helper_reads_three_indexed_arrays": all(
            ovr[HELPER_FILE + at:HELPER_FILE + at + 4] == bytes((0x8A, 0x85, lo, hi))
            for at, addr in zip((0x0C, 0x19, 0x26), HELPER_ARRAYS)
            for lo, hi in [(addr & 0xFF, addr >> 8)]),
        "helper_returns_retf2": helper_bytes[-3:] == HELPER_RET,
        "helper_body_sha256": hashlib.sha256(helper_bytes).hexdigest() == HELPER_EXPECTED_SHA256,
    }
    rows = []
    for label, raw in dumps:
        base = pogm.resolve_dump_base(label, len(raw), None)
        dump = pogm.Dump(raw, base)
        gmap = pogm.map_group(group, ovr[GROUP_FILE:GROUP_FILE + group["codesz"]], fixups, dump)
        row = {"label": label, "sha256": pogm.sha256(raw), "known_dump": KNOWN_DUMPS.get(pogm.sha256(raw)),
               "group_status": gmap["status"], "group_base": gmap["base_linear"], "checks": {}}
        checks = row["checks"]
        if gmap["status"] == "unique" and gmap["base_linear"] == GROUP_BASE:
            call_linear = gmap["base_linear"] + site_body
            call_bytes = dump.read(call_linear, 5)
            seg_live = u16(call_bytes, 3)
            target = seg_live * 16 + u16(call_bytes, 1)
            target_in_dump = dump.covers(target, 5)
            thunk = dump.read(target, 5) if target_in_dump else b""
            helper_target = u16(thunk, 3) * 16 + u16(thunk, 1) if thunk[:1] == b"\xEA" else -1
            helper_in_dump = helper_target >= 0 and dump.covers(helper_target, HELPER_LEN)
            live_helper = dump.read(helper_target, HELPER_LEN) if helper_in_dump else b""
            checks.update({
                "group_unique_at_expected_base": True,
                "mapped_call_bytes_match_far_call": call_bytes[:3] == bytes.fromhex("9a 25 00"),
                "live_seg_is_1891": seg_live == LIVE_SEG,
                "target_is_1891_0025": target == THUNK_LINEAR,
                "target_is_far_jmp_thunk": target_in_dump and thunk == THUNK,
                "thunk_destination_is_40cc_0136": helper_target == HELPER_LINEAR,
                "destination_matches_complete_helper": helper_in_dump and live_helper == helper_bytes,
                "helper_bytes_match_unique_pinned_game_offset": live_helper == ovr[HELPER_FILE:HELPER_END]
                    and helper_in_dump and ovr.count(helper_bytes) == 1,
            })
            row["call"] = {"linear": call_linear, "bytes": call_bytes.hex(" "), "live_segment": seg_live,
                           "target_linear": target}
            row["thunk"] = {"linear": target, "bytes": thunk.hex(" "), "destination_linear": helper_target}
            row["helper"] = {"linear": helper_target, "game_offset": HELPER_FILE,
                             "length": HELPER_LEN, "bytes_sha256": hashlib.sha256(live_helper).hexdigest(),
                             "bytes_match_game": helper_in_dump and live_helper == helper_bytes}
        else:
            checks["group_unique_at_expected_base"] = False
        row["status"] = "ok" if all(checks.values()) else "diagnostic"
        rows.append(row)
    status = "ok" if all(file_checks.values()) and all(r["status"] == "ok" for r in rows) else "diagnostic"
    return {
        "schema": SCHEMA, "schema_version": 1, "tool": TOOL,
        "status_scope": "memory-byte-chain-cross-check-only", "playable": False,
        "status": status,
        "input_pins": {"GAME.OVR": {"size": len(ovr), "sha256": pogm.sha256(ovr)},
                       "START.EXE": {"size": len(exe), "sha256": pogm.sha256(exe)}},
        "file_side": {"checks": file_checks,
                      "helper": {"entry": HELPER_FILE, "end": HELPER_END, "length": HELPER_LEN,
                                 "decode_error": decode_error,
                                 "ret": {"at": helper[-1].off, "kind": helper[-1].flow, "imm": helper[-1].imm},
                                 "bp_displacements": sorted({i.bp_disp for i in helper if i.bp_disp is not None}),
                                 "indexed_array_displacements": list(HELPER_ARRAYS),
                                 "sha256": hashlib.sha256(helper_bytes).hexdigest()}},
        "dumps": rows,
        "not_established": ["that the handler or helper executed", "the meaning of the three DGROUP arrays or returned AL",
                            "that any returned byte is an ECL stream byte or GEO block id",
                            "register state, argument values, dump capture instant, and atomicity"],
    }


def _output_dir(source: Path, out: Path) -> Path:
    try:
        resolved = validate_output_dir(source, out)
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
        ovr, exe = (install / "GAME.OVR").read_bytes(), (install / "START.EXE").read_bytes()
        paths = args.dump or DEFAULT_DUMPS
        inputs = [(f"{p.parent.name}/{p.name}", p.read_bytes()) for p in paths]
        result = analyze(ovr, exe, inputs)
        out.mkdir(parents=True, exist_ok=True)
        (out / "por_ecl_21_operand_helper_dump_probe.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (Refusal, pogm.Refusal) as exc:
        print("REFUSED: " + str(exc), file=sys.stderr)
        return 2
    print("status=%s dumps=%s" % (result["status"], [(x["known_dump"], x["status"]) for x in result["dumps"]]))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
