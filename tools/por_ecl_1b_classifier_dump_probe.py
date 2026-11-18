#!/usr/bin/env python3
"""Cross-check the 0x1B handler's 002B:008E far call against pinned RAM dumps.

The result is memory-byte evidence only. It does not claim that the guard path
or the classifier ran.
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

SCHEMA = "openua.por-ecl-1b-classifier-dump-probe"
TOOL = "tools/por_ecl_1b_classifier_dump_probe.py"
ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-ecl-1b-classifier-dump-probe"
DEFAULT_DUMPS = [DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                 DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin"]

GROUP_DESC = 0x3C3
GROUP_FILE = 0x0D46
GROUP_BASE = 0x45C40
HANDLER_ENTRY = 0x1898
HELPER_CALL = 0x1907
RAW_SEG = 0x002B
HELPER_OFF = 0x008E
LIVE_SEG = 0x1891
THUNK_LINEAR = 0x1899E  # 1891:008E
THUNK = bytes.fromhex("ea a6 1e cc 40")  # jmp far 40CC:1EA6
CLASSIFIER_LINEAR = 0x42B66  # 40CC:1EA6
CLASSIFIER_FILE = 0x9379
CLASSIFIER_RET = 0x9483
CLASSIFIER_LEN = CLASSIFIER_RET + 1 - CLASSIFIER_FILE
CALL_BYTES = bytes.fromhex("9a 8e 00 2b 00")
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
    body_site = HELPER_CALL - group["fileofs"]
    classifier = dec.walk(ovr, CLASSIFIER_FILE)
    listing = classifier["listing"]
    classifier_end = max((r["at"] + len(bytes.fromhex(r["bytes"])) for r in listing), default=-1)
    classifier_len = classifier_end - CLASSIFIER_FILE
    classifier_bytes = ovr[CLASSIFIER_FILE:classifier_end] if classifier_len > 0 else b""
    classifier_coverage = sum(len(bytes.fromhex(r["bytes"])) for r in listing)
    classifier_complete = (
        classifier["complete"] and classifier_len == CLASSIFIER_LEN
        and classifier_coverage == classifier_len
        and classifier["returns"] == [{"at": CLASSIFIER_RET, "kind": "retf", "imm": None}]
        and ovr[CLASSIFIER_FILE:CLASSIFIER_FILE + 3] == bytes.fromhex("55 89 e5")
    )
    file_checks = {
        "handler_group_file_offset": group["fileofs"] == GROUP_FILE,
        "guarded_1b_helper_call_bytes": ovr[HELPER_CALL:HELPER_CALL + 5] == CALL_BYTES,
        "helper_call_segment_word_fixup_listed": body_site + 3 in fixups,
        "1b_cursor_increment_before_guard": ovr[HANDLER_ENTRY + 3:HANDLER_ENTRY + 7]
            == bytes.fromhex("ff 06 ed 49"),
        "1b_guard_and_call_order": ovr[0x1900:0x190C]
            == bytes.fromhex("80 3e 7d 6f 00 75 05 9a 8e 00 2b 00"),
        "classifier_walk_complete_to_retf": bool(classifier_complete),
        "classifier_walk_byte_coverage_contiguous": classifier_coverage == classifier_len,
        "classifier_start_unique_in_game": bool(classifier_bytes) and ovr.count(classifier_bytes) == 1,
    }

    rows = []
    for label, raw in dumps:
        base = pogm.resolve_dump_base(label, len(raw), None)
        dump = pogm.Dump(raw, base)
        gmap = pogm.map_group(group, ovr[GROUP_FILE:GROUP_FILE + group["codesz"]], fixups, dump)
        row = {"label": label, "sha256": pogm.sha256(raw),
               "known_dump": KNOWN_DUMPS.get(pogm.sha256(raw)),
               "group_status": gmap["status"], "group_base": gmap["base_linear"], "checks": {}}
        checks = row["checks"]
        if gmap["status"] == "unique" and gmap["base_linear"] == GROUP_BASE:
            call_linear = GROUP_BASE + body_site
            call = dump.read(call_linear, 5)
            live_seg, live_off = u16(call, 3), u16(call, 1)
            live_target = live_seg * 16 + live_off
            thunk = dump.read(live_target, 5) if dump.covers(live_target, 5) else b""
            thunk_dest = (u16(thunk, 3) * 16 + u16(thunk, 1)) if thunk[:1] == b"\xEA" else -1
            live_classifier = (dump.read(thunk_dest, classifier_len)
                               if thunk_dest >= 0 and dump.covers(thunk_dest, classifier_len) else b"")
            instruction_matches = sum(
                dump.read(thunk_dest + (r["at"] - CLASSIFIER_FILE), len(bytes.fromhex(r["bytes"])))
                == bytes.fromhex(r["bytes"]) for r in listing
            ) if live_classifier else 0
            checks.update({
                "group_unique_at_expected_base": True,
                "live_call_bytes_match_002b_008e": call == CALL_BYTES[:3] + struct.pack("<H", live_seg),
                "live_segment_is_1891": live_seg == LIVE_SEG,
                "live_target_is_1891_008e": live_target == THUNK_LINEAR,
                "target_is_expected_far_jmp_thunk": thunk == THUNK,
                "thunk_destination_is_40cc_1ea6": thunk_dest == CLASSIFIER_LINEAR,
                "destination_matches_complete_classifier": bool(live_classifier)
                    and live_classifier == classifier_bytes,
                "all_classifier_instruction_spans_match": instruction_matches == len(listing),
            })
            row["call"] = {"linear": call_linear, "bytes": call.hex(" "),
                           "live_segment": live_seg, "live_offset": live_off,
                           "target_linear": live_target}
            row["thunk"] = {"linear": live_target, "bytes": thunk.hex(" "),
                            "destination_linear": thunk_dest}
            row["classifier"] = {"linear": thunk_dest, "game_offset": CLASSIFIER_FILE,
                                 "length": classifier_len, "instruction_count": len(listing),
                                 "instruction_bytes_matching": instruction_matches,
                                 "sha256": hashlib.sha256(live_classifier).hexdigest(),
                                 "bytes_match_game": bool(live_classifier) and live_classifier == classifier_bytes}
        else:
            checks["group_unique_at_expected_base"] = False
        row["status"] = "ok" if all(checks.values()) else "diagnostic"
        rows.append(row)

    file_ok = all(file_checks.values())
    return {
        "schema": SCHEMA, "schema_version": 1, "tool": TOOL,
        "status_scope": "memory-byte-call-chain-cross-check-only", "playable": False,
        "status": "ok" if file_ok and all(r["status"] == "ok" for r in rows) else "diagnostic",
        "execution_established": False,
        "input_pins": {"GAME.OVR": {"size": len(ovr), "sha256": pogm.sha256(ovr)},
                       "START.EXE": {"size": len(exe), "sha256": pogm.sha256(exe)}},
        "file_side": {"checks": file_checks,
                      "call": {"at": HELPER_CALL, "bytes": ovr[HELPER_CALL:HELPER_CALL + 5].hex(" "),
                               "fixup_word_offset_in_group": body_site + 3},
                      "classifier": {"entry": CLASSIFIER_FILE, "end": classifier_end,
                                     "length": classifier_len, "instruction_count": len(listing),
                                     "returns": classifier["returns"],
                                     "decode_complete": bool(classifier_complete),
                                     "sha256": hashlib.sha256(classifier_bytes).hexdigest()}},
        "dumps": rows,
        "not_established": ["that the 0x1B guard path or far call executes",
                            "the run-time value of DS:0x6F7D",
                            "whether the classifier is reached from any ECL root",
                            "any ECL block-to-area or LOAD_PIECES archive mapping"],
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
        ovr, exe = (install / "GAME.OVR").read_bytes(), (install / "START.EXE").read_bytes()
        paths = args.dump or DEFAULT_DUMPS
        inputs = [(f"{p.parent.name}/{p.name}", p.read_bytes()) for p in paths]
        result = analyze(ovr, exe, inputs)
        out.mkdir(parents=True, exist_ok=True)
        (out / "por_ecl_1b_classifier_dump_probe.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (Refusal, pogm.Refusal) as exc:
        print("REFUSED: " + str(exc), file=sys.stderr)
        return 2
    print("status=%s dumps=%s" % (result["status"],
          [(x["known_dump"], x["status"]) for x in result["dumps"]]))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
