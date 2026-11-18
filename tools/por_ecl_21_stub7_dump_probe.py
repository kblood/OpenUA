#!/usr/bin/env python3
"""Pool of Radiance: the ECL 0x21 handler far call at GAME.OVR 0x1A27 vs. START stub 7, against RAM dumps.

Status: MEMORY-BYTE-CROSS-CHECK-ONLY. playable: false. Stdlib-only. Read-only.

Inputs (never written to):
  * the pinned retail GAME.OVR and START.EXE (exact size + SHA-256; no override);
  * one or more raw linear RAM dumps named ram-LO-HI.bin (the base comes from the name).

What it checks
  File side (pinned GAME.OVR and START.EXE):
    - the group header at START 0x3C3 has fileofs 0xD46; the far call at GAME.OVR 0x1A27 is
      9A 43 00 D5 03 (offset 0x0043, raw seg 0x03D5); its seg word (body 0xCE4) is fixup-listed;
    - START stub 7 at 0x3E11 is CD 3F C7 10 27: proc 0x10C7, run from header 0x3DD7 (+0x17),
      owner fileofs 0x2E8F7; the proc lies inside the owner codesz and GAME.OVR 0x2F9BE is 55 89 E5.
  Dump side (each dump, by stable bytes):
    - the 0xD46 group maps uniquely at linear 0x45C40 (fixup bytes excluded, as the mapper does);
    - the live far call at that base reads 9A, offset 0x0043, live seg 0x1C3B, so the live target is
      1C3B:0043 = linear 0x1C3F3;
    - the file-side handler's pushed byte is the first local populated by a three-call
      loop through 002B:0025; the candidate fill argument/return bytes have a one-word-
      compatible stack shape, but helper semantics and fixup target remain open;
    - the 16 target bytes are compared with START 0x3E11. The classification is one of
      exact-16-match / stub5-match / prefix4-match-trailer-differs / prefix-absent. The EXPECTED
      result is prefix4-match-trailer-differs: the first four bytes CD 3F C7 10 match; the trailer
      is 00 in RAM and 27 in START. Full identity is NOT claimed;
    - positive control: START 0x3E02 (stub 4, the callee-identity match) must sit at linear 0x1C3E4;
    - the owner group 0x2E8F7 is mapped in each dump and recorded (expected absent).

What it does NOT establish, and the report says so in "not_established":
  * that the 0x1A27 far call executes, or is reached from the ECL 0x21 dispatch at any instant;
  * that the dump window is the call target at any instant, or that group 0x2E8F7 was resident;
  * that a trailer of 00 (RAM) or 27 (START) is meaningful, or that the 16 bytes are one stub;
  * the capture instant or atomicity of either dump; that the call reaches the candidate fill;
    the pushed byte's value/meaning; any GEO meaning.

Exit codes: 0 every file-side check and every dump check holds; 1 a check fails (diagnostic);
2 a named refusal (unpinned or missing input, unreadable structure, bad dump name, bad output path).
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import por_overlay_group_map as pogm  # noqa: E402  (read-only reuse: parse, fixups, map, classify)
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

Refusal = pogm.Refusal

SCHEMA = "openua.por-ecl-21-stub7-dump-probe"
SCHEMA_VERSION = 1
TOOL = "tools/por_ecl_21_stub7_dump_probe.py"
STATUS_SCOPE = "memory-byte-cross-check-only"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-ecl-21-stub7-dump-probe"
DEFAULT_DUMPS = [DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                 DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin"]
OUT_NAME = "por_ecl_21_stub7_dump_probe.json"
PARA = 16
WINDOW = 16
STUB_STRIDE = 5
STUB_RUN_OFFSET = 0x17           # the stub run starts at header + 0x17 (both owner runs in retail)
PROLOGUE = bytes.fromhex("55 89 e5")
HANDLER_ARG_PUSH = bytes.fromhex("8a 46 fd 50")
HANDLER_OPERAND_LOOP_AT = 0x19CD
HANDLER_OPERAND_LOOP = bytes.fromhex(
    "c6 46 fc 01 eb 03 fe 46 fc 8a 46 fc 50 9a 25 00 2b 00 "
    "8a d0 8a 46 fc 30 e4 8b f8 88 53 fc 80 7e fc 03 75 e2")
FILL_ARG_READ_DELTA = 0x4B
FILL_ARG_READ = bytes.fromhex("8a 46 06")
FILL_RETF_DELTA = 0x13C
FILL_RETF = bytes.fromhex("ca 02 00")
EXPECTED_RESULT = "prefix4-match-trailer-differs"
RESULTS = ("exact-16-match", "stub5-match", EXPECTED_RESULT, "prefix-absent")

# The two dumps the callee/copy probes already used, pinned by SHA-256 (size is checked too).
KNOWN_DUMPS = {
    "f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895": "por-live-memory-pid34644",
    "3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa": "por-wheel-live-capture",
}
KNOWN_DUMP_SIZE = 1048576

CLAIMS = {
    "memory_present": "the 16 target bytes match START 0x3E11 in the first four bytes only; memory bytes",
    "candidate_argument_provenance": "[bp-3] is the first AL result stored by a 1..3 loop of calls to 002B:0025; helper semantics unknown",
    "candidate_stack_shape": "one pushed word matches candidate fill's byte argument and retf 2; conditional on target",
    "executed": "not_established",
    "called": "not_established",
}
NOT_ESTABLISHED = [
    "that the 0x1A27 far call executes, or is reached from the ECL 0x21 dispatch at any instant",
    "that the dump window is the call target at any instant, or that group 0x2E8F7 was resident",
    "that the trailer (00 in RAM, 27 in START) is meaningful, or that the 16 bytes are one stub",
    "the capture instant or atomicity of either dump",
    "that the far call reaches candidate proc 0x10C7; the pushed byte's value or meaning; any GEO meaning",
]


@dataclasses.dataclass(frozen=True)
class Cfg:
    """The expected retail facts. Defaults are the values the callee and copy probes recorded."""
    group_descriptor: int = 0x3C3       # START header of the group that holds the far call
    group_fileofs: int = 0xD46          # GAME.OVR fileofs of that group's code
    group_base_expected: int = 0x45C40  # linear base both dumps show
    site_file: int = 0x1A27             # GAME.OVR offset of the 9A opcode
    site_raw_seg: int = 0x03D5
    site_off: int = 0x0043
    site_live_seg: int = 0x1C3B         # live seg both dumps show
    stub_file: int = 0x3E11             # START offset of stub 7
    stub_slot: int = 7
    stub_bytes: bytes = bytes.fromhex("cd 3f c7 10 27")
    stub_proc: int = 0x10C7
    owner_descriptor: int = 0x3DD7      # header of the group that owns the stub run
    owner_fileofs: int = 0x2E8F7
    control_stub_file: int = 0x3E02     # stub 4: the positive control (matched by the callee probe)
    control_slot: int = 4


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _hx(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def _leading_equal(a: bytes, b: bytes) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def _positions(data: bytes, needle: bytes) -> list[str]:
    return ["0x%X" % i for i in range(len(data) - len(needle) + 1) if data[i:i + len(needle)] == needle]


def file_checks(ovr: bytes, exe: bytes, cfg: Cfg) -> dict:
    """File-side facts. Each check is a boolean. Refusal only when a structure cannot be read."""
    group = pogm.parse_descriptor(exe, ovr, cfg.group_descriptor)
    fixups = pogm.read_fixups(ovr, group)
    owner = pogm.parse_descriptor(exe, ovr, cfg.owner_descriptor)
    site = cfg.site_file
    if site < group["fileofs"] or site + 5 > group["fileofs"] + group["codesz"]:
        raise Refusal("far-call site 0x%X lies outside the group code" % site)
    site_body = site - group["fileofs"]
    seg_body = site_body + 3
    run = cfg.owner_descriptor + STUB_RUN_OFFSET
    proc_file = cfg.owner_fileofs + cfg.stub_proc
    handler_push_at = site - 4
    fill_arg_read_at = proc_file + FILL_ARG_READ_DELTA
    fill_retf_at = proc_file + FILL_RETF_DELTA
    checks = {
        "group_descriptor_fileofs": group["fileofs"] == cfg.group_fileofs,
        "site_opcode_9a": ovr[site] == 0x9A,
        "site_offset_word": _u16(ovr, site + 1) == cfg.site_off,
        "site_raw_seg_word": _u16(ovr, site + 3) == cfg.site_raw_seg,
        "seg_word_fixup_listed": seg_body in fixups,
        "stub_bytes": exe[cfg.stub_file:cfg.stub_file + 5] == cfg.stub_bytes,
        "stub_proc_word": _u16(exe, cfg.stub_file + 2) == cfg.stub_proc,
        "stub_slot_in_owner_run": cfg.stub_file == run + STUB_STRIDE * cfg.stub_slot,
        "control_slot_in_owner_run": cfg.control_stub_file == run + STUB_STRIDE * cfg.control_slot,
        "owner_descriptor_fileofs": owner["fileofs"] == cfg.owner_fileofs,
        "proc_inside_owner_codesz": cfg.stub_proc < owner["codesz"],
        "proc_prologue_in_file": ovr[proc_file:proc_file + 3] == PROLOGUE,
        "candidate_handler_pushes_one_word":
            ovr[handler_push_at:handler_push_at + len(HANDLER_ARG_PUSH)] == HANDLER_ARG_PUSH,
        "candidate_argument_local_filled_by_helper_loop":
            ovr[HANDLER_OPERAND_LOOP_AT:HANDLER_OPERAND_LOOP_AT + len(HANDLER_OPERAND_LOOP)]
            == HANDLER_OPERAND_LOOP,
        "candidate_fill_reads_low_argument_byte":
            ovr[fill_arg_read_at:fill_arg_read_at + len(FILL_ARG_READ)] == FILL_ARG_READ,
        "candidate_fill_returns_popping_one_word":
            ovr[fill_retf_at:fill_retf_at + len(FILL_RETF)] == FILL_RETF,
    }
    facts = {
        "group": {k: _hx(v) if isinstance(v, int) else v for k, v in group.items()},
        "owner": {k: _hx(v) if isinstance(v, int) else v for k, v in owner.items()},
        "group_fixup_count": len(fixups),
        "site_body_offset": _hx(site_body), "seg_word_body_offset": _hx(seg_body),
        "stub_run_start": _hx(run), "proc_file_offset": _hx(proc_file),
        "candidate_frame": {
            "argument_provenance":
                "[bp-3] is the first local filled from AL by the 1..3 loop of calls to 002B:0025; helper semantics unknown",
            "handler_push_at": _hx(handler_push_at),
            "argument_source": "byte [bp-3], first helper-result local, pushed as AX word",
            "candidate_fill_arg_read_at": _hx(fill_arg_read_at),
            "candidate_fill_reads": "AL <- byte [bp+6]",
            "candidate_fill_retf_at": _hx(fill_retf_at),
            "candidate_fill_retf": FILL_RETF.hex(" "),
            "shape": "one pushed word matches retf 2; conditional on candidate target",
        },
        "stub_16_bytes_hex": exe[cfg.stub_file:cfg.stub_file + WINDOW].hex(" "),
        "control_16_bytes_hex": exe[cfg.control_stub_file:cfg.control_stub_file + WINDOW].hex(" "),
    }
    return {"checks": checks, "facts": facts}


def analyze_dump(label: str, data: bytes, ovr: bytes, exe: bytes, cfg: Cfg) -> dict:
    """One dump: map the group, read the live call, compare the 16 target bytes with START stub 7."""
    base = pogm.resolve_dump_base(label, len(data), None)
    dump = pogm.Dump(data, base)
    sha = pogm.sha256(data)
    out = {"label": label, "size": len(data), "sha256": sha, "base": _hx(base),
           "known_dump": KNOWN_DUMPS.get(sha), "known_size_ok": len(data) == KNOWN_DUMP_SIZE}
    group = pogm.parse_descriptor(exe, ovr, cfg.group_descriptor)
    gcode = ovr[group["fileofs"]:group["fileofs"] + group["codesz"]]
    gmap = pogm.map_group(group, gcode, pogm.read_fixups(ovr, group), dump)
    out["group"] = {"status": gmap["status"], "base_linear": _hx(gmap["base_linear"]),
                    "hit_count": len(gmap["hits"]), "rejected_candidates": gmap["rejected_candidates"]}
    if gmap["status"] != "unique":
        out.update(window_result=None, dump_status="diagnostic", reason="group " + gmap["status"])
        return out
    glin = gmap["base_linear"]
    if glin != cfg.group_base_expected:
        out.update(window_result=None, dump_status="diagnostic",
                   reason="group unique at %s, expected %s" % (_hx(glin), _hx(cfg.group_base_expected)))
        return out
    site_lin = glin + (cfg.site_file - group["fileofs"])
    if not dump.covers(site_lin, 5):
        out.update(window_result=None, dump_status="diagnostic", reason="site outside dump")
        return out
    op = dump.read(site_lin, 5)                 # 9A off16 seg16
    off_live, seg_live = _u16(op, 1), _u16(op, 3)
    out["site"] = {"linear": _hx(site_lin), "opcode_9a": op[0] == 0x9A,
                   "offset_live": _hx(off_live), "seg_live": _hx(seg_live),
                   "seg_live_expected": _hx(cfg.site_live_seg),
                   "seg_live_matches_expected": seg_live == cfg.site_live_seg,
                   "live_minus_raw_seg": _hx((seg_live - cfg.site_raw_seg) & 0xFFFF)}
    target = seg_live * PARA + off_live
    out["target"] = {"seg_live": _hx(seg_live), "offset": _hx(off_live), "linear": _hx(target)}
    if not dump.covers(target, WINDOW):
        out.update(window_result=None, dump_status="diagnostic", reason="target outside dump")
        return out
    win = dump.read(target, WINDOW)
    stub16 = exe[cfg.stub_file:cfg.stub_file + WINDOW]
    if win == stub16:
        result = "exact-16-match"
    elif win[:5] == cfg.stub_bytes:
        result = "stub5-match"
    elif win[:4] == cfg.stub_bytes[:4]:
        result = EXPECTED_RESULT
    else:
        result = "prefix-absent"
    out["target"].update({
        "window_hex": win.hex(" "), "file_stub7_16_hex": stub16.hex(" "),
        "prefix4_match": win[:4] == cfg.stub_bytes[:4],
        "trailer_dump": "0x%02X" % win[4], "trailer_file": "0x%02X" % cfg.stub_bytes[4],
        "leading_equal_bytes_vs_file": _leading_equal(win, stub16),
        "exact_full_stub_identity": win == stub16,
        "prologue_positions": {"dump": _positions(win, PROLOGUE), "file": _positions(stub16, PROLOGUE)},
        "window_vs_pinned_files": pogm.classify_target(win, {"GAME.OVR": ovr, "START.EXE": exe}),
    })
    ctl_lin = target - (cfg.stub_file - cfg.control_stub_file)
    ctl_ok = dump.covers(ctl_lin, WINDOW) and \
        dump.read(ctl_lin, WINDOW) == exe[cfg.control_stub_file:cfg.control_stub_file + WINDOW]
    out["control"] = {"linear": _hx(ctl_lin), "file_offset": _hx(cfg.control_stub_file),
                      "exact_16_match": bool(ctl_ok)}
    ofile = pogm.parse_descriptor(exe, ovr, cfg.owner_descriptor)
    omap = pogm.map_group(ofile, ovr[ofile["fileofs"]:ofile["fileofs"] + ofile["codesz"]],
                          pogm.read_fixups(ovr, ofile), dump)
    out["owner_group"] = {"status": omap["status"], "base_linear": _hx(omap["base_linear"]),
                          "hit_count": len(omap["hits"])}
    out["window_result"] = result
    checks = {
        "site_opcode_9a": out["site"]["opcode_9a"],
        "site_offset_live": off_live == cfg.site_off,
        "site_seg_live_expected": out["site"]["seg_live_matches_expected"],
        "window_result_expected": result == EXPECTED_RESULT,
        "control_exact": bool(ctl_ok),
    }
    out["checks"] = checks
    out["dump_status"] = "ok" if all(checks.values()) else "diagnostic"
    return out


def run(ovr: bytes, exe: bytes, dumps: list[tuple[str, bytes]], *, pins: dict = pogm.PINS,
        cfg: Cfg = Cfg(), meta: Optional[dict] = None) -> dict:
    """Pure analysis: no I/O. Pins are checked first; a failed pin is a refusal."""
    pogm.check_pin("GAME.OVR", ovr, pins)
    pogm.check_pin("START.EXE", exe, pins)
    if not dumps:
        raise Refusal("no RAM dump given")
    fc = file_checks(ovr, exe, cfg)
    rows = [analyze_dump(label, data, ovr, exe, cfg) for label, data in dumps]
    file_ok = all(fc["checks"].values())
    dumps_ok = all(r["dump_status"] == "ok" for r in rows)
    status = "ok" if file_ok and dumps_ok else "diagnostic"
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL,
        "status_scope": STATUS_SCOPE, "playable": False, "status": status,
        "inputs": {
            "GAME.OVR": {"size": len(ovr), "sha256": pogm.sha256(ovr), "pinned": True},
            "START.EXE": {"size": len(exe), "sha256": pogm.sha256(exe), "pinned": True},
            "dumps": [{"label": r["label"], "size": r["size"], "sha256": r["sha256"],
                       "known_dump": r["known_dump"]} for r in rows],
        },
        "caller_metadata": {"unverified": True, "values": dict(meta or {})},
        "file_side": {"checks": fc["checks"], "facts": fc["facts"], "ok": file_ok},
        "dumps": rows,
        "dumps_ok": dumps_ok,
        "claims": dict(CLAIMS),
        "not_established": list(NOT_ESTABLISHED),
    }


def _check_out(folder: Path, out: Path) -> Path:
    try:
        out_dir = validate_output_dir(folder, out)
    except PorSourceError as exc:
        raise Refusal(str(exc))
    if DATA_WORK.resolve() not in out_dir.parents:
        raise Refusal("output must be a folder under data/work; got %s" % out_dir)
    return out_dir


def probe(install: Optional[Path], dump_paths: list[Path], *, out: Path, meta: dict,
          cfg: Cfg = Cfg()) -> tuple[dict, int]:
    folder = pogm.find_install(install)
    out_dir = _check_out(folder, out)
    dumps = []
    for p in dump_paths:
        if not p.is_file():
            raise Refusal("dump not found: %s" % p)
        dumps.append(("%s/%s" % (p.parent.name, p.name), p.read_bytes()))
    ovr = (folder / "GAME.OVR").read_bytes()
    exe = (folder / "START.EXE").read_bytes()
    doc = run(ovr, exe, dumps, cfg=cfg, meta=meta)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / OUT_NAME).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc, (0 if doc["status"] == "ok" else 1)


def _meta(items: list[str]) -> dict:
    out = {}
    for item in items:
        if "=" not in item:
            raise Refusal("--meta expects KEY=VALUE, got %r" % item)
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ECL 0x21 far call (GAME.OVR 0x1A27) vs. stub 7, dumps (read-only).")
    ap.add_argument("--install", type=Path, default=None,
                    help="PoR install folder (or POOLRAD inside it); default $%s" % pogm.INSTALL_ENV)
    ap.add_argument("--dump", type=Path, action="append", default=[],
                    help="raw dump, named ram-LO-HI.bin; repeat per dump (default: the two known dumps)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output folder under data/work")
    ap.add_argument("--meta", action="append", default=[], metavar="KEY=VALUE",
                    help="caller provenance, recorded and unverified")
    args = ap.parse_args(argv)
    try:
        dumps = args.dump or DEFAULT_DUMPS
        doc, code = probe(args.install, dumps, out=args.out, meta=_meta(args.meta))
    except Refusal as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2
    print("status=%s file_ok=%s dumps=%s" % (doc["status"], doc["file_side"]["ok"],
          [(r["label"], r["window_result"], r["dump_status"]) for r in doc["dumps"]]))
    return code


if __name__ == "__main__":
    sys.exit(main())
