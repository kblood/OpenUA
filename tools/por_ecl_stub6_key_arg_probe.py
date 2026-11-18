#!/usr/bin/env python3
"""Trace the stub-6 far calls in the shared 0x19BA handler to the WALLDEF wrapper at GAME.OVR 0x2F6FF.

Question: does the stub-6 route give any PoR-byte evidence for the archive selector the wrapper reads
(DS:[0x5376], the WALLDEF digit) or its requested block id (the loader's TOC compare at START 0x88DE)?

Status: static byte probe plus memory-byte presence. ``playable: false``. Read-only. It never
claims that a call ran, that a file was opened, or that a GEO block was loaded.

Findings this tool re-derives from the pinned bytes (see docs/por-ecl-stub6-key-arg-probe.md):

* The four ``9A 3E 00 D5 03`` sites at 0x1A77/0x1A9E/0x1AAA/0x1AD6 sit on the NON-0x21 side of the
  handler's ``cmp [0x6F7F],0x21`` (0x19F1); the 0x21 side ends at ``jmp 0x1B05`` (0x1A63). The
  only other caller of the handler is the 0x37 case (0x3D9E). So these four calls are the 0x37
  route, not the 0x21 route.
* Each call pushes two words: first an id byte (AL), then a gate byte (AL). The wrapper at
  0x2F6FF gates its second argument ``[bp+6]`` to 1..3, and passes its first argument ``[bp+8]``
  to the loader as the requested id.
* The wrapper builds ``WALLDEF<d>.dax`` from ``DS:[0x5376]``, not from its arguments. No instruction
  in the handler or the wrapper stores to ``DS:[0x5376]``.
* The id bytes for paths B, C and D come from the far call ``0x002B:0x0025`` (return AL), which is
  not identified here.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import por_loadpieces_handler as h  # noqa: E402  (read-only decoder)
import por_overlay_group_map as pogm  # noqa: E402  (pins, install lookup, sha256)
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

SCHEMA = "openua.por-ecl-stub6-key-arg-probe"
SCHEMA_VERSION = 1
TOOL = "tools/por_ecl_stub6_key_arg_probe.py"
ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-ecl-stub6-key-arg-probe"
DEFAULT_DUMPS = [DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                 DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin"]
KNOWN_DUMPS = {
    "f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895": "por-live-memory-pid34644",
    "3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa": "por-wheel-live-capture",
}

# ---- file-side anchors (GAME.OVR file offsets unless marked START) ----
DISPATCH_21 = 0x3D9A        # 3C 21 (cmp al,0x21)
DISPATCH_JZ = 0x3D9C        # 74 04 -> 0x3DA2
DISPATCH_37 = 0x3D9E        # 3C 37 (cmp al,0x37)
DISPATCH_JNZ37 = 0x3DA0     # 75 07 -> 0x3DA9
DISPATCH_CALL = 0x3DA3      # E8 -> 0x19BA
HANDLER = 0x19BA
KEY_CMP = 0x19F1            # 80 3E 7F 6F 21 (cmp [0x6F7F],0x21)
KEY_JNZ = 0x19F6            # 75 6E -> 0x1A66 (non-0x21 side)
NONKEY = 0x1A66
KEY21_END = 0x1A63          # E9 9F 00 -> 0x1B05 (end of 0x21 side)
EXIT = 0x1B05
STUB7_SITE = 0x1A27         # 9A 43 00 D5 03 (0x21 side)
ARG_LOOP_CALL = 0x19DA      # 9A 25 00 2B 00 (call 0x002B:0x0025, return AL)
ARG_LOOP_STORE = 0x19E8     # 88 53 FC (mov [bp+di-4],dl)
STUB6_SITES = (0x1A77, 0x1A9E, 0x1AAA, 0x1AD6)
STUB6_CALL = bytes.fromhex("9a 3e 00 d5 03")
# argument pushes that precede each stub-6 site, as bytes (id word first, gate word second)
PATH_PATTERNS = {
    0x1A77: ("A", bytes.fromhex("b0 00 50 b0 01 50"), "literal 0x00", "literal 0x01"),
    0x1A9E: ("B", bytes.fromhex("8a 46 fd 50 b0 01 50"), "[bp-3]", "literal 0x01"),
    0x1AAA: ("C", bytes.fromhex("8a 46 ff 50 b0 03 50"), "[bp-1]", "literal 0x03"),
    0x1AD6: ("D", bytes.fromhex("8a 43 fc 50 8a 46 fc 50"), "[bp+di-4] (loop k)", "[bp-4] (loop k)"),
}
PATH_A_GUARD = bytes.fromhex("80 7e fd 7f 75 0e")          # cmp [bp-3],0x7f ; jnz 0x1A7F
PATH_B_GUARD_1 = bytes.fromhex("26 83 bd ce 01 00 74 26")  # es cmp [di+462],0 ; jz 0x1AB1
PATH_B_GUARD_2 = bytes.fromhex("26 83 bd d0 01 00 74 1a")  # es cmp [di+464],0 ; jz 0x1AB1
PATH_D_LOOP_INIT = bytes.fromhex("c6 46 fc 01")            # mov [bp-4],1
PATH_D_SKIP = bytes.fromhex("80 7b fc ff 74 16")            # cmp [bp+di-4],0xff ; jz 0x1ADD
PATH_D_LOOP_END = bytes.fromhex("80 7e fc 03 75 b2")        # cmp [bp-4],3 ; jnz 0x1AB7
# ---- WALLDEF wrapper (GAME.OVR, group base 0x2E8F7 proc 0x0E08) ----
WRAPPER = 0x2F6FF
WRAPPER_GATE = bytes.fromhex("80 7e 06 01 72 06 80 7e 06 03 76 03 e9 79 02")
WRAPPER_SEL_LOAD = 0x2F715                                   # a0 76 53 : mov al,[0x5376]
WRAPPER_FORMAT_CALL = 0x2F72A                                # 9a 66 13 f8 0a : call 0x0AF8:0x1366
WRAPPER_ID_LOAD = 0x2F759                                    # 8a 46 08 50 : mov al,[bp+8] ; push ax
WRAPPER_ID_PUSH = bytes.fromhex("8a 46 08 50")
WRAPPER_LOADER_CALL = 0x2F767                                # 9a 16 07 02 08 : call 0x0802:0x0716
WRAPPER_RETF = 0x2F991                                       # ca 04 00
SEL_OFF = 0x5376
SEL_BYTES_LOAD = bytes.fromhex("a0 76 53")
LOADER_LIVE_SEG_ADD = 0x1866                                 # live = raw + 0x1866 (START stub model)
# ---- START loader (conditional identity of 0x0802:0x0716) ----
START_LOADER = 0x876D
START_LOADER_PROLOGUE = bytes.fromhex("55 89 e5 81 ec 3e 02")
START_ID_COMPARE = 0x88DE                                    # 3a 46 0e : cmp al,[bp+14]
START_ID_COMPARE_BYTES = bytes.fromhex("3a 46 0e")
START_RETF = 0x899E                                          # ca 12 00
# ---- dump-side windows ----
HANDLER_DUMP_BASE = 0x45C40      # group 0x03C3 (file 0x0D46) unique at this linear base in both dumps
HANDLER_GROUP_FILE = 0x0D46
LOADER_DISPLACEMENT_DUMP = 0x20D96   # START 0x876D at this linear address (open-chain probe)
LIVE_OVERLAY_SEG_0x002B = 0x002B


class Refusal(Exception):
    pass


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _walk(data: bytes, start: int, end: int) -> dict[int, "h.Insn"]:
    """Instruction-aligned linear walk from ``start``; returns {offset: Insn} for offsets in [start, end)."""
    insns, _stop = h.linear(data, start, end + 0x40, stop_on_ret=False)
    return {i.off: i for i in insns if start <= i.off < end}


def _bytes(data: bytes, off: int, n: int) -> bytes:
    return data[off:off + n]


def _check(name: str, ok: bool, detail: str) -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def analyze(ovr: bytes, exe: bytes, dumps: list[tuple[str, bytes]], *, check_pins: bool = True) -> dict:
    if check_pins:
        pogm.check_pin("GAME.OVR", ovr, pogm.PINS)
        pogm.check_pin("START.EXE", exe, pogm.PINS)
    if not dumps:
        raise Refusal("no RAM dump given")

    checks: list[dict] = []
    handler_insns = _walk(ovr, HANDLER, 0x1B10)
    wrapper_insns = _walk(ovr, WRAPPER, WRAPPER_RETF + 3)

    # --- dispatch: 0x21 jz and 0x37 fallthrough both reach the handler block; no other E8 caller ---
    block_start = DISPATCH_CALL - 1                      # 0x3DA2 'push cs'
    jz_target = DISPATCH_JZ + 2 + ovr[DISPATCH_JZ + 1]
    jnz37_target = DISPATCH_JNZ37 + 2 + ovr[DISPATCH_JNZ37 + 1]
    rel = struct.unpack_from("<h", ovr, DISPATCH_CALL + 1)[0]
    e8_target = (DISPATCH_CALL + 3 + rel) & 0xFFFF
    checks.append(_check("dispatch_21_jz_to_handler_block",
                         ovr[DISPATCH_21:DISPATCH_21 + 2] == b"\x3c\x21" and ovr[DISPATCH_JZ] == 0x74
                         and jz_target == block_start, "jz 0x%05x -> 0x%05x" % (DISPATCH_JZ, jz_target)))
    checks.append(_check("dispatch_37_falls_into_handler_block",
                         ovr[DISPATCH_37:DISPATCH_37 + 2] == b"\x3c\x37" and ovr[DISPATCH_JNZ37] == 0x75
                         and DISPATCH_JNZ37 + 2 == block_start and jnz37_target == 0x3DA9,
                         "0x37 jnz 0x%05x skips the block only when not 0x37; fallthrough is 0x%05x"
                         % (jnz37_target, DISPATCH_JNZ37 + 2)))
    checks.append(_check("dispatch_call_is_handler", ovr[DISPATCH_CALL] == 0xE8 and e8_target == HANDLER,
                         "E8 target 0x%04x" % e8_target))
    e8_callers = []
    for s in range(len(ovr) - 3):
        if ovr[s] == 0xE8:
            if (s + 3 + struct.unpack_from("<h", ovr, s + 1)[0]) & 0xFFFF == HANDLER:
                e8_callers.append(s)
    checks.append(_check("handler_only_e8_caller_is_dispatch", e8_callers == [DISPATCH_CALL],
                         "E8 callers of 0x19BA: %s" % ["0x%05x" % x for x in e8_callers]))

    # --- key split inside the handler ---
    key_ok = (ovr[KEY_CMP:KEY_CMP + 5] == bytes.fromhex("80 3e 7f 6f 21")
              and ovr[KEY_JNZ] == 0x75 and KEY_JNZ + 2 + ovr[KEY_JNZ + 1] == NONKEY)
    checks.append(_check("handler_key_split_0x21_vs_other", key_ok,
                         "cmp [0x6F7F],0x21 at 0x%05x; jnz 0x%05x" % (KEY_CMP, NONKEY)))
    key21_window = [i for o, i in handler_insns.items() if 0x19F8 <= o < KEY21_END]
    stub6_in_21 = any(ovr[i.off:i.off + 5] == STUB6_CALL for i in key21_window)
    checks.append(_check("no_stub6_site_on_0x21_side", not stub6_in_21 and ovr[KEY21_END:KEY21_END + 3] == b"\xe9\x9f\x00",
                         "0x21 side 0x19F8..0x1A63 has no 9A 3E 00 D5 03; jmp 0x1B05 at 0x1A63"))
    checks.append(_check("stub7_site_on_0x21_side", ovr[STUB7_SITE:STUB7_SITE + 5] == bytes.fromhex("9a 43 00 d5 03")
                         and STUB7_SITE in handler_insns and 0x19F8 <= STUB7_SITE < KEY21_END,
                         "9A 43 00 D5 03 at 0x1A27 (0x21 side)"))

    # --- stub-6 sites: instruction boundaries and argument patterns ---
    sites = []
    for site in STUB6_SITES:
        label, pat, id_src, gate_src = PATH_PATTERNS[site]
        boundary = site in handler_insns
        pre = ovr[site - len(pat):site]
        call_ok = ovr[site:site + 5] == STUB6_CALL
        sites.append({"site": "0x%05x" % site, "path": label, "instruction_boundary": boundary,
                      "call_bytes_ok": call_ok, "pushes_match": pre == pat,
                      "id_source": id_src, "gate_source": gate_src,
                      "bytes_before": pre.hex(" ")})
        checks.append(_check("stub6_site_0x%05x_arg_pattern" % site,
                             boundary and call_ok and pre == pat,
                             "path %s: id=%s gate=%s" % (label, id_src, gate_src)))
    checks.append(_check("stub6_path_A_guard",
                         ovr[0x1A6B:0x1A6B + 6] == PATH_A_GUARD and 0x1A6F + 2 + ovr[0x1A6F + 1] == 0x1A7F,
                         "cmp [bp-3],0x7f; jnz 0x1A7F"))
    checks.append(_check("stub6_path_B_guard",
                         ovr[0x1A83:0x1A83 + 8] == PATH_B_GUARD_1[:8] and ovr[0x1A8F:0x1A8F + 8] == PATH_B_GUARD_2[:8]
                         and ovr[0x1A89] == 0x74 and ovr[0x1A95] == 0x74,
                         "es cmp [di+462],0 / jz 0x1AB1 at 0x1A89; es cmp [di+464],0 / jz 0x1AB1 at 0x1A95"))
    checks.append(_check("stub6_path_D_loop", PATH_D_LOOP_INIT in ovr[0x1AB1:0x1AB5]
                         and PATH_D_SKIP in ovr[0x1AB7:0x1AC7 + 2] and PATH_D_LOOP_END == ovr[0x1AFF:0x1B05],
                         "loop k=1..3; skip when element == 0xff"))

    # --- the id source: loop return AL stored into [bp+di-4] ---
    arg_loop_ok = (ovr[ARG_LOOP_CALL:ARG_LOOP_CALL + 5] == bytes.fromhex("9a 25 00 2b 00")
                   and ovr[ARG_LOOP_STORE:ARG_LOOP_STORE + 3] == bytes.fromhex("88 53 fc")
                   and ovr[ARG_LOOP_CALL - 4:ARG_LOOP_CALL] == bytes.fromhex("8a 46 fc 50"))
    checks.append(_check("id_array_from_call_0x002B_0x0025", arg_loop_ok,
                         "push k; call 0x002B:0x0025; mov dl,al; mov [bp+di-4],dl"))

    # --- wrapper 0x2F6FF: gate, selector, id, loader call, return ---
    gate_jb = 0x2F70A
    gate_jbe = 0x2F710
    checks.append(_check("wrapper_gate_1_to_3",
                         ovr[WRAPPER:WRAPPER + 7] == bytes.fromhex("55 89 e5 81 ec 18 01")
                         and ovr[WRAPPER + 7:WRAPPER + 7 + 15] == WRAPPER_GATE
                         and gate_jb + 2 + ovr[gate_jb + 1] == 0x2F712
                         and gate_jbe + 2 + ovr[gate_jbe + 1] == WRAPPER_SEL_LOAD
                         and 0x2F712 + 3 + struct.unpack_from("<h", ovr, 0x2F713)[0] == 0x2F98E,
                         "cmp [bp+6],1 / jb / cmp [bp+6],3 / jbe 0x2F715; else jmp 0x2F98E"))
    checks.append(_check("wrapper_selector_read", ovr[WRAPPER_SEL_LOAD:WRAPPER_SEL_LOAD + 3] == SEL_BYTES_LOAD
                         and ovr[WRAPPER_FORMAT_CALL:WRAPPER_FORMAT_CALL + 5] == bytes.fromhex("9a 66 13 f8 0a"),
                         "mov al,[0x5376] then call 0x0AF8:0x1366 (formatter)"))
    checks.append(_check("wrapper_id_from_bp8_to_loader",
                         ovr[WRAPPER_ID_LOAD:WRAPPER_ID_LOAD + 4] == WRAPPER_ID_PUSH
                         and ovr[WRAPPER_LOADER_CALL:WRAPPER_LOADER_CALL + 5] == bytes.fromhex("9a 16 07 02 08"),
                         "mov al,[bp+8]; push ax; call 0x0802:0x0716"))
    checks.append(_check("wrapper_retf4", ovr[WRAPPER_RETF:WRAPPER_RETF + 3] == bytes.fromhex("ca 04 00"),
                         "retf 4 (the 4 stub-pushed bytes)"))
    checks.append(_check("loader_compare_on_requested_id",
                         exe[START_ID_COMPARE:START_ID_COMPARE + 3] == START_ID_COMPARE_BYTES
                         and exe[START_LOADER:START_LOADER + 7] == START_LOADER_PROLOGUE
                         and exe[START_RETF:START_RETF + 3] == bytes.fromhex("ca 12 00"),
                         "START 0x88DE cmp al,[bp+14]; body 0x876D; retf 0x12"))

    # --- the wrapper's name pieces: WALLDEF stem and .dax suffix (not GEO) ---
    stem_bytes = bytes.fromhex("07 57 41 4c 4c 44 45 46")       # Pascal "WALLDEF"
    suffix_bytes = bytes.fromhex("04 2e 64 61 78")              # Pascal ".dax"
    geo_stem_bytes = bytes.fromhex("03 47 45 4f")               # Pascal "GEO"
    checks.append(_check("wrapper_stem_literal_is_WALLDEF",
                         ovr[0x2F6AB:0x2F6AB + 8] == stem_bytes
                         and ovr[0x2F735:0x2F738] == bytes.fromhex("bf b4 0d"),
                         "CS:0x0DB4 -> file 0x2F6AB = 07 'WALLDEF'; copied at 0x2F735"))
    checks.append(_check("wrapper_suffix_literal_is_dax",
                         ovr[0x2F6B3:0x2F6B3 + 5] == suffix_bytes
                         and ovr[0x2F74F:0x2F752] == bytes.fromhex("bf bc 0d"),
                         "CS:0x0DBC -> file 0x2F6B3 = 04 '.dax'; copied at 0x2F74F"))
    checks.append(_check("wrapper_does_not_copy_GEO_stem",
                         bytes.fromhex("bf 9d 10") not in ovr[WRAPPER:WRAPPER_RETF + 3]
                         and ovr[0x2F994:0x2F994 + 4] == geo_stem_bytes,
                         "no mov di,0x109D in the wrapper; GEO literal (0x2F994) belongs to the fill"))

    # --- store census for DS:[0x5376] in the wrapper and the handler window ---
    def direct_hits(insns: dict, lo: int, hi: int) -> list[dict]:
        out = []
        for o in sorted(insns):
            i = insns[o]
            if i.direct is not None and lo <= i.direct <= hi:
                out.append({"off": "0x%05x" % o, "bytes": ovr[o:i.end].hex(" "), "text": i.text()})
        return out

    sel_wrap = direct_hits(wrapper_insns, SEL_OFF, SEL_OFF + 1)
    sel_hand = direct_hits(handler_insns, SEL_OFF, SEL_OFF + 1)
    checks.append(_check("wrapper_only_selector_access_is_load", len(sel_wrap) == 1
                         and sel_wrap[0]["off"] == "0x%05x" % WRAPPER_SEL_LOAD
                         and sel_wrap[0]["bytes"] == "a0 76 53", "%d access(es) in wrapper" % len(sel_wrap)))
    checks.append(_check("handler_has_no_selector_access", len(sel_hand) == 0,
                         "%d access(es) in 0x19BA..0x1B10" % len(sel_hand)))

    # --- memory-byte presence (unknown capture instants) ---
    dump_rows = []
    for label, raw in dumps:
        sha = pogm.sha256(raw)
        hh = HANDLER_DUMP_BASE + (HANDLER - HANDLER_GROUP_FILE)
        # relocation-invariant window: wrapper prologue through the first DS-direct load (no segment words)
        window = ovr[WRAPPER:WRAPPER_SEL_LOAD + 3]
        body_hits = []
        start = 0
        while True:
            k = raw.find(window, start)
            if k < 0:
                break
            body_hits.append(k)
            start = k + 1
        row = {"label": label, "sha256": sha,
               "known_dump": KNOWN_DUMPS.get(sha),
               "handler_prologue_at_expected": raw[hh:hh + 6] == ovr[HANDLER:HANDLER + 6],
               "handler_key_window_at_expected": raw[hh + (KEY_CMP - HANDLER):hh + (KEY_CMP - HANDLER) + 5]
               == ovr[KEY_CMP:KEY_CMP + 5],
               "wrapper_window_hits": ["0x%06x" % x for x in body_hits],
               "loader_prologue_at_displacement": raw[LOADER_DISPLACEMENT_DUMP:LOADER_DISPLACEMENT_DUMP + 7]
               == START_LOADER_PROLOGUE,
               "live_0x002B_0x0025_bytes": raw[(LIVE_OVERLAY_SEG_0x002B + LOADER_LIVE_SEG_ADD) * 16 + 0x25:
                                               (LIVE_OVERLAY_SEG_0x002B + LOADER_LIVE_SEG_ADD) * 16 + 0x25 + 5].hex(" "),
               "live_0x03D5_0x003E_bytes": raw[(0x03D5 + LOADER_LIVE_SEG_ADD) * 16 + 0x3E:
                                               (0x03D5 + LOADER_LIVE_SEG_ADD) * 16 + 0x3E + 5].hex(" ")}
        dump_rows.append(row)
    checks.append(_check("handler_prologue_in_both_dumps",
                         all(r["handler_prologue_at_expected"] for r in dump_rows),
                         "linear 0x%05x" % (HANDLER_DUMP_BASE + HANDLER - HANDLER_GROUP_FILE)))
    checks.append(_check("loader_prologue_in_both_dumps",
                         all(r["loader_prologue_at_displacement"] for r in dump_rows),
                         "START 0x876D at linear 0x%05x" % LOADER_DISPLACEMENT_DUMP))

    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL,
        "status_scope": "static-byte-trace-and-memory-presence-only",
        "playable": False,
        "status": "ok" if all(c["ok"] for c in checks) else "diagnostic",
        "execution_established": False,
        "input_pins": {"GAME.OVR": {"size": len(ovr), "sha256": pogm.sha256(ovr)},
                       "START.EXE": {"size": len(exe), "sha256": pogm.sha256(exe)}},
        "route": {
            "stub6_sites_key_side": "non-0x21 (0x37 case)",
            "non_0x21_block_start": "0x%05x" % NONKEY,
            "handler_callers": ["0x%05x" % DISPATCH_CALL],
            "stub6_sites": sites,
        },
        "wrapper": {
            "entry": "GAME.OVR 0x%05x" % WRAPPER,
            "name_pieces": "stem WALLDEF (file 0x2F6AB) + formatter digit of DS:[0x5376] + suffix .dax (0x2F6B3)",
            "gate_arg_bp6": "1..3 (else exit at 0x2F98E)",
            "name_source": "DS:[0x5376] via mov al,[0x5376] at 0x%05x" % WRAPPER_SEL_LOAD,
            "requested_id_arg": "[bp+8], pushed at 0x%05x and passed as loader id" % WRAPPER_ID_LOAD,
            "loader_call": "0x0802:0x0716 at 0x%05x (START 0x876D, conditional)" % WRAPPER_LOADER_CALL,
            "retf": "0x%05x retf 4" % WRAPPER_RETF,
        },
        "selector": {
            "wrapper_accesses_to_5376": sel_wrap,
            "handler_accesses_to_5376": sel_hand,
            "stub6_route_writes_5376": False,
            "note": "pointer stores via DS:[0x49D2]/[0x49D6] in the handler are not resolved",
        },
        "requested_id": {
            "compare": "START 0x%05x cmp al,[bp+14]" % START_ID_COMPARE,
            "id_sources": {"A": "literal 0x00", "B": "[bp-3] = AL of call 0x002B:0x0025(k=1)",
                           "C": "[bp-1] = AL of call 0x002B:0x0025(k=3)",
                           "D": "[bp-3..-1] = AL of call 0x002B:0x0025(k), k=1..3"},
            "values_established": False,
            "narrowest_missing_edge": "the far target 0x002B:0x0025 (its return AL for k=1..3) is not identified",
        },
        "checks": checks,
        "dumps": dump_rows,
        "not_established": [
            "that any stub-6 call executed, or that the handler ran at any dump instant",
            "the runtime value of DS:[0x5376] (DS is not established) and so the archive digit",
            "the return AL of the far call 0x002B:0x0025 and so the requested id values of paths B, C, D",
            "that the INT 3Fh stub dispatch reached the wrapper at 0x2F6FF",
            "any file opened, any GEO block loaded, any plane binding",
        ],
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
        (out / "por_ecl_stub6_key_arg_probe.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (Refusal, pogm.Refusal) as exc:
        print("REFUSED: " + str(exc), file=sys.stderr)
        return 2
    failed = [c["name"] for c in report["checks"] if not c["ok"]]
    print("status=%s checks=%d failed=%d %s" % (report["status"], len(report["checks"]), len(failed), failed))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
