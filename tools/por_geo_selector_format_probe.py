#!/usr/bin/env python3
"""Pool of Radiance GEO selector to filename chain: formatter bytes, fill arguments and dataflow.

Static and observe-only. Pins GAME.OVR and START.EXE, reads only them plus a directory listing of
the install (for presence checks), and never executes code. Reuses read-only helpers:
``por_loadpieces_handler`` (decoder), ``por_overlay_group_map`` (pins, descriptors),
``por_geo_archive_selector_probe`` (Image, selector writes, callers, address passes).

What it does:

1. Pins the module routine ``0x0AF8:0x1366`` (START file 0xBFDC, base 0xAC76, conditional), its near
   helper (file 0xBECA) and the power-of-ten table (file 0xBF1C) by SHA-256 of their decoded spans.
2. Reads the GEO fill (GAME.OVR 0x2F9BE): the selector load, zero extension, the pushed 32-bit
   value, the width argument and the destination, and the two copy-and-append pieces it leaves on
   the stack for the loader.
3. Models the formatter and the Pascal copy/append routines as their decoded instructions define
   them. This is a hand reading of the bytes, not a CPU emulator, and every model input is tied to
   a checked byte site.
4. Checks the loader (START 0x876D, conditional identity of 0x0802:0x0716), the open routine
   (START 0x8624), the path check (START 0x82B4), the name probe (START 0x8342), the record writer
   (0x13E2) and the open wrapper (0x1410, file 0xC086), at the byte level.
5. Lists every decoded writer of DS:[0x5376] and DS:[0x5377], its root, the decoded direct callers
   of that root, and whether the write lies on every path from the root's entry to a return.

Nothing is claimed about runtime values. Output is deterministic (sorted keys, no timestamps, no
absolute paths) and is written only under ``data/work``.

Usage:
  python -I tools/por_geo_selector_format_probe.py --install "G:/Games/Pool of Radiance/POOLRAD"

Exit codes: 0 all byte checks passed; 1 output written and a byte check failed; 2 named refusal
(missing or unpinned install, unsafe output location).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import por_geo_archive_selector_probe as sel  # noqa: E402
import por_loadpieces_handler as decoder  # noqa: E402
import por_overlay_group_map as groups  # noqa: E402

SCHEMA = "openua.por-geo-selector-format-probe"
VERSION = 1
TOOL = "tools/por_geo_selector_format_probe.py"
DATA_WORK = ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-selector-format-probe"
OUT_JSON = "por_geo_selector_format_probe.json"
OUT_MD = "por_geo_selector_format_probe_report.md"
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"
MASK32 = 0xFFFFFFFF

# ---- module segment 0x0AF8 (copy helpers, formatter). File = base + offset. CONDITIONAL base.
MODULE_BASE = 0xAC76
FORMAT_ENTRY = 0x1366            # 0x0AF8:0x1366, retf 0x0C, START file 0xBFDC
FORMAT_TABLE_FILE = 0xBF1C       # CS:0x12A6 in the formatter, 10 u32 (10^9 .. 10^0)
HELPER_FILE = 0xBECA             # near helper, reached by the rel16 call at file 0xBFED
COPY_B0B = 0x0B0B                # Pascal copy: dst pushed first, src second, retf 4 (pops src)
COPY_B98 = 0x0B98                # Pascal append: dst += src, retf 4 (pops src)
COPY_B25 = 0x0B25                # Pascal copy with clamp: CL = low byte of the count word, retf 10
WRITE_13E2 = 0x13E2              # file-record writer (state word 0xD7B0, path at +0x30), retf 8
WRITE_0C3B = 0x0C3B              # one-character Pascal string writer, retf 2
OPEN_WRAPPER = 0x1410            # 0x0AF8:0x1410 = START file 0xC086 (open-chain probe, conditional)

# ---- GAME.OVR
FILL = 0x2F9BE                   # GEO fill procedure (root)
FILL_LOADER_CALL = 0x2FA17       # far call 0x0802:0x0716
LOADER_FAR = (0x0802, 0x0716)
LOADER_FILE = 0x876D             # START body (conditional identity, loader-target probe)
OPEN_ROUTINE = 0x8624
PATH_CHECK = 0x82B4
NAME_PROBE = 0x8342

# ---- data slots
SELECTOR = 0x5376                # DS: GEO selector byte
SAVE = 0x5377                    # DS: one-byte save slot (START set/restore)
ROW_BASE = 0x2614                # DS: table, stride 0x1E, indexed by the selector
ROW_STRIDE = 0x1E
PREFIX_ADDR = 0x547C             # DS: Pascal prefix piece copied by the loader (value not in bytes)
PREFIX_CHAR_ADDR = 0x547D        # DS: byte passed to 0x0C3B (prompt text)
GEO_LITERAL_CS = 0x109D          # GAME.OVR CS-relative literal "\x03GEO"
DAX_LITERAL_CS = 0x10A1          # GAME.OVR CS-relative literal "\x04.dax"
INSTALL_ENV = "OPENUA_POR_INSTALL"

# Pinned SHA-256 of the decoded spans (START.EXE), from the decoder's ret-to-ret linear spans.
PINNED_SPANS = {
    "formatter_0x0AF8_1366": (0xBFDC, 0xC027, "e1b3b1952105b79c16db3429efa5be364318cf12c145d074f319fdccee589362"),
    "helper_0x0AF8_0ECA_file_BECA": (0xBECA, 0xBF1C, "20438c4c9e2a4c979493d273262e03e5217a1b16bb3372bd48d22d00982492ec"),
    "copy_0x0AF8_0B0B": (0xB781, 0xB79B, "4681f1935f55d71f05afab0b13fff0505aa17e9a04fb372ff559ef28ed88058f"),
    "append_0x0AF8_0B98": (0xB80E, 0xB83A, "c51c23b93b560cbbd48e3002e63b6bee1d24387a95f33915616ec64bfcebbb64"),
    "copy_clamp_0x0AF8_0B25": (0xB79B, 0xB7BF, "009955722e8f73d0a0f7076aa418d141f642c5a729b2a58dfa7a7a3922989118"),
    "record_writer_0x0AF8_13E2": (0xC058, 0xC086, "94e00b1b9e01bc846824e0f7eb23bc8d3c80c28b089995524ce99045af95ffa7"),
    "one_char_writer_0x0AF8_0C3B": (0xB8B1, 0xB8C3, "b2f0ef7b50632ff33ad1b2b251db935542c81b596360ac8b7cd6b391f3fca484"),
}
POWERS_OF_TEN = [10 ** k for k in range(9, -1, -1)]

# Raw byte sites, (file offset, hex, meaning). Each is checked against the pinned image.
FILL_SITES = [
    (0x2F9C5, "a07653", "mov al,[0x5376]: selector load"),
    (0x2F9C8, "30e4", "xor ah,ah: zero-extend selector"),
    (0x2F9CA, "31d2", "xor dx,dx: high word of the value is 0"),
    (0x2F9CC, "52", "push dx: value high word (bp+16)"),
    (0x2F9CD, "50", "push ax: value low word = selector (bp+14)"),
    (0x2F9CE, "31c0", "xor ax,ax"),
    (0x2F9D0, "50", "push ax: min count word (bp+12) = 0"),
    (0x2F9D1, "8d7ef6", "lea di,[bp-10]: destination offset"),
    (0x2F9D4, "16", "push ss: destination segment"),
    (0x2F9D5, "57", "push di"),
    (0x2F9D6, "b80100", "mov ax,1: width (bp+6)"),
    (0x2F9D9, "50", "push ax"),
    (0x2F9DA, "9a6613f80a", "call 0x0AF8:0x1366: formatter"),
    (0x2F9DF, "8dbef5fe", "lea di,[bp-267]: GEO piece destination"),
    (0x2F9E5, "bf9d10", "mov di,0x109d: GEO literal (CS-relative)"),
    (0x2F9E8, "0e", "push cs"),
    (0x2F9EA, "9a0b0bf80a", "call 0x0AF8:0x0B0B: copy GEO literal, dst left on stack"),
    (0x2F9EF, "8d7ef6", "lea di,[bp-10]: formatter output as source"),
    (0x2F9F4, "9a980bf80a", "call 0x0AF8:0x0B98: append formatter output to GEO piece"),
    (0x2F9F9, "8dbef0fe", "lea di,[bp-272]: suffix destination"),
    (0x2F9FF, "bfa110", "mov di,0x10a1: .dax literal (CS-relative)"),
    (0x2FA04, "9a0b0bf80a", "call 0x0AF8:0x0B0B: copy .dax literal, dst left on stack"),
    (0x2FA09, "8a4606", "mov al,[bp+6]: id word"),
    (0x2FA17, "9a16070208", "call 0x0802:0x0716: loader (START 0x876D, conditional)"),
]
FILL_GROUP_LITERAL_SITES = [
    (GEO_LITERAL_CS, b"\x03GEO", "GEO literal (CS:0x109D)"),
    (DAX_LITERAL_CS, b"\x04.dax", ".dax literal (CS:0x10A1)"),
]
LOADER_SITES = [
    (0x8774, "c47e14", "les di,[bp+20]: P20 (GEO piece)"),
    (0x8782, "9a250bf80a", "call 0x0AF8:0x0B25: copy P20, clamp 0x14"),
    (0x8787, "c47e10", "les di,[bp+16]: P16 (.dax piece)"),
    (0x8795, "9a250bf80a", "call 0x0AF8:0x0B25: copy P16, clamp 0x14"),
    (0x879A, "8dbec3fd", "lea di,[bp-573]: destination of the prefix copy"),
    (0x87A0, "bf7c54", "mov di,0x547c: prefix piece (DS)"),
    (0x87A3, "1e", "push ds"),
    (0x87A5, "9a0b0bf80a", "call 0x0AF8:0x0B0B: copy prefix piece"),
    (0x87AA, "8d7eeb", "lea di,[bp-21]: copy of P20"),
    (0x87AF, "9a980bf80a", "call 0x0AF8:0x0B98: append P20 copy to prefix copy"),
    (0x87CB, "0e", "push cs"),
    (0x87CC, "e855fe", "call near 0x8624: open routine"),
]
OPEN_SITES = [
    (0x8624, "5589e5", "push bp; mov bp,sp"),
    (0x862B, "c47e16", "les di,[bp+22]: P_a (prefix + GEO piece)"),
    (0x863E, "c47e12", "les di,[bp+18]: P_b (.dax piece)"),
    (0x8651, "8dbeabfe", "lea di,[bp-341]: composed name destination"),
    (0x865C, "9a0b0bf80a", "call 0x0AF8:0x0B0B: copy bp-42 (P_a copy)"),
    (0x8666, "9a980bf80a", "call 0x0AF8:0x0B98: append bp-83 (P_b copy)"),
    (0x866B, "8dbeabfc", "lea di,[bp-853]: row-text destination"),
    (0x8671, "a07653", "mov al,[0x5376]: selector"),
    (0x8676, "ba1e00", "mov dx,0x1e: row stride"),
    (0x867D, "81c71426", "add di,0x2614: row base"),
    (0x8683, "9a0b0bf80a", "call 0x0AF8:0x0B0B: copy the selected DS row"),
    (0x868E, "a07d54", "mov al,[0x547d]: prefix character"),
    (0x8692, "9a3b0cf80a", "call 0x0AF8:0x0C3B"),
    (0x8697, "9a980bf80a", "call 0x0AF8:0x0B98: row text (not the name)"),
    (0x86A1, "9a980bf80a", "call 0x0AF8:0x0B98: CS literal appended to row text"),
    (0x86A6, "a07c55", "mov al,[0x557c]: flag byte"),
    (0x86B0, "e801fc", "call near 0x82B4: path check"),
]
PATH_CHECK_SITES = [
    (0x82B4, "5589e583ec54", "push bp; mov bp,sp; sub sp,0x54"),
    (0x82BA, "c47e10", "les di,[bp+16]: composed name (bp-341 of the caller)"),
    (0x82CD, "c47e0c", "les di,[bp+12]: row text (bp-853 of the caller)"),
    (0x82E0, "8d7ed6", "lea di,[bp-42]: name copy"),
    (0x82E6, "e85900", "call near 0x8342: name probe"),
    (0x82F8, "b00e", "mov al,0x0e: prompt code"),
    (0x82FB, "8d7ead", "lea di,[bp-83]: row-text copy, prompt only"),
    (0x8301, "e8e6fe", "call near 0x81EA: prompt"),
]
NAME_PROBE_SITES = [
    (0x8342, "5589e5", "push bp; mov bp,sp"),
    (0x8349, "c47e06", "les di,[bp+6]: name argument"),
    (0x8367, "9ae213f80a", "call 0x0AF8:0x13E2: record writer"),
    (0x8372, "b88000", "mov ax,0x80: probe record size"),
    (0x8376, "9a1014f80a", "call 0x0AF8:0x1410: open wrapper (probe)"),
    (0x8381, "9a9114f80a", "call 0x0AF8:0x1491: close"),
]
WRAPPER_SITES = [
    (0xC086, "a02c44", "mov al,[0x442c]: access byte"),
    (0xC089, "b43d", "mov ah,0x3d: DOS open"),
    (0xC09B, "26817d02b0d7", "es cmp [di+2],0xd7b0: record state"),
    (0xC0BD, "26807d3000", "es cmp [di+48],0: path present"),
    (0xC0C5, "8d5530", "lea dx,[di+0x30]: path field"),
    (0xC0CC, "cd21", "int 21h"),
]

CLAIM_LABELS = (
    "bytes_established", "bytes_established_conditional", "model_from_decoded_bytes",
    "not_established",
)


class Refusal(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: Optional[int]) -> Optional[str]:
    return None if value is None else "0x%05X" % value


def check(check_id: str, what: str, expected, observed, label: str = "bytes_established") -> dict:
    return {"id": check_id, "what": what, "expected": expected, "observed": observed,
            "ok": expected == observed, "label": label}


def site_check(data: bytes, prefix: str, sites: list) -> list[dict]:
    rows = []
    for at, hexbytes, what in sites:
        want = bytes.fromhex(hexbytes)
        got = data[at:at + len(want)]
        rows.append(check("%s@%s" % (prefix, hx(at)), what, hexbytes, got.hex()))
    return rows


def span(data: bytes, start: int) -> tuple[int, int]:
    """Linear ret-to-ret span from a routine start, for the pinned routines (straight-line bodies)."""
    off = start
    for _ in range(4096):
        ins = decoder.decode(data, off)
        off = ins.end
        if ins.flow in ("ret", "retf"):
            return start, off
    raise Refusal("no return reached from %s" % hx(start))


def u32_table(data: bytes, file_off: int, count: int = 10) -> list[int]:
    return [int.from_bytes(data[file_off + 4 * i:file_off + 4 * i + 4], "little") for i in range(count)]


def avoid_witness(data: bytes, entry: int, at: int) -> Optional[list[dict]]:
    """Shortest decoded path from `entry` to a return that does not pass `at`, as its branch decisions.

    Returns None when no such path exists (the write is on every path) or when the walk is incomplete.
    Each jcc on the path is labelled taken or fall-through by the next instruction on the path.
    """
    from collections import deque
    w = decoder.walk(data, entry)
    if not w["complete"]:
        return None
    nodes = {row["at"]: decoder.decode(data, row["at"]) for row in w["listing"]}
    prev: dict[int, Optional[int]] = {entry: None}
    queue = deque([entry])
    while queue:
        a = queue.popleft()
        ins = nodes.get(a)
        if ins is None:
            continue
        if ins.flow in ("ret", "retf"):
            path = []
            cur: Optional[int] = a
            while cur is not None:
                path.append(cur)
                cur = prev[cur]
            path.reverse()
            decisions = []
            for i, p in enumerate(path):
                node = nodes[p]
                if node.flow not in ("jcc", "jmp", "ret", "retf"):
                    continue
                nxt = path[i + 1] if i + 1 < len(path) else None
                arm = None
                if node.flow == "jcc" and nxt is not None:
                    arm = "taken" if nxt == node.target else "fall-through"
                decisions.append({"at": hx(p), "text": node.text(), "flow": node.flow, "arm": arm})
            return decisions
        if ins.flow in ("seq", "call", "call_far", "indirect_call", "indirect_callf"):
            succ = [ins.end]
        elif ins.flow == "jcc":
            succ = [ins.end, ins.target]
        elif ins.flow == "jmp":
            succ = [ins.target]
        else:
            succ = []
        for s in succ:
            if s == at or s in prev:
                continue
            prev[s] = a
            queue.append(s)
    return None


def must_pass(data: bytes, entry: int, at: int) -> Optional[bool]:
    """True when every path from `entry` to a return passes `at`; False when one avoids it; None if undecided."""
    w = decoder.walk(data, entry)
    if not w["complete"]:
        return None
    nodes = {row["at"]: decoder.decode(data, row["at"]) for row in w["listing"]}
    if at not in nodes:
        return None
    stack = [entry]
    seen: set[int] = set()
    while stack:
        a = stack.pop()
        if a == at or a in seen:
            continue
        seen.add(a)
        ins = nodes.get(a)
        if ins is None:
            return None
        if ins.flow in ("ret", "retf"):
            return False
        if ins.flow in ("seq", "call", "call_far", "indirect_call", "indirect_callf"):
            stack.append(ins.end)
        elif ins.flow == "jcc":
            stack.append(ins.end)
            stack.append(ins.target)
        elif ins.flow == "jmp":
            stack.append(ins.target)
        else:
            return None
    return True


# ---------------------------------------------------------------- formatter and Pascal model
# Each function mirrors the decoded instructions; the byte checks above pin the bytes it reads.

def helper_text(value: int, table: list[int]) -> str:
    """Model of the near helper at file 0xBECA: signed 32-bit value to decimal text (with '-')."""
    v = value & MASK32
    out = ""
    if v & 0x80000000:                    # "or dx,dx; jge" : negative -> '-' and two's complement
        out = "-"
        v = (-v) & MASK32
    k = 9                                 # first table entry (10^9 .. 10^1) that v reaches; else 10^0
    for idx in range(9):
        if v >= table[idx]:
            k = idx
            break
    for idx in range(k, 10):              # digit loop: count successful subtractions
        d = 0
        while v >= table[idx]:
            v -= table[idx]
            d += 1
        out += chr(0x30 + d)
    return out


def format_field(value: int, bp12: int, bp6: int, table: list[int]) -> bytes:
    """Model of the formatter at 0x0AF8:0x1366: Pascal field, right-justified, width clipped to bp6."""
    text = helper_text(value, table)
    cx = len(text)                        # helper returns the character count in CX
    ax = min(bp12, bp6)                   # cmp ax,dx ; jle ; mov ax,dx
    cx = min(cx, bp6)                     # cmp cx,dx ; jle ; mov cx,dx
    ax = max(ax, cx)                      # cmp ax,cx ; jge ; mov ax,cx
    pad = ax - cx                         # sub ax,cx : spaces are stored BEFORE the digits
    return bytes([ax & 0xFF]) + (" " * pad).encode("ascii") + text[:cx].encode("ascii")


def p_copy(src: bytes) -> bytes:          # 0x0B0B: length byte and characters, no clamp
    return bytes(src[:1 + src[0]])


def p_copy_clamp(src: bytes, count: int) -> bytes:   # 0x0B25: min(length, CL)
    n = min(src[0], count & 0xFF)
    return bytes([n]) + src[1:1 + n]


def p_append(dst: bytes, src: bytes) -> bytes:       # 0x0B98: dst += src
    n = dst[0] + src[0]
    if n > 255:
        raise Refusal("Pascal append overflows the length byte (not modelled)")
    return bytes([n]) + dst[1:] + src[1:1 + src[0]]


def p_record(src: bytes) -> bytes:                   # 0x13E2: +0 0, +2 0xD7B0, +4.. 0, path +0x30 (<=79)
    n = min(src[0], 0x4F)
    rec = bytearray(0x30 + n + 1)
    rec[2:4] = (0xD7B0).to_bytes(2, "little")
    rec[0x30:0x30 + n] = src[1:1 + n]
    return bytes(rec)


def fill_name(selector: int, prefix: bytes, table: list[int]) -> dict:
    """The fill's composed path, under the decoded copy/append semantics. Every argument is a checked site."""
    value = selector & 0xFF               # DX:AX = 0:selector (zero-extended)
    piece = format_field(value, 0, 1, table)          # formatter output at SS:[bp-10]
    p20 = p_append(p_copy(b"\x03GEO"), piece)          # 0x0B0B(GEO) then 0x0B98(piece) -> SS:[bp-267]
    p16 = p_copy(b"\x04.dax")                          # 0x0B0B(.dax) -> SS:[bp-272]
    loc1 = p_copy_clamp(p20, 0x14)                     # loader 0x0B25 on P20
    loc2 = p_copy_clamp(p16, 0x14)                     # loader 0x0B25 on P16
    loc3 = p_append(p_copy(prefix), loc1)              # 0x0B0B(DS:0x547C) then 0x0B98(loc1)
    a = p_copy_clamp(loc3, 0x28)                       # open routine: bp-42 from P_a
    b = p_copy_clamp(loc2, 0x28)                       # open routine: bp-83 from P_b
    name = p_append(p_copy(a), b)                      # bp-341
    name40 = p_copy_clamp(name, 0x28)                  # 0x82B4: bp-42
    path = p_copy_clamp(name40, 0x28)                  # 0x8342: bp-42
    rec = p_record(path)                               # 0x13E2 into the record path field (+0x30)
    return {
        "selector": selector,
        "formatter_piece_hex": piece.hex(),
        "formatter_digit": chr(piece[1]) if len(piece) > 1 else "",
        "p20_geo_piece": p20[1:1 + p20[0]].decode("ascii", "replace"),
        "p16_suffix_piece": p16[1:1 + p16[0]].decode("ascii", "replace"),
        "composed_name_before_40_clamp": name[1:1 + name[0]].decode("ascii", "replace"),
        "composed_name": path[1:1 + path[0]].decode("ascii", "replace"),
        "record_path_at_0x30": rec[0x30:rec.index(0, 0x30)].decode("ascii", "replace"),
        "record_state_word": "0x%04X" % int.from_bytes(rec[2:4], "little"),
    }


# ---------------------------------------------------------------- structure checks

def structure_checks(ovr: bytes, exe: bytes, fill_group_base: Optional[int]) -> list[dict]:
    rows: list[dict] = []
    for name, (a, b, digest) in PINNED_SPANS.items():
        start, end = span(exe, a)
        rows.append(check("span:" + name, "decoded span %s..%s sha256" % (hx(a), hx(b)), digest,
                          sha(exe[start:end])))
        rows.append(check("span-end:" + name, "span end", hx(b), hx(end)))
    rows.append(check("table:powers-of-ten", "u32 table at file %s = 10^9..10^0" % hx(FORMAT_TABLE_FILE),
                      POWERS_OF_TEN, u32_table(exe, FORMAT_TABLE_FILE)))
    rel = decoder.decode(exe, 0xBFED)
    rows.append(check("call:formatter-helper", "rel16 call at file 0xBFED targets file 0xBECA", hx(HELPER_FILE),
                      hx(rel.target)))
    ret = decoder.decode(exe, 0xC024)
    rows.append(check("ret:formatter", "formatter returns retf 0x0C", "retf 0xc", ret.text()))
    rows.extend(site_check(ovr, "fill", FILL_SITES))
    rows.extend(site_check(exe, "loader", LOADER_SITES))
    rows.extend(site_check(exe, "open", OPEN_SITES))
    rows.extend(site_check(exe, "pathcheck", PATH_CHECK_SITES))
    rows.extend(site_check(exe, "nameprobe", NAME_PROBE_SITES))
    rows.extend(site_check(exe, "wrapper", WRAPPER_SITES))
    rows.append(check("fill:group-base", "fill group code base (overlay group map)", "present",
                      "present" if fill_group_base is not None else "absent"))
    if fill_group_base is not None:
        for lit_off, lit, what in FILL_GROUP_LITERAL_SITES:
            at = fill_group_base + lit_off
            rows.append(check("literal:" + what, "%s at file %s (group base + CS offset)" % (what, hx(at)),
                              lit.hex(), ovr[at:at + len(lit)].hex(), label="bytes_established_conditional"))
    # The path check passes the row text only to the prompt: the decoded lea [bp-83] sites are the copy
    # into the prompt and nothing else. (Count of decoded lea di,[bp-83] in the routine.)
    ph = decoder.walk(exe, PATH_CHECK)
    lea83 = [row["at"] for row in ph["listing"] if row["bytes"].startswith("8d7ead")]
    rows.append(check("pathcheck:row-only-prompt", "decoded lea di,[bp-83] sites in 0x82B4",
                      ["0x%05X" % 0x82D2, "0x%05X" % 0x82FB], [hx(x) for x in lea83]))
    return rows


# ---------------------------------------------------------------- writers, callers, address passes

def roots_for(ovr: bytes, exe: bytes) -> tuple[list[dict], list[int], list[int]]:
    groups.check_pin(OVR_NAME, ovr, groups.PINS)
    groups.check_pin(EXE_NAME, exe, groups.PINS)
    group_list = []
    for pos in range(0, len(exe) - groups.DESC_MIN + 1):
        if exe[pos:pos + 4] != groups.DESC_MAGIC:
            continue
        try:
            group_list.append(groups.parse_descriptor(exe, ovr, pos))
        except groups.Refusal:
            continue
    ovr_roots: list[int] = []
    for g in group_list:
        lo, hi = g["fileofs"], g["fileofs"] + g["codesz"]
        for entry in range(lo, hi - len(sel.PROLOGUE) + 1):
            if ovr[entry:entry + len(sel.PROLOGUE)] == sel.PROLOGUE:
                ovr_roots.append(entry)
    exe_roots = [i for i in range(len(exe) - len(sel.PROLOGUE) + 1)
                 if exe[i:i + len(sel.PROLOGUE)] == sel.PROLOGUE]
    return group_list, ovr_roots, exe_roots


def group_base_of(group_list: list[dict], at: int) -> Optional[int]:
    for g in group_list:
        if g["fileofs"] <= at < g["fileofs"] + g["codesz"]:
            return g["fileofs"]
    return None


def writer_rows(oi, ei, ovr: bytes, exe: bytes) -> list[dict]:
    data = {OVR_NAME: ovr, EXE_NAME: exe}
    rows = []
    for img, name in ((oi, OVR_NAME), (ei, EXE_NAME)):
        for off in (SELECTOR, SAVE):
            for w in sel.selector_writes(img, off):
                at = int(w["at"], 16)
                roots = [int(r, 16) for r in w["roots"]]
                per_root = {}
                witness = {}
                for r in roots:
                    per_root[hx(r)] = must_pass(data[name], r, at)
                    if per_root[hx(r)] is False:
                        witness[hx(r)] = avoid_witness(data[name], r, at)
                callers = {hx(r): sel.callers([oi, ei], r, name, data)["decoded_near_calls"] for r in roots}
                raw = {hx(r): len(sel.callers([oi, ei], r, name, data)["raw_near_e8"]) for r in roots}
                rows.append({
                    "image": name, "at": hx(at), "slot": hx(off), "bytes": w["bytes"], "text": w["text"],
                    "source_class": w["source_class"], "value": w.get("value"), "roots": [hx(r) for r in roots],
                    "must_pass_entry_per_root": per_root,
                    "avoid_path_decisions_per_root": witness,
                    "decoded_direct_callers_per_root": callers,
                    "raw_e8_matches_per_root": raw,
                })
    return rows


def pointer_pass_rows(oi, ei) -> list[dict]:
    rows = []
    for img in (oi, ei):
        for r in sel.pointer_passes(img, (SELECTOR, SAVE)):
            rows.append({"image": img.name, "at": r["at"], "address": r["address"],
                         "next_call_target": r["next_call_target"], "text": r["text"]})
    return rows


# ---------------------------------------------------------------- digit mapping

def digit_map(table: list[int], install_names: set[str]) -> dict:
    rows = {}
    counts: dict[str, int] = {}
    for v in range(256):
        d = helper_text(v, table)[0]
        counts[d] = counts.get(d, 0) + 1
        stem = "GEO%s.DAX" % d
        rows[str(v)] = {"digit": d, "file": stem, "present_in_install": stem in install_names}
    absent = sorted({rows[str(v)]["file"] for v in range(256) if not rows[str(v)]["present_in_install"]})
    return {"per_value": rows, "digit_counts": dict(sorted(counts.items())),
            "files_named_by_some_value_absent_from_install": absent}


# ---------------------------------------------------------------- analysis

def analyze(ovr: bytes, exe: bytes, install_names: set[str]) -> dict:
    group_list, ovr_roots, exe_roots = roots_for(ovr, exe)
    oi = sel.Image(OVR_NAME, ovr, ovr_roots)
    ei = sel.Image(EXE_NAME, exe, exe_roots)
    fill_base = group_base_of(group_list, FILL)
    table = u32_table(exe, FORMAT_TABLE_FILE)
    checks = structure_checks(ovr, exe, fill_base)

    fill_walk = oi.walks.get(FILL)
    data = {OVR_NAME: ovr, EXE_NAME: exe}
    fill_callers = sel.callers([oi, ei], FILL, OVR_NAME, data)
    writers = writer_rows(oi, ei, ovr, exe)
    chain_examples = {}
    # Prefix is the Pascal piece at DS:[0x547C]; its real value is not in the bytes. Two probe values only.
    for label, prefix in (("prefix_empty", b"\x00"), ("prefix_probe_3_chars", b"\x03ABC")):
        chain_examples[label] = {str(v): fill_name(v, prefix, table) for v in (0, 1, 3, 9, 10, 19, 20, 255)}
    fmt_examples = {}
    for v in (0, 1, 3, 9, 10, 19, 99, 100, 255):
        fmt_examples[str(v)] = {"helper_text": helper_text(v, table),
                                "field_W1": format_field(v, 0, 1, table).hex(),
                                "field_W3": format_field(v, 0, 3, table).hex()}
    neg = {"-2147483648": helper_text(-2147483648, table), "-1": helper_text(-1, table),
           "2147483647": helper_text(2147483647, table)}
    mapping = digit_map(table, install_names)
    failed = [c["id"] for c in checks if not c["ok"]]
    return {
        "schema": SCHEMA, "schema_version": VERSION, "tool": TOOL, "playable": False,
        "status": "bounded-static-format-trace",
        "pins": {OVR_NAME: {"size": len(ovr), "sha256": sha(ovr), "match": True},
                 EXE_NAME: {"size": len(exe), "sha256": sha(exe), "match": True}},
        "coverage": {"ovr_prologue_roots": len(ovr_roots),
                     "ovr_complete_walks": sum(bool(oi.walks[r]["complete"]) for r in ovr_roots),
                     "exe_prologue_roots": len(exe_roots),
                     "fill_walk_complete": bool(fill_walk and fill_walk["complete"]),
                     "fill_group_base": hx(fill_base)},
        "module_placement": {"segment": "0x0AF8", "base_file": hx(MODULE_BASE), "conditional": True,
                             "formatter_file": hx(FORMAT_ENTRY + MODULE_BASE)},
        "formatter": {"entry_module_offset": hx(FORMAT_ENTRY), "table_file": hx(FORMAT_TABLE_FILE),
                      "table_values": table, "helper_file": hx(HELPER_FILE),
                      "helper_module_offset": hx(HELPER_FILE - MODULE_BASE),
                      "examples": fmt_examples, "negative_examples": neg},
        "fill": {"root": hx(FILL), "decoded_direct_callers": fill_callers["decoded_near_calls"],
                 "raw_e8_matches": fill_callers["raw_near_e8"],
                 "argument_model": {"value_hi_word": 0, "value_lo_word": "DS:[0x5376] zero-extended",
                                    "min_count_bp12": 0, "max_width_bp6": 1,
                                    "destination": "SS:[bp-10]"}},
        "chain": chain_examples,
        "writers": writers,
        "address_passes": pointer_pass_rows(oi, ei),
        "digit_mapping": mapping,
        "checks": checks,
        "checks_failed": failed,
        "verdict": {
            "formatter": "decimal_signed32_right_justified_width_clipped" if not failed else "failed_byte_checks",
            "digit_in_composed_name": "static_dataflow_conditional_on_module_loader_and_wrapper_identity",
            "prefix_DS_547C": "not_established",
            "selector_literal_values": sorted({w["value"] for w in writers if w["value"] is not None}),
            "selector_values_at_runtime": "not_established",
            "selector_to_stem_digit": "formula_from_bytes_conditional",
            "selector_to_block_or_area": "not_established",
        },
    }


# ---------------------------------------------------------------- IO and report

def find_install(install: Optional[Path]) -> Path:
    return groups.find_install(install)


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def validate_output(out: Path, install_dir: Path) -> Path:
    out = out.resolve()
    if not _inside(out, DATA_WORK.resolve()):
        raise Refusal("output must be under %s" % DATA_WORK)
    if _inside(out, install_dir):
        raise Refusal("output must not be inside the install")
    return out


def probe(install: Path, out: Path = DEFAULT_OUT) -> tuple[dict, int]:
    install_dir = find_install(install)
    out = validate_output(out, install_dir)
    paths = {name: install_dir / name for name in (OVR_NAME, EXE_NAME)}
    before = {n: p.read_bytes() for n, p in paths.items()}
    names = {p.name.upper() for p in install_dir.iterdir() if p.is_file()}
    doc = analyze(before[OVR_NAME], before[EXE_NAME], names)
    after = {n: p.read_bytes() for n, p in paths.items()}
    if any(sha(after[n]) != sha(before[n]) for n in before):
        raise Refusal("pinned inputs changed during the probe")
    doc["input_unchanged"] = True
    write_outputs(doc, out)
    return doc, (0 if not doc["checks_failed"] else 1)


def render_report(doc: dict) -> str:
    L = ["# PoR GEO selector to filename: format and dataflow (static)", "",
         "**Status: `playable: false`. Static, observe-only. Byte checks: %s.**" %
         ("all passed" if not doc["checks_failed"] else "FAILED: " + ", ".join(doc["checks_failed"])), "",
         "## Formatter (module 0x0AF8:0x1366, base 0xAC76 conditional)", "",
         "| Argument | Value at the fill | Source |", "|---|---|---|",
         "| value (bp+14/bp+16) | `0:selector`, selector = DS:[0x5376] zero-extended | fill `0x2F9C5`-`0x2F9CD` |",
         "| min count (bp+12) | 0 | fill `0x2F9D0` |",
         "| max width (bp+6) | 1 | fill `0x2F9D6` |",
         "| destination (bp+8/bp+10) | SS:[bp-10] | fill `0x2F9D1`-`0x2F9D4` |", "",
         "Helper output: decimal text, `-` first for negatives, digits from 10^9 down; the formatter writes a",
         "Pascal length byte, then (width - copied) spaces, then the first `min(len, width)` digits. With width 1 the",
         "output is one byte: the leading character of the decimal text.", "",
         "| Selector | Decimal text | Field W=1 (hex) | Field W=3 (hex) |", "|---:|---|---|---|"]
    for v, row in doc["formatter"]["examples"].items():
        L.append("| %s | `%s` | `%s` | `%s` |" % (v, row["helper_text"], row["field_W1"], row["field_W3"]))
    L += ["", "## Composed name (conditional chain; prefix DS:[0x547C] not established)", ""]
    for label in ("prefix_empty", "prefix_probe_3_chars"):
        L.append("### %s" % label)
        L += ["", "| Selector | Digit | Composed name (record path) | Record state |", "|---:|---|---|---|"]
        for v, row in doc["chain"][label].items():
            L.append("| %s | `%s` | `%s` | %s |" % (v, row["formatter_digit"], row["record_path_at_0x30"],
                                                  row["record_state_word"]))
        L.append("")
    L += ["## Writers of DS:[0x5376] / DS:[0x5377]", "",
          "| Image | Site | Slot | Source | Value | Root(s) | Must pass entry | Decoded direct callers |",
          "|---|---|---|---|---:|---|---|---|"]
    for w in doc["writers"]:
        callers = [c["site"] for lst in w["decoded_direct_callers_per_root"].values() for c in lst]
        L.append("| %s | `%s` | %s | %s | %s | %s | %s | %s |" % (
            w["image"], w["at"], w["slot"], w["source_class"], w["value"] if w["value"] is not None else "-",
            ", ".join(w["roots"]), ", ".join("%s=%s" % (k, v) for k, v in w["must_pass_entry_per_root"].items()),
            ", ".join(callers) if callers else "none decoded"))
    L += ["", "## Digit mapping (GEO stem from the leading decimal digit)", "",
          "Digit counts over 0..255: %s." % ", ".join("%s:%d" % kv for kv in doc["digit_mapping"]["digit_counts"].items()),
          "Files named by some value that are absent from the pinned install: %s." %
          (", ".join(doc["digit_mapping"]["files_named_by_some_value_absent_from_install"]) or "none"), "",
          "## Byte checks", "", "| Check | Result |", "|---|---|"]
    for c in doc["checks"]:
        L.append("| %s | %s |" % (c["what"], "ok" if c["ok"] else "FAILED"))
    L += ["", "## Verdict", "", "```json", json.dumps(doc["verdict"], indent=2, sort_keys=True), "```", ""]
    return "\n".join(L)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / OUT_JSON).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / OUT_MD).write_text(render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--install", type=Path, default=None,
                    help="install folder holding GAME.OVR and START.EXE (or set %s)" % INSTALL_ENV)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output folder under data/work")
    args = ap.parse_args(argv)
    if args.install is None and os.environ.get(INSTALL_ENV):
        args.install = Path(os.environ[INSTALL_ENV])
    try:
        doc, code = probe(args.install, args.out)
    except (Refusal, groups.Refusal) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s (checks=%d failed=%d)" % (args.out, len(doc["checks"]), len(doc["checks_failed"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
