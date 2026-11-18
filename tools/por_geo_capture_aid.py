#!/usr/bin/env python3
"""Pool of Radiance GEO-load capture aid: checklist, DOSBox-X command template, and
observation checker for binding a GEO load to a DAX TOC block.

Status: CAPTURE-AID-ONLY. playable: false. Read-only over the install, stdlib-only plus the
existing por_* helpers. This tool never launches DOSBox-X, never injects input, never
writes to the install, and never creates an area mapping. Nothing it prints is a runtime
observation; the only runtime evidence is the observation JSON a person records.

The question it serves: which GEO<n>.DAX TOC block a GEO load reads. CORRECTION (2026-11-18):
the routine at GAME.OVR:0x2F6FF is the WALLDEF wrapper (START stub 6 at 0x3E0C enters it and
builds WALLDEF<d>.dax). It is NOT the GEO loader, and this tool no longer targets it. The owner
targets are the GEO fill at GAME.OVR:0x2F9BE (group-relative 0x10C7; the GEO literal at 0x2F994 is
read there). Its entry is reached by START stub 7 (0x3E11, proc 0x10C7), whose fifth byte is 0x27
where its seven siblings hold 0x00. That tail is undecided, and the RAM dump disagrees on it, so the
fill's ENTRY is UNESTABLISHED. It is established only by an observed stop at the fill in a run. The
fill takes one byte argument, read as [bp+6] (mov al,[bp+6] at 0x2FA09), and exits with retf 2. The
argument is recorded as a byte; its meaning is unresolved. A TOC block is bound (toc_block_bound)
only when a stop at the GEO fill and an INT 21 open/seek of GEO<n>.DAX to a TOC block start agree
in the same run. The seek alone is reported as toc_seek_is_block_start.

Subcommands

  plan   Writes a checklist (Markdown), a DOSBox-X debugger command sequence (text), and
         an observation template (JSON). Concrete CS:IP breakpoint lines are emitted ONLY
         when the observed load segment is supplied with --load-seg. Without it the
         breakpoint lines are blocked comments. Every breakpoint is labelled UNVERIFIED.
         With --install it also checks the retail pins and static bytes and lists the
         expected absolute seek offset of every TOC block of GEO1..8.DAX.

  check  Reads an observation JSON (schema openua.por-geo-capture-observation), translates
         file offsets to CS:IP from the observed load segment, checks the observed stop
         bytes and dump, and binds the observed GEO seek to a TOC block (needs --install).

Exit codes
  0  observation complete and consistent (no blockers); or plan written
  1  observation consistent so far, but evidence is still missing (blockers listed)
  2  named refusal: bad input, a refused translation, a contradiction, pin mismatch,
     or an unsafe output location

Usage
  python3 tools/por_geo_capture_aid.py plan --install "PATH/TO/POOLRAD" \
      [--load-seg 23A5 --buffer-off 0000] [--dosbox PATH/TO/dosbox-x.exe] \
      -o data/work/por-geo-capture-aid
  python3 tools/por_geo_capture_aid.py check --observation OBS.json \
      --install "PATH/TO/POOLRAD" -o data/work/por-geo-capture-aid/check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path
from typing import Callable, Optional

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
from por_convert import DATA_DIR, PorSourceError, REPO_ROOT, validate_output_dir  # noqa: E402
import por_farcall_resolve as fc  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_map  # noqa: E402
import por_runtime_capture_plan as rcp  # noqa: E402

SCHEMA = "openua.por-geo-capture-aid"
OBS_SCHEMA = "openua.por-geo-capture-observation"
SCHEMA_VERSION = 2   # v2: owner targets moved from the WALLDEF wrapper (0x2F6FF) to the GEO fill
STATUS = "capture-aid-only"
TOOL = "tools/por_geo_capture_aid.py"
OVR = "GAME.OVR"
EXE = "START.EXE"
EMULATOR_ENV = rcp.EMULATOR_ENV
DEBUGGER_STRINGS = (b"BPINT", b"BPLIST", b"BPDEL", b"Breakpoint")

# --- GEO fill (GAME.OVR), the owner of the GEO literal (static; docs/por-geo-buffer-fill-probe.md)
# The GEO fill is the reader of the literal at 0x2F994. It is NOT the WALLDEF wrapper at 0x2F6FF.
OWNER_OFF = 0x2F9BE          # 55 89 E5: push bp; mov bp,sp  (GEO fill entry; group-relative 0x10C7)
POST_FRAME_OFF = 0x2F9C1     # after mov bp,sp; 81 EC 10 01 = sub sp,0x110 (272-byte frame)
ARG_BP6_READ_OFF = 0x2FA09   # 8A 46 06 = mov al,[bp+6]: the one byte argument (also read at 0x2FAE9)
RETF_OFF = 0x2FAFA           # CA 02 00 = retf 2: the only exit; pops the one word argument
LITERAL_OFF = 0x2F994        # 03 'GEO' 04 '.dax' (Pascal strings); read by the GEO fill at 0x2F9BE
WALLDEF_OFF = 0x2F6FF        # 55 89 E5: the WALLDEF wrapper. NOT a GEO target; refused, never bound.

# START.EXE: the owner's overlay header and the stub slot whose proc word names the GEO fill.
# Header at 0x3DD7 (fileofs 0x2E8F7, codesz 0x120B, fixupsz 0x50, nstubs 8); the stub run starts at
# header + 0x17 (0x3DEE) and has 5-byte slots. Slot 7 is 0x3E11: CD 3F C7 10 27.
START_HDR_OFF = 0x3DD7
START_STUB_RUN_OFF = 0x3DEE
START_STUB_SLOT_LEN = 5

# Overlay group that GoldBox's runtime overlay map places over the owner. It is a
# candidate: its destination segment is route-specific (one snapshot).
GROUP = {
    "descriptor": 29,
    "seek": 0x2E8F7,
    "code_size": 0x120B,
    "dest_candidate": 0x23A5,
    "source": ("GoldBox docs/engine/research/pool-runtime-overlay-map.md, descriptor 29, "
               "snapshot 7 (2026-07-15, DOSBox-X 2026.07.02); destination is route-specific"),
}

# The three breakpoint targets, in file order. ``at`` is the observation key for a stop.
TARGETS = [
    {"id": "owner_entry", "at": "owner_entry", "file_off": OWNER_OFF, "expect_hex": "55 89 E5",
     "role": "GEO fill entry (push bp). Entry is UNESTABLISHED until a stop here is observed; "
             "[bp+4] is not yet a frame, so the return address is at [sp+2]"},
    {"id": "owner_post_frame", "at": "post_frame", "file_off": POST_FRAME_OFF,
     "expect_hex": "81 EC 10 01",
     "role": "after mov bp,sp: [bp+2] return IP, [bp+4] return CS, [bp+6] one byte argument "
             "(read as a byte, meaning unresolved)"},
    {"id": "owner_retf", "at": "retf", "file_off": RETF_OFF, "expect_hex": "CA 02 00",
     "role": "retf 2 exit: pops the one word argument"},
]
TARGET_BY_AT = {t["at"]: t for t in TARGETS}

GEO_NAME_RE = re.compile(r"^GEO([0-9]{1,2})\.DAX$", re.IGNORECASE)
_HEX_RE = re.compile(r"^(?:0x)?([0-9A-Fa-f]{1,8})$")
_SEG_OFF_RE = re.compile(r"^([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4})$")


class AidRefusal(Exception):
    """A named refusal. The message says what was refused and why."""


# --------------------------------------------------------------------------
# Parsing (strict: refuse rather than guess)
# --------------------------------------------------------------------------

def parse_hex(value, what: str, max_value: int) -> int:
    """Parse an unsigned hex value such as ``"0x2E8F7"`` or ``"2E8F7"``. Ints are accepted
    when in range. Booleans, empty strings and decimal-looking text are refused."""
    if isinstance(value, bool):
        raise AidRefusal("%s: a boolean is not an address" % what)
    if isinstance(value, int):
        if not 0 <= value <= max_value:
            raise AidRefusal("%s: %d is outside 0..0x%X" % (what, value, max_value))
        return value
    if not isinstance(value, str):
        raise AidRefusal("%s: expected a hex string, got %s" % (what, type(value).__name__))
    m = _HEX_RE.match(value.strip())
    if not m:
        raise AidRefusal("%s: %r is not a hex value" % (what, value))
    n = int(m.group(1), 16)
    if n > max_value:
        raise AidRefusal("%s: %s is outside 0..0x%X" % (what, value, max_value))
    return n


def parse_seg_off(value, what: str) -> tuple[int, int]:
    """Parse ``"SEG:OFF"`` with 16-bit hex halves. ``"23A5"`` alone is refused."""
    if not isinstance(value, str):
        raise AidRefusal("%s: expected SEG:OFF text" % what)
    m = _SEG_OFF_RE.match(value.strip())
    if not m:
        raise AidRefusal("%s: %r is not SEG:OFF (two 16-bit hex halves)" % (what, value))
    return int(m.group(1), 16), int(m.group(2), 16)


def parse_bytes_hex(value, what: str, min_len: int = 1) -> bytes:
    """Parse hex bytes, spaces allowed, even digit count only."""
    if not isinstance(value, str):
        raise AidRefusal("%s: expected hex byte text" % what)
    compact = value.replace(" ", "").strip()
    if len(compact) == 0 or len(compact) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        raise AidRefusal("%s: %r is not hex bytes" % (what, value))
    raw = bytes.fromhex(compact)
    if len(raw) < min_len:
        raise AidRefusal("%s: %d bytes given, at least %d needed" % (what, len(raw), min_len))
    return raw


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fmt_seg_off(seg: int, off: int) -> str:
    return "%04X:%04X" % (seg, off)


# --------------------------------------------------------------------------
# Address translation (the core of the aid; pure functions, tested directly)
# --------------------------------------------------------------------------

def file_to_cs_ip(file_off: int, group: dict, load_seg: int, buffer_off: int) -> tuple[int, int]:
    """Translate a GAME.OVR file offset to CS:IP for a group loaded at ``load_seg:buffer_off``.

    The byte at file offset ``group.seek`` is at ``buffer_off`` in the load segment, so
    the translation is ``seg : buffer_off + (file_off - seek)``. Refused when the offset is
    outside the group, when a segment word is out of range, or when the result would
    cross the 64 KiB segment (it would wrap, not translate)."""
    seek, size = group["seek"], group["code_size"]
    if not (seek <= file_off < seek + size):
        raise AidRefusal("file offset 0x%X is outside group %d [0x%X, 0x%X)"
                         % (file_off, group["descriptor"], seek, seek + size))
    if not 0 <= load_seg <= 0xFFFF:
        raise AidRefusal("load segment %r is not a 16-bit value" % (load_seg,))
    if not 0 <= buffer_off <= 0xFFFF:
        raise AidRefusal("buffer offset %r is not a 16-bit value" % (buffer_off,))
    off = buffer_off + (file_off - seek)
    if off > 0xFFFF:
        raise AidRefusal("file offset 0x%X maps to linear offset 0x%X in segment %04X, "
                         "past the 64 KiB segment; the load does not hold it"
                         % (file_off, off, load_seg))
    return load_seg, off


def cs_ip_to_file(seg: int, off: int, group: dict, load_seg: int, buffer_off: int) -> int:
    """Inverse of :func:`file_to_cs_ip` for an observed CS:IP. Refused when the segment is
    not the observed load segment (the code is not in this group, as far as is known),
    when the offset is below the buffer start, or when it is past the group."""
    if seg != load_seg:
        raise AidRefusal("CS %04X is not the observed load segment %04X of group %d"
                         % (seg, load_seg, group["descriptor"]))
    if off < buffer_off:
        raise AidRefusal("IP %04X is below the buffer start %04X" % (off, buffer_off))
    file_off = group["seek"] + (off - buffer_off)
    if file_off >= group["seek"] + group["code_size"]:
        raise AidRefusal("IP %04X is past group %d (file 0x%X)" % (off, group["descriptor"], file_off))
    return file_off


def build_targets(load_seg: Optional[int], buffer_off: int = 0) -> list[dict]:
    """The three breakpoint targets. ``cs_ip`` is None unless the load segment is observed."""
    out = []
    for t in TARGETS:
        rel = t["file_off"] - GROUP["seek"]
        rec = {
            "id": t["id"],
            "at": t["at"],
            "file_off": "0x%X" % t["file_off"],
            "group_rel_off": "0x%X" % rel,
            "expect_hex": t["expect_hex"],
            "role": t["role"],
            "status": "UNVERIFIED candidate",
        }
        if load_seg is None:
            rec["cs_ip"] = None
            rec["blocked"] = "no observed load segment; no CS:IP is emitted"
        else:
            seg, off = file_to_cs_ip(t["file_off"], GROUP, load_seg, buffer_off)
            rec["cs_ip"] = _fmt_seg_off(seg, off)
        out.append(rec)
    return out


# --------------------------------------------------------------------------
# Retail checks (bytes in, result out; no I/O here so tests can use synthetic bytes)
# --------------------------------------------------------------------------

def static_checks(ovr: bytes) -> list[dict]:
    """Static byte and decode checks on GAME.OVR. Each entry has ok, expected and observed."""
    checks = []

    def add(cid: str, off: int, expect: bytes) -> None:
        got = ovr[off:off + len(expect)]
        checks.append({"id": cid, "file_off": "0x%X" % off, "expected": expect.hex().upper(),
                       "observed": got.hex().upper(), "ok": got == expect})

    add("owner_prologue", OWNER_OFF, bytes.fromhex("5589E5"))
    add("owner_post_frame_sub_sp", POST_FRAME_OFF, bytes.fromhex("81EC1001"))
    add("arg_bp6_read", ARG_BP6_READ_OFF, bytes.fromhex("8A4606"))
    add("retf_2", RETF_OFF, bytes.fromhex("CA0200"))
    add("geo_pascal_literal", LITERAL_OFF, b"\x03GEO\x04.dax")

    # Decode checks: the owner's first two instructions must end exactly at the post-frame
    # stop, and the exit must decode as a far return.
    try:
        insns, err = lh.linear(ovr, OWNER_OFF, 2, stop_on_ret=False)
        raws = [i.raw.hex().upper() for i in insns]
        boundary_ok = (err is None and raws == ["55", "89E5"]
                       and insns[-1].end == POST_FRAME_OFF)
        observed = raws
    except (lh.DecodeError, IndexError) as exc:
        boundary_ok, observed = False, str(exc)
    checks.append({"id": "post_frame_is_insn_boundary", "file_off": "0x%X" % POST_FRAME_OFF,
                   "expected": "['55', '89E5'] ending at 0x%X" % POST_FRAME_OFF,
                   "observed": str(observed), "ok": boundary_ok})
    try:
        flow = lh.decode(ovr, RETF_OFF).flow
    except (lh.DecodeError, IndexError) as exc:
        flow = str(exc)
    checks.append({"id": "retf_decodes_as_retf", "file_off": "0x%X" % RETF_OFF,
                   "expected": "retf", "observed": flow, "ok": flow == "retf"})

    # Single exit: a linear walk from the entry must reach RETF_OFF as its ONLY return.
    try:
        walk, werr = lh.linear(ovr, OWNER_OFF, 400, stop_on_ret=True)
        rets = [i.off for i in walk if i.flow in ("ret", "retf")]
        exit_ok = (werr is None and rets == [RETF_OFF])
        exit_obs = ["0x%X" % r for r in rets] if werr is None else str(werr)
    except (lh.DecodeError, IndexError) as exc:
        exit_ok, exit_obs = False, str(exc)
    checks.append({"id": "fill_exit_is_single", "file_off": "0x%X" % OWNER_OFF,
                   "expected": "one return, at 0x%X" % RETF_OFF, "observed": str(exit_obs),
                   "ok": exit_ok})
    return checks


def geo_entry_candidate(start: bytes) -> dict:
    """Static byte evidence for an ENTRY to the GEO fill in START.EXE: the owner header and the
    stub slots whose proc word lands on OWNER_OFF (fileofs + proc). It names a candidate only.
    The fifth byte (tail) of a slot is undecided (docs/por-stub-tail-byte.md), so a nonzero tail
    is recorded and not used to accept or reject the slot. The binding stays UNESTABLISHED until a
    stop at the fill is observed in a run. Reads bytes only; no emulator."""
    if len(start) < START_HDR_OFF + 14:
        raise AidRefusal("START.EXE is too short to hold the owner header at 0x%X" % START_HDR_OFF)
    if start[START_HDR_OFF:START_HDR_OFF + 2] != b"\xCD\x3F":
        raise AidRefusal("no INT 3F at the owner header 0x%X" % START_HDR_OFF)
    fileofs, codesz, fixupsz, nstubs = struct.unpack_from("<IHHH", start, START_HDR_OFF + 4)
    header = {"file_off": "0x%X" % START_HDR_OFF, "fileofs": "0x%X" % fileofs,
              "codesz": "0x%X" % codesz, "fixupsz": "0x%X" % fixupsz, "nstubs": nstubs,
              "is_group_29": fileofs == GROUP["seek"] and codesz == GROUP["code_size"]}
    slots = []
    for i in range(nstubs):
        off = START_STUB_RUN_OFF + START_STUB_SLOT_LEN * i
        if off + START_STUB_SLOT_LEN > len(start):
            break
        raw = start[off:off + START_STUB_SLOT_LEN]
        if raw[:2] != b"\xCD\x3F":
            continue
        proc = struct.unpack_from("<H", raw, 2)[0]
        if fileofs + proc != OWNER_OFF:
            continue
        slots.append({"index": i, "file_off": "START:0x%X" % off, "bytes": raw.hex(" ").upper(),
                      "proc": "0x%04X" % proc, "target": "GAME.OVR:0x%X" % (fileofs + proc),
                      "tail": "0x%02X" % raw[4], "tail_is_zero": raw[4] == 0})
    if not header["is_group_29"]:
        status = "not-group-29"
    elif not slots:
        status = "absent"
    elif len(slots) == 1:
        status = "candidate"
    else:
        status = "ambiguous"
    return {"header": header, "slots": slots, "status": status,
            "binding": "unestablished",
            "tail_meaning": "undecided (docs/por-stub-tail-byte.md); not used",
            "note": ("the RAM dumps record tail 00 at this slot (docs/por-ecl-21-stub7-dump-probe.md); "
                     "not reconciled here")}


def load_check(load: dict, ovr: Optional[bytes]) -> dict:
    """Validate the observed overlay read. Returns the translated load and the dump check."""
    if not isinstance(load, dict):
        raise AidRefusal("load: expected an object")
    if load.get("file") != OVR:
        raise AidRefusal("load.file must be %r" % OVR)
    seek = parse_hex(load.get("seek_abs"), "load.seek_abs", 0xFFFFFFFF)
    count = parse_hex(load.get("read_count"), "load.read_count", 0xFFFFFFFF)
    dest_seg, dest_off = parse_seg_off(load.get("dest"), "load.dest")
    if seek != GROUP["seek"]:
        raise AidRefusal("observed overlay read starts at 0x%X; the group %d candidate starts "
                         "at 0x%X. This aid knows no other group, so the owner is not bound "
                         "on this route" % (seek, GROUP["descriptor"], GROUP["seek"]))
    if count < GROUP["code_size"]:
        raise AidRefusal("observed read of 0x%X bytes does not cover group %d (code size 0x%X)"
                         % (count, GROUP["descriptor"], GROUP["code_size"]))
    owner_seg, owner_off = file_to_cs_ip(OWNER_OFF, GROUP, dest_seg, dest_off)
    result = {
        "file": OVR,
        "seek_abs": "0x%X" % seek,
        "read_count": "0x%X" % count,
        "dest": _fmt_seg_off(dest_seg, dest_off),
        "owner_cs_ip": _fmt_seg_off(owner_seg, owner_off),
        "dump": {"status": "not-dumped"},
    }
    dump_hex = load.get("dest_dump_hex")
    if dump_hex in (None, ""):
        return result
    dump = parse_bytes_hex(dump_hex, "load.dest_dump_hex", min_len=4)
    if dest_off + len(dump) > 0x10000:
        raise AidRefusal("load.dest_dump_hex runs past the end of segment %04X" % dest_seg)
    if ovr is None:
        result["dump"] = {"status": "not-compared", "bytes": len(dump),
                          "reason": "no install bytes to compare against"}
        return result
    want = ovr[seek:seek + len(dump)]
    if want != dump:
        raise AidRefusal("dumped bytes at %s do not match GAME.OVR[0x%X:+%d]: the load segment "
                         "is not %04X or the read is not this group"
                         % (result["dest"], seek, len(dump), dest_seg))
    result["dump"] = {"status": "matched", "bytes": len(dump)}
    return result


def owner_stop_check(stop: dict, group_load: dict, dest_seg: int, dest_off: int,
                     ovr: Optional[bytes]) -> dict:
    """Validate one observed owner stop against its translated CS:IP and the expected bytes."""
    if not isinstance(stop, dict):
        raise AidRefusal("owner_stop: expected an object")
    at = stop.get("at")
    if at not in TARGET_BY_AT:
        raise AidRefusal("owner_stop.at must be one of %s, got %r"
                         % (sorted(TARGET_BY_AT), at))
    tgt = TARGET_BY_AT[at]
    seg, off = file_to_cs_ip(tgt["file_off"], GROUP, dest_seg, dest_off)
    cs = parse_hex(stop.get("cs"), "owner_stop.cs", 0xFFFF)
    ip = parse_hex(stop.get("ip"), "owner_stop.ip", 0xFFFF)
    if (cs, ip) != (seg, off):
        raise AidRefusal("owner stop %04X:%04X is not the translated %s (%s) for load %s"
                         % (cs, ip, at, _fmt_seg_off(seg, off), group_load["dest"]))
    code = parse_bytes_hex(stop.get("code_hex"), "owner_stop.code_hex", min_len=len(
        bytes.fromhex(tgt["expect_hex"].replace(" ", ""))))
    expect = bytes.fromhex(tgt["expect_hex"].replace(" ", ""))
    if code[:len(expect)] != expect:
        raise AidRefusal("owner stop at %s shows bytes %s, expected %s: wrong code at this CS:IP"
                         % (at, code[:len(expect)].hex(" ").upper(), tgt["expect_hex"]))
    if ovr is not None and ovr[tgt["file_off"]:tgt["file_off"] + len(expect)] != expect:
        raise AidRefusal("install bytes at 0x%X disagree with the expected constant"
                         % tgt["file_off"])
    out = {"at": at, "cs_ip": _fmt_seg_off(seg, off), "code_hex": code.hex(" ").upper(),
           "bytes_ok": True, "file_off": "0x%X" % tgt["file_off"], "frame": None}
    if at != "post_frame":
        return out
    for key in ("bp", "return_cs", "return_ip", "arg_bp6_word"):
        if key not in stop:
            raise AidRefusal("owner_stop.%s is required at post_frame" % key)
    bp = parse_hex(stop["bp"], "owner_stop.bp", 0xFFFF)
    ret_cs = parse_hex(stop["return_cs"], "owner_stop.return_cs", 0xFFFF)
    ret_ip = parse_hex(stop["return_ip"], "owner_stop.return_ip", 0xFFFF)
    arg6 = parse_hex(stop["arg_bp6_word"], "owner_stop.arg_bp6_word", 0xFFFF)
    try:
        caller_off = cs_ip_to_file(ret_cs, ret_ip, GROUP, dest_seg, dest_off)
        caller = {"in_group": True, "file_off": "0x%X" % caller_off,
                  "reason": "return CS equals the observed load segment"}
    except AidRefusal as exc:
        caller = {"in_group": False, "reason": str(exc)}
    out["frame"] = {
        "bp": "%04X" % bp,
        "saved_bp_ret_ip": "%04X:%04X" % (ret_cs, ret_ip),
        "caller": caller,
        # The fill reads ONE byte argument ([bp+6], mov al,[bp+6]); only its low byte is read.
        "arg_bp6": {"word": "%04X" % arg6, "low_byte": "%02X" % (arg6 & 0xFF)},
        "args_semantics": "unresolved",
    }
    return out


def bind_toc(geo_name: str, dax: bytes, seek_abs: int, read_count: Optional[int]) -> dict:
    """Bind an absolute seek offset in GEO<n>.DAX to a TOC block. The DAX absolute offset of
    block i is ``base + data_offset`` with ``base = 2 + toc_bytes``. Refused unless the seek
    is the exact start of a TOC block."""
    m = GEO_NAME_RE.match(geo_name)
    if not m:
        raise AidRefusal("open name %r is not GEO<n>.DAX" % geo_name)
    try:
        entries, base = por_map.parse_dax(dax)
    except por_map.PorMapError as exc:
        raise AidRefusal("%s is not a valid DAX container: %s" % (geo_name, exc))
    hits = [e for e in entries if base + e.data_offset == seek_abs]
    if not hits:
        raise AidRefusal("seek 0x%X is not the start of any TOC block of %s (base 0x%X, "
                         "%d blocks)" % (seek_abs, geo_name.upper(), base, len(entries)))
    e = hits[0]
    return {
        "geo": "GEO%d.DAX" % int(m.group(1)),
        "toc_index": e.index,
        "block_id": e.block_id,
        "abs_offset": "0x%X" % seek_abs,
        "comp_size": e.comp_size,
        "raw_size": e.raw_size,
        "read_count": None if read_count is None else "0x%X" % read_count,
        "read_matches_comp_size": None if read_count is None else read_count == e.comp_size,
        "mapping": None,
    }


def toc_table(dax_by_n: dict[int, bytes]) -> list[dict]:
    """Expected absolute seek offsets for every TOC block, for the checklist."""
    rows = []
    for n in sorted(dax_by_n):
        entries, base = por_map.parse_dax(dax_by_n[n])
        for e in entries:
            rows.append({"geo": "GEO%d.DAX" % n, "toc_index": e.index, "block_id": e.block_id,
                         "abs_offset": "0x%X" % (base + e.data_offset),
                         "comp_size": e.comp_size, "raw_size": e.raw_size})
    return rows


# --------------------------------------------------------------------------
# Observation check (bytes in; the CLI layer does the install I/O)
# --------------------------------------------------------------------------

def check_observation(obs: dict, ovr: Optional[bytes],
                      geo_bytes: Optional[Callable[[int], Optional[bytes]]],
                      start: Optional[bytes] = None) -> dict:
    """Check a parsed observation. ``ovr`` is GAME.OVR bytes or None (not compared).
    ``geo_bytes(n)`` returns GEO<n>.DAX bytes or None. ``start`` is START.EXE bytes or None (the
    static entry candidate is then not checked). Raises AidRefusal on contradiction."""
    if not isinstance(obs, dict):
        raise AidRefusal("observation must be a JSON object")
    if obs.get("schema") != OBS_SCHEMA:
        raise AidRefusal("schema must be %r" % OBS_SCHEMA)
    if obs.get("schema_version") == 1:
        raise AidRefusal("schema_version 1 targeted the WALLDEF wrapper (GAME.OVR:0x%X); re-record "
                         "at version %d against the GEO fill (GAME.OVR:0x%X)"
                         % (WALLDEF_OFF, SCHEMA_VERSION, OWNER_OFF))
    if obs.get("schema_version") != SCHEMA_VERSION:
        raise AidRefusal("schema_version must be %d" % SCHEMA_VERSION)
    route = obs.get("route")
    if not isinstance(route, str) or not route.strip():
        raise AidRefusal("route: a non-empty description of the save and key path is required")
    if "load" not in obs:
        raise AidRefusal("load is required (the observed GAME.OVR overlay read)")

    load = load_check(obs["load"], ovr)
    dest_seg, dest_off = parse_seg_off(obs["load"]["dest"], "load.dest")

    blockers: list[str] = []
    result = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": "observation-checked",
        "playable": False,
        "performed": False,
        "runtime_evidence_source": "user-supplied observation; this tool did not run DOSBox-X",
        "route": route.strip(),
        "emulator_sha256": obs.get("emulator_sha256") or None,
        "group": {"descriptor": GROUP["descriptor"], "seek": "0x%X" % GROUP["seek"],
                  "code_size": "0x%X" % GROUP["code_size"], "source": GROUP["source"]},
        "load": load,
        "owner_stop": None,
        "dax": None,
        "geo_entry": {"static": geo_entry_candidate(start) if start is not None else "not-checked",
                      "binding": "unestablished"},
        "claims": {},
        "args_semantics": "unresolved",
        "mappings": [],
    }

    if ovr is None:
        blockers.append("install not given: GAME.OVR bytes were not compared (load dump and "
                        "owner bytes are unchecked)")
    if load["dump"]["status"] != "matched":
        blockers.append("load segment not confirmed by a matching dump of GAME.OVR bytes")

    if obs.get("owner_stop") is None:
        blockers.append("owner stop not observed: the GEO fill entry (GAME.OVR:0x%X) stays "
                        "unestablished without a stop there" % OWNER_OFF)
    else:
        result["owner_stop"] = owner_stop_check(obs["owner_stop"], load, dest_seg, dest_off, ovr)
        # A byte-checked stop at the fill is the only thing that establishes the entry, and only
        # for the run it was observed in. The static stub-7 candidate never does.
        result["geo_entry"]["binding"] = "observed-in-this-run"

    dax = obs.get("dax")
    if dax is None:
        blockers.append("GEO DAX seek not observed")
    else:
        if not isinstance(dax, dict):
            raise AidRefusal("dax: expected an object")
        name = dax.get("open_name")
        if not isinstance(name, str) or not GEO_NAME_RE.match(name):
            raise AidRefusal("dax.open_name must be GEO<n>.DAX, got %r" % (name,))
        open_h = parse_hex(dax.get("open_handle"), "dax.open_handle", 0xFFFF)
        seek_h = parse_hex(dax.get("seek_handle"), "dax.seek_handle", 0xFFFF)
        if open_h != seek_h:
            raise AidRefusal("dax.seek_handle %04X is not the open handle %04X" % (seek_h, open_h))
        al = parse_hex(dax.get("seek_al", "0x0"), "dax.seek_al", 0xFF)
        if al != 0:
            raise AidRefusal("dax.seek_al %02X is not absolute (AL=0); only absolute seeks bind" % al)
        seek_abs = parse_hex(dax.get("seek_abs"), "dax.seek_abs", 0xFFFFFFFF)
        read_count = None
        if dax.get("read_count") not in (None, ""):
            read_count = parse_hex(dax.get("read_count"), "dax.read_count", 0xFFFFFFFF)
        dax_out = {"open_name": name.upper(), "open_handle": "%04X" % open_h,
                   "seek_abs": "0x%X" % seek_abs, "toc_binding": {"status": "not-checked"}}
        if geo_bytes is None:
            blockers.append("TOC binding not checked: no install given")
        else:
            m = GEO_NAME_RE.match(name)
            data = geo_bytes(int(m.group(1)))
            if data is None:
                raise AidRefusal("%s is not in the install folder" % name.upper())
            dax_out["toc_binding"] = bind_toc(name, data, seek_abs, read_count)
        result["dax"] = dax_out

    seek_is_block_start = bool(result["dax"] and "toc_index" in result["dax"]["toc_binding"])
    fill_observed = result["owner_stop"] is not None
    result["claims"] = {
        "load_segment_confirmed": load["dump"]["status"] == "matched",
        "owner_stop_observed": fill_observed,
        "geo_fill_entry": result["geo_entry"]["binding"],
        "geo_seek_observed": result["dax"] is not None,
        # The seek alone: the absolute offset is a TOC block start. Not a GEO binding by itself.
        "toc_seek_is_block_start": seek_is_block_start,
        # The binding: the same run also observed a stop at the GEO fill. Never from the WALLDEF.
        "toc_block_bound": seek_is_block_start and fill_observed,
        "area_mapping": None,
    }
    result["blockers"] = sorted(set(blockers))
    return result


# --------------------------------------------------------------------------
# Output text (deterministic; no timestamps, no absolute paths)
# --------------------------------------------------------------------------

def render_debugger_commands(targets: list[dict], load_seg: Optional[int], buffer_off: int) -> str:
    lines = [
        "; por_geo_capture_aid: DOSBox-X debugger command TEMPLATE (NOT EXECUTED BY THIS TOOL)",
        "; playable: false. Run only against a TEMPORARY COPY of the retail folder, never the install.",
        "; Every BP below is an UNVERIFIED candidate (static layout + one GoldBox route snapshot).",
        "; Command grounding: GoldBox scripts use BPDEL *, BPINT 21 42, BPINT 21 3D, BP seg:off,",
        ";   D seg:off, RUN and BPLIST (PoR trace scripts); BPINT 21 3F appears only in CoK material.",
        ";   The register command R and the stack form D SS:<value> have no GoldBox evidence:",
        ";   check each with HELP before use.",
        "",
        "BPDEL *",
        "BPINT 21 3D          ; open: record DS:DX file name (expect GEO<n>.DAX), AL mode",
        "BPINT 21 42          ; seek: record AL mode, BX handle, CX:DX absolute offset",
        "BPINT 21 3F          ; read: record BX handle, CX count, DS:DX destination (overlay load)",
        "",
    ]
    if load_seg is None:
        lines += [
            "; BLOCKED: no observed load segment. The owner breakpoints are NOT emitted.",
            "; Step 1: run the overlay read and record its DS:DX destination (BPINT 21 3F stop).",
            "; Step 2: rerun the plan with --load-seg <SEG> --buffer-off <OFF> to emit BP lines.",
        ]
    else:
        lines.append("; Observed load segment %04X, buffer offset %04X (user-supplied)."
                     % (load_seg, buffer_off))
        for t in targets:
            lines.append("BP %s          ; %s file %s expect %s  [UNVERIFIED]"
                         % (t["cs_ip"], t["id"], t["file_off"], t["expect_hex"]))
    lines += [
        "BPLIST                ; confirm the list before RUN (check the output format first)",
        "RUN",
        "",
        "; At EACH stop, record manually (the form must be confirmed in the debugger first):",
        ";  (a) registers AX BX CX DX SI DI BP SP DS ES SS CS IP FLAGS   (R)",
        ";  (b) D CS:IP          -> 3 bytes at owner_entry must read 55 89 E5",
        ";  (c) D SS:<BP>        -> saved BP, return IP at +2, return CS at +4, arg byte at +6",
        ";  (d) D SS:<SP>        -> stack top",
        ";  (e) INT 21 3D stop   -> DS:DX file name, AL mode",
        ";  (f) INT 21 42 stop   -> AL mode, BX handle, CX:DX absolute offset (a TOC block start?)",
        ";  (g) INT 21 3F stop   -> BX handle, CX count, DS:DX destination (the overlay load)",
        "; Then type RUN again. Stop and record a mismatch if (b) does not show the expected bytes.",
        "",
    ]
    return "\n".join(lines)


def render_checklist(targets: list[dict], load_seg: Optional[int], buffer_off: int,
                     toc: Optional[list[dict]], emu: dict) -> str:
    seg_text = ("%04X (observed, user-supplied)" % load_seg) if load_seg is not None \
        else "NOT OBSERVED: no CS:IP may be used"
    out = [
        "# Pool of Radiance GEO-load capture checklist",
        "",
        "**Status: capture aid, not a capture. `playable: false`. `mappings: []`.**",
        "",
        "Generated by `tools/por_geo_capture_aid.py plan`. Nothing here is a runtime observation.",
        "",
        "## Question this run must answer",
        "",
        "Which TOC block of `GEO<n>.DAX` does a GEO load read? CORRECTION (2026-11-18): the",
        "routine at `GAME.OVR:0x2F6FF` is the WALLDEF wrapper (START stub 6), not the GEO loader,",
        "and this checklist no longer targets it. The owner targets are the GEO fill at",
        "`GAME.OVR:0x2F9BE` (it reads the GEO literal at `0x2F994`). Its ENTRY is UNESTABLISHED: the",
        "static stub-7 candidate is recorded below, and only a stop at the fill in a run establishes it.",
        "The fill's one byte argument `[bp+6]` is recorded as a byte; its meaning is unresolved.",
        "A TOC block is bound only when the fill stop and a TOC-start seek agree in one run.",
        "This checklist does not map a block to an area. Area mapping needs more than one run.",
        "",
        "## Layout (static, pinned bytes)",
        "",
        "| Item | Value | Status |",
        "| --- | --- | --- |",
        "| Owner entry (GEO fill) | `GAME.OVR:0x2F9BE`, `55 89 E5`, group-relative `0x10C7` | static bytes; entry UNESTABLISHED |",
        "| Post-frame stop | `GAME.OVR:0x2F9C1`, `81 EC 10 01` (sub sp,0x110) | decode boundary, static |",
        "| Byte argument read | `GAME.OVR:0x2FA09`, `8A 46 06` (mov al,[bp+6]) | static |",
        "| Exit | `GAME.OVR:0x2FAFA`, `CA 02 00` (retf 2), the only return | static, single exit |",
        "| Static entry candidate | START `0x3E11` (stub 7), `CD 3F C7 10 27`; proc `0x10C7` | candidate; tail `0x27` undecided |",
        "| Overlay group | descriptor 29, seek `0x2E8F7`, size `0x120B` | GoldBox runtime map, one snapshot |",
        "| Destination | `%s` (snapshot 7) | route-specific candidate, NOT verified |"
        % ("%04X" % GROUP["dest_candidate"]),
        "",
        "The fill falls in group 29 only by the GoldBox runtime map and by stub 7's proc word. Treat group",
        "29 as a candidate until a run observes its read.",
        "",
        "## Emulator and helpers (inspected statically, not launched)",
        "",
        "- DOSBox-X: %s" % _emu_line(emu),
        "- Debugger command syntax: see the Command grounding note in the command file.",
        "",
        "## Breakpoint targets (CS:IP needs the observed load segment)",
        "",
        "Load segment: %s. Buffer offset: `%04X`." % (seg_text, buffer_off),
        "",
        "| Id | File offset | Group-relative | CS:IP | Expected bytes | Status |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for t in targets:
        out.append("| %s | %s | %s | %s | %s | %s |" % (
            t["id"], t["file_off"], t["group_rel_off"],
            t["cs_ip"] if t["cs_ip"] else "blocked", t["expect_hex"], t["status"]))
    out += ["", "## Evidence required (all of it, from one run)", ""]
    out += [
        "1. **Overlay read.** A `BPINT 21 3F` stop reading `GAME.OVR` at seek `0x2E8F7` with count",
        "   `>= 0x120B`, destination `SEG:OFF`. Record `dest_dump_hex` (at least 4 bytes, from `D`)",
        "   and confirm it equals `GAME.OVR[0x2E8F7:]` bytes. A match confirms the load segment.",
        "2. **Owner stop.** A stop at `owner_entry` (or `owner_post_frame`) at the translated CS:IP,",
        "   with its code bytes and, at post-frame, BP, return CS:IP and the one argument word.",
        "   This stop is what establishes the GEO fill entry, for that run only.",
        "3. **GEO open.** A `BPINT 21 3D` stop whose name is `GEO<n>.DAX` (the open handle).",
        "4. **GEO seek.** A `BPINT 21 42` stop on that handle with AL=0 and the absolute offset in",
        "   CX:DX. The offset must be exactly a TOC block start (table below).",
        "5. **Repeat.** A second run with the same save and keys must agree on every value above.",
        "",
        "## Stop rules",
        "",
        "- If `D CS:IP` at a stop does not show the expected bytes, the segment is wrong: stop.",
        "  Do not reuse breakpoints from another run.",
        "- Do not write to the retail folder. Hash `GAME.OVR` and `START.EXE` before and after.",
        "- Do not type input into an unverified debugger form. Check HELP first.",
        "- Do not interpret `[bp+6]` yet. Record it as a byte.",
        "",
        "## Observation",
        "",
        "Copy `por_geo_capture_observation.template.json`, fill every field from the run, and run:",
        "",
        "```sh",
        "python tools/por_geo_capture_aid.py check --observation OBS.json --install \"PATH/TO/POOLRAD\" \\",
        "    -o data/work/por-geo-capture-aid/check",
        "```",
        "",
        "`check` refuses a contradiction (exit 2). It reports blockers (exit 1) for evidence not yet",
        "present. Exit 0 means the observation is complete and consistent. It does not create a",
        "mapping.",
        "",
    ]
    if toc is not None:
        out += ["## Expected DAX seek offsets (TOC block starts, from the install)", "",
                "| GEO | TOC index | Block id | Absolute offset | Comp size | Raw size |",
                "| --- | ---: | ---: | ---: | ---: | ---: |"]
        for r in toc:
            out.append("| %s | %d | %d | %s | %d | %d |" % (
                r["geo"], r["toc_index"], r["block_id"], r["abs_offset"],
                r["comp_size"], r["raw_size"]))
        out.append("")
    out += [
        "## Claim boundary",
        "",
        "- Proves nothing at runtime. A run that follows this checklist can produce the",
        "  observation; `check` then binds the seek to a TOC block if the evidence agrees.",
        "- Does not prove what `[bp+6]` means, which block an area uses, or that the caller is a",
        "  GEO load. PoR and CoK are separate: no CoK fact is used here.",
        "",
    ]
    return "\n".join(out)


def _emu_line(emu: dict) -> str:
    status = emu.get("status")
    if status == "not-given":
        return "not given (pass `--dosbox`, or set `%s`)" % EMULATOR_ENV
    if status == "absent":
        return "not found (`%s`)" % emu.get("basename")
    return "%s, SHA-256 `%s`, pin %s, debugger strings %s, not launched" % (
        emu["basename"], emu["sha256"], "matches" if emu["matches_pin"] else "DOES NOT match",
        ", ".join("%s=%s" % (k, "yes" if v else "no") for k, v in sorted(emu["debugger_strings"].items())))


def observation_template() -> dict:
    return {
        "schema": OBS_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "route": "",
        "emulator_sha256": "",
        "retail_pins_before": {"GAME.OVR": "", "START.EXE": ""},
        "retail_pins_after": {"GAME.OVR": "", "START.EXE": ""},
        "load": {"file": OVR, "seek_abs": "", "read_count": "", "dest": "", "dest_dump_hex": ""},
        "owner_stop": {"at": "", "cs": "", "ip": "", "code_hex": "", "bp": "",
                       "return_cs": "", "return_ip": "", "arg_bp6_word": ""},
        "dax": {"open_name": "", "open_handle": "", "seek_handle": "", "seek_al": "0x0",
                "seek_abs": "", "read_count": ""},
    }


# --------------------------------------------------------------------------
# Install and output I/O (CLI layer)
# --------------------------------------------------------------------------

def load_pinned_install(install: Path) -> tuple[bytes, bytes]:
    """Read GAME.OVR and START.EXE, read-only, and refuse unless both match their pins."""
    out = []
    for name in (OVR, EXE):
        path = fc.find_file(install, name)
        data = path.read_bytes()
        size, sha = fc.PINNED[name]
        if len(data) != size or _sha(data) != sha:
            raise AidRefusal("%s does not match its pin (size %d, sha256 %s)"
                             % (name, len(data), _sha(data)))
        out.append(data)
    return out[0], out[1]


def make_geo_reader(install: Path) -> Callable[[int], Optional[bytes]]:
    def read(n: int) -> Optional[bytes]:
        try:
            return por_map.resolve_geo(install, n).read_bytes()
        except por_map.PorMapError:
            return None
    return read


def _inspect_file(path_text: Optional[str], label: str) -> dict:
    if not path_text:
        return {"status": "not-given", "label": label}
    p = Path(path_text)
    if not p.is_file():
        return {"status": "absent", "basename": p.name, "label": label}
    data = p.read_bytes()
    sha = _sha(data)
    return {"status": "present", "basename": p.name, "label": label, "sha256": sha,
            "matches_pin": sha == rcp.EMULATOR_PIN_SHA256,
            "debugger_strings": {s.decode(): (s in data) for s in DEBUGGER_STRINGS},
            "launched": False}


def _inspect_emulator(path_arg: Optional[str]) -> dict:
    path_text = path_arg or os.environ.get(EMULATOR_ENV)
    return _inspect_file(path_text, "dosbox-x")


def _check_out(out: Path, install: Optional[Path]) -> Path:
    if install is not None:
        validate_output_dir(install, out)
    dst = Path(out).resolve()
    if dst.is_relative_to(REPO_ROOT.resolve()) and not dst.is_relative_to(DATA_DIR.resolve()):
        raise AidRefusal("output folder inside the repository must be under data/ "
                         "(git-ignored); choose another location")
    return dst


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def cmd_plan(args: argparse.Namespace) -> int:
    install = Path(args.install) if args.install else None
    out = _check_out(Path(args.out), install)
    load_seg = None
    if args.load_seg is not None:
        load_seg = parse_hex(args.load_seg, "--load-seg", 0xFFFF)
    buffer_off = parse_hex(args.buffer_off, "--buffer-off", 0xFFFF)

    static = None
    toc = None
    pins = None
    geo_entry = None
    if install is not None:
        ovr, exe = load_pinned_install(install)
        static = static_checks(ovr)
        bad = [c["id"] for c in static if not c["ok"]]
        if bad:
            raise AidRefusal("static checks failed on the pinned GAME.OVR: %s" % ", ".join(bad))
        geo_entry = geo_entry_candidate(exe)
        pins = {OVR: fc.PINNED[OVR][1], EXE: fc.PINNED[EXE][1]}
        reader = make_geo_reader(install)
        dax = {}
        for n in range(1, 9):
            data = reader(n)
            if data is None:
                raise AidRefusal("GEO%d.DAX not found in the install folder" % n)
            dax[n] = data
        try:
            toc = toc_table(dax)
        except por_map.PorMapError as exc:
            raise AidRefusal("a GEO archive is not a valid DAX container: %s" % exc)

    targets = build_targets(load_seg, buffer_off)
    emu = _inspect_emulator(args.dosbox)
    helper = _inspect_file(args.debugger_helper, "debugger-helper")

    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "performed": False,
        "group": {"descriptor": GROUP["descriptor"], "seek": "0x%X" % GROUP["seek"],
                  "code_size": "0x%X" % GROUP["code_size"],
                  "dest_candidate": "%04X" % GROUP["dest_candidate"],
                  "source": GROUP["source"]},
        "load_segment": None if load_seg is None else _fmt_seg_off(load_seg, buffer_off),
        "load_segment_source": "user-supplied (--load-seg)" if load_seg is not None else "not observed",
        "targets": targets,
        "install": None if install is None else {
            "pins": pins, "static_checks": static, "geo_entry_static": geo_entry,
            "toc_blocks": toc},
        "emulator": emu,
        "debugger_helper": helper,
        "claims": {"caller": "unresolved", "args_semantics": "unresolved", "area_mapping": None},
        "mappings": [],
        "files": {
            "checklist": "por_geo_capture_checklist.md",
            "dosbox_commands": "por_geo_capture_dosbox_commands.txt",
            "observation_template": "por_geo_capture_observation.template.json",
        },
    }
    _write(out / "por_geo_capture_aid.json",
           json.dumps(doc, indent=2, sort_keys=True) + "\n")
    _write(out / "por_geo_capture_checklist.md",
           render_checklist(targets, load_seg, buffer_off, toc, emu))
    _write(out / "por_geo_capture_dosbox_commands.txt",
           render_debugger_commands(targets, load_seg, buffer_off))
    _write(out / "por_geo_capture_observation.template.json",
           json.dumps(observation_template(), indent=2, sort_keys=True) + "\n")
    print("wrote capture aid to %s (playable: false, performed: false)" % out.name)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    install = Path(args.install) if args.install else None
    out = _check_out(Path(args.out), install)
    obs_path = Path(args.observation)
    if not obs_path.is_file():
        raise AidRefusal("observation file not found")
    raw = obs_path.read_bytes()
    try:
        obs = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AidRefusal("observation is not valid JSON: %s" % exc)
    ovr = None
    geo = None
    start = None
    if install is not None:
        ovr, start = load_pinned_install(install)
        geo = make_geo_reader(install)
    doc = check_observation(obs, ovr, geo, start=start)
    doc["observation_sha256"] = _sha(raw)
    out.mkdir(parents=True, exist_ok=True)
    _write(out / "por_geo_capture_check.json", json.dumps(doc, indent=2, sort_keys=True) + "\n")
    lines = ["# GEO capture observation check", "",
             "`playable: false`, `performed: false` (observation supplied by a person).", "",
             "- GEO fill CS:IP (owner target): %s" % (doc["load"]["owner_cs_ip"]),
             "- GEO fill entry: %s" % doc["claims"]["geo_fill_entry"],
             "- Load confirmed: %s" % doc["claims"]["load_segment_confirmed"],
             "- Owner stop observed (a stop at the GEO fill): %s" % doc["claims"]["owner_stop_observed"],
             "- GEO seek observed: %s" % doc["claims"]["geo_seek_observed"],
             "- TOC seek is a block start: %s" % doc["claims"]["toc_seek_is_block_start"],
             "- TOC block bound (fill stop and seek, same run): %s" % doc["claims"]["toc_block_bound"],
             "- Area mapping: none (`mappings: []`)", "", "## Blockers", ""]
    lines += ["- %s" % b for b in doc["blockers"]] or ["- none"]
    lines.append("")
    _write(out / "por_geo_capture_check_report.md", "\n".join(lines))
    if doc["blockers"]:
        print("observation consistent; %d blocker(s) remain (exit 1)" % len(doc["blockers"]))
        return 1
    print("observation complete and consistent (exit 0)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="write the checklist, command template and observation template")
    p.add_argument("--install", help="PoR install folder (read-only; pins checked)")
    p.add_argument("--load-seg", help="observed load segment (hex). Without it no CS:IP is emitted")
    p.add_argument("--buffer-off", default="0", help="observed destination offset of the read (hex)")
    p.add_argument("--dosbox", help="DOSBox-X binary (inspected statically, never launched)")
    p.add_argument("--debugger-helper", help="optional debugger helper binary (presence and hash only)")
    p.add_argument("-o", "--out", required=True, help="output folder (under data/ inside the repo)")
    p.set_defaults(func=cmd_plan)
    c = sub.add_parser("check", help="check a user-supplied observation JSON")
    c.add_argument("--observation", required=True, help="observation JSON (openua.por-geo-capture-observation)")
    c.add_argument("--install", help="PoR install folder (enables the byte dump and TOC binding)")
    c.add_argument("-o", "--out", required=True, help="output folder")
    c.set_defaults(func=cmd_check)
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AidRefusal, PorSourceError, por_map.PorMapError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
