#!/usr/bin/env python3
"""Observe-only probe: which code is the far helper 0x0AF8:0x1685, and what ABI do its bytes show?

The buffer-fill probe (tools/por_geo_buffer_fill_probe.py) pushes four copies to the far helper
0x0AF8:0x1685 and left open two things: which pushed pointer the helper reads as its source, and
which bytes the helper is. This probe asks the same question from three kinds of evidence, and
refuses to promote anything the evidence does not carry:

1. File bytes (pinned GAME.OVR and START.EXE). Every translation of the raw `seg:off` into a START
   file offset is listed with its code evidence. A translation that lands on text, or on bytes with
   no code shape, is rejected as data.
2. RAM dumps (pinned, unknown instant). The START image's load segment is read from the relocated
   copy's own link word (copy seg : 0004 holds the DOS load segment). The live segment of the raw
   0x0AF8 is then `0x0AF8 + load`. The target bytes at that live address are compared with each
   file translation. Resident call instructions `9A 85 16 <seg>` are histogrammed, and any resident
   overlay group that maps uniquely is checked for the loader's rewritten segment word.
3. The exact opcode sequence at the identified target, decoded by hand. Only an exact match yields
   an ABI, and the caller's five pushed words are checked against the offsets the helper reads.

Identity is a candidate, not a mapping, unless exactly one file offset passes every gate in every
covering dump. Nothing here says the helper runs, that the fill runs, or what the loader returns.
Every gate is a named check in the JSON; a failed gate is reported, not hidden.

Usage:
    python tools/por_geo_copy_helper_probe.py [--install PATH/TO/POOLRAD] \
        [--dump data/work/por-live-memory-pid34644/ram-000000-100000.bin ...] \
        [-o data/work/por-geo-copy-helper-probe]

Exit: 0 the probe ran (its verdict may be `unresolved` or `ambiguous`; that is the result); 2 a named
refusal (unpinned input, bad dump, output outside data/work).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_farcall_resolve as fr  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_geo_callee_identity_probe as gcp  # noqa: E402
import por_geo_buffer_fill_probe as fill  # noqa: E402

SCHEMA = "openua.por-geo-copy-helper-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "copy-helper-probe-only"
TOOL = "tools/por_geo_copy_helper_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-copy-helper-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMPS = [
    DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
    DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin",
]
Refusal = om.Refusal
OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME

TARGET_SEG = 0x0AF8                 # raw segment word in the GAME.OVR call
TARGET_OFF = 0x1685                 # offset word in the GAME.OVR call
ALLOC_OFF = 0x023F                  # same module, one-word allocator (cross-check only)
HDR = 0x200                         # START.EXE MZ header bytes (cparhdr * 16)
START_CS_FILE = 0x0F72              # START entry CS in the pinned header
ENTRY_IP = 0x0012
ENTRY_FILE = HDR + START_CS_FILE * 16 + ENTRY_IP   # 0xF932, the entry window
ENTRY_LEN = 16
LINK_OFF = 0x0004                   # copy seg:0004 holds the DOS load segment (identity probe)
ROUTINE_B_HANDLER = bytes.fromhex("b8 d0 00 83 c4 06 eb 03")   # mov ax,00D0; add sp,6; jmp
ROUTINE_B_HANDLER_OFF = 0x00D7      # module-relative handler IP, quoted from the INT 3Fh capture
ANCHOR_OFF = 0x00D0                 # 16-byte window inside the module used as the dump anchor
ANCHOR_LEN = 16
DOSBOX_QUOTED_LOAD = 0x0824         # load segment in the DOSBox run, quoted (not re-observable here)
COPY_CALL = bytes.fromhex("9a 85 16 f8 0a")
CALL_PREFIX = b"\x9a\x85\x16"
ALLOC_PREFIX = b"\x9a\x3f\x02"
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
DATA_RUN = 8                        # a printable run this long at a target means data, not code
DEGENERATE_ZEROS = 14               # a window with this many zeros cannot place anything

# The copy helper's exact opcode sequence (hand-decoded; the match is byte-exact, fail closed).
ABI_STEPS = [
    ("8b dc", "mov bx,sp"),
    ("8c da", "mov dx,ds"),
    ("36 c5 77 0a", "lds si,[ss:bx+0x0a]"),
    ("36 c4 7f 06", "les di,[ss:bx+0x06]"),
    ("36 8b 4f 04", "mov cx,[ss:bx+0x04]"),
    ("fc", "cld"),
    ("3b f7", "cmp si,di"),
    ("73 07", "jnb +7"),
    ("03 f1", "add si,cx"),
    ("03 f9", "add di,cx"),
    ("4e", "dec si"),
    ("4f", "dec di"),
    ("fd", "std"),
    ("f3 a4", "rep movsb"),
    ("8e da", "mov ds,dx"),
    ("ca 0a 00", "retf 0x0a"),
]
BODY = b"".join(bytes.fromhex(h) for h, _ in ABI_STEPS)
BODY_LEN = len(BODY)
DISP_LDS, DISP_LES, DISP_CX = BODY[7], BODY[11], BODY[15]     # the [bx+disp] offsets read
RETF_IMM = BODY[-2] | (BODY[-1] << 8)

NOT_ESTABLISHED = [
    "that the helper runs, or that the fill or any caller runs, at any instant",
    "that the loader's rewritten segment word is the live segment at any instant after the dump",
    "that the module at the live segment is the file's module at every offset: only the target bytes, "
    "the anchor window and the linked segment words are compared",
    "what the loader 0x0802:0x0716 returns, and whether the fill's source block is a GEO block",
    "the meaning of the id byte, the block index, and any PoR meaning of the copied bytes",
    "the DF flag after a backward copy: the backward path sets it and no cld follows (recorded as a byte fact)",
    "copy semantics across two different segments, where the offset comparison decides the direction",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _positions(data: bytes, pat: bytes) -> list[int]:
    out, pos = [], data.find(pat)
    while pos != -1:
        out.append(pos)
        pos = data.find(pat, pos + 1)
    return out


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def printable_run(b: bytes) -> int:
    best = cur = 0
    for c in b:
        if 0x20 <= c <= 0x7E:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def code_evidence(start: bytes, off: int) -> dict:
    """Shape of the bytes at a candidate entry: a prologue, or a return just before it. Shape only."""
    head = start[off:off + 3]
    ret_before = (off >= 1 and start[off - 1] in (0xC3, 0xCB)) or (off >= 3 and start[off - 3] == 0xCA)
    run = printable_run(start[off:off + 16])
    return {"prologue": head in PROLOGUES, "ret_before": ret_before, "printable_run": run,
            "data_like": run >= DATA_RUN, "code_shape": (head in PROLOGUES or ret_before) and run < DATA_RUN}


def check_pins(ovr: bytes, exe: bytes) -> dict:
    return gcp.check_pins(ovr, exe, om.PINS)


# ---- ABI at the identified target (exact sequence) ------------------------------------

def abi_decode(start: bytes, off: Optional[int]) -> dict:
    """Byte-exact match of the copy helper at `off`. Returns the argument layout only on a full match."""
    if off is None or off < 0 or off + BODY_LEN > len(start):
        return {"matched": False, "reason": "no target bytes"}
    if start[off:off + BODY_LEN] != BODY:
        return {"matched": False, "reason": "target bytes differ from the copy helper's exact sequence"}
    # The jnb must land on rep movsb, or the skip is wrong.
    jnb_at = sum(len(bytes.fromhex(h)) for h, _ in ABI_STEPS[:7])
    rep_at = sum(len(bytes.fromhex(h)) for h, _ in ABI_STEPS[:13])
    if jnb_at + 2 + BODY[jnb_at + 1] != rep_at:
        return {"matched": False, "reason": "jnb does not land on rep movsb"}
    src_off, src_seg = DISP_LDS, DISP_LDS + 2
    dst_off, dst_seg = DISP_LES, DISP_LES + 2
    return {
        "matched": True,
        "steps": [{"at": "0x%X" % (off + sum(len(bytes.fromhex(h)) for h, _ in ABI_STEPS[:i])),
                   "bytes": h, "text": t} for i, (h, t) in enumerate(ABI_STEPS)],
        "entry_layout_from_sp": {"return_ip": 0, "return_cs": 2, "count": DISP_CX,
                                 "dst_off": dst_off, "dst_seg": dst_seg,
                                 "src_off": src_off, "src_seg": src_seg},
        "retf_imm": RETF_IMM,
        "callee_pops_bytes": RETF_IMM,
        "copy": "rep movsb of CX bytes from DS:SI (src) to ES:DI (dst); forward when SI >= DI (offsets), "
                "backward (std) otherwise",
        "df_after_return": "clear on the forward path; set on the backward path (no cld)",
    }


def push_order_check(abi: dict, copies: list[dict]) -> dict:
    """The caller pushes src.seg, src.off, dst.seg, dst.off, count (in that order). The callee reads
    them at sp+12, +10, +8, +6, +4. The caller side is the buffer-fill reader's shape check (`ok`):
    every fill copy must have exactly that five-word push shape."""
    if not abi.get("matched"):
        return {"checked": False, "reason": "no ABI"}
    lay = abi["entry_layout_from_sp"]
    return {"checked": True,
            "callee_read_offsets_in_push_order": [lay["src_seg"], lay["src_off"], lay["dst_seg"],
                                                  lay["dst_off"], lay["count"]],
            "caller_copies": len(copies),
            "caller_shape": "src.seg, src.off, dst.seg, dst.off, count",
            "agrees": len(copies) == 4 and all(c.get("ok") for c in copies)}


# ---- translations and dump agreement ---------------------------------------------------

def handler_base(start: bytes) -> dict:
    hits = _positions(start, ROUTINE_B_HANDLER)
    if len(hits) != 1:
        raise Refusal("routine B handler pattern occurs %d times in START.EXE; refusing an ambiguous base"
                      % len(hits))
    base = hits[0] - ROUTINE_B_HANDLER_OFF
    if base < 0:
        raise Refusal("routine B handler offset places the module base before the file")
    return {"handler_file": hits[0], "base_file": base, "handler_hits_in_start": len(hits)}


def dump_module(dump: om.Dump, start: bytes, base_file: int) -> dict:
    anchor = start[base_file + ANCHOR_OFF:base_file + ANCHOR_OFF + ANCHOR_LEN]
    hits = dump.find_all(anchor)
    if len(hits) != 1:
        return {"status": "absent" if not hits else "ambiguous", "hits": ["0x%X" % h for h in hits[:4]]}
    lin = hits[0] - ANCHOR_OFF
    if lin % 16:
        return {"status": "unaligned", "linear": "0x%X" % lin}
    seg = lin >> 4
    return {"status": "unique", "linear": "0x%X" % lin, "seg": seg, "load_seg": seg - TARGET_SEG}


def dump_entry(dump: om.Dump, start: bytes) -> dict:
    hits = dump.find_all(start[ENTRY_FILE:ENTRY_FILE + ENTRY_LEN])
    if len(hits) != 1:
        return {"status": "absent" if not hits else "ambiguous", "hits": ["0x%X" % h for h in hits[:4]]}
    lin = hits[0]
    if (lin - ENTRY_IP) % 16:
        return {"status": "unaligned", "linear": "0x%X" % lin}
    cs = (lin - ENTRY_IP) >> 4
    link = _u16(dump.read(cs * 16 + LINK_OFF, 2), 0) if dump.covers(cs * 16 + LINK_OFF, 2) else None
    return {"status": "unique", "copy_seg": cs, "load_seg_from_entry": cs - START_CS_FILE,
            "link_word": link}


def _row_key(l_name: str, f_name: str) -> str:
    return "%s|%s" % (l_name, f_name)


def translation_rows(start: bytes, dump: om.Dump, base_file: int, mod: dict, ent: dict) -> list[dict]:
    """Each (load-segment source, file mapping) pair, checked against this dump's live bytes."""
    l_sources = []
    if mod.get("status") == "unique":
        l_sources.append(("module-anchor-in-dump", mod["load_seg"]))
    if ent.get("status") == "unique":
        l_sources.append(("copy-entry-segment-in-dump", ent["load_seg_from_entry"]))
    l_sources.append(("quoted-dosbox-routine-b", DOSBOX_QUOTED_LOAD))
    file_maps = [("contiguous-mz", HDR + TARGET_SEG * 16 + TARGET_OFF),
                 ("routine-b-module-base", base_file + TARGET_OFF)]
    rows = []
    for l_name, load in l_sources:
        live_lin = (TARGET_SEG + load) * 16 + TARGET_OFF
        covered = dump.covers(live_lin, BODY_LEN)
        dbytes = dump.read(live_lin, BODY_LEN) if covered else None
        for f_name, foff in file_maps:
            row = {"load_source": l_name, "load_seg": "0x%04X" % load, "file_map": f_name,
                   "file_offset": "0x%X" % foff, "live_linear": "0x%X" % live_lin,
                   "live_covered": covered}
            fb = start[foff:foff + BODY_LEN] if foff + BODY_LEN <= len(start) else None
            if fb is None:
                row["state"] = "not-in-file"
                rows.append(row)
                continue
            ev = code_evidence(start, foff)
            row["file_code_evidence"] = ev
            row["file_bytes_are_copy_helper"] = fb == BODY
            if ev["data_like"]:
                row["state"] = "file-data-like"
            elif not covered:
                row["state"] = "memory-not-covered"
            elif dbytes != fb:
                row["state"] = "memory-disagrees"
                row["differing_offsets"] = [i for i in range(BODY_LEN) if dbytes[i] != fb[i]][:8]
            elif dbytes == BODY:
                row["state"] = "memory-agrees-and-body"
            else:
                row["state"] = "memory-agrees"
            if covered and dbytes is not None:
                # Placement uses the whole body, not a prefix: a 16-byte prefix can recur in START.EXE.
                row["dump_window_degenerate"] = dbytes[:16].count(0) >= DEGENERATE_ZEROS
                if not row["dump_window_degenerate"]:
                    placed = _positions(start, dbytes)
                    row["dump_window_file_placements"] = ["0x%X" % p for p in placed[:4]]
            rows.append(row)
    return rows


def decide_identity(per_dump: list[dict]) -> dict:
    """A target is identified only if it is code-shaped, memory-agrees in every covering dump, and has a
    unique file placement. Distinct identified file offsets make the answer ambiguous, not chosen."""
    good_by_off: dict[str, list[str]] = {}
    for d in per_dump:
        for r in d["rows"]:
            if r["state"] not in ("memory-agrees", "memory-agrees-and-body"):
                continue
            if not r.get("file_code_evidence", {}).get("code_shape"):
                continue
            if r.get("dump_window_degenerate") or r.get("dump_window_file_placements") != [r["file_offset"]]:
                continue
            good_by_off.setdefault(r["file_offset"], []).append("%s|%s" % (d["dump"], r["load_source"]))
    covering = [d for d in per_dump if any(r["live_covered"] for r in d["rows"])]
    if not good_by_off:
        return {"verdict": "unresolved", "file_offsets": [], "covering_dumps": len(covering)}
    if len(good_by_off) > 1:
        return {"verdict": "ambiguous", "file_offsets": sorted(good_by_off), "covering_dumps": len(covering)}
    (off,) = good_by_off
    rows_needed = len(covering)
    agreeing = {k.split("|", 1)[0] for k in good_by_off[off]}
    if len(agreeing) < rows_needed:
        return {"verdict": "unresolved", "file_offsets": [off], "covering_dumps": rows_needed,
                "reason": "not every covering dump agrees"}
    return {"verdict": "identified-by-bytes-in-pinned-dumps", "file_offset": off,
            "covering_dumps": rows_needed, "agreeing_dumps": sorted(agreeing)}


# ---- resident call sites and the loader's rewritten segment ---------------------------

def resident_seg_words(dump_data: bytes, prefix: bytes) -> dict:
    counts: Counter = Counter()
    pos = dump_data.find(prefix)
    while pos != -1:
        if pos + 5 <= len(dump_data):
            counts["0x%04X" % _u16(dump_data, pos + 3)] += 1
        pos = dump_data.find(prefix, pos + 1)
    return dict(sorted(counts.items()))


def copy_call_sites(ovr: bytes) -> list[int]:
    return _positions(ovr, COPY_CALL)


def static_call_rows(ovr: bytes, exe: bytes, sites: list[int]) -> list[dict]:
    groups = gcp.all_groups(exe, ovr)
    rows = []
    for s in sites:
        g = gcp.owner_group(groups, s)
        listed = None
        if g is not None:
            listed = (s + 3 - g["fileofs"]) in fr.fixup_table(ovr, g)
        rows.append({"site": "0x%X" % s, "owner_group": None if g is None else "0x%X" % g["fileofs"],
                     "seg_word_listed_as_fixup": listed})
    return rows


def group_scan(ovr: bytes, exe: bytes, dump: om.Dump, sites: list[int], load: Optional[int]) -> dict:
    """Resident overlay groups holding copy calls. A group is used only if it maps uniquely."""
    groups = gcp.all_groups(exe, ovr)
    out_rows, unique = [], 0
    for g in groups:
        code = ovr[g["fileofs"]:g["fileofs"] + g["codesz"]]
        if len(code) < g["codesz"]:
            continue
        fx = sorted(fr.fixup_table(ovr, g))
        try:
            r = om.map_group(g, code, fx, dump)
        except Refusal as exc:
            r = {"status": "refused", "reason": str(exc)}
        if r["status"] == "unique":
            unique += 1
        here = [s for s in sites if g["fileofs"] <= s < g["fileofs"] + g["codesz"]]
        if not here:
            continue
        row = {"group": "0x%X" % g["fileofs"], "status": r["status"], "sites": []}
        if r["status"] == "unique":
            base = r["base_linear"]
            row["base_linear"] = "0x%X" % base
            for s in here:
                rel = s + 3 - g["fileofs"]
                live = _u16(dump.read(base + rel, 2), 0)
                row["sites"].append({"site": "0x%X" % s, "seg_word_fixup_listed": rel in fx,
                                     "live_seg": "0x%04X" % live,
                                     "expected_seg": None if load is None else "0x%04X" % (TARGET_SEG + load),
                                     "match": None if load is None else live == TARGET_SEG + load})
        out_rows.append(row)
    return {"groups_scanned": len(groups), "groups_unique_in_dump": unique, "copy_group_rows": out_rows}


# ---- caller side (reuses the buffer-fill probe, read-only) ------------------------------

def caller_copies(install: Path, dump_paths: list[Path]) -> dict:
    doc = fill.probe(install, DEFAULT_OUT, dump_paths)
    f = doc["fill"]
    return {"fill_entry": f["entry_hex"], "copies": f["copies"], "copy_simulation_ok": f["copy_simulation_ok"]}


# ---- top-level -------------------------------------------------------------------------

def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = check_pins(ovr, exe)
    base = handler_base(exe)
    sites = copy_call_sites(ovr)
    static_rows = static_call_rows(ovr, exe, sites)
    alloc_sites = _positions(ovr, b"\x9a\x3f\x02\xf8\x0a")
    per_dump, dumps_meta = [], []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        label = "%s/%s" % (dp.parent.name, dp.name)     # both dumps share a file name
        base_lin = om.resolve_dump_base(dp.name, len(raw), None)
        dump = om.Dump(raw, base_lin)
        mod = dump_module(dump, exe, base["base_file"])
        ent = dump_entry(dump, exe)
        load = mod.get("load_seg") if mod.get("status") == "unique" else None
        rows = translation_rows(exe, dump, base["base_file"], mod, ent)
        call_hist = resident_seg_words(raw, CALL_PREFIX)
        alloc_hist = resident_seg_words(raw, ALLOC_PREFIX)
        link_ok = None
        if ent.get("status") == "unique" and mod.get("status") == "unique":
            link_ok = ent["link_word"] == mod["load_seg"]
        groups_rep = group_scan(ovr, exe, dump, sites, load)
        per_dump.append({"dump": label, "dump_sha256": _sha(raw), "dump_base": "0x%X" % base_lin,
                         "module": mod, "entry": ent, "link_word_equals_module_load": link_ok,
                         "rows": rows, "resident_copy_call_seg_words": call_hist,
                         "resident_alloc_call_seg_words": alloc_hist,
                         "group_scan": groups_rep})
        dumps_meta.append(label)
    identity = decide_identity(per_dump)
    identified = identity["verdict"] == "identified-by-bytes-in-pinned-dumps"
    abi = abi_decode(exe, int(identity["file_offset"], 16) if identified else None)
    caller = caller_copies(install, dump_paths)
    push = push_order_check(abi, caller["copies"]) if abi.get("matched") else {"checked": False,
                                                                                 "reason": "no ABI"}
    seg_rule = {"verdict": "memory-checked" if per_dump and all(
        d["link_word_equals_module_load"] is True and set(d["resident_copy_call_seg_words"]) ==
        {"0x%04X" % (TARGET_SEG + d["module"]["load_seg"])} and d["resident_copy_call_seg_words"]
        for d in per_dump if d["module"].get("status") == "unique") else "not-established",
                "rule": "live seg = raw 0x0AF8 + load seg; load seg from the copy's link word"}
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL, "status_scope": STATUS_SCOPE,
        "playable": False,
        "inputs": {"pins": pins, "dumps": dumps_meta},
        "target": {"raw": "0x%04X:0x%04X" % (TARGET_SEG, TARGET_OFF),
                   "fill_copy_calls": "GAME.OVR 0x2FA70, 0x2FA92, 0x2FAB4, 0x2FAD6"},
        "module_file_base": "0x%X" % base["base_file"],
        "module_handler": {"file": "0x%X" % base["handler_file"], "ip": "0x%04X" % ROUTINE_B_HANDLER_OFF,
                           "basis": "quoted routine-B IVT IP 131C:00D7 (por-int3f-runtime-capture.md)"},
        "static_copy_call_sites": static_rows,
        "static_copy_call_sites_count": len(sites),
        "static_alloc_call_sites_count": len(alloc_sites),
        "segment_rule": seg_rule,
        "per_dump": per_dump,
        "identity": identity,
        "abi": abi,
        "caller": caller,
        "push_order_check": push,
        "not_established": NOT_ESTABLISHED,
        "verdict": ("helper bytes identified in pinned dumps; ABI decoded from those bytes; "
                    "execution and loader source not established") if identity["verdict"] ==
        "identified-by-bytes-in-pinned-dumps" else "helper not identified: %s" % identity["verdict"],
        "fill_established": False,
        "executed": "not_established",
    }
    return doc


def render_report(doc: dict) -> str:
    L = ["# Pool of Radiance: far helper 0x0AF8:0x1685 (observe-only)", "",
         "**Status: observe-only. `playable: false`. `executed: not_established`. `fill_established: false`.**", "",
         "## Identity", "",
         "- identity: `%s`" % doc["identity"]["verdict"],
         "- file offset: %s" % doc["identity"].get("file_offset", "none"),
         "- module file base: `%s` (anchor from the quoted routine-B handler)" % doc["module_file_base"],
         "- verdict: %s" % doc["verdict"], "",
         "## Translations", "",
         "| dump | load source | load | file map | file | live | state |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
    for d in doc["per_dump"]:
        for r in d["rows"]:
            L.append("| %s | %s | %s | %s | %s | %s | %s |" % (d["dump"], r["load_source"], r["load_seg"],
                                                             r["file_map"], r["file_offset"], r["live_linear"],
                                                             r["state"]))
    L += ["", "## Segment rule (loader)", "", "- `%s`" % doc["segment_rule"]["verdict"]]
    for d in doc["per_dump"]:
        L.append("- %s: module %s; entry %s; link word equals module load: %s; resident copy seg words %s"
                 % (d["dump"], d["module"].get("status"), d["entry"].get("status"),
                    d["link_word_equals_module_load"], d["resident_copy_call_seg_words"]))
    L += ["", "## ABI at the identified target", ""]
    if doc["abi"].get("matched"):
        lay = doc["abi"]["entry_layout_from_sp"]
        L += ["- entry layout (from SP): count `+%d`, dst `+%d/+%d`, src `+%d/+%d` (off/seg)" % (
            lay["count"], lay["dst_off"], lay["dst_seg"], lay["src_off"], lay["src_seg"]),
              "- `retf 0x%X` (callee pops %d bytes)" % (doc["abi"]["retf_imm"], doc["abi"]["callee_pops_bytes"]),
              "- copy: %s" % doc["abi"]["copy"], "- DF: %s" % doc["abi"]["df_after_return"]]
    else:
        L.append("- not decoded: %s" % doc["abi"].get("reason"))
    L += ["", "## Caller (buffer-fill copies, read-only reuse)", ""]
    for c in doc["caller"]["copies"]:
        L.append("- %s ok=%s src=%s dst=%s count=%s" % (c.get("call_at"), c.get("ok"), c.get("src"),
                                                      c.get("dst"), c.get("count")))
    L += ["", "## Not established", ""] + ["- " + x for x in doc["not_established"]]
    return "\n".join(L) + "\n"


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_copy_helper_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_geo_copy_helper_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only probe of the far copy helper 0x0AF8:0x1685.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    ap.add_argument("--dump", type=Path, action="append", default=None)
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    dumps = args.dump if args.dump else DEFAULT_DUMPS
    try:
        doc = probe(args.install, dumps)
    except (Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s (identity=%s, abi matched=%s)" % (args.out, doc["identity"]["verdict"],
                                                     doc["abi"].get("matched")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
