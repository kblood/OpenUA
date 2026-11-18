#!/usr/bin/env python3
"""Pool of Radiance: bounded static trace of an 8X8D DAX read path (observe-only).

Status: STATIC-PROBE-ONLY. Read-only, playable: false, mappings: [], binding_established: false.

Question this probe narrows (it does not answer it): does any decoded routine in the
pinned retail START.EXE or GAME.OVR open or read an 8X8D DAX archive, select a block
or tile id, and do those routines have a call path that is established by bytes?

What it measures, from the retail bytes only (nothing is executed):

  * pinned hashes of START.EXE, GAME.OVR and the eight 8X8D archives, before and after
    the run (source immutability);
  * the Turbo Pascal length-prefixed pieces "8X8d<n>", "8x8d", ".dax" and the
    "Unable to load 8x8D" text, scanned at every byte offset;
  * two candidate reader routines and their decoded facts:
      - START.EXE 0x7245: pointer-referenced name pieces (CS:0x171, CS:0x177, checked
        against a CS base derived from the pieces), a byte-constant block request
        (0xC9), and the far calls it makes;
      - GAME.OVR 0x32270: a byte parameter, a DS-table slot test, a read of the
        selector DS:[0x5376] and the far calls it makes; its VROOMM stub is located;
  * every decode-verified INT 21h site in both images, with the AH value taken from
    the instruction immediately before it;
  * callers of each candidate by decode-verified E8 near call, and by far call
    (9A) whose linear image address equals the target (model-conditional);
  * a far-call model check: whether far targets under the image-relative model
    `file = 0x200 + seg*16 + off` decode as routines, with a delta sweep;
  * a bounded call closure under that model, recording any INT 21h site reached;
  * the TOC of each 8X8D archive, read with the shared tools/por_map.parse_dax.

It binds no block to a PoR screen, no slot to a tile, and writes no mapping. Its
`unresolved_edges` list says exactly which far or indirect edges the bytes do not settle.

Usage
  python tools/por_8x8d_archive_chain_probe.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-8x8d-archive-chain-probe/retail [--allow-unpinned]

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_8x8d_archive_chain_probe.json        schema openua.por-8x8d-archive-chain-probe
  por_8x8d_archive_chain_probe_report.md   the readable summary

Exit codes
  0  every pin matched and the scan completed
  1  output written with a diagnostic (a pin or archive did not match, or a parse
     error was met); with --allow-unpinned the output is not retail evidence
  2  named refusal: missing install files, an output folder that is not under data/
     or is inside the install, or a file not matching its pin without --allow-unpinned
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Optional

import por_loadpieces_handler as h
import por_farcall_resolve as fr
import por_map
from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-8x8d-archive-chain-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_8x8d_archive_chain_probe.py"
EXE_NAME = "START.EXE"
OVR_NAME = "GAME.OVR"

PINNED_EXE = {k: v for k, v in fr.PINNED.items()}          # (size, sha256), shared resolver pins

X8D_PINS = {
    "8X8D1.DAX": (9711, "cce9313f23a600200fec60b5d46cd08aa9535a6143eee5d5d768a1d4e0415021"),
    "8X8D2.DAX": (12190, "418fc6cfa448646d3f0b590b53d1c926a0b308a521260469c0d06d05a7869cf4"),
    "8X8D3.DAX": (12967, "379aea0e70fe2f74512a2845176b3fb65d2d1f883abf661e7c8a9813e319c223"),
    "8X8D4.DAX": (14343, "02dbb15f007e8609d365dcbf47b1ae850bff577569e5b844931f9312569fa032"),
    "8X8D5.DAX": (5847, "90698c59d65d38b5cd4fb80c7ec8e9ad90f7ecce087d66dc47f5cf5b56ff3a2f"),
    "8X8D6.DAX": (10285, "f24577eec17af3bbfe0ee8517391157b4b655a35082429d2618de223c2021083"),
    "8X8D7.DAX": (9820, "d8086eb6b52f8a0b04156d67d2cfc16d4aefc571aad440285a55a601236bf0a2"),
    "8X8D8.DAX": (14510, "05590e593534715f26790a82f9dbaf1ee73e29e7b71a038ee039a3d64651c4d5"),
}

IMAGE_BASE = 0x200                 # MZ header size (e_cparhdr * 16) of START.EXE; checked in probe()
MAX_WALK = 800
MODEL_SEGS = (0x0AF8, 0x0899, 0x0802, 0x0464)
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")

# Anchors: entry points the probe starts from. Everything else is found from the bytes.
L_ROUTINE = 0x7245                 # START.EXE routine that follows the "8X8d1" + ".dax" pieces
L_CALLEE = (0x0802, 0x0716)        # far callee that takes the block-201 request byte
R_ROUTINE = 0x32270                # GAME.OVR routine that follows the "8x8d" + message pieces
SELECTOR_ADDR = 0x5376             # DS-relative selector read by R (also read by the GEO probe)
SLOT_TABLE = 0x5E3A                # DS table indexed 4*n by R's byte parameter

PIECE_RE = [
    ("stem", re.compile(rb"8x8d\d?", re.I)),
    ("ext", re.compile(rb"\.dax", re.I)),
    ("message", re.compile(rb"Unable to load 8x8D", re.I)),
]


class ProbeError(PorSourceError):
    """A named refusal, or a source that cannot be read as pinned."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve_folder(install: Path) -> Path:
    for cand in (install, install / "POOLRAD"):
        if (cand / OVR_NAME).is_file() and (cand / EXE_NAME).is_file():
            return cand
    raise ProbeError("no %s and %s pair found in %s or its POOLRAD folder"
                     % (OVR_NAME, EXE_NAME, install))


def _pinned_row(name: str, data: bytes, pin: tuple, allow_unpinned: bool) -> dict:
    size, sha = pin
    ok = len(data) == size and _sha(data) == sha
    if not ok and not allow_unpinned:
        raise ProbeError("%s does not match its pinned size and SHA-256" % name)
    return {"bytes": len(data), "sha256": _sha(data), "pin_match": ok}


# --------------------------------------------------------------------------
# Name pieces
# --------------------------------------------------------------------------

def pieces(data: bytes) -> list[dict]:
    """Every case-insensitive stem, extension and message occurrence at every offset.

    ``pascal`` is True when the byte before the match equals the match length, the
    Turbo Pascal length-prefixed form. ``block_start`` is that length byte."""
    rows = []
    for kind, rx in PIECE_RE:
        for m in rx.finditer(data):
            p = m.start()
            text = m.group(0)
            pascal = p >= 1 and data[p - 1] == len(text)
            rows.append({
                "kind": kind,
                "offset": p,
                "text": text.decode("ascii"),
                "pascal": pascal,
                "length_byte": p - 1 if pascal else None,
            })
    rows.sort(key=lambda r: (r["offset"], r["kind"]))
    return rows


# --------------------------------------------------------------------------
# Routine facts (decoded, ret-stopped walk from an entry)
# --------------------------------------------------------------------------

def routine(data: bytes, entry: int) -> dict:
    insns, err = h.linear(data, entry, MAX_WALK)
    if not insns:
        return {"entry": entry, "status": "decode-failed", "decode_error": err, "instructions": 0,
                "end": None, "last_flow": None, "last_at": None, "far_calls": [], "near_calls": [],
                "int21_sites": [], "cs_pointer_pushes": [], "byte_constants": [], "bp_plus6_reads": [],
                "bp_displacement_counts": {}, "selector_refs": [], "slot_table_refs": []}
    last = insns[-1]
    ret_complete = err is None and last.flow in ("ret", "retf")
    far = [{"at": i.off, "seg": i.far[0], "off": i.far[1]}
           for i in insns if i.flow == "call_far" and i.far]
    near = [{"at": i.off, "target": i.target}
            for i in insns if i.flow == "call" and i.target is not None]
    int21 = [i.off for i in insns if data[i.off:i.end] == b"\xcd\x21"]
    jcc = [{"at": i.off, "target": i.target} for i in insns if i.flow == "jcc" and i.target is not None]
    ptrs = []
    byte_consts = []
    for a, b in zip(insns, insns[1:]):
        if a.name.startswith("mov ") and a.length == 3 and a.imm is not None and b.name == "push cs":
            ptrs.append({"at": a.off, "imm": a.imm, "reg": a.name[4:]})
        if a.name.startswith("mov al") and a.imm is not None and a.length == 2:
            byte_consts.append({"at": a.off, "imm": a.imm})
    bp6 = [{"at": i.off, "text": i.text()} for i in insns if i.bp_disp == 6]
    bp_counts = Counter(i.bp_disp for i in insns if i.bp_disp is not None)
    bp_counts_out = {"%d" % k: v for k, v in sorted(bp_counts.items())}
    selector = [{"at": i.off, "text": i.text()} for i in insns if "[0x%x]" % SELECTOR_ADDR in i.text()]
    slot = [{"at": i.off, "text": i.text()} for i in insns if str(SLOT_TABLE) in i.text()
            or "0x%x" % SLOT_TABLE in i.text()]
    return {
        "entry": entry,
        "status": "ret-complete" if ret_complete else "walk-incomplete",
        "instructions": len(insns),
        "end": last.end,
        "last_flow": last.flow,
        "last_at": last.off,
        "decode_error": err,
        "far_calls": far,
        "near_calls": near,
        "int21_sites": int21,
        "conditional_jumps": jcc,
        "cs_pointer_pushes": ptrs,
        "byte_constants": byte_consts,
        "bp_plus6_reads": bp6,
        "bp_displacement_counts": bp_counts_out,
        "selector_refs": selector,
        "slot_table_refs": slot,
    }


# --------------------------------------------------------------------------
# DOS INT 21h inventory
# --------------------------------------------------------------------------

def int21_inventory(data: bytes) -> dict:
    """Every ``CD 21`` that starts an instruction, with the AH value set by the instruction
    immediately before it (``mov ah,imm8`` or ``mov ax,imm16``). ``ah`` is None when the
    immediate predecessor does not set it; such sites are counted, not guessed."""
    sites = []
    for i in range(len(data) - 1):
        if data[i] != 0xCD or data[i + 1] != 0x21:
            continue
        try:
            ins = h.decode(data, i)
        except h.DecodeError:
            continue
        if ins.length != 2:
            continue
        ah = None
        for p in range(i - 1, max(0, i - 4) - 1, -1):      # nearest predecessor first
            if data[p] not in (0xB4, 0xB8):                 # only mov ah,imm8 / mov ax,imm16 set AH
                continue
            try:
                pre = h.decode(data, p)
            except h.DecodeError:
                continue
            if pre.end != i:
                continue
            ah = data[p + 1] if data[p] == 0xB4 else (pre.imm or 0) >> 8
            break
        sites.append({"at": i, "ah": ah})
    counts = Counter("0x%02x" % s["ah"] if s["ah"] is not None else "unknown" for s in sites)
    return {"count": len(sites), "by_ah": dict(sorted(counts.items())), "sites": sites}


# --------------------------------------------------------------------------
# Callers (candidates; decode-verified where the instruction is decoded)
# --------------------------------------------------------------------------

def near_callers(data: bytes, target: int) -> list[dict]:
    out = []
    for i in range(len(data) - 2):
        if data[i] != 0xE8:
            continue
        if i + 3 + struct.unpack_from("<h", data, i + 1)[0] != target:
            continue
        try:
            ins = h.decode(data, i)
            status = ins.flow
        except h.DecodeError as exc:
            status = "decode-error:%s" % exc.reason
        out.append({"at": i, "site_decode": status})
    return out


def linear_far_callers(data: bytes, image_offset: int) -> list[dict]:
    """9A sites whose ``seg*16 + off`` equals ``image_offset`` (any split). Model-conditional."""
    out = []
    for i in range(len(data) - 4):
        if data[i] != 0x9A:
            continue
        off, seg = struct.unpack_from("<HH", data, i + 1)
        if seg * 16 + off != image_offset:
            continue
        try:
            ins = h.decode(data, i)
            status = ins.flow
        except h.DecodeError as exc:
            status = "decode-error:%s" % exc.reason
        out.append({"at": i, "segment_literal": "0x%04x" % seg, "offset_literal": "0x%04x" % off,
                    "site_decode": status})
    return out


def far_call_sites(data: bytes) -> list[tuple[int, int, int]]:
    """Decode-verified 9A far calls: (at, seg, off)."""
    out = []
    for i in range(len(data) - 4):
        if data[i] != 0x9A:
            continue
        try:
            ins = h.decode(data, i)
        except h.DecodeError:
            continue
        if ins.flow == "call_far" and ins.far:
            out.append((i, ins.far[0], ins.far[1]))
    return out


# --------------------------------------------------------------------------
# Model check and bounded closure (image-relative model; model-conditional)
# --------------------------------------------------------------------------

def _model_target(seg: int, off: int, delta: int = 0) -> int:
    return IMAGE_BASE + seg * 16 + off + delta


def model_check(start: bytes, sites: list[tuple[int, int, int]]) -> dict:
    targets = sorted({(s, o) for _, s, o in sites})
    rows = {}
    for seg in MODEL_SEGS:
        offs = [o for s, o in targets if s == seg]
        if not offs:
            continue
        d0_ret = d0_pro = d0_err = 0
        sweep = []
        for delta in range(-8, 9):
            ret_ok = 0
            for o in offs:
                f = _model_target(seg, o, delta)
                if not (0 <= f < len(start)):
                    continue
                ins, err = h.linear(start, f, MAX_WALK)
                if ins and err is None and ins[-1].flow in ("ret", "retf"):
                    ret_ok += 1
                if delta == 0:
                    if start[f:f + 3] in PROLOGUES:
                        d0_pro += 1
                    if err is not None:
                        d0_err += 1
            sweep.append((delta, ret_ok))
            if delta == 0:
                d0_ret = ret_ok
        best = max(sweep, key=lambda r: (r[1], -abs(r[0])))
        rows["0x%04x" % seg] = {
            "targets": len(offs),
            "delta0_ret_complete": d0_ret,
            "delta0_prologue": d0_pro,
            "delta0_decode_error": d0_err,
            "best_delta_by_ret_complete": best[0],
            "best_ret_complete": best[1],
        }
    return rows


def closure(start: bytes, roots: list[tuple[int, str]], depth: int = 3, budget: int = 60) -> list[dict]:
    """Breadth-first closure under the image model (far) and exact near targets."""
    seen: dict[int, dict] = {}
    q = deque((f, 0, lab) for f, lab in roots)
    while q and len(seen) < budget:
        f, dep, lab = q.popleft()
        if f in seen or not (0 <= f < len(start)):
            continue
        ins, err = h.linear(start, f, MAX_WALK)
        ints = [i.off for i in ins if start[i.off:i.end] == b"\xcd\x21"]
        seen[f] = {"entry": f, "from": lab, "depth": dep, "instructions": len(ins),
                   "decode_error": err, "int21_sites": ints}
        if dep >= depth:
            continue
        for i in ins:
            if i.flow == "call_far" and i.far:
                q.append((_model_target(i.far[0], i.far[1]), dep + 1,
                          "far 0x%04x:0x%04x at 0x%05x" % (i.far[0], i.far[1], i.off)))
            elif i.flow == "call" and i.target is not None:
                q.append((i.target, dep + 1, "near at 0x%05x" % i.off))
    return [seen[k] for k in sorted(seen)]


# --------------------------------------------------------------------------
# Pointer base check (a CS base derived from the pieces, tested on the other pointers)
# --------------------------------------------------------------------------

def pascal_printable(data: bytes, at: int) -> Optional[str]:
    """The Pascal string at ``at`` (length byte 1..60, then that many printable ASCII), or None."""
    if not (0 <= at < len(data)):
        return None
    n = data[at]
    if not (1 <= n <= 60) or at + 1 + n > len(data):
        return None
    body = data[at + 1:at + 1 + n]
    if all(0x20 <= c < 0x7F for c in body):
        return body.decode("ascii")
    return None


def _base_row(data: bytes, base: int, ptrs: list[dict], length_bytes: dict) -> dict:
    matched, unmatched = [], []
    for p in ptrs:
        tgt = base + p["imm"]
        if tgt in length_bytes:
            matched.append({"imm": "0x%04x" % p["imm"], "target": tgt, "piece": length_bytes[tgt]["text"]})
        else:
            label = pascal_printable(data, tgt)
            unmatched.append({"imm": "0x%04x" % p["imm"], "target": tgt,
                              "other": ("pascal %r" % label) if label is not None else "not-a-printable-pascal"})
    return {"cs_base": "0x%05x" % base, "matched": matched, "unmatched": unmatched}


def base_check(data: bytes, ptrs: list[dict], piece_rows: list[dict], preferred: Optional[int] = None) -> dict:
    """Test whether a CS base places each pointer on a length byte of a Pascal piece.

    ``candidates`` are the bases that place at least one pointer on a piece, derived
    from the first pointer and each piece; they are consistency tests, not proofs.
    ``preferred`` is a base established by other evidence (for GAME.OVR, the VROOMM
    body start from the descriptor), tested on its own."""
    length_bytes = {r["length_byte"]: r for r in piece_rows if r["pascal"]}
    if not ptrs:
        return {"candidates": [], "pointer_count": 0, "preferred": None}
    first = ptrs[0]["imm"]
    cands = sorted({lb - first for lb in length_bytes if 0 <= lb - first < len(data)})
    results = []
    for base in cands:
        row = _base_row(data, base, ptrs, length_bytes)
        if row["matched"]:
            results.append(row)
    results.sort(key=lambda r: (-len(r["matched"]), len(r["unmatched"])))
    pref = _base_row(data, preferred, ptrs, length_bytes) if preferred is not None else None
    return {"candidates": results[:8], "pointer_count": len(ptrs), "preferred": pref}


def immediates(data: bytes, entry: int) -> list[dict]:
    """Immediate operands of a ret-stopped walk, with their instruction offsets."""
    insns, _err = h.linear(data, entry, MAX_WALK)
    return [{"at": i.off, "imm": "0x%04x" % i.imm, "text": i.text()} for i in insns if i.imm is not None]


OVERLAY_HEADER_ROUTINE = 0xA728     # START.EXE routine that reads 8 header bytes of a file (decoded)


def containing_routines(data: bytes, site: int, back: int = 0x3000) -> list[dict]:
    """Prologue-entered routines whose ret-stopped walk contains ``site`` as an instruction."""
    out = []
    for p in range(max(0, site - back), site):
        if data[p:p + 3] not in PROLOGUES:
            continue
        ins, err = h.linear(data, p, MAX_WALK)
        if not ins or err is not None or ins[-1].flow not in ("ret", "retf"):
            continue
        if any(i.off == site for i in ins):
            out.append({"entry": p, "end": ins[-1].end})
    return out




# --------------------------------------------------------------------------
# Group and stub context for R (VROOMM descriptor, read through the shared resolver)
# --------------------------------------------------------------------------

def group_context(start: bytes, ovr: bytes, entry: int) -> dict:
    groups = fr.scan_groups(start, ovr)
    g = fr.group_containing_code(groups, entry)
    if g is None:
        return {"status": "no-group"}
    rel = entry - g["fileofs"]
    stub = None
    for k in range(g["stub_count"]):
        a = g["stub_start"] + fr.STUB_LEN * k
        if start[a:a + 2] == fr.STUB_OPCODE:
            word = struct.unpack_from("<H", start, a + 2)[0]
            if word == rel:
                stub = {"index": k, "start_file_offset": a, "word": "0x%04x" % word,
                        "bytes": start[a:a + fr.STUB_LEN].hex(" ")}
    return {
        "status": g["status"],
        "body_fileofs": g["fileofs"],
        "relative_entry": rel,
        "code_size": g["codesz"],
        "procs": ["0x%04x" % p for p in g["procs"]],
        "entry_is_proc": rel in g["procs"],
        "stub_start": g["stub_start"],
        "stub_count": g["stub_count"],
        "stub_matching_entry": stub,
    }


# --------------------------------------------------------------------------
# 8X8D archive TOCs (read-only, shared parser)
# --------------------------------------------------------------------------

def archive_tocs(install: Path, allow_unpinned: bool) -> dict:
    out = {}
    for name, pin in sorted(X8D_PINS.items()):
        path = install / name
        if not path.is_file():
            out[name] = {"status": "absent"}
            continue
        data = path.read_bytes()
        row = _pinned_row(name, data, pin, allow_unpinned)
        try:
            ents, base = por_map.parse_dax(data)
            row["toc"] = [{"index": e.index, "block_id": e.block_id, "raw_size": e.raw_size}
                          for e in ents]
            row["toc_base"] = base
        except Exception as exc:  # parse failures are recorded, not raised
            row["toc_error"] = str(exc)
        out[name] = row
    return out


# --------------------------------------------------------------------------
# Probe
# --------------------------------------------------------------------------

def chain_facts(start: bytes, ovr: bytes, tocs: dict) -> dict:
    exe_pieces = pieces(start)
    ovr_pieces = pieces(ovr)
    L = routine(start, L_ROUTINE)
    R = routine(ovr, R_ROUTINE)
    gctx = group_context(start, ovr, R_ROUTINE)
    L_base = base_check(start, L.get("cs_pointer_pushes", []), exe_pieces)
    R_base = base_check(ovr, R.get("cs_pointer_pushes", []), ovr_pieces,
                        preferred=gctx.get("body_fileofs"))
    int21_s = int21_inventory(start)
    open_sites = [s["at"] for s in int21_s["sites"] if s["ah"] == 0x3D]
    read_sites = [s["at"] for s in int21_s["sites"] if s["ah"] == 0x3F]
    dos_containment = {
        "open_3D": {"sites": ["0x%05x" % a for a in open_sites],
                    "containing": {"0x%05x" % a: containing_routines(start, a) for a in open_sites}},
        "read_3F": {"sites": ["0x%05x" % a for a in read_sites],
                    "containing": {"0x%05x" % a: containing_routines(start, a) for a in read_sites}},
    }
    overlay_probe = {
        "routine": routine(start, OVERLAY_HEADER_ROUTINE),
        "immediates": immediates(start, OVERLAY_HEADER_ROUTINE),
        "game_ovr_first_8_bytes": ovr[:8].hex(" "),
        "game_ovr_first_8_ascii": "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in ovr[:8]),
    }
    L_callee_closure = closure(start, [(_model_target(*L_CALLEE), "L far callee 0x%04x:0x%04x"
                                         % L_CALLEE)], depth=3, budget=60)
    R_callee_roots = [(_model_target(c["seg"], c["off"]), "R far callee 0x%04x:0x%04x at 0x%05x"
                       % (c["seg"], c["off"], c["at"])) for c in R.get("far_calls", [])]
    R_closure = closure(start, R_callee_roots, depth=2, budget=60)
    stub_k = gctx.get("stub_matching_entry")
    if stub_k is None:
        stub_callers = {"status": "no-stub-matches-entry"}
    else:
        stub_image = stub_k["start_file_offset"]
        stub_callers = {
            "status": "stub-located",
            "stub_file_offset": stub_image,
            "near_E8_in_START": near_callers(start, stub_image),
            "near_E8_in_GAME_OVR": near_callers(ovr, stub_image),
            "linear_far_9A_in_START": linear_far_callers(start, stub_image - IMAGE_BASE),
            "linear_far_9A_in_GAME_OVR": linear_far_callers(ovr, stub_image - IMAGE_BASE),
        }
    sites = far_call_sites(start)
    return {
        "pieces": {"START.EXE": exe_pieces, "GAME.OVR": ovr_pieces},
        "START_0x7245_routine": L,
        "START_0x7245_cs_base_check": L_base,
        "START_0x7245_callers": {"near_E8": near_callers(start, L_ROUTINE),
                                 "linear_far_9A": linear_far_callers(start, L_ROUTINE)},
        "START_0x7245_callee_closure_model": L_callee_closure,
        "GAME_OVR_0x32270_routine": R,
        "GAME_OVR_0x32270_cs_base_check": R_base,
        "GAME_OVR_0x32270_group": gctx,
        "GAME_OVR_0x32270_stub_callers": stub_callers,
        "GAME_OVR_0x32270_callee_closure_model": R_closure,
        "far_call_model_check_START": model_check(start, sites),
        "int21_START": int21_s,
        "int21_START_dos_containment": dos_containment,
        "START_0xA728_overlay_header_probe": overlay_probe,
        "int21_GAME_OVR": int21_inventory(ovr),
        "archive_tocs": tocs,
    }


UNRESOLVED = [
    {"id": "U1", "edge": "callers of START 0x7245 (block-201 request)",
     "status": "not-established", "why": "no decode-verified E8 or linear 9A site targets it"},
    {"id": "U2", "edge": "callers of GAME.OVR 0x32270 (R), including its VROOMM stub",
     "status": "not-established",
     "why": "no E8, and no 9A whose linear address equals the stub at START file 0x42DE"},
    {"id": "U3", "edge": "far calls 0x0802:0x0716 and 0x0AF8:0x0254 (and R's far callees)",
     "status": "model-conditional",
     "why": "the image model `0x200 + seg*16 + off` is not validated: START.EXE has no MZ "
            "relocation entries (e_crlc=0), and at delta 0 no far target begins a prologue; see "
            "far_call_model_check_START for the ret-complete counts"},
    {"id": "U4", "edge": "routine that contains the START INT 21h open (AH=3Dh, 0x0A8B6) and the "
                         "reads at 0x0A9B5, 0x0A9D6, 0x0B333, 0x0B374 (AH=3Fh)",
     "status": "not-established",
     "why": "no prologue-entered ret-complete walk contains them (int21_START_dos_containment). The one "
            "read that is contained, at 0x0A77A, is in the overlay header probe at 0xA728 (it compares "
            "the first 8 bytes with MZ, FB and OV and sets vector 3Fh), so it is not a DAX read"},
    {"id": "U5", "edge": "name construction: which archive the block-201 request reads from",
     "status": "not-established",
     "why": "the copies of \"8X8d1\" and \".dax\" into locals have no consumer in the routine; the "
            "callee 0x0802:0x0716 takes only the byte and two result slots"},
    {"id": "U6", "edge": "meaning of R's byte parameters [bp+6] (slot index) and [bp+8], and of the words at "
                         "DS:0x5E3A+4n and +2",
     "status": "not-established",
     "why": "0x0464:0x0111 is called unconditionally with ([bp+8], 1, 13, slot pointer) before the slot words "
            "are tested (a non-zero result jumps to the epilogue at 0x32364); the callee is not entered, so "
            "whether the words are a loaded-archive record is a hypothesis"},
    {"id": "U7", "edge": "use of R's pointer CS:0x39 (Pascal '-') and how the name is assembled",
     "status": "not-established",
     "why": "CS:0x20 (the 8x8d stem) and CS:0x25 (the message) match the group base, but the '-' string "
            "has no decoded consumer, and no extension literal is referenced by R"},
    {"id": "U8", "edge": "block-201 request id: the high byte of the pushed word",
     "status": "not-established", "why": "`mov al,0xc9` leaves AH as the prior value"},
]


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    folder = resolve_folder(install)
    exe = (folder / EXE_NAME).read_bytes()
    ovr = (folder / OVR_NAME).read_bytes()
    pins = {
        EXE_NAME: _pinned_row(EXE_NAME, exe, PINNED_EXE[EXE_NAME], allow_unpinned),
        OVR_NAME: _pinned_row(OVR_NAME, ovr, PINNED_EXE[OVR_NAME], allow_unpinned),
    }
    if fr.mz_image_base(exe) != IMAGE_BASE:
        raise ProbeError("START.EXE header base is not 0x200 (model constant)")
    tocs = archive_tocs(folder, allow_unpinned)
    facts = chain_facts(exe, ovr, tocs)
    # source immutability: hash again after the analysis
    after = {
        EXE_NAME: _sha((folder / EXE_NAME).read_bytes()),
        OVR_NAME: _sha((folder / OVR_NAME).read_bytes()),
    }
    unchanged = after[EXE_NAME] == pins[EXE_NAME]["sha256"] and after[OVR_NAME] == pins[OVR_NAME]["sha256"]
    all_pins = all(p["pin_match"] for p in pins.values()) and all(
        t.get("pin_match", False) for t in tocs.values() if "pin_match" in t)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "playable": False,
        "mappings": [],
        "binding_established": False,
        "verdict": "bounded-negative: no end-to-end DAX read path is established",
        "pins": pins,
        "source_unchanged": unchanged,
        "facts": facts,
        "unresolved_edges": UNRESOLVED,
    }
    code = 0 if (all_pins and unchanged) else 1
    if not unchanged:
        raise ProbeError("a pinned source changed during the run")
    if not all_pins:
        code = 1
    return doc, code


def _hx(v) -> str:
    return "n/a" if v is None else "0x%05x" % v


def render_report(doc: dict) -> str:
    f = doc["facts"]
    a = []
    a.append("# PoR 8X8D archive chain: bounded static probe (observe-only)")
    a.append("")
    a.append("Status: `%s`. `playable: false`. `mappings: []`. `binding_established: false`." % doc["status"])
    a.append("Verdict: %s." % doc["verdict"])
    a.append("")
    a.append("## Pins")
    a.append("")
    for name, row in doc["pins"].items():
        a.append("- `%s`: %d bytes, sha256 `%s`, pin match %s" % (name, row["bytes"], row["sha256"], row["pin_match"]))
    a.append("- source unchanged after the run: %s" % doc["source_unchanged"])
    a.append("")
    a.append("## START.EXE 0x7245 (name pieces, block request, far calls)")
    L = f["START_0x7245_routine"]
    a.append("")
    a.append("- status %s: %d instructions, ends %s (%s)" % (
        L["status"], L["instructions"], _hx(L["end"]), L["last_flow"]))
    a.append("- CS pointer pushes: %s" % ", ".join("0x%05x imm 0x%04x" % (p["at"], p["imm"]) for p in L["cs_pointer_pushes"]))
    a.append("- byte constants (mov al): %s" % ", ".join("0x%05x=0x%02x" % (b["at"], b["imm"]) for b in L["byte_constants"]))
    a.append("- far calls: %s" % ", ".join("0x%05x->0x%04x:0x%04x" % (c["at"], c["seg"], c["off"]) for c in L["far_calls"]))
    a.append("- CS base check (consistency, not proof): %s" % json.dumps(f["START_0x7245_cs_base_check"]["candidates"][:1]))
    a.append("")
    a.append("## GAME.OVR 0x32270 (byte parameter, selector, slot test, VROOMM stub)")
    R = f["GAME_OVR_0x32270_routine"]
    g = f["GAME_OVR_0x32270_group"]
    a.append("")
    a.append("- status %s: %d instructions, ends %s (%s)" % (
        R["status"], R["instructions"], _hx(R["end"]), R["last_flow"]))
    if "body_fileofs" in g:
        a.append("- group body 0x%05x, relative entry 0x%04x, entry is a proc: %s" % (
            g["body_fileofs"], g["relative_entry"], g["entry_is_proc"]))
    else:
        a.append("- group: %s" % g.get("status"))
    a.append("- stub matching entry: %s" % json.dumps(g.get("stub_matching_entry")))
    a.append("- selector reads: %s" % ", ".join(s["text"] for s in R["selector_refs"]))
    a.append("- CS pointer pushes: %s" % ", ".join("0x%05x imm 0x%04x" % (p["at"], p["imm"]) for p in R["cs_pointer_pushes"]))
    a.append("- CS pointers under the group body base (preferred): %s" % json.dumps(f["GAME_OVR_0x32270_cs_base_check"]["preferred"]))
    a.append("- byte parameter reads [bp+6]: %d; BP displacement counts: %s" % (len(R["bp_plus6_reads"]), json.dumps(R["bp_displacement_counts"])))
    a.append("- far calls: %d; INT 21h sites: %d" % (len(R["far_calls"]), len(R["int21_sites"])))
    a.append("")
    a.append("## INT 21h inventory")
    a.append("")
    a.append("- START.EXE: %d sites, by AH %s" % (f["int21_START"]["count"], json.dumps(f["int21_START"]["by_ah"])))
    a.append("- GAME.OVR: %d sites, by AH %s" % (f["int21_GAME_OVR"]["count"], json.dumps(f["int21_GAME_OVR"]["by_ah"])))
    for key in ("open_3D", "read_3F"):
        row = f["int21_START_dos_containment"][key]
        a.append("- %s sites %s; prologue-entered ret-complete containers: %s" % (
            key, row["sites"], json.dumps(row["containing"], sort_keys=True)))
    a.append("")
    a.append("## Far-call model check (START.EXE targets; model-conditional)")
    a.append("")
    for seg, row in f["far_call_model_check_START"].items():
        a.append("- seg %s: %s" % (seg, json.dumps(row, sort_keys=True)))
    a.append("")
    a.append("## 8X8D archive TOCs")
    a.append("")
    for name, row in doc["facts"]["archive_tocs"].items():
        if "toc" in row:
            a.append("- `%s`: block ids %s" % (name, [t["block_id"] for t in row["toc"]]))
    a.append("")
    a.append("## Unresolved edges")
    a.append("")
    for u in doc["unresolved_edges"]:
        a.append("- %s %s: %s. %s" % (u["id"], u["edge"], u["status"], u["why"]))
    a.append("")
    return "\n".join(a)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_8x8d_archive_chain_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_8x8d_archive_chain_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--install", required=True, type=Path)
    ap.add_argument("-o", "--out", required=True, type=Path)
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="analyse files that do not match their pins; output is not retail evidence")
    args = ap.parse_args(argv)
    try:
        folder = resolve_folder(args.install)
        validate_output_dir(folder, args.out)
        doc, code = probe(args.install, args.out, args.allow_unpinned)
    except ProbeError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    except PorSourceError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s" % (args.out / "por_8x8d_archive_chain_probe.json"))
    return code


if __name__ == "__main__":
    sys.exit(main())
