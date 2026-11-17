#!/usr/bin/env python3
"""Pool of Radiance: static caller and argument probe for the START.EXE 0x7180 chain.

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only apart from the repo's PoR helpers.
playable: false. mappings: []. binding_established: false.

Question this probe narrows (it does not answer it in general): does any caller on the
START.EXE routine chain that starts at 0x7180 select a block or tile of an 8X8D DAX
archive? 0x7180 is the layout-unique owner of the Pascal literal "8X8d1" at 0x723A
(docs/por-wall-render-probe.md). That owner is a layout candidate, not a reference.

What it measures, from the pinned retail bytes only:

  * the pins of START.EXE and GAME.OVR (size and SHA-256), taken before and after the run;
  * for each chain routine, a ret-stopped linear decode from its entry (the boundary rule
    of por_loadpieces_handler.linear): frame arguments, return width, near calls (E8),
    far calls (9A), INT instructions, port writes (DX tracked from `mov dx,imm`), direct
    data references with read/write, indexed memory operands, and far pointers loaded
    from the caller's frame (les/lds);
  * the callers of each chain routine. Decoded callers are E8 sites that decode as a call
    and lie on a ret-stopped walk from a prologue, and 9A sites whose literal resolves
    under the START image model (file = image base + seg*16 + off). Byte-pattern-only
    hits (zero-base 9A offsets, stub words, word-table hits) are labelled as candidates;
  * for each decoded call site, a straight-line forward simulation of the instructions
    before the call (cut at any control transfer) that gives the source of every pushed
    word: constant, caller frame [bp+d], local address, segment register, global memory,
    indexed memory, or unknown. A consistency check compares the words pushed with the
    callee's return width when the callee is decoded;
  * the existing far-call resolver's classification of every far literal in the chain;
  * byte-level references to the literal offset 0x723A and to the video-mode byte
    [0x4A1E], with the selector byte [0x484C] they test.

Evidence labels used in the output:
  decoded       the instruction decodes and lies on a ret-stopped walk from a prologue
  byte-pattern  the bytes match but the site is not on a decoded walk
  model         the result depends on the stated START image model

It binds nothing, opens no 8X8D archive, and writes no mapping. A constant argument that
happens to equal an 8X8D block id would not establish a binding, and this probe does not
test for one.

Usage
  python tools/por_8x8d_loader_probe.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-8x8d-loader-probe/retail [--allow-unpinned]

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_8x8d_loader_probe.json        schema openua.por-8x8d-loader-probe, playable: false
  por_8x8d_loader_probe_report.md   the readable summary

Exit codes
  0  every pin matched and every scan completed
  1  output written with a diagnostic (a pin did not match, under --allow-unpinned)
  2  named refusal: missing or ambiguous install files, an unsafe output location, or
     a file not matching its pin without --allow-unpinned
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

import por_farcall_resolve as farcall
import por_loadpieces_handler as h
import por_wall_render_probe as wrp
from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-8x8d-loader-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_8x8d_loader_probe.py"
OVR_NAME = farcall.OVR_NAME
EXE_NAME = farcall.EXE_NAME
PINNED = farcall.PINNED

LITERAL_OFF = 0x723A          # the Pascal piece "8X8d1" in START.EXE (length byte 0x723A)
LITERAL_TEXT = "8X8d1"
OWNER = 0x7180                # layout-unique owner of that literal (a candidate, not a reference)
MODE_ADDR = 0x4A1E            # video-mode byte, dispatched by the chain
SELECTOR_ADDR = 0x484C       # byte the mode is derived from (compared with 'E' and 'T')

PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
RET_FLOWS = ("ret", "retf")
MAX_WALK = 4000
WINDOW = 24                   # straight-line instructions simulated before a call site
MAX_DEPTH = 4                 # caller levels followed for forwarded arguments
NEAR_WINDOW = 0x400           # bytes searched backward for a prologue that reaches a site

# Chain routines (entry offsets in START.EXE file coordinates). Roles are inferred from
# the bytes in docs/por-8x8d-loader-probe.md; they are labels, not established names.
CHAIN = (
    ("owner-fill", OWNER),
    ("ega-page-select", 0x7169),
    ("ega-sequencer-reset", 0x70C9),
    ("clear-dispatch", 0x7D74),
    ("rect-erase-dispatch", 0x7E9C),
    ("text-window", 0x7831),
)

BYTE_REGS = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
WORD_REGS = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
HALVES = {"ax": ("al", "ah"), "cx": ("cl", "ch"), "dx": ("dl", "dh"), "bx": ("bl", "bh")}
SEG_PUSH = {0x06: "es", 0x0E: "cs", 0x16: "ss", 0x1E: "ds"}
SEG_POP = {0x07: "es", 0x17: "ss", 0x1F: "ds"}
WRITE_OPS = (0x88, 0x89, 0xA2, 0xA3, 0xC6, 0xC7)
STRING_OPS = (0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF)
DIRECT_OPS = (0x80, 0x81, 0x83, 0x88, 0x89, 0x8A, 0x8B, 0x38, 0x39, 0x3A, 0x3B,
              0xC6, 0xC7, 0xFE, 0xFF)

NOT_ESTABLISHED = [
    "Which routine, if any, calls the chain's top-level entries 0x7D74 and 0x7831. "
    "No decoded or byte-pattern caller was found for either.",
    "The bodies of the far callees 0x0AF8:xxxx and 0x0899:xxxx. They are not stub-classified "
    "under the START image model and their identity is not established.",
    "Whether the layout owner 0x7180 is the routine that reads the literal 8X8d1 or any "
    "8X8D archive. No reference from its body or from any decoded caller to 0x723A exists.",
    "Which 8X8D block, tile or bank any caller selects. No caller passes a block or tile "
    "index in any decoded argument.",
    "The palette, the transparency rule, and any screen equivalence with the DOS game.",
]

# --------------------------------------------------------------------------
# Errors and small helpers
# --------------------------------------------------------------------------


class ProbeError(PorSourceError):
    """A named refusal: missing files, an unpinned file without the flag, or an unsafe output."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%04x" % v


def _mov_dx_imm(ins: h.Insn) -> bool:
    return ins.op == 0xBA


# --------------------------------------------------------------------------
# Routine profiles (decoded, ret-stopped)
# --------------------------------------------------------------------------

def _rm_is_write(ins: h.Insn) -> bool:
    """Coarse read/write for a direct data operand: stores and read-modify-write forms."""
    if ins.op in WRITE_OPS or ins.op in (0xA2, 0xA3):
        return True
    reg = ins.modrm[1] if ins.modrm else None
    if ins.op in (0x80, 0x81, 0x83) and reg is not None and reg != 7:
        return True
    if ins.op in (0xFE, 0xFF) and reg in (0, 1):
        return True
    if ins.op in (0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7) and reg is not None and reg != 7:
        return True
    return False


def routine_profile(data: bytes, entry: int) -> dict:
    """Ret-stopped linear profile of the routine at ``entry`` (file offset)."""
    prologue = data[entry:entry + 3] in PROLOGUES
    insns, err = h.linear(data, entry, MAX_WALK)
    if not insns:
        return {"entry": _hex(entry), "status": "decode-failed", "reason": err,
                "prologue": prologue}
    last = insns[-1]
    ret = last if last.flow in RET_FLOWS else None
    bp_args = sorted({i.bp_disp for i in insns if i.bp_disp is not None and i.bp_disp >= 6})
    bp_locals = sorted({i.bp_disp for i in insns if i.bp_disp is not None and i.bp_disp < 0})
    near = []
    far = []
    indirect = []
    ints = []
    ports = []
    direct = []
    indexed = []
    frame_far_ptr = []
    string_ops = []
    dx_val: Optional[int] = None
    for ins in insns:
        if ins.flow == "call":
            near.append({"at": _hex(ins.off), "target": _hex(ins.target)})
        elif ins.flow == "call_far":
            far.append({"at": _hex(ins.off), "seg": "0x%04x" % ins.far[0],
                        "off": "0x%04x" % ins.far[1]})
        elif ins.flow in ("indirect_call", "indirect_callf"):
            indirect.append({"at": _hex(ins.off), "text": ins.text()})
        if ins.op == 0xCD:
            ints.append({"at": _hex(ins.off), "vector": "0x%02x" % ins.imm})
        if ins.op in (0xE4, 0xE5, 0xE6, 0xE7, 0xEC, 0xED, 0xEE, 0xEF):
            port = ins.imm if ins.op in (0xE4, 0xE5, 0xE6, 0xE7) else dx_val
            ports.append({"at": _hex(ins.off), "op": "out" if ins.op in (0xE6, 0xE7, 0xEE, 0xEF)
                          else "in", "port": None if port is None else "0x%04x" % port})
        if ins.direct is not None and ins.op not in (0x8D,):
            direct.append({"at": _hex(ins.off), "addr": "0x%04x" % ins.direct,
                           "rw": "write" if _rm_is_write(ins) else "read", "op": "0x%02x" % ins.op})
        if (ins.op in (0xC4, 0xC5) and ins.bp_disp is not None):
            frame_far_ptr.append({"at": _hex(ins.off), "bp_disp": ins.bp_disp,
                                  "op": "les" if ins.op == 0xC4 else "lds"})
        if (ins.mem is not None and ins.direct is None and ins.modrm is not None
                and ins.modrm[0] != 3 and ins.op != 0x8D and ins.bp_disp is None
                and ins.modrm[2] in (0, 1, 2, 3, 4, 5, 7)):
            indexed.append({"at": _hex(ins.off), "text": ins.mem,
                            "rw": "write" if _rm_is_write(ins) else "read"})
        if ins.op in STRING_OPS:
            string_ops.append({"at": _hex(ins.off), "op": "0x%02x" % ins.op})
        # track DX only through `mov dx,imm` and invalidate it on other DX writes
        if _mov_dx_imm(ins):
            dx_val = ins.imm
        elif ins.op in (0x99, 0xF7) or (ins.op == 0x8B and ins.modrm and ins.modrm[1] == 2) \
                or (ins.op == 0x89 and ins.modrm and ins.modrm[0] == 3 and ins.modrm[2] == 2):
            dx_val = None
    pixel_sources = []
    for f in frame_far_ptr:
        pixel_sources.append({"kind": "far-pointer-from-frame", **f})
    for x in indexed:
        if x["rw"] == "read":
            pixel_sources.append({"kind": "indexed-read", **x})
    for s in string_ops:
        if s["op"] in ("0xa4", "0xa5", "0xac", "0xad"):
            pixel_sources.append({"kind": "string-read", **s})
    return {
        "entry": _hex(entry),
        "prologue": prologue,
        "status": "decoded" if ret is not None else "no-ret-within-walk",
        "instructions": len(insns),
        "walk_stop": err if ret is None else "ret",
        "ret_at": _hex(ret.off) if ret is not None else None,
        "ret_flow": ret.flow if ret is not None else None,
        "return_bytes": ret.imm if (ret is not None and ret.imm is not None) else 0,
        "frame_args_bp": bp_args,
        "frame_locals_bp": bp_locals,
        "near_calls": near,
        "far_calls": far,
        "indirect_calls": indirect,
        "int_calls": ints,
        "port_io": ports,
        "direct_refs": direct,
        "indexed_refs": indexed,
        "frame_far_pointers": frame_far_ptr,
        "pixel_source_candidates": pixel_sources,
        "file_io_candidates": [i for i in ints if i["vector"] == "0x21"],
    }


def _ret_bytes_of(data: bytes, entry: int) -> Optional[int]:
    prof = routine_profile(data, entry)
    return prof.get("return_bytes") if prof.get("ret_at") else None


# --------------------------------------------------------------------------
# Decoded-boundary test for a site, and the containing routine
# --------------------------------------------------------------------------

def containing_walk(data: bytes, site: int) -> Optional[tuple[int, list]]:
    """The nearest prologue whose ret-stopped linear walk passes ``site`` on an instruction
    boundary. Returns (entry, insns) or None. A site found only by byte pattern is not
    on any walk and returns None."""
    for p in range(site - 1, max(-1, site - NEAR_WINDOW - 1), -1):
        if data[p:p + 3] not in PROLOGUES:
            continue
        insns, _err = h.linear(data, p, MAX_WALK)
        if any(ins.off == site for ins in insns):
            return p, insns
    return None


# --------------------------------------------------------------------------
# Straight-line simulation of the instructions before a call site
# --------------------------------------------------------------------------

def _init_state() -> dict:
    st = {r: ("unknown", "entry") for r in BYTE_REGS}
    st.update({r: ("unknown", "entry") for r in ("sp", "bp", "si", "di")})
    st.update({s: ("unknown", "entry") for s in ("cs", "ds", "es", "ss")})
    return st


def _word(st: dict, r: str) -> tuple:
    if r in HALVES:
        return st[HALVES[r][0]], st[HALVES[r][1]]
    return st[r], st[r]


def _set_word(st: dict, r: str, lo: tuple, hi: tuple) -> None:
    if r in HALVES:
        st[HALVES[r][0]] = lo
        st[HALVES[r][1]] = hi
    else:
        st[r] = lo


def _unknown(why: str) -> tuple:
    return ("unknown", why)


def _mem_src(ins: h.Insn, size: int) -> tuple:
    if ins.bp_disp is not None:
        return ("bp", ins.bp_disp, size)
    if ins.direct is not None:
        return ("mem", ins.direct, size)
    return ("index", ins.mem or "?", size)


def simulate(window: list) -> dict:
    """Forward simulation of a straight-line window. Returns the pushes in order.

    Each word push is (lo, hi) source tuples; each segment push names the segment.
    Registers the model does not track are set to unknown, so an unmodelled write can
    only make an argument less specific, never more."""
    st = _init_state()
    pushes: list[dict] = []
    for ins in window:
        op = ins.op
        mod, reg, rm = ins.modrm if ins.modrm else (None, None, None)
        if 0xB0 <= op <= 0xB7:
            st[BYTE_REGS[op & 7]] = ("const", ins.imm)
        elif 0xB8 <= op <= 0xBF:
            r = WORD_REGS[op & 7]
            if r in HALVES:
                _set_word(st, r, ("const", ins.imm & 0xFF), ("const", ins.imm >> 8))
            else:
                _set_word(st, r, ("const", ins.imm), ("const", ins.imm))
        elif op == 0x8A:
            st[BYTE_REGS[reg]] = st[BYTE_REGS[rm]] if mod == 3 else _mem_src(ins, 8)
        elif op == 0x8B:
            if mod == 3:
                lo, hi = _word(st, WORD_REGS[rm])
                _set_word(st, WORD_REGS[reg], lo, hi)
            else:
                v = _mem_src(ins, 16)
                _set_word(st, WORD_REGS[reg], v, v)
        elif op == 0x88 and mod == 3:
            st[BYTE_REGS[rm]] = st[BYTE_REGS[reg]]
        elif op == 0x89 and mod == 3:
            lo, hi = _word(st, WORD_REGS[reg])
            _set_word(st, WORD_REGS[rm], lo, hi)
        elif op == 0x8D:
            if ins.bp_disp is not None:
                v = ("lea", ins.bp_disp, 16)
                _set_word(st, WORD_REGS[reg], v, v)
            else:
                _set_word(st, WORD_REGS[reg], _unknown("lea"), _unknown("lea"))
        elif op in (0xC4, 0xC5):
            if ins.bp_disp is not None:
                v = ("bp", ins.bp_disp, 16)
                _set_word(st, WORD_REGS[reg], v, v)
                st["es" if op == 0xC4 else "ds"] = ("bp", ins.bp_disp + 2, 16)
            else:
                _set_word(st, WORD_REGS[reg], _unknown("les-lds"), _unknown("les-lds"))
        elif op == 0xA0 and ins.direct is not None:
            st["al"] = ("mem", ins.direct, 8)
        elif op == 0xA1 and ins.direct is not None:
            v = ("mem", ins.direct, 16)
            _set_word(st, "ax", v, v)
        elif op == 0x30 and mod == 3 and reg == rm:
            st[BYTE_REGS[rm]] = ("const", 0)
        elif op == 0x98:
            st["ah"] = ("sext", st["al"])
        elif op == 0x99:
            st["dl"] = st["dh"] = ("sext", st["ah"])
        elif op in SEG_PUSH:
            pushes.append({"kind": "seg", "seg": SEG_PUSH[op], "at": ins.off})
        elif op in SEG_POP:
            st[SEG_POP[op]] = _unknown("seg-pop")
        elif 0x50 <= op <= 0x57:
            lo, hi = _word(st, WORD_REGS[op & 7])
            pushes.append({"kind": "word", "reg": WORD_REGS[op & 7], "lo": lo, "hi": hi,
                           "at": ins.off})
        elif 0x58 <= op <= 0x5F:
            r = WORD_REGS[op & 7]
            _set_word(st, r, _unknown("pop"), _unknown("pop"))
        elif op == 0xFF and reg == 6:
            v = _mem_src(ins, 16) if mod != 3 else _word(st, WORD_REGS[rm])[0]
            pushes.append({"kind": "word", "reg": "mem", "lo": v, "hi": v, "at": ins.off})
        elif 0x40 <= op <= 0x4F:
            r = WORD_REGS[op & 7]
            _set_word(st, r, _unknown("incdec"), _unknown("incdec"))
        elif op < 0x40 and (op & 7) < 6 and (op >> 3) != 7:
            sub = op & 7
            if sub in (0, 1) and mod == 3:
                if sub == 0:
                    st[BYTE_REGS[rm]] = _unknown("alu")
                else:
                    _set_word(st, WORD_REGS[rm], _unknown("alu"), _unknown("alu"))
            elif sub in (2, 3):
                if sub == 2:
                    st[BYTE_REGS[reg]] = _unknown("alu")
                else:
                    _set_word(st, WORD_REGS[reg], _unknown("alu"), _unknown("alu"))
            elif sub in (4, 5):
                if sub == 4:
                    st["al"] = _unknown("alu")
                else:
                    _set_word(st, "ax", _unknown("alu"), _unknown("alu"))
        elif op in (0x80, 0x81, 0x83) and mod == 3 and reg != 7:
            if op == 0x80:
                st[BYTE_REGS[rm]] = _unknown("grp1")
            else:
                _set_word(st, WORD_REGS[rm], _unknown("grp1"), _unknown("grp1"))
        elif op in (0xFE, 0xFF) and mod == 3 and reg in (0, 1):
            if op == 0xFE:
                st[BYTE_REGS[rm]] = _unknown("incdec")
            else:
                _set_word(st, WORD_REGS[rm], _unknown("incdec"), _unknown("incdec"))
        elif op in (0xD0, 0xD1, 0xD2, 0xD3) and mod == 3:
            if op in (0xD0, 0xD2):
                st[BYTE_REGS[rm]] = _unknown("shift")
            else:
                _set_word(st, WORD_REGS[rm], _unknown("shift"), _unknown("shift"))
        elif op in (0xF6, 0xF7) and mod is not None and reg in (4, 5, 6, 7):
            if op == 0xF6:
                st["al"] = st["ah"] = _unknown("mul-div")
            else:
                _set_word(st, "ax", _unknown("mul-div"), _unknown("mul-div"))
                _set_word(st, "dx", _unknown("mul-div"), _unknown("mul-div"))
        elif op in (0x86, 0x87) and mod is not None:
            if mod == 3:
                if op == 0x86:
                    st[BYTE_REGS[rm]] = _unknown("xchg")
                else:
                    _set_word(st, WORD_REGS[rm], _unknown("xchg"), _unknown("xchg"))
            if op == 0x86:
                st[BYTE_REGS[reg]] = _unknown("xchg")
            else:
                _set_word(st, WORD_REGS[reg], _unknown("xchg"), _unknown("xchg"))
        elif op in (0xAC, 0xAD):
            if op == 0xAC:
                st["al"] = _unknown("lods")
            else:
                _set_word(st, "ax", _unknown("lods"), _unknown("lods"))
        elif op in (0xE4, 0xE5, 0xEC, 0xED):
            if op in (0xE4, 0xEC):
                st["al"] = _unknown("in")
            else:
                _set_word(st, "ax", _unknown("in"), _unknown("in"))
        elif op in (0xC6, 0xC7) and mod == 3:
            if op == 0xC6:
                st[BYTE_REGS[rm]] = ("const", ins.imm)
            else:
                _set_word(st, WORD_REGS[rm], ("const", ins.imm & 0xFF), ("const", ins.imm >> 8))
        elif op == 0x8F and mod == 3:
            _set_word(st, WORD_REGS[rm], _unknown("pop"), _unknown("pop"))
        elif mod == 3 and op not in (0x84, 0x85, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xA8, 0xA9,
                                     0x90, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xF5):
            # any other register-destination form: the destination is no longer known
            if op & 1:
                _set_word(st, WORD_REGS[rm], _unknown("other"), _unknown("other"))
            else:
                st[BYTE_REGS[rm]] = _unknown("other")
    return {"pushes": pushes, "final": {k: v for k, v in st.items() if k in ("al", "ah", "ax")}}


def describe(src: tuple) -> str:
    kind = src[0]
    if kind == "const":
        return "0x%x" % src[1]
    if kind == "bp":
        return "[bp%+d]/%d" % (src[1], src[2])
    if kind == "lea":
        return "lea bp%+d" % src[1]
    if kind == "mem":
        return "[0x%04x]/%d" % (src[1], src[2])
    if kind == "index":
        return "[%s]/%d" % (src[1], src[2])
    if kind == "sext":
        return "sext(%s)" % describe(src[1]) if isinstance(src[1], tuple) else "sext"
    return "?(%s)" % (src[1] if len(src) > 1 else "")


def classify_src(src: tuple) -> str:
    kind = src[0]
    if kind == "const":
        return "const"
    if kind == "bp":
        # [bp+6] and above are the caller's words; negative offsets are the routine's locals
        return "frame-forward" if src[1] >= 6 else "frame-local"
    if kind == "lea":
        return "local-address"
    if kind == "mem":
        return "global-memory"
    if kind == "index":
        return "indexed-memory"
    if kind == "sext":
        return classify_src(src[1]) if isinstance(src[1], tuple) else "unknown"
    return "unknown"


def classify_word(lo: tuple, hi: tuple) -> tuple[str, str]:
    """Class and text for a pushed 16-bit word from its low and high byte sources."""
    if lo[0] == "const" and hi[0] == "const":
        return "const", "0x%x" % ((lo[1] & 0xFF) | ((hi[1] & 0xFF) << 8))
    if lo[0] == "const" and hi[0] == "unknown":
        return "const", "0x%x (high byte not established)" % (lo[1] & 0xFF)
    if lo == hi and lo[0] in ("bp", "mem", "index", "lea"):
        return classify_src(lo), describe(lo)
    if hi[0] == "unknown" and lo[0] in ("bp", "mem", "index") and lo[2] == 8:
        return classify_src(lo), "low byte %s; high byte not established" % describe(lo)
    classes = [classify_src(x) for x in (lo, hi)]
    for c in ("indexed-memory", "global-memory"):
        if c in classes:
            return c, "%s / %s" % (describe(lo), describe(hi))
    if "frame-forward" in classes:
        return "frame-forward", "%s / %s" % (describe(lo), describe(hi))
    return classify_src(lo), "%s / %s" % (describe(lo), describe(hi))


def call_window(insns: list, idx: int) -> list:
    """The straight-line instructions before insns[idx], cut at the previous control transfer."""
    out = []
    j = idx - 1
    while j >= 0 and len(out) < WINDOW:
        ins = insns[j]
        if ins.flow != "seq" or ins.op in (0xE8, 0x9A, 0xC2, 0xC3, 0xCA, 0xCB):
            break
        # frame setup (push bp; mov bp,sp) is not an argument push, so the window stops there
        if ins.op == 0x55 or (ins.op == 0x89 and ins.modrm == (3, 4, 5)):
            break
        out.insert(0, ins)
        j -= 1
    return out


def trace_site(insns: list, site: int, near: bool, callee_bytes: Optional[int]) -> dict:
    """Argument sources of the call at ``site`` within its decoded containing walk."""
    idx = next((k for k, i in enumerate(insns) if i.off == site), None)
    if idx is None:
        return {"status": "not-on-walk"}
    win = call_window(insns, idx)
    sim = simulate(win)
    pushes = sim["pushes"]
    far_by_near = bool(near and pushes and pushes[-1]["kind"] == "seg"
                       and pushes[-1]["seg"] == "cs")
    # addresses written by direct stores earlier in the same walk (a save/restore shows here)
    written = {ins.direct for ins in insns[:idx] if ins.direct is not None and _rm_is_write(ins)}
    words = [p for p in pushes if p["kind"] == "word"]
    args = []
    n = len(words)
    for k, p in enumerate(words):
        cls, text = classify_word(p["lo"], p["hi"])
        src = p["lo"] if p["lo"][0] == "mem" else p["hi"]
        if cls == "global-memory":
            cls = "global-restore" if src[0] == "mem" and src[1] in written else "global-read"
        param_bp = (6 + 2 * (n - 1 - k)) if callee_bytes is not None else None
        args.append({"slot": k, "pushed_from": p["reg"], "class": cls, "source": text,
                     "callee_param_bp": param_bp, "at": _hex(p["at"])})
    seg_pushes = [p["seg"] for p in pushes if p["kind"] == "seg"]
    width_match = None
    if callee_bytes is not None:
        width_match = (2 * n == callee_bytes)
    return {
        "status": "traced",
        "window_len": len(win),
        "far_by_near": far_by_near,
        "word_args": n,
        "segment_pushes": seg_pushes,
        "frame_width_match": width_match,
        "forwards_frame": any(a["class"] == "frame-forward" for a in args),
        "args": args,
    }


def verdict_for(trace: dict) -> str:
    """Priority: register-indexed memory, then unclassified, then fixed-address state, then
    forwarded frame words, then constants and locals only. A fixed address is not index
    evidence on its own."""
    if trace.get("status") != "traced":
        return "not-traced"
    classes = [a["class"] for a in trace["args"]]
    if "indexed-memory" in classes:
        return "index-like-argument"
    if "unknown" in classes:
        return "unclassified-argument"
    if any(c in ("global-read", "global-restore") for c in classes):
        return "global-state-argument"
    if "frame-forward" in classes:
        return "forwards-caller-frame"
    return "constants-and-locals-only"


# --------------------------------------------------------------------------
# Callers of a target (decoded and byte-pattern candidates)
# --------------------------------------------------------------------------

def find_callers(start: bytes, ovr: bytes, target: int) -> dict:
    """Callers of ``target`` (a START.EXE file offset). Decoded sites are E8 sites on a
    walk and 9A sites that decode; byte-pattern-only hits are listed as candidates."""
    image = farcall.mz_image_base(start)
    decoded: list[dict] = []
    candidates: list[dict] = []
    for fname, data in ((EXE_NAME, start), (OVR_NAME, ovr)):
        for i in range(len(data) - 2):
            if data[i] == 0xE8:
                rel = struct.unpack_from("<h", data, i + 1)[0]
                if i + 3 + rel != target:
                    continue
                try:
                    ins = h.decode(data, i)
                except h.DecodeError as exc:
                    candidates.append({"file": fname, "at": _hex(i), "kind": "near",
                                       "why": "decode-error:%s" % exc.reason})
                    continue
                cw = containing_walk(data, i) if fname == EXE_NAME else None
                if cw is None:
                    candidates.append({"file": fname, "at": _hex(i), "kind": "near",
                                       "why": "decodes-as-call-off-walk"})
                    continue
                entry, insns = cw
                trace = trace_site(insns, i, True, _ret_bytes_of(start, target))
                decoded.append({"file": fname, "at": _hex(i), "kind": "near",
                                "containing_routine": _hex(entry), "trace": trace,
                                "verdict": verdict_for(trace)})
        for i in range(len(data) - 4):
            if data[i] != 0x9A:
                continue
            off = struct.unpack_from("<H", data, i + 1)[0]
            seg = struct.unpack_from("<H", data, i + 3)[0]
            model = None
            if seg * 16 + off == target - image:
                model = "start-image"
            elif off == target:
                model = "zero-base-offset-only"
            if model is None:
                continue
            try:
                ins = h.decode(data, i)
            except h.DecodeError as exc:
                candidates.append({"file": fname, "at": _hex(i), "kind": "far", "model": model,
                                   "seg": "0x%04x" % seg, "off": "0x%04x" % off,
                                   "why": "decode-error:%s" % exc.reason})
                continue
            if model == "start-image" and fname == EXE_NAME:
                cw = containing_walk(data, i)
                if cw is not None:
                    entry, insns = cw
                    trace = trace_site(insns, i, False, None)
                    decoded.append({"file": fname, "at": _hex(i), "kind": "far", "model": model,
                                    "seg": "0x%04x" % seg, "off": "0x%04x" % off,
                                    "containing_routine": _hex(entry), "trace": trace,
                                    "verdict": verdict_for(trace)})
                    continue
            candidates.append({"file": fname, "at": _hex(i), "kind": "far", "model": model,
                               "seg": "0x%04x" % seg, "off": "0x%04x" % off,
                               "why": "decodes-off-walk" if ins else "other"})
    # VROOMM stub form CD 3F <word> 00 whose word equals the target offset (candidates)
    stub_hits = []
    for fname, data in ((EXE_NAME, start), (OVR_NAME, ovr)):
        for w in (target, target - image):
            pat = b"\xcd\x3f" + struct.pack("<H", w & 0xFFFF) + b"\x00"
            for k in _find_all(data, pat):
                stub_hits.append({"file": fname, "at": _hex(k), "word": "0x%04x" % (w & 0xFFFF)})
    # word-table hits at any alignment (noise-prone; counted, never treated as a caller).
    # A hit right after a VROOMM descriptor magic (CD 3F 00 00) is a descriptor field.
    word_hits = {}
    for fname, data in ((EXE_NAME, start), (OVR_NAME, ovr)):
        hits = _find_all(data, struct.pack("<H", target))
        desc = [k for k in hits if k >= 4 and data[k - 4:k] == b"\xcd\x3f\x00\x00"]
        word_hits[fname] = {"count": len(hits), "after_vroomm_descriptor_magic": len(desc),
                            "first": [_hex(k) for k in hits[:8]]}
    return {
        "decoded": decoded,
        "candidates": candidates,
        "stub_form_hits": stub_hits,
        "word_table_hits": word_hits,
    }


def _direct_refs(data: bytes, addr: int) -> list[dict]:
    """Decode-checked instructions that address DS:addr directly (modrm mod 00 rm 110 with any
    reg field, or moffs). The byte pattern is a filter only; the decoder's direct field must
    equal ``addr`` for the site to count."""
    out = []
    pat = struct.pack("<H", addr)
    for i in range(len(data) - 3):
        op = data[i]
        if op in (0xA0, 0xA1, 0xA2, 0xA3):
            if data[i + 1:i + 3] != pat:
                continue
        elif op in DIRECT_OPS:
            if (data[i + 1] & 0xC7) != 0x06 or data[i + 2:i + 4] != pat:
                continue
        else:
            continue
        try:
            ins = h.decode(data, i)
        except h.DecodeError:
            continue
        if ins.direct != addr:
            continue
        rw = "write" if (op in (0xA2, 0xA3) or _rm_is_write(ins)) else "read"
        out.append({"at": _hex(i), "op": "0x%02x" % op, "text": ins.text(), "rw": rw,
                    "imm": None if ins.imm is None else "0x%x" % ins.imm})
    return out


def _find_all(data: bytes, pat: bytes) -> list[int]:
    out, k = [], data.find(pat)
    while k >= 0:
        out.append(k)
        k = data.find(pat, k + 1)
    return out


def literal_refs(start: bytes, ovr: bytes) -> dict:
    """Byte-level references to the literal offset 0x723A as an immediate or a direct address.
    The push-cs pointer forms are covered by por_wall_render_probe and are not repeated."""
    out = {}
    for fname, data in ((EXE_NAME, start), (OVR_NAME, ovr)):
        imm_hits = []
        pat = struct.pack("<H", LITERAL_OFF)
        for i in range(len(data) - 2):
            if 0xB8 <= data[i] <= 0xBF and data[i + 1:i + 3] == pat:
                imm_hits.append({"at": _hex(i), "form": "mov-r16-imm"})
            if data[i] in (0x05, 0x3D, 0x68) and data[i + 1:i + 3] == pat:
                imm_hits.append({"at": _hex(i), "form": "imm16-byte-pattern"})
        moffs = [r for r in _direct_refs(data, LITERAL_OFF)]
        out[fname] = {"imm_byte_candidates": imm_hits, "direct_refs": moffs}
    return out


def mode_writers(start: bytes) -> dict:
    """Every decode-checked write to the video-mode byte [0x4A1E], and the reads of the
    selector byte [0x484C] that precede them."""
    refs = _direct_refs(start, MODE_ADDR)
    writes = [r for r in refs if r["rw"] == "write"]
    reads = [r for r in refs if r["rw"] == "read"]
    selector = _direct_refs(start, SELECTOR_ADDR)
    return {
        "mode_addr": "0x%04x" % MODE_ADDR,
        "writes": writes,
        "reads": reads,
        "selector_addr": "0x%04x" % SELECTOR_ADDR,
        "selector_refs": selector,
    }


def far_callee_table(start: bytes, ovr: bytes, sites: list[tuple]) -> list[dict]:
    """Classification of far literals in the chain by the existing resolver (read-only).
    ``sites`` holds (routine, call site offset, seg, off) tuples."""
    calls = [{"at": at, "seg": seg, "off": off} for _, at, seg, off in sites]
    if not calls:
        return []
    try:
        res = farcall.resolve(start, ovr, calls)
        resolver_error = None
    except (ValueError, KeyError, IndexError, struct.error) as exc:
        res = {"far_calls": []}
        resolver_error = "%s: %s" % (type(exc).__name__, exc)
    rows = []
    image = farcall.mz_image_base(start)
    by_at = {r["at"]: r for r in res.get("far_calls", [])}
    for _, at, seg, off in sites:
        r = by_at.get(at, {})
        target_file = image + seg * 16 + off
        head = start[target_file:target_file + 8].hex(" ") if 0 <= target_file < len(start) else ""
        try:
            dec = h.decode(start, target_file)
            dec_text = dec.text()
        except (h.DecodeError, IndexError):
            dec_text = None
        rows.append({"resolver_error": resolver_error, "at": _hex(at), "seg": "0x%04x" % seg, "off": "0x%04x" % off,
                     "image_model_file": _hex(target_file),
                     "classification": r.get("classification",
                                             "resolver-error" if resolver_error else "unresolved"),
                     "bytes_at_target": head, "decodes_as": dec_text})
    return rows


# --------------------------------------------------------------------------
# The analysis
# --------------------------------------------------------------------------

def analyze(start: bytes, ovr: bytes) -> dict:
    routines = {}
    names = {}
    for name, entry in CHAIN:
        routines[_hex(entry)] = routine_profile(start, entry)
        names[_hex(entry)] = name
    # one level of near callees (decoded) for each chain routine
    closure = {}
    for key, prof in list(routines.items()):
        for c in prof.get("near_calls", []):
            t = int(c["target"], 16)
            if _hex(t) not in routines and _hex(t) not in closure:
                closure[_hex(t)] = routine_profile(start, t)
    routines_all = dict(routines)
    routines_all.update(closure)

    callers = {}
    for name, entry in CHAIN:
        callers[_hex(entry)] = find_callers(start, ovr, entry)

    # forwarded arguments: follow each decoded caller whose verdict forwards a frame word
    upstream = {}
    for key in callers:
        upstream[key] = _upstream(start, ovr, int(key, 16), 0)

    far_sites = []
    seen = set()
    for key, prof in routines_all.items():
        for f in prof.get("far_calls", []):
            at = int(f["at"], 16)
            if at in seen:
                continue
            seen.add(at)
            far_sites.append((key, at, int(f["seg"], 16), int(f["off"], 16)))
    far_table = far_callee_table(start, ovr, far_sites)

    literal = literal_refs(start, ovr)
    modes = mode_writers(start)

    index_like = []
    unclassified = []
    for key, entry_callers in callers.items():
        for c in entry_callers["decoded"]:
            if c["verdict"] == "index-like-argument":
                index_like.append({"callee": key, "site": c["at"]})
            if c["verdict"] == "unclassified-argument":
                unclassified.append({"callee": key, "site": c["at"]})
    tops = [k for k in callers if not callers[k]["decoded"]]
    pixel_routines = [k for k, p in routines.items() if p.get("pixel_source_candidates")]
    int_in_chain = [k for k, p in routines_all.items() if p.get("int_calls")]
    doc = {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "question": "Does any caller on the START.EXE 0x7180 chain select a block or tile of an "
                    "8X8D DAX archive?",
        "answer": "not-established",
        "binding_established": False,
        "playable": False,
        "mappings": [],
        "chain_names": {k: v for k, v in names.items()},
        "routines": routines,
        "near_closure": closure,
        "callers": callers,
        "upstream": upstream,
        "far_callees": far_table,
        "literal": {"text": LITERAL_TEXT, "offset": "0x%04x" % LITERAL_OFF,
                    "layout_owner_candidate": _hex(OWNER), "refs": literal},
        "video_mode": modes,
        "summary": {
            "owner_fill_color_source": _fill_color_source(start),
            "owner_fill_pushes": _fill_pushes(start),
            "index_like_call_sites": index_like,
            "unclassified_call_sites": unclassified,
            "entries_without_decoded_caller": tops,
            "routines_with_pixel_source_candidates": pixel_routines,
            "routines_with_int_calls": int_in_chain,
        },
        "not_established": NOT_ESTABLISHED,
    }
    return doc


def _fill_color_source(start: bytes) -> dict:
    """The source of the last word pushed before the owner's far fill call (the colour byte)."""
    insns, _err = h.linear(start, OWNER, MAX_WALK)
    far = [i for i in insns if i.flow == "call_far"]
    if not far:
        return {"status": "no-far-call"}
    site = far[0].off
    idx = next(k for k, i in enumerate(insns) if i.off == site)
    sim = simulate(call_window(insns, idx))
    words = [p for p in sim["pushes"] if p["kind"] == "word"]
    if not words:
        return {"status": "no-word-push", "site": _hex(site)}
    last = words[-1]
    cls, text = classify_word(last["lo"], last["hi"])
    return {"status": "traced", "site": _hex(site), "last_pushed_class": cls, "source": text,
            "expected": "frame-forward [bp+6] (the colour byte of the rectangle fill)"}


def _fill_pushes(start: bytes) -> list[dict]:
    """Every push in the straight-line window before the owner's far call, with its source.
    The callee's arity is not established, so these are reported as pushed, not as parameters."""
    insns, _err = h.linear(start, OWNER, MAX_WALK)
    far = [i for i in insns if i.flow == "call_far"]
    if not far:
        return []
    idx = next(k for k, i in enumerate(insns) if i.off == far[0].off)
    out = []
    for p in simulate(call_window(insns, idx))["pushes"]:
        if p["kind"] == "seg":
            out.append({"at": _hex(p["at"]), "pushed": p["seg"], "class": "segment",
                        "source": p["seg"]})
        else:
            cls, text = classify_word(p["lo"], p["hi"])
            cls = "global-read" if cls == "global-memory" else cls
            out.append({"at": _hex(p["at"]), "pushed": p["reg"], "class": cls, "source": text})
    return out


def _upstream(start: bytes, ovr: bytes, target: int, depth: int) -> list[dict]:
    """For each decoded caller of ``target`` that forwards a frame word, the callers of that
    caller, up to MAX_DEPTH. A terminal entry with no decoded caller is recorded as such."""
    if depth >= MAX_DEPTH:
        return []
    out = []
    for c in find_callers(start, ovr, target)["decoded"]:
        if not c["trace"].get("forwards_frame"):
            continue
        up_target = int(c["containing_routine"], 16)
        up = find_callers(start, ovr, up_target)["decoded"]
        out.append({"from": c["at"], "routine": c["containing_routine"],
                    "decoded_callers": [u["at"] for u in up],
                    "next": _upstream(start, ovr, up_target, depth + 1) if up else [],
                    "terminal": not up})
    return out


# --------------------------------------------------------------------------
# Report, outputs, and CLI
# --------------------------------------------------------------------------

def _render_upstream(key: str, items: list, depth: int) -> list[str]:
    out = []
    pad = "  " * depth
    if depth == 0:
        if not items:
            return ["- %s: no decoded caller that forwards a frame word" % key]
        out.append("- %s:" % key)
    for it in items:
        tag = "terminal, no decoded caller" if it["terminal"] else \
            "decoded callers of %s: %s" % (it["routine"], ", ".join(it["decoded_callers"]))
        out.append("%s  - via call at %s in routine %s (%s)" % (pad, it["from"], it["routine"], tag))
        out.extend(_render_upstream(it["routine"], it["next"], depth + 1))
    return out


def render_report(doc: dict) -> str:
    lines: list[str] = []
    a = lines.append
    a("# Pool of Radiance: 0x7180 chain, caller and argument probe (static)")
    a("")
    a("**Status: %s. `playable: false`. `mappings: []`. `binding_established: false`.**" % doc["status"])
    a("**Answer: %s.** %s" % (doc["answer"], doc["question"]))
    a("")
    s = doc["summary"]
    a("- Call sites with register-indexed arguments: %d. Chain entries with no decoded caller: %s."
      % (len(s["index_like_call_sites"]), ", ".join(s["entries_without_decoded_caller"]) or "none"))
    a("- Routines with a pixel-source operand (far pointer from frame, register-indexed or string "
      "read): %s. Routines with INT calls: %s." % (
          ", ".join(s["routines_with_pixel_source_candidates"]) or "none",
          ", ".join(s["routines_with_int_calls"]) or "none"))
    a("")
    a("## Pins")
    a("")
    for name, info in doc.get("pins", {}).items():
        a("- `%s`: %d bytes, sha256 `%s`, pin match %s" % (name, info["bytes"], info["sha256"],
                                                          info["pin_match"]))
    a("")
    a("## Chain routines (decoded, ret-stopped)")
    a("")
    a("| entry | role (inferred) | ret | return bytes | arg bp | near calls | far calls | INT | ports | pixel-source candidates |")
    a("| --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |")
    for key in sorted(doc["routines"]):
        r = doc["routines"][key]
        a("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %d |" % (
            key, doc["chain_names"].get(key, ""), r.get("ret_at"), r.get("return_bytes"),
            ",".join(str(x) for x in r.get("frame_args_bp", [])),
            ",".join(c["target"] for c in r.get("near_calls", [])),
            ",".join(f["seg"] + ":" + f["off"] for f in r.get("far_calls", [])),
            ",".join(i["vector"] for i in r.get("int_calls", [])) or "none",
            ",".join(p["port"] or "?" for p in r.get("port_io", [])) or "none",
            len(r.get("pixel_source_candidates", []))))
    a("")
    a("## Callers (decoded sites first; byte-pattern candidates separate)")
    a("")
    for key in sorted(doc["callers"]):
        c = doc["callers"][key]
        a("### %s (%s)" % (key, doc["chain_names"].get(key, "")))
        a("")
        if not c["decoded"]:
            a("- No decoded caller. Byte-pattern candidates: %d. Stub-form hits: %d. "
              "Word-table hits (noise-prone): %s." % (len(c["candidates"]), len(c["stub_form_hits"]),
                                                     c["word_table_hits"]))
        for d in c["decoded"]:
            t = d["trace"]
            a("- %s `%s` %s in `%s`: verdict `%s`, far-by-near %s, word args %s, "
              "frame width match %s" % (d["file"], d["at"], d["kind"], d["containing_routine"],
                                       d["verdict"], t.get("far_by_near"), t.get("word_args"),
                                       t.get("frame_width_match")))
            for arg in t.get("args", []):
                a("    - slot %d (%s): %s, source %s" % (arg["slot"], arg["pushed_from"],
                                                         arg["class"], arg["source"]))
        a("")
    a("## Forwarded arguments (caller chain upward)")
    a("")
    a("A caller that forwards its own frame word is followed to that routine's callers, up to "
      "%d levels. A terminal entry has no decoded caller, so the argument's origin is not "
      "established above it." % MAX_DEPTH)
    a("")
    for key in sorted(doc["upstream"]):
        for line in _render_upstream(key, doc["upstream"][key], 0):
            a(line)
    a("")
    a("## Far callees (existing resolver, read-only)")
    a("")
    a("| call site | literal | image-model file offset | classification | bytes at target | decodes as |")
    a("| --- | --- | --- | --- | --- | --- |")
    for f in doc["far_callees"]:
        a("| %s | %s:%s | %s | %s | `%s` | %s |" % (f["at"], f["seg"], f["off"], f["image_model_file"],
                                                 f["classification"], f["bytes_at_target"],
                                                 f["decodes_as"] or "no"))
    a("")
    a("## Literal and video-mode references")
    a("")
    a("- Literal `%s` at `%s`: owner candidate `%s` (layout only)." % (
        doc["literal"]["text"], doc["literal"]["offset"], doc["literal"]["layout_owner_candidate"]))
    for fname, refs in doc["literal"]["refs"].items():
        a("  - %s: %d immediate candidates, %d direct references" % (
            fname, len(refs["imm_byte_candidates"]), len(refs["direct_refs"])))
    a("- Video-mode byte `%s`: %d writes, %d reads in START.EXE." % (
        doc["video_mode"]["mode_addr"], len(doc["video_mode"]["writes"]),
        len(doc["video_mode"]["reads"])))
    for w in doc["video_mode"]["writes"]:
        a("  - write at `%s`: `%s`" % (w["at"], w["text"]))
    a("- Selector byte `%s` references (START.EXE): %s" % (
        doc["video_mode"]["selector_addr"],
        "; ".join("`%s` %s (%s)" % (r["at"], r["text"], r["rw"])
                  for r in doc["video_mode"]["selector_refs"]) or "none"))
    a("")
    a("## Owner far-fill call (0x7209): pushes in the window before the call")
    a("")
    a("The callee's arity is not established. These are the pushed words, in order, with the "
      "source the simulation gives each one.")
    a("")
    for p in doc["summary"]["owner_fill_pushes"]:
        a("- `%s` pushed %s: %s, source %s" % (p["at"], p["pushed"], p["class"], p["source"]))
    a("")
    a("## Not established")
    a("")
    for item in doc["not_established"]:
        a("- " + item)
    a("")
    return "\n".join(lines) + "\n"


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    folder = wrp.resolve_folder(install)
    out = validate_output_dir(folder, out)
    ovr_path, exe_path = folder / OVR_NAME, folder / EXE_NAME
    before = {p.name: _sha(p.read_bytes()) for p in (ovr_path, exe_path)}
    ovr = ovr_path.read_bytes()
    start = exe_path.read_bytes()
    pins = {}
    diagnostics = []
    for name, data in ((OVR_NAME, ovr), (EXE_NAME, start)):
        size, sha = PINNED[name]
        ok = len(data) == size and _sha(data) == sha
        pins[name] = {"bytes": len(data), "sha256": _sha(data), "pin_match": ok}
        if not ok:
            if not allow_unpinned:
                raise ProbeError("%s does not match its pinned size and SHA-256 (use "
                                 "--allow-unpinned to probe it anyway; the output is not "
                                 "retail evidence)" % name)
            diagnostics.append("%s is not its pinned file; output is not retail evidence" % name)
    doc = analyze(start, ovr)
    doc["pins"] = pins
    doc["diagnostics"] = diagnostics
    doc["retail_evidence"] = all(p["pin_match"] for p in pins.values())
    after = {p.name: _sha(p.read_bytes()) for p in (ovr_path, exe_path)}
    doc["source_unchanged"] = before == after
    if not doc["source_unchanged"]:
        raise ProbeError("source bytes changed during the run")
    code = 0 if doc["retail_evidence"] and doc["source_unchanged"] else 1
    return doc, code


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_8x8d_loader_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_8x8d_loader_probe_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Pool of Radiance 0x7180 chain caller and argument probe.")
    ap.add_argument("--install", required=True, type=Path,
                    help="the DOS install folder or its POOLRAD folder (read-only)")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="probe files that do not match their pins (output is not retail evidence)")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out, args.allow_unpinned)
    except PorSourceError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s and %s (answer=%s, binding_established=false, playable=false, mappings=%d)" % (
        args.out / "por_8x8d_loader_probe.json", args.out / "por_8x8d_loader_probe_report.md",
        doc["answer"], len(doc["mappings"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
