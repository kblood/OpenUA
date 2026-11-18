#!/usr/bin/env python3
"""Bound-update probe: the far module routine 0x0AF8:0x0432, called twice from 0x0AF8:0x03D3.

0x03D3 is the release helper that the wrapper 0x0AF8:0x0254 calls. It calls 0x0432 twice (module
offsets 0x0426 and 0x042B) and 0x0491 once (0x03F9). The module-target note says 0x0432 "stores DS:0x4404
and DS:0x4406", and reads the two calls as a free-list bound update. This probe reads the pinned START.EXE
bytes and asks: what are the exact instructions of 0x03D3, 0x0432 and 0x0491 (and the blocks they reach),
which registers each one reads before it writes them, which stores each one makes and where they land,
who calls them, and which of the stores can touch the bound slots DS:0x4400..0x4407 or the list head
DS:0x440C.

Read-only and stdlib-only, apart from the existing modules it imports: por_loadpieces_handler (a length,
flow and target cross-check only), por_wall_0111_module_target_probe (module constants), and
por_geo_copy_helper_probe (pins, handler base, dump anchor). It writes only under
data/work/por-wall-0111-bound-update-probe/.

The decoder here is its own. The repo decoder's text() drops register operands for memory-form
instructions (it prints `add [di+4]` for `26 03 4d 04`, which is `add cx,es:[di+4]`), so every operand in
this file is read from the ModRM byte. The repo decoder is used only to check length, flow and target.

Every claim is conditional on the module mapping of the module-target note (file = 0xAC76 + module
offset, live segment 0x235E). Nothing here runs the code, reads a bound or head value, or says what the
allocator does at run time. "Reads as" describes the bytes; the bytes are the evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_overlay_group_map as om  # noqa: E402
import por_geo_copy_helper_probe as gcp  # noqa: E402
import por_loadpieces_handler as lp  # noqa: E402
import por_wall_0111_module_target_probe as mt  # noqa: E402

Refusal = om.Refusal
SCHEMA = "openua.por-wall-0111-bound-update-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "bound-update-probe-only"
TOOL = "tools/por_wall_0111_bound_update_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-wall-0111-bound-update-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMPS = gcp.DEFAULT_DUMPS
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"

MODULE_SEG = mt.MODULE_SEG            # 0x0AF8
EXPECT_LOAD = mt.EXPECT_LOAD          # 0x1866
EXPECT_BASE = 0xAC76                  # module file base (routine-B handler pattern; module-target note)
PARA = 16

# Module offsets of the routines this probe decodes. Each span is inclusive and is decoded linearly; the
# linear decode must land exactly on its end. The spans are contiguous: 0x03D3..0x0431, 0x0432..0x0490,
# 0x0491..0x04A1.
ENTRY_RELEASE = 0x03D3
ENTRY_LINK = 0x0432
ENTRY_SIZE = 0x0491
SPAN_RANGES = {
    ENTRY_RELEASE: (0x03D3, 0x0431),
    ENTRY_LINK: (0x0432, 0x0490),
    ENTRY_SIZE: (0x0491, 0x04A1),
}
SPAN_NAMES = {ENTRY_RELEASE: "0x03D3", ENTRY_LINK: "0x0432", ENTRY_SIZE: "0x0491"}

# Bound and head slots, DS-relative. Low bound = DS:0x4400 (offset) and DS:0x4402 (segment); high bound
# = DS:0x4404 (offset) and DS:0x4406 (segment). The head slot is the far pointer at DS:0x440C.
SLOT_RANGES = {
    "low": range(0x4400, 0x4404),
    "high": range(0x4404, 0x4408),
    "head": range(0x440C, 0x4410),
}

# Checked against the decode (the "flag producer -> consumer" pairs of the size and normalisation
# arithmetic). A flag producer and its consumer must be separated only by flag-neutral instructions.
FLAG_PAIRS = (
    (0x0491, "add ax,0x7", 0x0496, "rcr dx,1"),
    (0x0442, "add cl,0xf0", 0x0445, "adc bx,0x0"),
    (0x047C, "add al,0xf0", 0x047E, "adc dx,0x0"),
)

NOT_ESTABLISHED = [
    "That any of these routines runs at any instant, or with which arguments: the caller's DS, the size, the block and the list state are not measured.",
    "The values of DS:0x4400..0x4407 and DS:0x440C..0x440F at any instant: the bytes write and read them; no value is read from any dump here.",
    "That the list is ordered, initialised, or sentinel-terminated as the reading below suggests: the reading comes from the compare and store shapes only.",
    "What the allocator does at run time: the search that feeds 0x0254 (0x0308 and its successors) was not decoded here, so whether the top bound is ever raised is not shown.",
    "The order and the data conditions of the two calls in 0x03D3: the bytes fix the order (first with the successor, then with the predecessor) and the compare shapes; which branch each call takes depends on values that were not measured.",
    "The predecessor of the first block: when the insertion point is the head, the predecessor is DS:0x440C itself; the bytes do not say whether DS:0x4410..0x4413 holds a sane size in that case.",
    "Whether a free node can be adjacent to the top bound when the release absorbs a block into it; the bytes handle that case with the same compare, and no invariant is decoded.",
    "Indirect callers of 0x0432 or 0x03D3 (far pointers in data, jump tables): only direct byte candidates were searched.",
    "The meaning of node offsets other than 0 and 8, and of size lo-words other than 0 and 8, for nodes that did not come from 0x03D3. The normalisation is exact only under those ranges.",
    "The zero-size and bad-offset error codes of the wrapper: the wrapper's carry convention is taken from the module-target note; the error join at module 0x00E2 was not decoded.",
]


class Unsupported(Exception):
    """An opcode outside the subset this probe decodes. The probe fails closed on it."""


REG16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
REG8 = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
SREGS = ("es", "cs", "ss", "ds")
PARENT = {"al": "ax", "ah": "ax", "cl": "cx", "ch": "cx", "dl": "dx", "dh": "dx", "bl": "bx", "bh": "bx"}
ALU = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFT = ("rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar")
JCC = {0x70: "jo", 0x71: "jno", 0x72: "jb", 0x73: "jnb", 0x74: "jz", 0x75: "jnz", 0x76: "jbe", 0x77: "ja",
       0x78: "js", 0x79: "jns", 0x7A: "jp", 0x7B: "jnp", 0x7C: "jl", 0x7D: "jge", 0x7E: "jle", 0x7F: "jg"}
SEG_PREFIX = {0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds"}
ADDR_REGS = {0: ("bx", "si"), 1: ("bx", "di"), 2: ("bp", "si"), 3: ("bp", "di"), 4: ("si",), 5: ("di",),
             6: ("bp",), 7: ("bx",)}
# Instructions that do not change the flags. A producer and its consumer may be separated only by these.
FLAG_NEUTRAL = frozenset({"mov", "xchg", "push", "pop", "les", "lds", "lodsb", "lodsw", "movsb", "movsw",
                          "stosb", "stosw", "nop"})


# ---- byte readers -------------------------------------------------------------------------------

def _byte(d: bytes, p: int) -> int:
    if not 0 <= p < len(d):
        raise Unsupported("truncated at 0x%x" % p)
    return d[p]


def _u16(d: bytes, p: int) -> int:
    if p < 0 or p + 2 > len(d):
        raise Unsupported("truncated word at 0x%x" % p)
    return int.from_bytes(d[p:p + 2], "little")


def _s8(v: int) -> int:
    return v - 256 if v >= 128 else v


def _s16(d: bytes, p: int) -> int:
    v = _u16(d, p)
    return v - 65536 if v >= 32768 else v


# ---- ModRM and operands ------------------------------------------------------------------------

def _modrm(d: bytes, p: int, seg_ovr: Optional[str]) -> dict:
    m = _byte(d, p)
    p += 1
    mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
    if mod == 3:
        return {"mod": 3, "reg": reg, "rm": rm, "p": p, "mem": None}
    if mod == 0 and rm == 6:
        addr = _u16(d, p)
        p += 2
        seg = seg_ovr or "ds"
        mem = {"seg": seg, "direct": addr, "base": (), "disp": 0, "text": "%s:[0x%04x]" % (seg, addr)}
        return {"mod": 0, "reg": reg, "rm": rm, "p": p, "mem": mem}
    base = ADDR_REGS[rm]
    seg = seg_ovr or ("ss" if rm in (2, 3, 6) else "ds")
    disp = 0
    if mod == 1:
        disp = _s8(_byte(d, p))
        p += 1
    elif mod == 2:
        disp = _s16(d, p)
        p += 2
    inner = "+".join(base)
    if disp > 0:
        inner += "+%d" % disp
    elif disp < 0:
        inner += "%d" % disp
    mem = {"seg": seg, "direct": None, "base": base, "disp": disp, "text": "%s:[%s]" % (seg, inner)}
    return {"mod": mod, "reg": reg, "rm": rm, "p": p, "mem": mem}


def _reg_name(width: int, n: int) -> str:
    return (REG16 if width == 16 else REG8)[n]


def _rm(m: dict, width: int) -> tuple:
    """(operand text, registers the address uses, memory operand or None, register written or None)."""
    if m["mem"] is None:
        r = _reg_name(width, m["rm"])
        return r, set(), None, r
    mem = m["mem"]
    return mem["text"], set(mem["base"]) | {mem["seg"]}, mem, None


def _def_reg(r: str, width: int, uses: set, defs: set) -> None:
    """A register written by an instruction. An 8-bit write is partial: it also reads the other byte."""
    if r in SREGS:
        defs.add(r)
        return
    parent = PARENT.get(r, r)
    if width == 16:
        defs.add(parent)
    else:
        uses.add(parent)


def _mrec(mem: dict, access: str, width: int) -> dict:
    return {"seg": mem["seg"], "text": mem["text"], "direct": mem["direct"], "access": access,
            "width": width}


# ---- instruction record and decoder ------------------------------------------------------------

@dataclass
class Ins:
    off: int                      # file offset
    base: int                     # file offset of module offset 0
    length: int
    raw: bytes
    name: str
    text: str                     # module-relative, Intel-style operands
    flow: str                     # seq, jcc, jmp, call, ret, retf
    target: Optional[int]         # file offset of a near branch target
    uses: frozenset
    defs: frozenset
    mems: list = field(default_factory=list)

    @property
    def mo(self) -> int:
        return self.off - self.base

    @property
    def end(self) -> int:
        return self.off + self.length

    @property
    def tmo(self) -> Optional[int]:
        return None if self.target is None else self.target - self.base


def decode(d: bytes, off: int, base: int) -> Ins:
    """Decode one instruction of the subset at file offset `off`. Raises Unsupported outside the subset."""
    p = off
    seg_ovr = None
    while _byte(d, p) in SEG_PREFIX:
        seg_ovr = SEG_PREFIX[d[p]]
        p += 1
    op = _byte(d, p)
    p += 1
    uses: set = set()
    defs: set = set()
    mems: list = []
    flow, target, name = "seq", None, ""
    text = ""

    if op < 0x40 and (op & 7) < 6:
        name, sub = ALU[op >> 3], op & 7
        if sub >= 4:
            width = 8 if sub == 4 else 16
            if width == 8:
                imm = _byte(d, p)
                p += 1
                acc = "al"
            else:
                imm = _u16(d, p)
                p += 2
                acc = "ax"
            uses.add(PARENT.get(acc, acc))
            if name != "cmp":
                _def_reg(acc, width, uses, defs)
            text = "%s %s,0x%x" % (name, acc, imm)
        else:
            width = 8 if sub in (0, 2) else 16
            m = _modrm(d, p, seg_ovr)
            p = m["p"]
            rtext, addr, mem, rreg = _rm(m, width)
            rn = _reg_name(width, m["reg"])
            uses |= addr
            if rreg:
                uses.add(PARENT.get(rreg, rreg))
            if sub < 2:  # r/m op= reg
                text = "%s %s,%s" % (name, rtext, rn)
                uses.add(PARENT.get(rn, rn))
                if rreg and name != "cmp":
                    _def_reg(rreg, width, uses, defs)
            else:        # reg op= r/m
                text = "%s %s,%s" % (name, rn, rtext)
                uses.add(PARENT.get(rn, rn))
                if name != "cmp":
                    _def_reg(rn, width, uses, defs)
            if mem:
                mems.append(_mrec(mem, "read" if name == "cmp" else ("rmw" if sub < 2 else "read"), width))
    elif op in (0x80, 0x81, 0x83):
        width = 8 if op == 0x80 else 16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        if op == 0x81:
            imm = _u16(d, p)
            p += 2
        else:
            raw_imm = _byte(d, p)
            p += 1
            imm = raw_imm if op == 0x80 else (raw_imm | 0xFF00 if raw_imm >= 0x80 else raw_imm)
        name = ALU[m["reg"]]
        rtext, addr, mem, rreg = _rm(m, width)
        uses |= addr
        if rreg:
            uses.add(PARENT.get(rreg, rreg))
            if name != "cmp":
                _def_reg(rreg, width, uses, defs)
        text = "%s %s,0x%x" % (name, rtext, imm)
        if mem:
            mems.append(_mrec(mem, "read" if name == "cmp" else "rmw", width))
    elif op in (0x84, 0x85):
        width = 8 if op == 0x84 else 16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        rtext, addr, mem, rreg = _rm(m, width)
        rn = _reg_name(width, m["reg"])
        name = "test"
        uses |= addr | {PARENT.get(rn, rn)}
        if rreg:
            uses.add(PARENT.get(rreg, rreg))
        text = "test %s,%s" % (rtext, rn)
        if mem:
            mems.append(_mrec(mem, "read", width))
    elif op in (0x88, 0x89, 0x8A, 0x8B):
        width = 8 if op in (0x88, 0x8A) else 16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        rtext, addr, mem, rreg = _rm(m, width)
        rn = _reg_name(width, m["reg"])
        name = "mov"
        if op in (0x88, 0x89):   # r/m <- reg
            text = "mov %s,%s" % (rtext, rn)
            uses |= addr | {PARENT.get(rn, rn)}
            if rreg:
                _def_reg(rreg, width, uses, defs)
            if mem:
                mems.append(_mrec(mem, "write", width))
        else:                    # reg <- r/m
            text = "mov %s,%s" % (rn, rtext)
            uses |= addr
            if rreg:
                uses.add(PARENT.get(rreg, rreg))
            _def_reg(rn, width, uses, defs)
            if mem:
                mems.append(_mrec(mem, "read", width))
    elif op == 0x8C:            # r/m16 <- sreg
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        rtext, addr, mem, rreg = _rm(m, 16)
        sn = SREGS[m["reg"]]
        name = "mov"
        text = "mov %s,%s" % (rtext, sn)
        uses |= addr | {sn}
        if rreg:
            _def_reg(rreg, 16, uses, defs)
        if mem:
            mems.append(_mrec(mem, "write", 16))
    elif op == 0x8E:            # sreg <- r/m16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        rtext, addr, mem, rreg = _rm(m, 16)
        sn = SREGS[m["reg"]]
        name = "mov"
        text = "mov %s,%s" % (sn, rtext)
        uses |= addr
        if rreg:
            uses.add(PARENT.get(rreg, rreg))
        defs.add(sn)
        if mem:
            mems.append(_mrec(mem, "read", 16))
    elif op in (0xC4, 0xC5):    # les / lds reg, mem
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        if m["mem"] is None:
            raise Unsupported("les/lds with a register operand at 0x%x" % off)
        name = "les" if op == 0xC4 else "lds"
        rtext, addr, mem, _ = _rm(m, 16)
        rn = REG16[m["reg"]]
        text = "%s %s,%s" % (name, rn, rtext)
        uses |= addr
        defs.add(rn)
        defs.add("es" if op == 0xC4 else "ds")
        mems.append(_mrec(mem, "read", 32))
    elif op in (0xC6, 0xC7):    # mov r/m, imm
        width = 8 if op == 0xC6 else 16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        if width == 16:
            imm = _u16(d, p)
            p += 2
        else:
            imm = _byte(d, p)
            p += 1
        rtext, addr, mem, rreg = _rm(m, width)
        name = "mov"
        text = "mov %s,0x%x" % (rtext, imm)
        uses |= addr
        if rreg:
            _def_reg(rreg, width, uses, defs)
        if mem:
            mems.append(_mrec(mem, "write", width))
    elif op in (0xD0, 0xD1, 0xD2, 0xD3):   # shift/rotate group 2
        width = 8 if op in (0xD0, 0xD2) else 16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        rtext, addr, mem, rreg = _rm(m, width)
        name = SHIFT[m["reg"]]
        count = "cl" if op in (0xD2, 0xD3) else "1"
        text = "%s %s,%s" % (name, rtext, count)
        uses |= addr
        if rreg:
            uses.add(PARENT.get(rreg, rreg))
            _def_reg(rreg, width, uses, defs)
        if op in (0xD2, 0xD3):
            uses.add("cx")
        if mem:
            mems.append(_mrec(mem, "rmw", width))
    elif op in (0xF6, 0xF7):    # group 3: test / not / neg only
        width = 8 if op == 0xF6 else 16
        m = _modrm(d, p, seg_ovr)
        p = m["p"]
        rtext, addr, mem, rreg = _rm(m, width)
        sub = m["reg"]
        uses |= addr
        if rreg:
            uses.add(PARENT.get(rreg, rreg))
        if sub == 0:
            if width == 16:
                imm = _u16(d, p)
                p += 2
            else:
                imm = _byte(d, p)
                p += 1
            name = "test"
            text = "test %s,0x%x" % (rtext, imm)
            if mem:
                mems.append(_mrec(mem, "read", width))
        elif sub in (2, 3):
            name = ("not", "neg")[sub - 2]
            text = "%s %s" % (name, rtext)
            if rreg:
                _def_reg(rreg, width, uses, defs)
            if mem:
                mems.append(_mrec(mem, "rmw", width))
        else:
            raise Unsupported("group 3 /%d at 0x%x is outside the subset" % (sub, off))
    elif 0x70 <= op <= 0x7F or op == 0xEB:
        rel = _s8(_byte(d, p))
        p += 1
        target = p + rel
        flow = "jcc" if op != 0xEB else "jmp"
        name = JCC.get(op, "jmp")
        text = "%s 0x%%TARGET%%" % name
    elif op in (0xE8, 0xE9):
        rel = _s16(d, p)
        p += 2
        target = p + rel
        flow = "call" if op == 0xE8 else "jmp"
        name = "call" if op == 0xE8 else "jmp"
        text = "%s 0x%%TARGET%%" % name
    elif op in (0xC3, 0xC2, 0xCB, 0xCA):
        if op in (0xC2, 0xCA):
            p += 2
        flow = "ret" if op in (0xC3, 0xC2) else "retf"
        name = "ret" if flow == "ret" else "retf"
        text = name
    elif 0x50 <= op <= 0x57:
        r = REG16[op & 7]
        name = "push"
        text = "push %s" % r
        uses.add(r)
    elif 0x58 <= op <= 0x5F:
        r = REG16[op & 7]
        name = "pop"
        text = "pop %s" % r
        defs.add(r)
    elif op in (0x06, 0x0E, 0x16, 0x1E):
        s = {0x06: "es", 0x0E: "cs", 0x16: "ss", 0x1E: "ds"}[op]
        name = "push"
        text = "push %s" % s
        uses.add(s)
    elif op in (0x07, 0x17, 0x1F):
        s = {0x07: "es", 0x17: "ss", 0x1F: "ds"}[op]
        name = "pop"
        text = "pop %s" % s
        defs.add(s)
    elif op == 0x90:
        name, text = "nop", "nop"
    elif 0x91 <= op <= 0x97:
        r = REG16[op & 7]
        name = "xchg"
        text = "xchg ax,%s" % r
        uses |= {"ax", r}
        defs |= {"ax", r}
    elif 0xB0 <= op <= 0xB7:
        imm = _byte(d, p)
        p += 1
        r8 = REG8[op & 7]
        name = "mov"
        text = "mov %s,0x%x" % (r8, imm)
        _def_reg(r8, 8, uses, defs)
    elif 0xB8 <= op <= 0xBF:
        imm = _u16(d, p)
        p += 2
        r = REG16[op & 7]
        name = "mov"
        text = "mov %s,0x%x" % (r, imm)
        defs.add(r)
    elif op in (0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD):
        width = 8 if op in (0xA4, 0xAA, 0xAC) else 16
        kind = {0xA4: "movsb", 0xA5: "movsw", 0xAA: "stosb", 0xAB: "stosw", 0xAC: "lodsb", 0xAD: "lodsw"}[op]
        name = kind
        text = kind
        acc = "al" if width == 8 else "ax"
        if kind.startswith("movs"):
            uses |= {"ds", "si", "es", "di"}
            defs |= {"si", "di"}
            mems.append({"seg": "ds", "text": "ds:[si]", "direct": None, "access": "read", "width": width})
            mems.append({"seg": "es", "text": "es:[di]", "direct": None, "access": "write", "width": width})
        elif kind.startswith("stos"):
            uses |= {"es", "di", acc}
            defs |= {"di"}
            mems.append({"seg": "es", "text": "es:[di]", "direct": None, "access": "write", "width": width})
        else:  # lods: reads DS:SI, writes AL/AX and SI
            uses |= {"ds", "si"}
            defs |= {"si"}
            _def_reg(acc, width, uses, defs)
            mems.append({"seg": "ds", "text": "ds:[si]", "direct": None, "access": "read", "width": width})
    elif op == 0xF8:
        name, text = "clc", "clc"
    elif op == 0xF9:
        name, text = "stc", "stc"
    elif op == 0xFC:
        name, text = "cld", "cld"
    elif op == 0xFD:
        name, text = "std", "std"
    else:
        raise Unsupported("opcode 0x%02x at 0x%x is outside the subset" % (op, off))

    length = p - off
    if target is not None:
        text = text.replace("%TARGET%", "%04x" % (target - base))
    return Ins(off=off, base=base, length=length, raw=bytes(d[off:off + length]), name=name, text=text,
               flow=flow, target=target, uses=frozenset(uses), defs=frozenset(defs), mems=mems)


def cross_check(d: bytes, ins: Ins) -> dict:
    """The repo decoder's length, flow and target for the same instruction (length and flow only)."""
    ref = lp.decode(d, ins.off)
    ok = ref.length == ins.length and ref.flow == ins.flow
    if ins.target is not None:
        ok = ok and ref.target == ins.target
    return {"ok": ok, "lp_length": ref.length, "lp_flow": ref.flow,
            "lp_target": None if ref.target is None else ref.target - ins.base}


def decode_span(d: bytes, base: int, lo: int, hi: int) -> list:
    """Linear decode of module offsets [lo, hi]. It must land exactly on hi + 1."""
    out = []
    p = base + lo
    while p <= base + hi:
        ins = decode(d, p, base)
        out.append(ins)
        p = ins.end
    if p != base + hi + 1:
        raise Refusal("linear decode of [0x%04x, 0x%04x] ends at 0x%04x, not on the span end" % (
            lo, hi, p - base))
    return out


# ---- control flow, dataflow, stores ------------------------------------------------------------

def reach(by_off: dict, entry: int) -> tuple:
    """Reachable instructions from `entry` inside the span. Calls fall through; the callee is recorded.

    Returns (seen: off -> Ins, edges: off -> [off], external: [off])."""
    seen: dict = {}
    edges: dict = {}
    external: list = []
    work = [entry]
    while work:
        a = work.pop()
        if a in seen:
            continue
        ins = by_off.get(a)
        if ins is None:
            external.append(a)
            continue
        seen[a] = ins
        if ins.flow in ("seq", "call"):
            succ = [ins.end]
        elif ins.flow == "jcc":
            succ = [ins.end, ins.target]
        elif ins.flow == "jmp":
            succ = [ins.target]
        else:
            succ = []
        edges[a] = succ
        work.extend(succ)
    return seen, edges, external


def definite_defs(by_off: dict, entry: int) -> frozenset:
    """Registers written on every path: the straight-line run from the entry up to its first branch."""
    out: set = set()
    a = entry
    while a in by_off:
        ins = by_off[a]
        if ins.flow != "seq":
            break
        out |= ins.defs
        a = ins.end
    return frozenset(out)


def upward_exposed(seen: dict, edges: dict, entry: int, summaries: dict) -> frozenset:
    """Registers and segments read before any write on some path from the entry (backward liveness)."""
    live_in = {a: frozenset() for a in seen}
    changed = True
    while changed:
        changed = False
        for a, ins in seen.items():
            out: set = set()
            for s in edges.get(a, []):
                out |= live_in.get(s, frozenset())
            if ins.flow == "call":
                cs = summaries.get(ins.tmo)
                if cs is None:
                    raise Refusal("no summary for the callee at module 0x%04x" % ins.tmo)
                uses, defs = cs["uses"], cs["defs"]
            else:
                uses, defs = ins.uses, ins.defs
            new = frozenset(set(uses) | (out - set(defs)))
            if new != live_in[a]:
                live_in[a] = new
                changed = True
    return live_in[entry]


def _listing_row(ins: Ins) -> dict:
    return {"mo": "0x%04x" % ins.mo, "hex": ins.raw.hex(), "text": ins.text, "name": ins.name,
            "flow": ins.flow, "target": None if ins.tmo is None else "0x%04x" % ins.tmo,
            "uses": sorted(ins.uses), "defs": sorted(ins.defs),
            "mem": [{"seg": m["seg"], "text": m["text"], "direct": m["direct"], "access": m["access"],
                     "width": m["width"]} for m in ins.mems]}


def routine(d: bytes, base: int, entry: int, summaries: dict) -> dict:
    lo, hi = SPAN_RANGES[entry]
    span = decode_span(d, base, lo, hi)
    by_off = {ins.off: ins for ins in span}
    xc = [cross_check(d, ins) for ins in span]
    seen, edges, external = reach(by_off, base + entry)
    order = sorted(seen.values(), key=lambda i: i.off)
    calls = [{"at": "0x%04x" % i.mo, "target": "0x%04x" % i.tmo} for i in order if i.flow == "call"]
    rets = ["0x%04x" % i.mo for i in order if i.flow in ("ret", "retf")]
    ue = upward_exposed(seen, edges, base + entry, summaries)
    dd = definite_defs(by_off, base + entry)
    stores = []
    for i in order:
        for m in i.mems:
            if m["access"] in ("write", "rmw"):
                stores.append({"at": "0x%04x" % i.mo, "text": i.text, "seg": m["seg"],
                               "addr": m["text"], "direct": m["direct"], "width": m["width"],
                               "access": m["access"]})
    return {"entry": "0x%04x" % entry, "span": ["0x%04x" % lo, "0x%04x" % hi],
            "instructions_in_span": len(span),
            "reachable": ["0x%04x" % i.mo for i in order],
            "cross_check_all_ok": all(x["ok"] for x in xc),
            "cross_check_failures": ["0x%04x" % ins.mo for ins, x in zip(span, xc) if not x["ok"]],
            "external_edges": ["0x%04x" % (a - base) for a in external],
            "calls": calls, "ret_sites": rets,
            "upward_exposed": sorted(ue), "definite_defs": sorted(dd),
            "stores": stores,
            "listing": [_listing_row(i) for i in span],
            "_seen": seen, "_edges": edges, "_span": span}


def analyse_routines(d: bytes, base: int) -> dict:
    """Decode and analyse the three routines. Pure: reads only `d` and `base`."""
    summaries: dict = {}
    out: dict = {}
    for entry in (ENTRY_SIZE, ENTRY_LINK, ENTRY_RELEASE):
        r = routine(d, base, entry, summaries)
        out[entry] = r
        summaries[entry] = {"uses": frozenset(r["upward_exposed"]), "defs": frozenset(r["definite_defs"])}
        # The summary uses the call-site view: the callee's own reads and writes, nothing else.
    return out


# ---- bounds, zero-size exit, flags, size model -------------------------------------------------

def slot_writes(routines: dict) -> dict:
    """Every DS-direct store reachable from the three entries, classified by the slot its bytes cover."""
    rows = []
    for entry, r in routines.items():
        for s in r["stores"]:
            if s["seg"] != "ds" or s["direct"] is None:
                continue
            covered = range(s["direct"], s["direct"] + s["width"] // 8)
            for name, rng in SLOT_RANGES.items():
                if any(a in rng for a in covered):
                    rows.append({"in": SPAN_NAMES[entry], "at": s["at"], "text": s["text"], "slot": name})
    return {"ds_direct_stores_in_slots": rows,
            "low_written": any(x["slot"] == "low" for x in rows),
            "high_written_at": sorted({x["at"] for x in rows if x["slot"] == "high"}),
            "head_written_direct": any(x["slot"] == "head" for x in rows)}


def es_relative_stores(routines: dict) -> list:
    out = []
    for entry, r in routines.items():
        for s in r["stores"]:
            if s["seg"] == "es":
                out.append({"in": SPAN_NAMES[entry], "at": s["at"], "text": s["text"]})
    return out


def head_chain(routines: dict) -> dict:
    """The instructions that carry the head slot DS:0x440C into the predecessor pointer (the first iteration)."""
    listing = {r["mo"]: r["text"] for r in routines[ENTRY_RELEASE]["listing"]}
    chain = [("0x0408", "mov di,0x440c"), ("0x040b", "mov ax,ds"), ("0x040d", "mov es,ax"),
             ("0x040f", "mov ax,di"), ("0x0411", "mov dx,es"), ("0x0413", "les di,es:[di]"),
             ("0x0424", "push dx"), ("0x0425", "push ax"), ("0x0429", "pop cx"), ("0x042a", "pop bx"),
             ("0x0426", "call 0x0432"), ("0x042b", "call 0x0432")]
    rows = []
    for at, want in chain:
        got = listing.get(at)
        rows.append({"at": at, "expected": want, "decoded": got, "matched": got == want})
    return {"rows": rows, "all_matched": all(x["matched"] for x in rows)}


def zero_size_exit(routines: dict) -> dict:
    """`or ax,ax; jz` at 0x03D3/0x03D5: where the zero branch lands and what carry it returns with."""
    rel = {r["mo"]: r for r in routines[ENTRY_RELEASE]["listing"]}
    first, jz = rel.get("0x03d3"), rel.get("0x03d5")
    landing = jz["target"] if jz else None
    ret_at = rel.get(landing) if landing else None
    skipped = rel.get("0x0430")
    return {"or_text": first["text"] if first else None,
            "jz_name": jz["name"] if jz else None,
            "jz_target": landing,
            "landing_is_bare_ret": bool(ret_at) and ret_at["name"] == "ret",
            "skipped_instruction_at_0x0430": skipped["text"] if skipped else None,
            "carry_on_zero_path": "clear (OR clears CF; stc at 0x0430 is skipped)",
            "returns_error": False}


def flag_adjacency(routines: dict) -> list:
    rows = []
    listing = {}
    for r in routines.values():
        for row in r["listing"]:
            listing[row["mo"]] = row
    for prod_at, prod_text, cons_at, cons_text in FLAG_PAIRS:
        pa, ca = "0x%04x" % prod_at, "0x%04x" % cons_at
        p_row, c_row = listing.get(pa), listing.get(ca)
        between = []
        if p_row and c_row:
            ordered = sorted(listing)
            i, j = ordered.index(pa), ordered.index(ca)
            between = [listing[k]["name"] for k in ordered[i + 1:j]]
        rows.append({"producer": pa, "producer_ok": bool(p_row) and p_row["text"] == prod_text,
                     "consumer": ca, "consumer_ok": bool(c_row) and c_row["text"] == cons_text,
                     "between": between,
                     "flag_neutral_between": all(n in FLAG_NEUTRAL for n in between) and bool(p_row and c_row)})
    return rows


def size_model_facts(routines: dict) -> dict:
    """The decoded 0x0491 sequence, and the algebra it implies (a reading check, not a run)."""
    seq = [r["text"] for r in routines[ENTRY_SIZE]["listing"]]
    expected = ["add ax,0x7", "mov dx,ax", "rcr dx,1", "shr dx,1", "shr dx,1", "shr dx,1", "and ax,0x8", "ret"]
    return {"decoded": seq, "expected": expected, "sequence_matched": seq == expected,
            "reading": "AX := S+7 (CF = carry out); DX := ((CF<<15)|((S+7)&0xFFFF)>>1)>>3; AX := (S+7)&8",
            "returned_pair": "DX:AX; a block's +4..+7 dword gets this pair, not the raw size"}


def size_model(s: int) -> tuple:
    """The algebra read from the 0x0491 sequence for an input word s (s = 0 is refused by the caller)."""
    x = s + 7
    cf = x >> 16
    x16 = x & 0xFFFF
    dx = ((cf << 15) | (x16 >> 1)) >> 3   # rcr dx,1 then shr dx,1 three times
    ax = x16 & 0x8                         # and ax,0x8
    return dx, ax


def normalise_model(lo_sum: int, hi: int) -> tuple:
    """The add-0xF0 / adc-0 / and-0x0F sequence, read as a paragraph/offset split of (hi, lo_sum)."""
    al = lo_sum & 0xFF
    carry = 1 if al + 0xF0 >= 256 else 0
    return (hi + carry) & 0xFFFF, (al + 0xF0) & 0xFF & 0x0F


# ---- identity in the dumps and the callers -----------------------------------------------------

def span_identity(d: bytes, base: int, dump: om.Dump, load: int) -> dict:
    out = {}
    for entry, (lo, hi) in SPAN_RANGES.items():
        fb = d[base + lo: base + hi + 1]
        lin = (MODULE_SEG + load) * PARA + lo
        row = {"live_linear": "0x%X" % lin, "covered": dump.covers(lin, len(fb))}
        if not row["covered"]:
            row["state"] = "memory-not-covered"
        else:
            db = dump.read(lin, len(fb))
            row["memory_equals_file"] = db == fb
            if db != fb:
                row["state"] = "memory-disagrees"
                row["differing_offsets"] = [i for i in range(len(fb)) if db[i] != fb[i]][:8]
            else:
                placed = gcp._positions(d, db)
                row["file_placements"] = ["0x%X" % p for p in placed[:4]]
                row["state"] = ("memory-agrees-unique-placement" if placed == [base + lo]
                                else "placement-not-unique")
        out[SPAN_NAMES[entry]] = row
    return out


def _near_sites(start: bytes, base: int, target_mo: int) -> list:
    """Byte candidates for a near branch (E8, E9, EB, 70..7F) in START.EXE whose target is the module offset."""
    tf = base + target_mo
    hits = []
    for f in range(len(start) - 1):
        b = start[f]
        if b in (0xE8, 0xE9) and f + 3 <= len(start):
            t = f + 3 + _s16(start, f + 1)
            kind = "call" if b == 0xE8 else "jmp"
        elif b == 0xEB or 0x70 <= b <= 0x7F:
            t = f + 2 + _s8(start[f + 1])
            kind = "jmp" if b == 0xEB else "jcc"
        else:
            continue
        if t == tf:
            hits.append({"at": "0x%04x" % (f - base) if f >= base else None, "kind": kind,
                         "opcode": "0x%02x" % b})
    return hits


def _far_sites(data: bytes, seg: int, off: int) -> dict:
    pat = b"\x9a" + off.to_bytes(2, "little") + seg.to_bytes(2, "little")
    jmp = b"\xea" + off.to_bytes(2, "little") + seg.to_bytes(2, "little")
    calls, pos = [], data.find(pat)
    while pos != -1:
        calls.append(pos)
        pos = data.find(pat, pos + 1)
    jumps, pos = [], data.find(jmp)
    while pos != -1:
        jumps.append(pos)
        pos = data.find(jmp, pos + 1)
    return {"far_call_file_offsets": ["0x%X" % p for p in calls],
            "far_jmp_file_offsets": ["0x%X" % p for p in jumps]}


def callers(start: bytes, ovr: bytes, base: int) -> dict:
    out = {}
    for entry in (ENTRY_RELEASE, ENTRY_LINK, ENTRY_SIZE):
        out[SPAN_NAMES[entry]] = {
            "near_candidates_in_START": _near_sites(start, base, entry),
            "far_START": _far_sites(start, MODULE_SEG, entry),
            "far_GAME_OVR": _far_sites(ovr, MODULE_SEG, entry),
        }
    return out


# ---- the self-check verdicts ------------------------------------------------------------------

def expected_listing_match(routines: dict) -> dict:
    out = {}
    for entry, r in routines.items():
        want = EXPECTED.get(entry)
        got = [(row["mo"], row["hex"], row["text"]) for row in r["listing"]]
        if want is None:
            out[SPAN_NAMES[entry]] = {"matched": False, "reason": "no expected listing"}
            continue
        mismatch = None
        for i, (g, w) in enumerate(zip(got, want)):
            if g != w:
                mismatch = {"index": i, "decoded": g, "expected": w}
                break
        matched = mismatch is None and len(got) == len(want)
        out[SPAN_NAMES[entry]] = {"matched": matched, "count": len(got), "expected_count": len(want),
                                  "first_mismatch": mismatch}
    return out


def build_checks(routines: dict, bounds: dict, zero: dict, flags: list, size: dict, norm_ok: bool,
                 head: dict, callers_doc: dict, listing_match: dict, identity: Optional[dict]) -> dict:
    rel, link, sz = routines[ENTRY_RELEASE], routines[ENTRY_LINK], routines[ENTRY_SIZE]
    ret_sets = {"0x03D3": sorted(rel["ret_sites"]), "0x0432": sorted(link["ret_sites"]),
                "0x0491": sorted(sz["ret_sites"])}
    checks = {
        "decode_cross_checked": all(r["cross_check_all_ok"] for r in routines.values()),
        "listing_matches_expected": all(v["matched"] for v in listing_match.values()),
        "no_external_edges": all(not r["external_edges"] for r in routines.values()),
        "ret_sites_as_read": ret_sets == {"0x03D3": ["0x042f", "0x0431"],
                                          "0x0432": ["0x0467", "0x0488", "0x0490"],
                                          "0x0491": ["0x04a1"]},
        "calls_as_read": ({(c["at"], c["target"]) for c in rel["calls"]} ==
                          {("0x0426", "0x0432"), ("0x042b", "0x0432"), ("0x03f9", "0x0491")}),
        "upward_exposed_0x0432": sorted(link["upward_exposed"]) == ["bx", "cx", "di", "ds", "es"],
        "upward_exposed_0x03d3": sorted(rel["upward_exposed"]) == ["ax", "bx", "cx", "ds"],
        "bound_low_never_written": not bounds["low_written"],
        "bound_high_written_at_0x045f_and_0x0463": bounds["high_written_at"] == ["0x045f", "0x0463"],
        "head_not_written_by_direct_store": not bounds["head_written_direct"],
        "head_chain_matched": head["all_matched"],
        "zero_size_exit_is_clear_carry": (zero["landing_is_bare_ret"] and zero["jz_target"] == "0x0431"
                                          and zero["jz_name"] == "jz"
                                          and zero["or_text"] == "or ax,ax"
                                          and zero["skipped_instruction_at_0x0430"] == "stc"),
        "size_sequence_matched": size["sequence_matched"],
        "flag_pairs_matched": all(r["producer_ok"] and r["consumer_ok"] and r["flag_neutral_between"]
                                  for r in flags),
        # The algebra is a reading of the decoded 0x0491 sequence: it counts only if that sequence matched.
        "size_model_is_round8": size["sequence_matched"] and all(size_model_round8(s)
                                                                 for s in range(1, 0x10000)),
        "normalise_model_exact_below_32": norm_ok,
    }
    # The near-caller candidates must include the two 0x03D3 -> 0x0432 sites, the wrapper's call to 0x03D3
    # and the 0x03F9 -> 0x0491 site.
    link_sites = {c["at"] for c in callers_doc["0x0432"]["near_candidates_in_START"]}
    rel_sites = {c["at"] for c in callers_doc["0x03D3"]["near_candidates_in_START"]}
    size_sites = {c["at"] for c in callers_doc["0x0491"]["near_candidates_in_START"]}
    checks["link_callers_present"] = {"0x0426", "0x042b"} <= link_sites
    checks["release_caller_present"] = "0x025f" in rel_sites
    checks["size_caller_present"] = "0x03f9" in size_sites
    if identity is not None:
        checks["identity_in_every_dump"] = all(
            row["state"] == "memory-agrees-unique-placement"
            for per in identity.values() for row in per.values())
    return checks


def size_model_round8(s: int) -> bool:
    dx, ax = size_model(s)
    return 16 * dx + ax == ((s + 7) & ~7)


def norm_model_ok() -> bool:
    # The normaliser keeps the value (16 * segment delta + offset) for lo sums below 32, the range the
    # bytes can produce when both lo words are in 0..15.
    for lo_sum in range(32):
        for hi in (0, 1, 0x1234, 0xFFFE):
            nh, nl = normalise_model(lo_sum, hi)
            if ((nh - hi) & 0xFFFF) * 16 + nl != lo_sum:
                return False
    return True


# Expected listing for the three spans. Generated from the pinned bytes, reviewed by hand against the
# ModRM and the opcode tables, then frozen here. Each row: (module offset, hex bytes, text).
EXPECTED: dict = {
    0x03D3: [
        ("0x03d3", "0bc0", "or ax,ax"),
        ("0x03d5", "745a", "jz 0x0431"),
        ("0x03d7", "f7c1f7ff", "test cx,0xfff7"),
        ("0x03db", "7553", "jnz 0x0430"),
        ("0x03dd", "3b1e0244", "cmp bx,ds:[0x4402]"),
        ("0x03e1", "7708", "ja 0x03eb"),
        ("0x03e3", "724b", "jb 0x0430"),
        ("0x03e5", "3b0e0044", "cmp cx,ds:[0x4400]"),
        ("0x03e9", "7245", "jb 0x0430"),
        ("0x03eb", "3b1e0644", "cmp bx,ds:[0x4406]"),
        ("0x03ef", "7208", "jb 0x03f9"),
        ("0x03f1", "773d", "ja 0x0430"),
        ("0x03f3", "3b0e0444", "cmp cx,ds:[0x4404]"),
        ("0x03f7", "7337", "jnb 0x0430"),
        ("0x03f9", "e89500", "call 0x0491"),
        ("0x03fc", "8bf9", "mov di,cx"),
        ("0x03fe", "8ec3", "mov es,bx"),
        ("0x0400", "26894504", "mov es:[di+4],ax"),
        ("0x0404", "26895506", "mov es:[di+6],dx"),
        ("0x0408", "bf0c44", "mov di,0x440c"),
        ("0x040b", "8cd8", "mov ax,ds"),
        ("0x040d", "8ec0", "mov es,ax"),
        ("0x040f", "8bc7", "mov ax,di"),
        ("0x0411", "8cc2", "mov dx,es"),
        ("0x0413", "26c43d", "les di,es:[di]"),
        ("0x0416", "8cc6", "mov si,es"),
        ("0x0418", "3bde", "cmp bx,si"),
        ("0x041a", "77f3", "ja 0x040f"),
        ("0x041c", "7206", "jb 0x0424"),
        ("0x041e", "3bcf", "cmp cx,di"),
        ("0x0420", "77ed", "ja 0x040f"),
        ("0x0422", "740c", "jz 0x0430"),
        ("0x0424", "52", "push dx"),
        ("0x0425", "50", "push ax"),
        ("0x0426", "e80900", "call 0x0432"),
        ("0x0429", "59", "pop cx"),
        ("0x042a", "5b", "pop bx"),
        ("0x042b", "e80400", "call 0x0432"),
        ("0x042e", "f8", "clc"),
        ("0x042f", "c3", "ret"),
        ("0x0430", "f9", "stc"),
        ("0x0431", "c3", "ret"),
    ],
    0x0432: [
        ("0x0432", "8bc7", "mov ax,di"),
        ("0x0434", "8cc2", "mov dx,es"),
        ("0x0436", "8bf9", "mov di,cx"),
        ("0x0438", "8ec3", "mov es,bx"),
        ("0x043a", "26034d04", "add cx,es:[di+4]"),
        ("0x043e", "26035d06", "add bx,es:[di+6]"),
        ("0x0442", "80c1f0", "add cl,0xf0"),
        ("0x0445", "83d300", "adc bx,0x0"),
        ("0x0448", "80e10f", "and cl,0xf"),
        ("0x044b", "3bda", "cmp bx,dx"),
        ("0x044d", "753a", "jnz 0x0489"),
        ("0x044f", "3bc8", "cmp cx,ax"),
        ("0x0451", "7536", "jnz 0x0489"),
        ("0x0453", "3b160644", "cmp dx,ds:[0x4406]"),
        ("0x0457", "750f", "jnz 0x0468"),
        ("0x0459", "3b060444", "cmp ax,ds:[0x4404]"),
        ("0x045d", "7509", "jnz 0x0468"),
        ("0x045f", "893e0444", "mov ds:[0x4404],di"),
        ("0x0463", "8c060644", "mov ds:[0x4406],es"),
        ("0x0467", "c3", "ret"),
        ("0x0468", "1e", "push ds"),
        ("0x0469", "57", "push di"),
        ("0x046a", "8bf0", "mov si,ax"),
        ("0x046c", "8eda", "mov ds,dx"),
        ("0x046e", "fc", "cld"),
        ("0x046f", "a5", "movsw"),
        ("0x0470", "a5", "movsw"),
        ("0x0471", "ad", "lodsw"),
        ("0x0472", "92", "xchg ax,dx"),
        ("0x0473", "ad", "lodsw"),
        ("0x0474", "92", "xchg ax,dx"),
        ("0x0475", "260305", "add ax,es:[di]"),
        ("0x0478", "26035502", "add dx,es:[di+2]"),
        ("0x047c", "04f0", "add al,0xf0"),
        ("0x047e", "83d200", "adc dx,0x0"),
        ("0x0481", "240f", "and al,0xf"),
        ("0x0483", "ab", "stosw"),
        ("0x0484", "92", "xchg ax,dx"),
        ("0x0485", "ab", "stosw"),
        ("0x0486", "5f", "pop di"),
        ("0x0487", "1f", "pop ds"),
        ("0x0488", "c3", "ret"),
        ("0x0489", "268905", "mov es:[di],ax"),
        ("0x048c", "26895502", "mov es:[di+2],dx"),
        ("0x0490", "c3", "ret"),
    ],
    0x0491: [
        ("0x0491", "050700", "add ax,0x7"),
        ("0x0494", "8bd0", "mov dx,ax"),
        ("0x0496", "d1da", "rcr dx,1"),
        ("0x0498", "d1ea", "shr dx,1"),
        ("0x049a", "d1ea", "shr dx,1"),
        ("0x049c", "d1ea", "shr dx,1"),
        ("0x049e", "250800", "and ax,0x8"),
        ("0x04a1", "c3", "ret"),
    ],
}


def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = mt.check_pins(ovr, exe)
    mt._need_pinned(pins)
    base = gcp.handler_base(exe)["base_file"]
    if base != EXPECT_BASE:
        raise Refusal("module file base 0x%X, expected 0x%X" % (base, EXPECT_BASE))
    dumps, dump_meta, identity = [], [], {}
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        lin_base = om.resolve_dump_base(dp.name, len(raw), None)
        dump = om.Dump(raw, lin_base)
        mod = gcp.dump_module(dump, exe, base)
        if mod.get("status") != "unique" or mod.get("load_seg") != EXPECT_LOAD:
            raise Refusal("module anchor in %s is not a unique load 0x%04X: %s" % (dp.parent.name, EXPECT_LOAD, mod))
        label = "%s/%s" % (dp.parent.name, dp.name)
        identity[label] = span_identity(exe, base, dump, mod["load_seg"])
        dump_meta.append({"label": label, "sha256_prefix": gcp._sha(raw)[:16], "dump_base": "0x%X" % lin_base,
                          "module_anchor": mod})
    return build_document(exe, ovr, base, pins, dump_meta, identity)


def build_document(exe: bytes, ovr: bytes, base: int, pins: dict, dump_meta: list, identity: dict) -> dict:
    routines = analyse_routines(exe, base)
    bounds = slot_writes(routines)
    zero = zero_size_exit(routines)
    flags = flag_adjacency(routines)
    size = size_model_facts(routines)
    head = head_chain(routines)
    callers_doc = callers(exe, ovr, base)
    listing_match = expected_listing_match(routines)
    norm_ok = norm_model_ok()
    checks = build_checks(routines, bounds, zero, flags, size, norm_ok, head, callers_doc,
                          listing_match, identity or None)
    ok = all(v is True for v in checks.values())
    public_routines = {}
    for entry, r in routines.items():
        public_routines[SPAN_NAMES[entry]] = {k: v for k, v in r.items() if not k.startswith("_")}
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL, "status_scope": STATUS_SCOPE,
        "playable": False, "executed": "not_established",
        "inputs": {"pins": pins, "dumps": dump_meta},
        "module": {"file_base": "0x%X" % base, "module_segment": "0x%04X" % MODULE_SEG,
                   "load_segment_measured": "0x%04X" % EXPECT_LOAD,
                   "live_segment": "0x%04X" % (MODULE_SEG + EXPECT_LOAD)},
        "routines": public_routines,
        "stores": {"es_relative": es_relative_stores(routines), "ds_direct_slots": bounds},
        "head_chain": head,
        "zero_size_exit": zero,
        "flag_adjacency": flags,
        "size_model": size,
        "normalise_model": {"exact_for_lo_sum_below_32": norm_ok,
                            "reading": "add al,0xf0 ; adc hi,0 ; and al,0x0f  => (hi + [al>=16], al&0xF)"},
        "identity": identity,
        "callers": callers_doc,
        "listing_match": listing_match,
        "bounds_hypothesis": {
            "note_claim": "module 0x0432 stores DS:0x4404 and DS:0x4406; the two calls update the free-list bounds",
            "low_bound_written": bounds["low_written"],
            "high_bound_written_at": bounds["high_written_at"],
            "status": ("partly-supported: the high bound (DS:0x4404:0x4406) is the only bound written by the "
                       "reachable bytes, on one path of the first call (block end == successor == high bound) "
                       "and, through a chain, on one path of the second call; the low bound is never written"),
        },
        "self_checks": checks,
        "self_checks_passed": ok,
        "not_established": NOT_ESTABLISHED,
        "verdict": ("routines decoded and cross-checked; bound-store and control-flow facts match the bytes"
                    if ok else "not all self-checks matched; see self_checks"),
    }
    return doc


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_0111_bound_update_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Bound-update probe for far module routines 0x0AF8:0x0432 and :0x03D3.")
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
    except (Refusal, FileNotFoundError, Unsupported) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s (self_checks_passed=%s, high_bound_written_at=%s, low_bound_written=%s)" % (
        args.out, doc["self_checks_passed"], doc["bounds_hypothesis"]["high_bound_written_at"],
        doc["bounds_hypothesis"]["low_bound_written"]))
    return 0 if doc["self_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
