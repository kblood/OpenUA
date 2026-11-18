#!/usr/bin/env python3
"""Pool of Radiance: the branch arms after each call to the plane-3 reader (static, observe-only).

Follow-up to tools/por_door_caller_probe.py. That probe found four far-call sites
(``9A 2F 00 D5 03``) into the reader GAME.OVR:0x2EC47 and decoded each consumer's compare bytes.
This probe asks what the code does on each arm after the reader returns, and whether any arm
writes the bytes the reader was given (party position / direction bytes) or only classifies.

Method (all from decoded instruction boundaries, tools/por_loadpieces_handler.decode):

  1. Site check. Each site's five bytes must be ``9A 2F 00 D5 03`` and its segment word must be
     in its owner group's fixup table (fixup words are group-relative). The caller is taken from
     the owner group's closure index in tools/por_door_caller_probe.py (imported, not edited).
  2. Reader return set. The reader body is run through the same interpreter with unknown
     arguments. Its returned AL is reported as constants and upper bounds. The reader's
     argument order is checked against the caller's three pushes.
  3. Caller paths. Each caller is interpreted from its entry with a per-run forced result at the
     target site: AL = R for R in 0, 1, 2, 3 (the reader's return set). Constant AL makes every
     compare on it exact; compares on unknown memory fork both arms. Values carry provenance, so
     a store to DS:xxxx that came from a reader argument is recognised as such.
  4. Verdict per site, by fact only: ``computed-party-byte-store`` if a reachable arm stores to a
     DS byte the reader was given; ``state-write-nonparty`` if it stores to other DS bytes or
     through an unknown pointer; ``calls-only`` if it only calls; else ``classifier-only``.
  5. Writer census. Static DS-direct writes to the party bytes, over the decoded walks of the two
     owner groups only (not every overlay group).

The far-call image model is NOT used to decide anything. The reader's identity (0x2EC47 behind
literal 03D5:002F) is an input carried over from the caller probe's M1 candidate; it is marked
unproven here. Arms are reachability over the decoded bytes; a reachable arm is not a proof that
the arm runs in play. Read-only. Refuses unpinned GAME.OVR or START.EXE (no override), and refuses
output outside data/work or inside the install.

Usage:
    python tools/por_door_reader_branch_probe.py --install PATH/TO/POOLRAD -o data/work/por-door-reader-branch-probe

Exit: 0 probe ran; 2 named refusal.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import deque
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_door_caller_probe as dcp  # noqa: E402  (imported for pinned load and closure index only)

SCHEMA = "openua.por-door-reader-branch-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_door_reader_branch_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-door-reader-branch-probe"

READER_ENTRY = 0x2EC47                    # plane-3 reader (identity: caller probe's M1 candidate, unproven here)
READER_LITERAL = (0x03D5, 0x002F)         # the 9A literal every site uses
SITES = (0x0C726, 0x1699F, 0x16D8B, 0x17469)
SITE_BYTES = bytes.fromhex("9a2f00d503")
RESULTS = (0, 1, 2, 3)                    # reader return set (checked in section 2)
PARTY_DS_RE = re.compile(r"DS:([0-9A-F]{4})")
CENSUS_ADDRS = (0x6AAD, 0x6AAE, 0x6AAF)   # DS bytes the caller probe and door docs name as party bytes
MAX_VISITS = 200000
MAX_PROV_PARTS = 4

MASK = {1: 0xFF, 2: 0xFFFF}
SIGN = {1: 0x80, 2: 0x8000}
REG8 = ("AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH")
REG16_SINGLE = {5: "BP", 6: "SI", 7: "DI"}      # SP (4) is not modelled; 0..3 are AL/AH halves
ALU = lh.ALU
SHIFTS = lh.SHIFTS
JCC_NAMES = lh.JCC
PRE_SEG = {0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds"}
RM_BASE = ("bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx")


class Refusal(Exception):
    pass


# --------------------------------------------------------------------------- values
# A value is (prov, const, ub): prov is where the low byte came from (a string), const is an
# exact int or None, ub is an inclusive upper bound or None. Provenance is the operative output.

def V(prov: str, const: Optional[int] = None, ub: Optional[int] = None) -> tuple:
    return (prov, const, ub)


def eff_ub(v: tuple) -> Optional[int]:
    return v[1] if v[1] is not None else v[2]


def _show(v: tuple) -> dict:
    return {"prov": v[0], "const": None if v[1] is None else "0x%04X" % v[1],
            "ub": None if v[2] is None else "0x%04X" % v[2]}


def _join_prov(p: str, q: str) -> str:
    parts = sorted(set(p.split("|")) | set(q.split("|")))
    if len(parts) > MAX_PROV_PARTS:
        return "JOIN*"
    return "|".join(parts)


def vjoin(a: tuple, b: tuple) -> tuple:
    if a == b:
        return a
    prov = a[0] if a[0] == b[0] else _join_prov(a[0], b[0])
    ea, eb = eff_ub(a), eff_ub(b)
    ub = max(ea, eb) if (ea is not None and eb is not None) else None
    return (prov, None, ub)


def combine(lo: tuple, hi: tuple) -> tuple:
    """16-bit value from low and high bytes. Provenance follows the low byte (the reader and
    the caller load their arguments as bytes, so the low byte is the operative source)."""
    prov = lo[0]
    if lo[1] is not None and hi[1] is not None:
        return (prov, (hi[1] << 8) | lo[1], None)
    hub = eff_ub(hi)
    if hub is None:
        return (prov, None, None)
    lub = eff_ub(lo)
    return (prov, None, hub * 256 + (lub if lub is not None else 255))


def split(v: tuple) -> tuple:
    """Low and high byte values of a 16-bit value."""
    prov, c, ub = v
    if c is not None:
        return (prov, c & 0xFF, None), (prov, (c >> 8) & 0xFF, None)
    if ub is None:
        return (prov, None, None), (prov, None, None)
    if ub < 256:
        return (prov, None, ub), (prov, 0, None)
    return (prov, None, None), (prov, None, ub >> 8)


def _alu_const(name: str, a: int, b: int, size: int):
    m, s = MASK[size], SIGN[size]
    a &= m
    b &= m
    if name == "add":
        r = (a + b) & m
        cf, of = (a + b) > m, bool(((a ^ r) & (b ^ r) & s))
    elif name in ("sub", "cmp"):
        r = (a - b) & m
        cf, of = a < b, bool(((a ^ b) & (a ^ r) & s))
    elif name == "and":
        r, cf, of = a & b, False, False
    elif name == "or":
        r, cf, of = a | b, False, False
    elif name == "xor":
        r, cf, of = a ^ b, False, False
    else:
        return None, None
    return r, (r == 0, bool(r & s), cf, of)


def cond_value(name: str, flags) -> Optional[bool]:
    """Branch condition from the flags tuple (ZF, SF, CF, OF); None when unknown (forks)."""
    if flags is None or name not in JCC_NAMES:
        return None
    zf, sf, cf, of = flags
    table = {"jo": of, "jno": not of, "jb": cf, "jnb": not cf, "jz": zf, "jnz": not zf,
             "jbe": cf or zf, "ja": not (cf or zf), "js": sf, "jns": not sf,
             "jl": sf != of, "jge": sf == of, "jle": zf or (sf != of), "jg": (not zf) and (sf == of)}
    return table.get(name)


# --------------------------------------------------------------------------- state
def _copy(st: dict) -> dict:
    return {"regs": dict(st["regs"]), "mem": dict(st["mem"]), "flags": st["flags"],
            "stack": st["stack"], "dsok": st["dsok"], "pushed": st["pushed"]}


def _default_mem(space: str, addr: int) -> tuple:
    if space == "BP":
        return V("BP:%+d" % addr)
    return V("DS:%04X" % (addr & 0xFFFF))


def _default_reg(name: str) -> tuple:
    return V("REG:" + name)


def _state_join(a: dict, b: dict) -> dict:
    regs = {}
    for k in set(a["regs"]) | set(b["regs"]):
        regs[k] = vjoin(a["regs"].get(k, _default_reg(k)), b["regs"].get(k, _default_reg(k)))
    mem = {}
    for k in set(a["mem"]) | set(b["mem"]):
        va = a["mem"].get(k, _default_mem(*k))
        vb = b["mem"].get(k, _default_mem(*k))
        mem[k] = vjoin(va, vb)
    if len(a["stack"]) == len(b["stack"]):
        stack = tuple(vjoin(x, y) for x, y in zip(a["stack"], b["stack"]))
    else:
        stack = tuple(V("STACK?") for _ in range(min(len(a["stack"]), len(b["stack"]))))
    return {"regs": regs, "mem": mem, "flags": a["flags"] if a["flags"] == b["flags"] else None,
            "stack": stack, "dsok": a["dsok"] and b["dsok"], "pushed": min(a["pushed"], b["pushed"])}


def _initial_state() -> dict:
    return {"regs": {}, "mem": {}, "flags": None, "stack": (), "dsok": True, "pushed": 0}


def get_r(st: dict, idx: int, size: int) -> tuple:
    if size == 1:
        return st["regs"].get(REG8[idx], _default_reg(REG8[idx]))
    if idx in (0, 1, 2, 3):
        return combine(st["regs"].get(REG8[idx], _default_reg(REG8[idx])),
                       st["regs"].get(REG8[idx + 4], _default_reg(REG8[idx + 4])))
    if idx == 4:
        return V("SP")
    name = REG16_SINGLE[idx]
    return st["regs"].get(name, _default_reg(name))


def set_r(st: dict, idx: int, size: int, v: tuple) -> None:
    if size == 1:
        st["regs"][REG8[idx]] = (v[0], None if v[1] is None else v[1] & 0xFF, v[2] if v[2] is None or v[2] < 256 else None)
        return
    if idx in (0, 1, 2, 3):
        lo, hi = split(v)
        st["regs"][REG8[idx]] = lo
        st["regs"][REG8[idx + 4]] = hi
    elif idx == 4:
        return
    else:
        st["regs"][REG16_SINGLE[idx]] = v


def mem_get(st: dict, space: str, addr: int, size: int) -> tuple:
    lo = st["mem"].get((space, addr), _default_mem(space, addr))
    if size == 1:
        return lo
    hi = st["mem"].get((space, addr + 1), _default_mem(space, addr + 1))
    return combine(lo, hi)


def mem_set(st: dict, space: str, addr: int, size: int, v: tuple) -> None:
    if size == 1:
        st["mem"][(space, addr)] = (v[0], None if v[1] is None else v[1] & 0xFF, v[2] if v[2] is None or v[2] < 256 else None)
        return
    lo, hi = split(v)
    st["mem"][(space, addr)] = lo
    st["mem"][(space, addr + 1)] = hi


def invalidate_ds(st: dict) -> None:
    """An unknown call or unknown store may change any DS byte: forget the DS knowledge."""
    for k in [k for k in st["mem"] if k[0] == "DS"]:
        del st["mem"][k]


# --------------------------------------------------------------------------- operands
def rm_operand(ins: lh.Insn) -> dict:
    """Decode the ModRM r/m operand from raw bytes (the decoder keeps only some displacements)."""
    pre = len(ins.prefixes)
    mb = ins.raw[pre + 1]
    mod, reg, rm = mb >> 6, (mb >> 3) & 7, mb & 7
    seg_ovr = next((PRE_SEG[p] for p in ins.prefixes if p in PRE_SEG), None)
    if mod == 3:
        return {"kind": "reg", "idx": rm, "reg": reg}
    if mod == 0 and rm == 6:
        addr = struct.unpack_from("<H", ins.raw, pre + 2)[0]
        return {"kind": "mem", "form": "direct", "seg": seg_ovr or "ds", "addr": addr, "reg": reg,
                "text": "%s:[0x%04X]" % (seg_ovr or "ds", addr)}
    if mod == 1:
        disp = struct.unpack_from("<b", ins.raw, pre + 2)[0]
    elif mod == 2:
        disp = struct.unpack_from("<h", ins.raw, pre + 2)[0]
    else:
        disp = 0
    if rm == 6:
        return {"kind": "mem", "form": "bp", "seg": seg_ovr or "ss", "disp": disp, "reg": reg,
                "text": "%s:[bp%+d]" % (seg_ovr or "ss", disp)}
    base = RM_BASE[rm]
    dseg = "ss" if "bp" in base else "ds"
    return {"kind": "mem", "form": "idx", "seg": seg_ovr or dseg, "base": base, "disp": disp, "reg": reg,
            "text": "%s:[%s%+d]" % (seg_ovr or dseg, base, disp)}


def _resolve(st: dict, o: dict) -> tuple:
    """Where a memory operand lands: ('BP', disp) | ('DS', addr) | ('DSIDX', base, disp, idx_v) | ('PTR', text)."""
    if o["form"] == "bp" and o["seg"] in ("ss", "ds"):
        return ("BP", o["disp"])
    if o["form"] == "direct" and o["seg"] == "ds":
        return ("DS", o["addr"]) if st["dsok"] else ("DSX", o["addr"])
    if o["form"] == "idx" and o["seg"] == "ds":
        if o["base"] == "di":
            di = get_r(st, 7, 2)
            if di[1] is not None and st["dsok"]:
                return ("DS", (di[1] + o["disp"]) & 0xFFFF)
            return ("DSIDX", o["base"], o["disp"], di)
        return ("DSIDX", o["base"], o["disp"], V("REG:" + o["base"]))
    return ("PTR", o["text"])


def read_op(st: dict, ins: lh.Insn, o: dict, size: int, emit) -> tuple:
    if o["kind"] == "reg":
        return get_r(st, o["idx"], size)
    r = _resolve(st, o)
    if r[0] == "BP":
        return mem_get(st, "BP", r[1], size)
    if r[0] == "DS":
        return mem_get(st, "DS", r[1], size)
    if r[0] == "DSIDX":
        emit("ds-indexed-read", base=r[1], disp=r[2], size=size, index=_show(r[3]))
        return V("DSIDX:%s%+d" % (r[1], r[2]))
    if r[0] == "DSX":
        return V("DS?:%04X" % r[1])
    return V("PTR:" + r[1])


def write_op(st: dict, ins: lh.Insn, o: dict, size: int, v: tuple, emit) -> None:
    if o["kind"] == "reg":
        set_r(st, o["idx"], size, v)
        return
    r = _resolve(st, o)
    if r[0] == "BP":
        mem_set(st, "BP", r[1], size, v)
    elif r[0] == "DS":
        emit("ds-write", addr="0x%04X" % r[1], size=size, value=_show(v))
        mem_set(st, "DS", r[1], size, v)
    elif r[0] == "DSX":
        emit("ds-write-unknown-seg", addr="0x%04X" % r[1], size=size, value=_show(v))
    elif r[0] == "DSIDX":
        emit("ds-indexed-write", base=r[1], disp=r[2], size=size, value=_show(v))
        invalidate_ds(st)
    else:
        emit("ptr-write", target=r[1], size=size, value=_show(v))


def _same_reg(o: dict) -> bool:
    return o["kind"] == "reg" and o["idx"] == o["reg"]


def _alu(st: dict, name: str, a: tuple, b: tuple, size: int, same: bool) -> Optional[tuple]:
    """Apply one ALU op. Returns the result value, or None when the op is cmp (no write)."""
    if same and name in ("xor", "sub", "cmp"):
        st["flags"] = (True, False, False, False)
        return None if name == "cmp" else V("CONST", 0, None)
    if a[1] is not None and b[1] is not None:
        r, fl = _alu_const(name, a[1], b[1], size)
        if r is None:
            st["flags"] = None
            return V("ADC/SBB", None, None)
        st["flags"] = fl
        return None if name == "cmp" else V("CONST", r, None)
    st["flags"] = None
    if name == "cmp":
        return None
    ub = None
    if name == "and":
        ubs = [u for u in (eff_ub(a), eff_ub(b)) if u is not None]
        ub = min(ubs) if ubs else None
    prov = ("%s~%s%s" % (a[0], name, b[0]))[:80]
    return V(prov, None, ub)


# --------------------------------------------------------------------------- machine
class Machine:
    def __init__(self, data: bytes, reader_literal: Optional[tuple], reader_ds_writes: bool,
                 target_pc: Optional[int], target_r: Optional[int]):
        self.data = data
        self.reader_literal = reader_literal
        self.reader_ds_writes = reader_ds_writes
        self.target_pc = target_pc
        self.target_r = target_r
        self._dec: dict[int, lh.Insn] = {}

    def decode(self, pc: int) -> lh.Insn:
        if pc not in self._dec:
            self._dec[pc] = lh.decode(self.data, pc)
        return self._dec[pc]

    # ---- one instruction: returns successor list [(pc or None, state)]
    def exec_insn(self, pc: int, st0: dict, emit) -> list:
        ins = self.decode(pc)
        op, flow, nxt = ins.op, ins.flow, ins.end
        st = _copy(st0)

        def top_args() -> list:
            n = len(st["stack"])
            return [_show(st["stack"][-1 - i]) if n >= 1 + i else None for i in range(3)]

        if flow == "jcc":
            c = cond_value(ins.name, st["flags"])
            if c is True:
                return [(ins.target, st)]
            if c is False:
                return [(nxt, st)]
            return [(ins.target, st), (nxt, _copy(st))]
        if flow == "jmp":
            return [(ins.target, st)]
        if flow in ("ret", "retf"):
            emit("return", imm=ins.imm, al=_show(get_r(st, 0, 1)))
            return []
        if flow in ("jmp_far", "indirect_jmp", "indirect_jmpf"):
            emit("unresolved-transfer", kind=flow)
            return []
        if flow == "call":
            emit("call-near", target=ins.target, args=top_args())
            self._unknown_call(st)
            return [(nxt, st)]
        if flow in ("indirect_call", "indirect_callf"):
            emit("indirect-call", kind=flow, args=top_args())
            self._unknown_call(st)
            return [(nxt, st)]
        if flow == "call_far":
            seg, off = ins.far
            if self.reader_literal is not None and (seg, off) == self.reader_literal:
                args = top_args()
                emit("reader-call", args=args, valid=st["pushed"] >= 3, forced=(pc == self.target_pc))
                if len(st["stack"]) >= 3:
                    st["stack"] = st["stack"][:-3]
                st["pushed"] = max(0, st["pushed"] - 3)
                if pc == self.target_pc and self.target_r is not None:
                    set_r(st, 0, 1, V("READER", self.target_r, None))
                else:
                    set_r(st, 0, 1, V("READER", None, None))
                set_r(st, 4, 1, V("READER-AH"))
                if self.reader_ds_writes:
                    invalidate_ds(st)
                st["flags"] = None
                return [(nxt, st)]
            emit("call-far", literal="0x%04X:0x%04X" % (seg, off), args=top_args())
            self._unknown_call(st)
            return [(nxt, st)]

        # ---- data-flow opcodes
        if op < 0x40 and (op & 7) < 6:
            name, form = ALU[op >> 3], op & 7
            if form in (0, 1, 2, 3):
                size = 1 if form in (0, 2) else 2
                o = rm_operand(ins)
                reg_v = get_r(st, o["reg"], size)
                same = _same_reg(o)
                if form in (0, 1):
                    rm_v = read_op(st, ins, o, size, emit)
                    r = _alu(st, name, rm_v, reg_v, size, same)
                    if r is not None:
                        write_op(st, ins, o, size, r, emit)
                else:
                    rm_v = read_op(st, ins, o, size, emit)
                    r = _alu(st, name, reg_v, rm_v, size, same)
                    if r is not None:
                        set_r(st, o["reg"], size, r)
            else:
                size = 1 if form == 4 else 2
                imm = ins.imm & MASK[size]
                r = _alu(st, name, get_r(st, 0, size), V("CONST", imm, None), size, False)
                if r is not None:
                    set_r(st, 0, size, r)
            return [(nxt, st)]
        if op in (0x80, 0x81, 0x83):
            size = 1 if op == 0x80 else 2
            o = rm_operand(ins)
            imm = ins.imm
            if op == 0x83 and imm & 0x80:
                imm |= 0xFF00
            name = ALU[o["reg"]]
            a = read_op(st, ins, o, size, emit)
            r = _alu(st, name, a, V("CONST", imm & MASK[size], None), size, False)
            if r is not None:
                write_op(st, ins, o, size, r, emit)
            return [(nxt, st)]
        if op in (0x84, 0x85):
            size = 1 if op == 0x84 else 2
            o = rm_operand(ins)
            a = read_op(st, ins, o, size, emit)
            b = get_r(st, o["reg"], size)
            _alu(st, "and", a, b, size, False)   # flags only; no write
            return [(nxt, st)]
        if op in (0x88, 0x89):
            size = 1 if op == 0x88 else 2
            o = rm_operand(ins)
            write_op(st, ins, o, size, get_r(st, o["reg"], size), emit)
            return [(nxt, st)]
        if op in (0x8A, 0x8B):
            size = 1 if op == 0x8A else 2
            o = rm_operand(ins)
            set_r(st, o["reg"], size, read_op(st, ins, o, size, emit))
            return [(nxt, st)]
        if op == 0x8C:
            o = rm_operand(ins)
            write_op(st, ins, o, 2, V("SREG"), emit)
            return [(nxt, st)]
        if op == 0x8E:
            o = rm_operand(ins)
            if o["reg"] == 3:
                st["dsok"] = False
            return [(nxt, st)]
        if op == 0x8D:
            o = rm_operand(ins)
            set_r(st, o["reg"], 2, V("LEA"))
            return [(nxt, st)]
        if op == 0x8F:
            o = rm_operand(ins)
            v = st["stack"][-1] if st["stack"] else V("POP?")
            st["stack"] = st["stack"][:-1]
            write_op(st, ins, o, 2, v, emit)
            return [(nxt, st)]
        if 0x40 <= op <= 0x4F:
            idx = op & 7
            v = get_r(st, idx, 2)
            delta = 1 if op < 0x48 else -1
            if v[1] is not None:
                r = (v[1] + delta) & 0xFFFF
                cf = st["flags"][2] if st["flags"] is not None else None
                set_r(st, idx, 2, V("CONST", r, None))
                st["flags"] = (r == 0, bool(r & 0x8000), cf, r == (0x8000 if delta > 0 else 0x7FFF)) if cf is not None else None
            else:
                set_r(st, idx, 2, V("INCDEC", None, None))
                st["flags"] = None
            return [(nxt, st)]
        if op in (0xFE, 0xFF) and ins.modrm is not None and ins.modrm[1] in (0, 1):
            size = 1 if op == 0xFE else 2
            o = rm_operand(ins)
            v = read_op(st, ins, o, size, emit)
            r = V("INCDEC~" + v[0], None, None)
            st["flags"] = None
            write_op(st, ins, o, size, r, emit)
            return [(nxt, st)]
        if op == 0xFF and ins.modrm is not None and ins.modrm[1] == 6:
            o = rm_operand(ins)
            st["stack"] = st["stack"] + (read_op(st, ins, o, 2, emit),)
            st["pushed"] += 1
            return [(nxt, st)]
        if 0x50 <= op <= 0x57:
            st["stack"] = st["stack"] + (get_r(st, op & 7, 2),)
            st["pushed"] += 1
            return [(nxt, st)]
        if 0x58 <= op <= 0x5F:
            if st["stack"]:
                v, st["stack"] = st["stack"][-1], st["stack"][:-1]
            else:
                v = V("POP?")
            set_r(st, op & 7, 2, v)
            return [(nxt, st)]
        if op in (0x06, 0x0E, 0x16, 0x1E):
            st["stack"] = st["stack"] + (V("SEG:" + {0x06: "es", 0x0E: "cs", 0x16: "ss", 0x1E: "ds"}[op]),)
            st["pushed"] += 1
            return [(nxt, st)]
        if op in (0x07, 0x17, 0x1F):
            st["stack"] = st["stack"][:-1]
            if op == 0x1F:
                st["dsok"] = False
            return [(nxt, st)]
        if op in (0x68, 0x6A):
            imm = ins.imm
            if op == 0x6A and imm & 0x80:
                imm |= 0xFF00
            st["stack"] = st["stack"] + (V("CONST", imm & 0xFFFF, None),)
            st["pushed"] += 1
            return [(nxt, st)]
        if op == 0x98:
            al = get_r(st, 0, 1)
            if al[1] is not None:
                set_r(st, 4, 1, V("CONST", 0xFF if al[1] & 0x80 else 0, None))
            else:
                set_r(st, 4, 1, V("CBW~" + al[0], None, None))
            return [(nxt, st)]
        if op == 0x99:
            ax = get_r(st, 0, 2)
            if ax[1] is not None:
                set_r(st, 2, 2, V("CONST", 0xFFFF if ax[1] & 0x8000 else 0, None))
            else:
                set_r(st, 2, 2, V("CWD~" + ax[0], None, None))
            return [(nxt, st)]
        if 0x91 <= op <= 0x97:
            a, b = get_r(st, 0, 2), get_r(st, op & 7, 2)
            set_r(st, 0, 2, b)
            set_r(st, op & 7, 2, a)
            return [(nxt, st)]
        if op == 0x90:
            return [(nxt, st)]
        if 0xA0 <= op <= 0xA3:
            size = 1 if op in (0xA0, 0xA2) else 2
            o = {"kind": "mem", "form": "direct", "seg": "ds", "addr": struct.unpack_from("<H", ins.raw, len(ins.prefixes) + 1)[0],
                 "text": "ds:[moffs]"}
            if op in (0xA0, 0xA1):
                set_r(st, 0, size, read_op(st, ins, o, size, emit))
            else:
                write_op(st, ins, o, size, get_r(st, 0, size), emit)
            return [(nxt, st)]
        if 0xB0 <= op <= 0xB7:
            set_r(st, op & 7, 1, V("CONST", ins.imm, None))
            return [(nxt, st)]
        if 0xB8 <= op <= 0xBF:
            set_r(st, op & 7, 2, V("CONST", ins.imm, None))
            return [(nxt, st)]
        if op in (0xC6, 0xC7):
            size = 1 if op == 0xC6 else 2
            o = rm_operand(ins)
            write_op(st, ins, o, size, V("CONST", ins.imm, None), emit)
            return [(nxt, st)]
        if op in (0xC4, 0xC5):
            o = rm_operand(ins)
            set_r(st, o["reg"], 2, V("FARPTR", None, None))
            if op == 0xC5:
                st["dsok"] = False
            return [(nxt, st)]
        if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
            size = 1 if op in (0xC0, 0xD0, 0xD2) else 2
            o = rm_operand(ins)
            name = SHIFTS[o["reg"]]
            if op in (0xC0, 0xC1):
                cnt = ins.imm
            elif op in (0xD0, 0xD1):
                cnt = 1
            else:
                cl = get_r(st, 1, 1)
                cnt = cl[1]
            a = read_op(st, ins, o, size, emit)
            if name in ("shl", "shr", "sar") and cnt is not None:
                if a[1] is not None:
                    m = MASK[size]
                    if name == "shl":
                        r = (a[1] << cnt) & m
                        cf = bool((a[1] >> (size * 8 - cnt)) & 1) if 0 < cnt <= size * 8 else False
                    elif name == "shr":
                        r = a[1] >> cnt
                        cf = bool((a[1] >> (cnt - 1)) & 1) if cnt > 0 else False
                    else:
                        s = a[1] - (1 << (size * 8)) if a[1] & SIGN[size] else a[1]
                        r = (s >> cnt) & m
                        cf = bool((s >> (cnt - 1)) & 1) if cnt > 0 else False
                    st["flags"] = None   # OF/AF are not modelled for shifts: keep unknown, forks
                    res = V("CONST", r, None)
                else:
                    ub = eff_ub(a)
                    res = V("%s%+d~%s" % (name, cnt, a[0]), None, (ub >> cnt) if (name == "shr" and ub is not None) else None)
                    st["flags"] = None
            else:
                st["flags"] = None
                res = V("%s?~%s" % (name, a[0]), None, None)
            write_op(st, ins, o, size, res, emit)
            return [(nxt, st)]
        if op in (0xF6, 0xF7) and ins.modrm is not None and ins.modrm[1] in (0, 1):
            size = 1 if op == 0xF6 else 2
            o = rm_operand(ins)
            a = read_op(st, ins, o, size, emit)
            _alu(st, "and", a, V("CONST", ins.imm & MASK[size], None), size, False)   # flags only
            return [(nxt, st)]
        if op in (0xF6, 0xF7) and ins.modrm is not None and ins.modrm[1] in (2, 3):
            size = 1 if op == 0xF6 else 2
            o = rm_operand(ins)
            st["flags"] = None
            write_op(st, ins, o, size, V("GRP3~", None, None), emit)
            return [(nxt, st)]
        if op in (0xF6, 0xF7) and ins.modrm is not None and ins.modrm[1] in (4, 5, 6, 7):
            # mul/imul/div/idiv: reads the operand, writes only AX (and DX); no memory write.
            o = rm_operand(ins)
            read_op(st, ins, o, 1 if op == 0xF6 else 2, emit)
            for r8 in ("AL", "AH", "DL", "DH"):
                st["regs"][r8] = V("MULDIV@0x%05X" % pc)
            st["flags"] = None
            return [(nxt, st)]
        if op == 0xC9:
            st["stack"] = ()
            st["pushed"] = 0
            return [(nxt, st)]
        if op == 0x9E or op == 0x9F or op == 0x9C or op == 0x9D:
            if op == 0x9C:
                st["stack"] = st["stack"] + (V("FLAGS"),)
            elif op == 0x9D and st["stack"]:
                st["stack"] = st["stack"][:-1]
            st["flags"] = None
            return [(nxt, st)]
        if op == 0x86 or op == 0x87:
            size = 1 if op == 0x86 else 2
            o = rm_operand(ins)
            a = read_op(st, ins, o, size, emit)
            b = get_r(st, o["reg"], size)
            write_op(st, ins, o, size, b, emit)
            set_r(st, o["reg"], size, a)
            return [(nxt, st)]

        # Anything else: honest gap. Its effect on memory and registers is unknown.
        emit("unmodeled", name=ins.name, op="0x%02X" % op)
        for r8 in REG8:
            st["regs"][r8] = V("UNMODELED@0x%05X" % pc)
        st["regs"]["SI"] = V("UNMODELED")
        st["regs"]["DI"] = V("UNMODELED")
        st["flags"] = None
        invalidate_ds(st)
        return [(nxt, st)]

    def _unknown_call(self, st: dict) -> None:
        for r8 in REG8:
            st["regs"][r8] = V("CALLRET")
        st["regs"]["SI"] = V("CALLRET")
        st["regs"]["DI"] = V("CALLRET")
        st["flags"] = None
        invalidate_ds(st)
        st["pushed"] = 0

    # ---- whole-function interpretation
    def run(self, entry: int) -> dict:
        states: dict[int, dict] = {entry: _initial_state()}
        work = deque([entry])
        inq = {entry}
        incomplete: list[dict] = []
        visits = 0
        sink = lambda kind, **kw: None  # noqa: E731
        while work:
            pc = work.popleft()
            inq.discard(pc)
            visits += 1
            if visits > MAX_VISITS:
                incomplete.append({"code": "visit-cap", "at": pc})
                break
            try:
                succ = self.exec_insn(pc, states[pc], sink)
            except lh.DecodeError as exc:
                incomplete.append({"code": exc.reason, "at": pc})
                continue
            for npc, nst in succ:
                if npc is None:
                    continue
                if not (0 <= npc < len(self.data)):
                    incomplete.append({"code": "target-out-of-range", "at": npc})
                    continue
                if npc not in states:
                    states[npc] = nst
                    if npc not in inq:
                        work.append(npc)
                        inq.add(npc)
                else:
                    j = _state_join(states[npc], nst)
                    if j != states[npc]:
                        states[npc] = j
                        if npc not in inq:
                            work.append(npc)
                            inq.add(npc)
        # Final pass on the fixed states: one event set per reached instruction.
        events: list[dict] = []

        def collect(kind: str, **kw) -> None:
            events.append({"pc": pc_now[0], "kind": kind, **kw})

        pc_now = [0]
        for pc in sorted(states):
            pc_now[0] = pc
            try:
                self.exec_insn(pc, states[pc], collect)
            except lh.DecodeError as exc:
                incomplete.append({"code": exc.reason, "at": pc})
        returns = [e for e in events if e["kind"] == "return"]
        return {"entry": entry, "reached": len(states), "visits": visits, "incomplete": incomplete,
                "events": events, "returns": returns,
                "unmodeled": sorted({(e["pc"], e["name"]) for e in events if e["kind"] == "unmodeled"})}


def _hex_events(events: list[dict]) -> list[dict]:
    out = []
    for e in sorted(events, key=lambda x: (x["pc"], x["kind"])):
        row = {k: v for k, v in e.items() if k not in ("pc",)}
        row["pc"] = "0x%05X" % e["pc"]
        out.append(row)
    return out


# --------------------------------------------------------------------------- reader and caller analysis
def reader_facts(data: bytes, reader_entry: int = READER_ENTRY) -> dict:
    """Run the reader with unknown arguments. Report its return set and whether it writes DS."""
    m = Machine(data, None, False, None, None)
    res = m.run(reader_entry)
    ds_writes = [e for e in res["events"] if e["kind"] in ("ds-write", "ds-indexed-write", "ds-write-unknown-seg")]
    consts = sorted({e["al"]["const"] for e in res["returns"] if e["al"]["const"] is not None})
    ubs = sorted({e["al"]["ub"] for e in res["returns"] if e["al"]["ub"] is not None})
    return {
        "entry": "0x%05X" % reader_entry,
        "return_count": len(res["returns"]),
        "return_al_consts": consts,
        "return_al_upper_bounds": ubs,
        "return_kinds": sorted({"retf %s" % e["imm"] if e["imm"] is not None else "ret" for e in res["returns"]}),
        "ds_write_events": len(ds_writes),
        "reached": res["reached"],
        "incomplete": res["incomplete"],
        "unmodeled": [{"pc": "0x%05X" % p, "name": n} for p, n in res["unmodeled"]],
        "_ds_write_count": len(ds_writes),
    }


def site_check(ovr: bytes, allg: list[dict], site: int, cache: "dcp.GroupCache") -> dict:
    """Exact bytes, owner group, fixup membership, and the caller from the owner's closure index."""
    g = fr.group_containing_code(allg, site)
    if g is None:
        return {"site": "0x%05X" % site, "ok": False, "reason": "no stub-carrying group contains this site"}
    rel = site - g["fileofs"]
    bytes_ok = ovr[site:site + 5] == SITE_BYTES
    fix = (site + 3 - g["fileofs"]) in fr.fixup_table(ovr, g)
    gw = cache.get(g)
    caller = None
    for k, w in list(gw.reached.items()) + list(gw.swept.items()):
        for fc in w["far_calls"]:
            if fc["at"] == site:
                caller = k
    return {"site": "0x%05X" % site, "owner_group": "0x%05X" % g["fileofs"],
            "site_rel": "0x%04X" % rel, "bytes": ovr[site:site + 5].hex(" "), "bytes_match": bytes_ok,
            "seg_word_in_fixup_table": fix, "caller_entry": None if caller is None else "0x%05X" % caller,
            "ok": bool(bytes_ok and fix and caller is not None),
            "_caller": caller}


def _party_addrs(args: list) -> list[str]:
    found = []
    for a in args:
        if a is None:
            continue
        for m in PARTY_DS_RE.finditer(a["prov"]):
            if m.group(1) not in found:
                found.append(m.group(1))
    return found


CALLEE_DEPTH = 3


def _cfg(data: bytes, entry: int) -> tuple[dict, dict, list]:
    """Decoded instructions, successor edges (flags ignored) and the walk listing of one function."""
    w = lh.walk(data, entry)
    insns = {r["at"]: lh.decode(data, r["at"]) for r in w["listing"]}
    succ: dict[int, list[int]] = {}
    for pc, ins in insns.items():
        if ins.flow == "jcc":
            succ[pc] = [ins.target, ins.end]
        elif ins.flow == "jmp":
            succ[pc] = [ins.target]
        elif ins.flow in ("ret", "retf", "jmp_far", "indirect_jmp", "indirect_jmpf"):
            succ[pc] = []
        else:
            succ[pc] = [ins.end]
    return insns, succ, w["listing"]


def post_site_pcs(data: bytes, entry: int, site: int) -> set[int]:
    """Instructions reachable from the reader call's successor over decoded edges (flags ignored).
    Effects before the call are common to every arm and are not attributed to one."""
    _, succ, _ = _cfg(data, entry)
    out, todo = set(), [s for s in succ.get(site, []) if s is not None]
    while todo:
        x = todo.pop()
        if x in out or x not in succ:
            continue
        out.add(x)
        todo.extend(succ[x])
    return out


def guards_for(data: bytes, entry: int, site: int) -> list[dict]:
    """Static guards: decoded conditional branches in the caller where only one arm can still reach
    the reader site (CFG reachability over decoded edges; flags ignored). Says which branches decide
    whether the site runs at all. Not value-aware: a guard can still be unsatisfiable."""
    insns, succ, listing = _cfg(data, entry)
    w = {"listing": listing}
    pred: dict[int, list[int]] = {}
    for pc, ss in succ.items():
        for s in ss:
            pred.setdefault(s, []).append(pc)
    can = {site}
    todo = [site]
    while todo:
        x = todo.pop()
        for p in pred.get(x, []):
            if p not in can:
                can.add(p)
                todo.append(p)
    prev_text = {}
    for r in w["listing"]:
        nxt = insns[r["at"]].end
        prev_text[nxt] = r["text"]
    out = []
    for pc in sorted(insns):
        ins = insns[pc]
        if ins.flow != "jcc" or pc == site:
            continue
        t_in, f_in = ins.target in can, ins.end in can
        if t_in != f_in:
            out.append({"pc": "0x%05X" % pc, "branch": ins.name,
                        "compare": prev_text.get(pc, "?"),
                        "site_reached_via": "taken" if t_in else "fallthrough"})
    return out


def run_closure(data: bytes, entry: int, site: int, R: int, reader_ds_writes: bool, owner: tuple,
                post: set) -> dict:
    """The caller's run plus the in-group near callees it reaches after the reader call (args unknown),
    to CALLEE_DEPTH. Only instructions in ``post`` (reachable from the call) are attributed to an arm.

    A callee is followed only when its entry lies inside the owner group's code. Far calls and
    calls outside the group are reported, not followed."""
    lo, hi = owner
    main = Machine(data, READER_LITERAL, reader_ds_writes, site, R).run(entry)
    events = [dict(e, via=None) for e in main["events"]
              if e["kind"] in ("return", "reader-call") or e["pc"] in post]
    incomplete = list(main["incomplete"])
    unmodeled = list(main["unmodeled"])
    callees: list[dict] = []
    frontier = [(e["target"], 1) for e in main["events"] if e["kind"] == "call-near" and e["pc"] in post]
    seen = {entry}
    while frontier:
        t, depth = frontier.pop(0)
        if t in seen or depth > CALLEE_DEPTH or not (lo <= t < hi):
            continue
        seen.add(t)
        sub = Machine(data, READER_LITERAL, reader_ds_writes, None, None).run(t)
        callees.append({"entry": "0x%05X" % t, "depth": depth, "reached": sub["reached"],
                        "incomplete": sub["incomplete"]})
        incomplete += [dict(x, in_callee="0x%05X" % t) for x in sub["incomplete"]]
        unmodeled += sub["unmodeled"]
        for e in sub["events"]:
            if e["kind"] in ("return", "reader-call"):
                continue
            events.append(dict(e, via="0x%05X" % t))
            if e["kind"] == "call-near":
                frontier.append((e["target"], depth + 1))
    return {"reached": main["reached"], "visits": main["visits"], "incomplete": incomplete,
            "unmodeled": unmodeled, "events": events, "returns": main["returns"], "callees": callees}


VERDICT_RANK = ("computed-party-byte-store", "edge-clamp-only", "state-write-nonparty", "calls-only",
                "classifier-only")


def _run_verdict(party_writes: list, other: list, ptr: list, calls: list) -> str:
    if any(w["value"]["const"] is None for w in party_writes):
        return "computed-party-byte-store"
    if party_writes:
        return "edge-clamp-only"
    if other or ptr:
        return "state-write-nonparty"
    if calls:
        return "calls-only"
    return "classifier-only"


def analyse_site(data: bytes, site: int, caller: int, reader_ds_writes: bool, owner: tuple) -> dict:
    """Interpret the caller once per forced reader result (plus in-group callees); classify each arm."""
    runs = {}
    all_args = None
    reader_valid = None
    post = post_site_pcs(data, caller, site)
    for R in RESULTS:
        res = run_closure(data, caller, site, R, reader_ds_writes, owner, post)
        reader_calls = [e for e in res["events"] if e["kind"] == "reader-call" and e.get("forced")]
        if all_args is None and reader_calls:
            all_args = reader_calls[0]["args"]
            reader_valid = reader_calls[0]["valid"]
        ev = [e for e in res["events"] if e["kind"] not in ("reader-call",)]
        runs["R=%d" % R] = {
            "forced_reader_calls_reached": len(reader_calls),
            "reached": res["reached"], "visits": res["visits"], "incomplete": res["incomplete"],
            "unmodeled": [{"pc": "0x%05X" % p, "name": n} for p, n in res["unmodeled"]],
            "returns": [{"pc": "0x%05X" % e["pc"], "imm": e["imm"], "al": e["al"]} for e in res["returns"]],
            "events": _hex_events(ev),
            "callees": res["callees"],
        }
    if all_args is None:
        return {"error": "forced reader call not reached in any run", "runs": runs}
    party = _party_addrs(all_args)
    # Classification, per run: every reachable event on the run's arms, including in-group callees.
    party_writes, other_ds, ptr_writes, calls, indexed = [], [], [], [], []
    per_run = {}
    for name, r in runs.items():
        rp, ro, rptr, rcalls = [], [], [], []
        for e in r["events"]:
            via = e.get("via")
            if e["kind"] == "ds-write":
                tag = {"run": name, "pc": e["pc"], "addr": e["addr"], "value": e["value"], "via": via}
                (rp if e["addr"][2:] in party else ro).append(tag)
            elif e["kind"] in ("ds-indexed-write", "ds-write-unknown-seg"):
                ro.append({"run": name, "pc": e["pc"], "kind": e["kind"], "via": via})
            elif e["kind"] == "ptr-write":
                rptr.append({"run": name, "pc": e["pc"], "target": e["target"], "via": via})
            elif e["kind"] in ("call-far", "call-near", "indirect-call"):
                rcalls.append({"run": name, "pc": e["pc"], "kind": e["kind"], "via": via,
                               "target": e.get("literal") or ("0x%05X" % e["target"] if isinstance(e.get("target"), int) else e.get("target")),
                               "args": e["args"]})
            elif e["kind"] == "ds-indexed-read":
                indexed.append({"run": name, "pc": e["pc"], "base": e["base"], "disp": "0x%04X" % (e["disp"] & 0xFFFF),
                                "index": e["index"], "via": via})
        party_writes += rp
        other_ds += ro
        ptr_writes += rptr
        calls += rcalls
        per_run[name] = _run_verdict(rp, ro, rptr, rcalls)
    best = min(per_run.values(), key=VERDICT_RANK.index)
    nonconst_party = [w for w in party_writes if w["value"]["const"] is None]
    return {
        "reader_args_top_first": {"reader[bp+6] (dir)": all_args[0], "reader[bp+8]": all_args[1],
                                  "reader[bp+10]": all_args[2]},
        "reader_args_valid_three_pushes_since_last_unknown_call": reader_valid,
        "party_bytes_from_args": ["DS:%s" % a for a in party],
        "verdict": best,
        "verdict_by_run": per_run,
        "static_guards_to_site": guards_for(data, caller, site),
        "verdict_basis": {
            "party_arg_ds_writes": party_writes,
            "party_arg_ds_writes_nonconst": nonconst_party,
            "other_ds_writes_or_unknown_seg": other_ds,
            "ptr_writes": ptr_writes,
            "calls": calls,
            "ds_indexed_reads": indexed,
        },
        "runs": runs,
    }


# --------------------------------------------------------------------------- census
def static_ds_writes(ins: lh.Insn) -> Optional[int]:
    """DS-direct address written by this instruction's r/m operand, else None (static, per opcode)."""
    op = ins.op
    if ins.modrm is None and op not in (0xA2, 0xA3):
        return None
    writes_rm = False
    if op in (0xA2, 0xA3):
        return struct.unpack_from("<H", ins.raw, len(ins.prefixes) + 1)[0]
    if op in (0x88, 0x89, 0xC6, 0xC7, 0x86, 0x87, 0x8F, 0x8C):
        writes_rm = True
    elif op < 0x40 and (op & 7) in (0, 1) and ((op >> 3) & 7) != 7:
        writes_rm = True
    elif op in (0x80, 0x81, 0x83) and ins.modrm[1] != 7:
        writes_rm = True
    elif op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
        writes_rm = True                      # every shift/rotate form writes its r/m operand
    elif op in (0xFE, 0xFF) and ins.modrm[1] in (0, 1):
        writes_rm = True                      # inc/dec (FF /2.. are transfers or push, not writes)
    elif op in (0xF6, 0xF7) and ins.modrm[1] in (2, 3):
        writes_rm = True
    if not writes_rm:
        return None
    pre = len(ins.prefixes)
    mb = ins.raw[pre + 1]
    if (mb >> 6) == 0 and (mb & 7) == 6:
        if any(p in PRE_SEG and PRE_SEG[p] != "ds" for p in ins.prefixes):
            return None
        return struct.unpack_from("<H", ins.raw, pre + 2)[0]
    return None


def census(ovr: bytes, cache: "dcp.GroupCache", owner_groups: list[dict]) -> dict:
    """Static DS-direct writes to the party bytes in the decoded walks of the owner groups."""
    hits, counted, seen = [], 0, set()
    for g in owner_groups:
        gw = cache.get(g)
        for walk in list(gw.reached.values()) + list(gw.swept.values()):
            for row in walk["listing"]:
                if row["at"] in seen:
                    continue
                seen.add(row["at"])
                counted += 1
                ins = lh.decode(ovr, row["at"])
                a = static_ds_writes(ins)
                if a in CENSUS_ADDRS:
                    hits.append({"group": "0x%05X" % g["fileofs"], "fn": "0x%05X" % walk["entry"],
                                 "site": "0x%05X" % row["at"], "addr": "0x%04X" % a, "text": row["text"]})
    return {"scope": "decoded walks (closure + prologue sweep) of the owner groups only; not exhaustive",
            "owner_groups": ["0x%05X" % g["fileofs"] for g in owner_groups],
            "instructions_checked": counted, "party_byte_writes": hits}


# --------------------------------------------------------------------------- probe
def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def analyse(ovr: bytes, start: bytes) -> dict:
    scan = fr.scan_all(start, ovr)
    allg = scan["groups"] + scan["partial_groups"]
    cache = dcp.GroupCache(ovr)
    rf = reader_facts(ovr)
    reader_ds = rf.pop("_ds_write_count") > 0
    sites_out = []
    owner_groups = []
    for s in SITES:
        chk = site_check(ovr, allg, s, cache)
        caller = chk.pop("_caller", None)
        row = {"check": chk}
        if chk["ok"]:
            g = fr.group_containing_code(allg, s)
            row["analysis"] = analyse_site(ovr, s, caller, reader_ds, (g["fileofs"], g["fileofs"] + g["codesz"]))
            if g not in owner_groups:
                owner_groups.append(g)
        else:
            row["analysis"] = {"error": "site check failed"}
        sites_out.append(row)
    return {"reader": rf, "reader_ds_writes_assumed_for_invalidation": reader_ds,
            "sites": sites_out, "census": census(ovr, cache, owner_groups)}


def probe(install: Path) -> dict:
    ovr, start, pins = dcp.load_pinned(install)
    result = analyse(ovr, start)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "pins": pins,
        "models": {
            "reader_identity": "0x2EC47 behind 03D5:002F is the caller probe's M1 candidate; NOT proven here",
            "arms": "reachability over decoded bytes; a reachable arm is not proof that it runs in play",
            "far_call_image": "not used to decide any verdict",
        },
        "analysis": result,
        "open_edges": [
            "Runtime: no dump or trace shows any of these arms executing or which R was returned.",
            "Reader identity: the 9A literal 03D5:002F is assumed to reach 0x2EC47 (M1 candidate). Byte consistency only: "
            "the reader ends in retf 6 and each caller pushes three words.",
            "Reader value 1 is also the reader's default return (no field read: helper returns zero, or an "
            "unlisted direction), so an R=1 arm is not proof that the field read 1.",
            "Far literal 03D5:002A (the 0x0C6FC second check, and the call inside 0x16E06 whose result is "
            "stored to DS:6AB0/6AB1) is not resolved to a body; its meaning is not decoded.",
            "Calls to other groups (far calls) are reported and not followed. Only in-group near callees are "
            "followed (depth %d)." % CALLEE_DEPTH,
            "Callee returns are unknown to the caller run (conservative): arms that depend on a callee's AL "
            "are reachable, not exact.",
            "The direction table (DS:2736+dir, DS:273F+dir) is DS data outside GAME.OVR: its values are not read here.",
            "What the party-byte writes mean in play (movement, facing, wall/door outcome) is not decoded.",
            "Callers of 0x0C6FC and 0x16D58 are not decoded here (the caller probe's tier A/B closure only).",
            "The GoldBox / CoK / COAB material was not used. No PoR semantics beyond these bytes.",
        ],
    }


def render_report(doc: dict) -> str:
    L = ["# PoR reader branch arms (static, observe-only)", "",
         "**Status: static-probe-only. `playable: false`.** Tool: `%s`." % TOOL, "", "## Pins", ""]
    for k, v in doc["pins"].items():
        L.append("- `%s` size %d sha256 `%s` pin_match %s" % (k, v["size"], v["sha256"], v["pin_match"]))
    L += ["", "## Models", ""] + ["- %s: %s" % (k, v) for k, v in doc["models"].items()]
    rf = doc["analysis"]["reader"]
    L += ["", "## Reader (%s): return set" % rf["entry"], "",
          "- returns: %d; AL constants %s; AL upper bounds %s; retf immediates %s"
          % (rf["return_count"], rf["return_al_consts"], rf["return_al_upper_bounds"], rf["return_kinds"]),
          "- DS write events in the reader: %d (invalidation assumed: %s)"
          % (rf["ds_write_events"], doc["analysis"]["reader_ds_writes_assumed_for_invalidation"]),
          "- unmodeled instructions in the reader: %d; incomplete: %d" % (len(rf["unmodeled"]), len(rf["incomplete"]))]
    for row in doc["analysis"]["sites"]:
        c, a = row["check"], row["analysis"]
        L += ["", "## Site `%s`" % c["site"], ""]
        L.append("- owner group `%s` (site rel `%s`), bytes `%s` match %s, fixup-listed %s, caller `%s`, ok %s"
                 % (c["owner_group"], c.get("site_rel"), c["bytes"], c.get("bytes_match"),
                    c.get("seg_word_in_fixup_table"), c.get("caller_entry"), c["ok"]))
        if "error" in a:
            L.append("- %s" % a["error"])
            continue
        L.append("- verdict (strongest over runs): **%s**; by run: %s"
                 % (a["verdict"], ", ".join("%s %s" % (k, v) for k, v in a["verdict_by_run"].items())))
        L.append("- reader args (top first): %s" % ", ".join("%s=%s" % (k, v["prov"]) for k, v in a["reader_args_top_first"].items()))
        L.append("- static guards (branches where only one arm can still reach the site): %s"
                 % ("; ".join("`%s` %s after `%s` (site via %s)" % (g["pc"], g["branch"], g["compare"], g["site_reached_via"])
                              for g in a["static_guards_to_site"]) or "none"))
        L.append("- party bytes from args: %s; three pushes valid: %s"
                 % (a["party_bytes_from_args"], a["reader_args_valid_three_pushes_since_last_unknown_call"]))
        for name, r in a["runs"].items():
            rets = ", ".join("%s al=%s/%s" % (x["pc"], x["al"]["const"], x["al"]["ub"]) for x in r["returns"]) or "none"
            callee = ", ".join(c["entry"] for c in r["callees"]) or "none"
            L.append("- %s: reached %d, forced reader calls %d, returns [%s], in-group callees [%s], incomplete %d, unmodeled %s"
                     % (name, r["reached"], r["forced_reader_calls_reached"], rets, callee, len(r["incomplete"]),
                        ", ".join("%s %s" % (u["pc"], u["name"]) for u in r["unmodeled"]) or "none"))
        vb = a["verdict_basis"]
        L.append("- party-arg DS writes (reachable): %d (non-constant: %d); other DS/unknown-seg: %d; ptr writes: %d; calls: %d; "
                 "DS-indexed table reads: %d"
                 % (len(vb["party_arg_ds_writes"]), len(vb["party_arg_ds_writes_nonconst"]),
                    len(vb["other_ds_writes_or_unknown_seg"]), len(vb["ptr_writes"]), len(vb["calls"]),
                    len(vb["ds_indexed_reads"])))
        for w in vb["party_arg_ds_writes"]:
            L.append("  - party store %s `%s` := %s (%s, via %s)" % (w["run"], w["pc"], w["value"]["const"] or w["value"]["prov"], w["addr"], w.get("via") or "caller"))
        for w in vb["other_ds_writes_or_unknown_seg"][:12]:
            L.append("  - other DS/unknown-seg write %s" % json.dumps(w, default=str))
        for c in vb["calls"]:
            L.append("  - call %s `%s` %s -> %s (in %s); args %s" % (
                c["run"], c["pc"], c["kind"], c["target"], c["via"] or "caller",
                ", ".join(x["prov"] if x else "-" for x in c["args"])))
        for x in vb["ds_indexed_reads"][:4]:
            L.append("  - DS-indexed read %s `%s` [%s%s] index %s (in %s)" % (
                x["run"], x["pc"], x["base"], x["disp"], x["index"]["prov"], x["via"] or "caller"))
    cs = doc["analysis"]["census"]
    L += ["", "## Writer census (party bytes)", "", "- scope: %s" % cs["scope"],
          "- instructions checked: %d; DS writes to %s: %d"
          % (cs["instructions_checked"], ", ".join("0x%04X" % x for x in CENSUS_ADDRS), len(cs["party_byte_writes"]))]
    for h in cs["party_byte_writes"]:
        L.append("  - group `%s` fn `%s` site `%s` addr `%s` `%s`" % (h["group"], h["fn"], h["site"], h["addr"], h["text"]))
    L += ["", "## Open edges", ""] + ["- " + x for x in doc["open_edges"]] + [""]
    return "\n".join(L)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_door_reader_branch_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_door_reader_branch_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only: branch arms after the PoR plane-3 reader call.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL,
                    help="folder with the pinned GAME.OVR and START.EXE")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    try:
        doc = probe(args.install)
    except (Refusal, dcp.Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
