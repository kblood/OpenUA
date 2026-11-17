#!/usr/bin/env python3
"""Pool of Radiance GAME.OVR 0x37 handler, dispatch and operand-parser probe.

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only, playable: false. This tool
reads the retail GAME.OVR bytes and reports what those bytes establish about:

  * the dispatcher at GAME.OVR:0x3c73 and its compare chain for opcode 0x37;
  * the 0x37 handler at GAME.OVR:0x19ba (reachable instructions, near and far
    call sites, direct DGROUP references, loop-shaped back-edges);
  * the operand parser entry at GAME.OVR:0x74d3 (prologue, stack-argument
    reads, return form, and near-call sites that target it);
  * the overlay header bytes, which this tool does NOT parse.

It does NOT give LOAD_PIECES (0x37) a meaning, does NOT name any far-call
target, does NOT bind WALLDEF blocks, and does NOT emit a module. A handler
address is structure, not opcode semantics. Every semantic question is listed
under ``not_established`` in the JSON and the report.

Why far-call targets stay unresolved. The handler calls through literal
``seg:off`` far-call operands (``9A``) whose segment values are not file
offsets. Resolving them needs the overlay manager's stub or fixup table, which
this tool does not parse. The handler therefore cannot be shown to reach the
parser at 0x74d3 by any path, and this tool says so rather than guessing.

Near calls are different. Dispatcher and parser near calls (``E8 rel16``) are
resolved to GAME.OVR file offsets under a same-code-space reading, which is an
assumption recorded in the output and not a proof.

Decoder. A small 8086/80186 real-mode length and flow decoder lives in this file
so that no third-party disassembler is needed. Unknown or two-byte (0F) opcodes
stop the walk and mark the function incomplete. The test suite checks it
against hand-encoded instructions; a one-off cross-check against an external
disassembler is a separate, unpinned step that is not part of this tool.

Usage
  python3 tools/por_loadpieces_handler.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-loadpieces-handler/retail

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_loadpieces_handler.json        schema openua.por-loadpieces-handler, playable: false
  por_loadpieces_handler_report.md   annotated listing and evidence boundaries

Exit codes
  0  every structural check passed and every walk was complete
  1  output written; a check failed or a walk was incomplete (see diagnostics)
  2  named refusal: bad install, GAME.OVR not pinned (without --allow-unpinned),
     or unsafe output location
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-loadpieces-handler"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_loadpieces_handler.py"
OVR_NAME = "GAME.OVR"

# Pinned retail GAME.OVR (user-supplied POOLRAD install, read-only check).
PINNED_SIZE = 206105
PINNED_SHA256 = "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"

DISPATCH_ENTRY = 0x3C73
DISPATCH_DOC_COUNT = 273          # instruction count claimed by docs/engine/research/pool-ecl-dispatch-map.md
PARSER_ENTRY = 0x74D3
HANDLER_0X37 = 0x19BA
OPCODE = 0x37
KEY_ADDRESS = 0x6F7F              # DGROUP byte the dispatcher loads into AL
PARSER_PROLOGUE = bytes([0x55, 0x89, 0xE5])  # push bp; mov bp, sp

MAX_WALK = 3000
MAX_DISPATCH = 400

ALU = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = ("rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar")
GRP3 = ("test", "test", "not", "neg", "mul", "imul", "div", "idiv")
JCC = ("jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
       "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg")
REG16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
REG8 = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
SREG = ("es", "cs", "ss", "ds")
RM16 = ("bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx")
SEG_PREFIX = {0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds"}
LOCK_REP = {0xF0: "lock", 0xF2: "repne", 0xF3: "rep"}

# Fixed-form opcodes: (name, flow, immediate-form). Forms: "" none, "ib", "iw",
# "iw_ib", "rel8", "rel16", "far", "moffs", "modrm", "modrm_ib", "modrm_iw".
SPECIAL = {
    0x06: ("push", "seq", "", "es"), 0x07: ("pop", "seq", "", "es"),
    0x0E: ("push", "seq", "", "cs"), 0x16: ("push", "seq", "", "ss"),
    0x17: ("pop", "seq", "", "ss"), 0x1E: ("push", "seq", "", "ds"),
    0x1F: ("pop", "seq", "", "ds"),
    0x27: ("daa", "seq", "", ""), 0x2F: ("das", "seq", "", ""),
    0x37: ("aaa", "seq", "", ""), 0x3F: ("aas", "seq", "", ""),
}


class DecodeError(Exception):
    def __init__(self, reason: str, off: int):
        super().__init__("%s at 0x%05x" % (reason, off))
        self.reason = reason
        self.off = off


@dataclass
class Insn:
    off: int
    length: int
    raw: bytes
    name: str
    flow: str                       # seq, jcc, jmp, call, call_far, jmp_far, ret, retf,
                                    # indirect_call, indirect_jmp, indirect_callf, indirect_jmpf
    prefixes: tuple
    op: int
    modrm: Optional[tuple] = None   # (mod, reg, rm)
    mem: Optional[str] = None       # coarse memory operand text
    direct: Optional[int] = None    # DS-direct address (mod 00, rm 110)
    bp_disp: Optional[int] = None   # [bp+disp] reference (mod 01/10, rm 110)
    imm: Optional[int] = None
    target: Optional[int] = None    # near branch/call target (file-offset space)
    far: Optional[tuple] = None     # literal (seg, off)

    @property
    def end(self) -> int:
        return self.off + self.length

    def text(self) -> str:
        parts = []
        if self.mem:
            parts.append(self.mem)
        elif self.modrm and self.modrm[0] == 3:
            parts.append("r%d" % self.modrm[2])
        if self.imm is not None:
            parts.append("0x%x" % self.imm)
        if self.target is not None:
            parts.append("0x%05x" % self.target)
        if self.far is not None:
            parts.append("0x%04x:0x%04x" % (self.far[0], self.far[1]))
        body = ", ".join(parts)
        pre = (" ".join(LOCK_REP.get(p, SEG_PREFIX.get(p, "")) for p in self.prefixes)).strip()
        return ((pre + " ") if pre else "") + self.name + ((" " + body) if body else "")


def _s16(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=True)


def _u16(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)


def _modrm_text(mod: int, rm: int, disp: int) -> str:
    if mod == 0 and rm == 6:
        return "[0x%04x]" % (disp & 0xFFFF)
    if mod == 0:
        return "[%s]" % RM16[rm]
    if mod == 3:
        return "r%d" % rm
    return "[%s%+d]" % (RM16[rm], disp)


def decode(data: bytes, off: int) -> Insn:
    """Decode one 8086/80186 real-mode instruction at file offset ``off``.

    Raises DecodeError for truncated input, two-byte (0F) opcodes, and opcodes
    that are undefined in real mode. Operand text is coarse; the length, flow
    class and literal operands are the parts intended for analysis.
    """
    p = off
    prefixes: list[int] = []
    while p < len(data) and (data[p] in SEG_PREFIX or data[p] in LOCK_REP):
        prefixes.append(data[p])
        p += 1
    if p >= len(data):
        raise DecodeError("truncated", off)
    op = data[p]
    p += 1
    name, flow, form, arg = "", "seq", "", None
    modrm_needed = False
    reg_for_group = None

    if op in SPECIAL:
        name, flow, form, arg = SPECIAL[op][0], SPECIAL[op][1], SPECIAL[op][2], SPECIAL[op][3]
        if arg:
            name = "%s %s" % (name, arg)
    elif op < 0x40 and (op & 7) < 6:
        name = ALU[op >> 3]
        sub = op & 7
        if sub < 4:
            modrm_needed = True
        elif sub == 4:
            form = "ib"
        else:
            form = "iw"
    elif 0x40 <= op <= 0x4F:
        name = "inc" if op < 0x48 else "dec"
        arg = REG16[op & 7]
        name = "%s %s" % (name, arg)
    elif 0x50 <= op <= 0x5F:
        name = ("push" if op < 0x58 else "pop") + " " + REG16[op & 7]
    elif op == 0x60:
        name = "pusha"
    elif op == 0x61:
        name = "popa"
    elif op == 0x62:
        name, modrm_needed = "bound", True
    elif op == 0x68:
        name, form = "push", "iw"
    elif op == 0x6A:
        name, form = "push", "ib"
    elif op == 0x69:
        name, modrm_needed, form = "imul", True, "modrm_iw"
    elif op == 0x6B:
        name, modrm_needed, form = "imul", True, "modrm_ib"
    elif 0x6C <= op <= 0x6F:
        name = ("insb", "insw", "outsb", "outsw")[op - 0x6C]
    elif 0x70 <= op <= 0x7F:
        name, flow, form = JCC[op & 0xF], "jcc", "rel8"
    elif op in (0x80, 0x82):
        name, modrm_needed, form = "grp1", True, "modrm_ib"
        reg_for_group = "alu"
    elif op == 0x81:
        name, modrm_needed, form = "grp1", True, "modrm_iw"
        reg_for_group = "alu"
    elif op == 0x83:
        name, modrm_needed, form = "grp1", True, "modrm_ib"
        reg_for_group = "alu"
    elif op in (0x84, 0x85):
        name, modrm_needed = "test", True
    elif op in (0x86, 0x87):
        name, modrm_needed = "xchg", True
    elif 0x88 <= op <= 0x8B:
        name, modrm_needed = "mov", True
    elif op == 0x8C:
        name, modrm_needed = "mov", True
    elif op == 0x8D:
        name, modrm_needed = "lea", True
    elif op == 0x8E:
        name, modrm_needed = "mov", True
    elif op == 0x8F:
        name, modrm_needed = "pop", True
    elif op == 0x90:
        name = "nop"
    elif 0x91 <= op <= 0x97:
        name = "xchg ax, " + REG16[op & 7]
    elif op == 0x98:
        name = "cbw"
    elif op == 0x99:
        name = "cwd"
    elif op == 0x9A:
        name, flow, form = "call", "call_far", "far"
    elif op == 0x9B:
        name = "wait"
    elif op == 0x9C:
        name = "pushf"
    elif op == 0x9D:
        name = "popf"
    elif op == 0x9E:
        name = "sahf"
    elif op == 0x9F:
        name = "lahf"
    elif 0xA0 <= op <= 0xA3:
        name, form = "mov", "moffs"
    elif 0xA4 <= op <= 0xA7:
        name = ("movsb", "movsw", "cmpsb", "cmpsw")[op - 0xA4]
    elif op == 0xA8:
        name, form = "test", "ib"
    elif op == 0xA9:
        name, form = "test", "iw"
    elif 0xAA <= op <= 0xAF:
        name = ("stosb", "stosw", "lodsb", "lodsw", "scasb", "scasw")[op - 0xAA]
    elif 0xB0 <= op <= 0xB7:
        name, form = "mov", "ib"
        arg = REG8[op & 7]
        name = "mov " + arg
    elif 0xB8 <= op <= 0xBF:
        name, form = "mov", "iw"
        arg = REG16[op & 7]
        name = "mov " + arg
    elif op in (0xC0, 0xC1):
        name, modrm_needed, form = "grp2", True, "modrm_ib"
        reg_for_group = "shift"
    elif op == 0xC2:
        name, flow, form = "ret", "ret", "iw"
    elif op == 0xC3:
        name, flow = "ret", "ret"
    elif op == 0xC4:
        name, modrm_needed = "les", True
    elif op == 0xC5:
        name, modrm_needed = "lds", True
    elif op == 0xC6:
        name, modrm_needed, form = "mov", True, "modrm_ib"
    elif op == 0xC7:
        name, modrm_needed, form = "mov", True, "modrm_iw"
    elif op == 0xC8:
        name, form = "enter", "iw_ib"
    elif op == 0xC9:
        name = "leave"
    elif op == 0xCA:
        name, flow, form = "retf", "retf", "iw"
    elif op == 0xCB:
        name, flow = "retf", "retf"
    elif op == 0xCC:
        name = "int3"
    elif op == 0xCD:
        name, form = "int", "ib"
    elif op == 0xCE:
        name = "into"
    elif op == 0xCF:
        name, flow = "iret", "ret"
    elif 0xD0 <= op <= 0xD3:
        name, modrm_needed = "grp2", True
        reg_for_group = "shift"
    elif op == 0xD4:
        name, form = "aam", "ib"
    elif op == 0xD5:
        name, form = "aad", "ib"
    elif op == 0xD6:
        name = "salc"
    elif op == 0xD7:
        name = "xlat"
    elif 0xD8 <= op <= 0xDF:
        name, modrm_needed = "esc", True
    elif 0xE0 <= op <= 0xE3:
        name, flow, form = ("loopne", "loope", "loop", "jcxz")[op - 0xE0], "jcc", "rel8"
    elif 0xE4 <= op <= 0xE7:
        name, form = ("in al", "in ax", "out al", "out ax")[op - 0xE4], "ib"
    elif op == 0xE8:
        name, flow, form = "call", "call", "rel16"
    elif op == 0xE9:
        name, flow, form = "jmp", "jmp", "rel16"
    elif op == 0xEA:
        name, flow, form = "jmp", "jmp_far", "far"
    elif op == 0xEB:
        name, flow, form = "jmp", "jmp", "rel8"
    elif 0xEC <= op <= 0xEF:
        name = ("in al, dx", "in ax, dx", "out dx, al", "out dx, ax")[op - 0xEC]
    elif op == 0xF4:
        name = "hlt"
    elif op == 0xF5:
        name = "cmc"
    elif op == 0xF6:
        name, modrm_needed = "grp3b", True
        reg_for_group = "grp3"
    elif op == 0xF7:
        name, modrm_needed = "grp3w", True
        reg_for_group = "grp3"
    elif 0xF8 <= op <= 0xFD:
        name = ("clc", "stc", "cli", "sti", "cld", "std")[op - 0xF8]
    elif op == 0xFE:
        name, modrm_needed = "grp4", True
    elif op == 0xFF:
        name, modrm_needed = "grp5", True
    else:
        # 0x0F two-byte escape, 0xF1, and 386+ prefixes are not decoded here.
        raise DecodeError("unsupported-opcode-0x%02x" % op, off)

    mod = rm = reg = None
    mem = None
    direct = bp_disp = None
    imm = target = None
    far = None
    if modrm_needed or reg_for_group is not None:
        if p >= len(data):
            raise DecodeError("truncated-modrm", off)
        mb = data[p]
        p += 1
        mod, reg, rm = mb >> 6, (mb >> 3) & 7, mb & 7
        disp = 0
        if mod == 0 and rm == 6:
            disp = _u16(data[p:p + 2])
            p += 2
            direct = disp
        elif mod == 1:
            disp = int.from_bytes(data[p:p + 1], "little", signed=True)
            p += 1
            if rm == 6:
                bp_disp = disp
        elif mod == 2:
            disp = _s16(data[p:p + 2])
            p += 2
            if rm == 6:
                bp_disp = disp
        if p > len(data):
            raise DecodeError("truncated-modrm", off)
        mem = _modrm_text(mod, rm, disp) if mod != 3 else None
        if reg_for_group == "alu":
            name = ALU[reg]
        elif reg_for_group == "shift":
            name = SHIFTS[reg]
        elif reg_for_group == "grp3":
            name = GRP3[reg]
            if reg in (0, 1):
                form = "modrm_iw" if op == 0xF7 else "modrm_ib"
        elif op == 0xFE:
            if reg > 1:
                raise DecodeError("unsupported-fe-reg-%d" % reg, off)
            name = ("inc", "dec")[reg]
        elif op == 0xFF:
            names = ("inc", "dec", "call", "callf", "jmp", "jmpf", "push")
            if reg == 7:
                raise DecodeError("unsupported-ff-reg-7", off)
            name = names[reg]
            if reg == 2:
                flow = "indirect_call"
            elif reg == 3:
                flow = "indirect_callf"
            elif reg == 4:
                flow = "indirect_jmp"
            elif reg == 5:
                flow = "indirect_jmpf"
        elif op == 0x8C or op == 0x8E:
            name = "mov %s" % SREG[reg] if op == 0x8E else "mov"
        elif op in (0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF):
            name = "esc%d" % (op - 0xD8)

    if form == "ib":
        imm = data[p]
        p += 1
    elif form == "iw":
        imm = _u16(data[p:p + 2]); p += 2
    elif form == "modrm_ib":
        imm = data[p]; p += 1
    elif form == "modrm_iw":
        imm = _u16(data[p:p + 2]); p += 2
    elif form == "iw_ib":
        imm = _u16(data[p:p + 2]); p += 3
    elif form == "rel8":
        target = p + 1 + int.from_bytes(data[p:p + 1], "little", signed=True)
        p += 1
    elif form == "rel16":
        target = p + 2 + _s16(data[p:p + 2])
        p += 2
    elif form == "far":
        far = (_u16(data[p + 2:p + 4]), _u16(data[p:p + 2]))  # (seg, off)
        p += 4
    elif form == "moffs":
        direct = _u16(data[p:p + 2])
        p += 2
        mem = "[0x%04x]" % direct
    if p > len(data):
        raise DecodeError("truncated", off)
    modrm =(mod, reg, rm) if mod is not None else None
    return Insn(off=off, length=p - off, raw=bytes(data[off:p]), name=name, flow=flow,
                prefixes=tuple(prefixes), op=op, modrm=modrm, mem=mem, direct=direct,
                bp_disp=bp_disp, imm=imm, target=target, far=far)


def linear(data: bytes, off: int, limit: int, stop_on_ret: bool = True) -> tuple[list[Insn], Optional[str]]:
    out: list[Insn] = []
    p = off
    while len(out) < limit:
        try:
            ins = decode(data, p)
        except DecodeError as exc:
            return out, "%s" % exc
        out.append(ins)
        p = ins.end
        if stop_on_ret and ins.flow in ("ret", "retf"):
            break
    return out, None


def walk(data: bytes, entry: int) -> dict:
    """Recursive-descent walk over one function. Follows fall-through and
    branch edges; records calls without entering them; stops at returns."""
    insns: dict[int, Insn] = {}
    work = [entry]
    seen_starts = set()
    incomplete: list[dict] = []
    conflicts: list[dict] = []
    owner: dict[int, int] = {}
    steps = 0
    while work:
        a = work.pop()
        if a in seen_starts:
            continue
        if not (0 <= a < len(data)):
            incomplete.append({"code": "target-out-of-range", "at": a})
            continue
        steps += 1
        if steps > MAX_WALK:
            incomplete.append({"code": "walk-budget-exhausted", "at": a})
            break
        try:
            ins = decode(data, a)
        except DecodeError as exc:
            incomplete.append({"code": exc.reason, "at": a})
            continue
        for b in range(ins.off, ins.end):
            if b in owner and owner[b] != ins.off:
                conflicts.append({"at": a, "overlaps": owner[b]})
            owner[b] = ins.off
        seen_starts.add(a)
        insns[a] = ins
        if ins.flow == "seq" or ins.flow in ("call", "call_far", "indirect_call", "indirect_callf"):
            work.append(ins.end)
        elif ins.flow == "jcc":
            work.append(ins.end)
            work.append(ins.target)
        elif ins.flow == "jmp":
            work.append(ins.target)
        elif ins.flow in ("ret", "retf"):
            pass
        elif ins.flow in ("jmp_far", "indirect_jmp", "indirect_jmpf"):
            incomplete.append({"code": ins.flow, "at": a})
        else:
            incomplete.append({"code": "flow-" + ins.flow, "at": a})

    ordered = [insns[k] for k in sorted(insns)]
    near_calls = [{"at": i.off, "target": i.target, "push_cs_before": (i.off > 0 and data[i.off - 1] == 0x0E)}
                  for i in ordered if i.flow == "call"]
    far_calls = [{"at": i.off, "seg": i.far[0], "off": i.far[1]}
                 for i in ordered if i.flow == "call_far"]
    indirect = [{"at": i.off, "kind": i.flow} for i in ordered if i.flow.startswith("indirect")]
    returns = [{"at": i.off, "kind": i.flow, "imm": i.imm} for i in ordered if i.flow in ("ret", "retf")]
    direct_refs = sorted({i.direct for i in ordered if i.direct is not None and i.op not in (0x9A,)})
    bp_refs = sorted({i.bp_disp for i in ordered if i.bp_disp is not None})
    backedges = []
    for i in ordered:
        if i.flow in ("jcc", "jmp") and i.target is not None and i.target < i.off and i.target in insns:
            prev = None
            for j in ordered:
                if j.end == i.off:
                    prev = j
                    break
            backedges.append({"at": i.off, "to": i.target,
                              "preceded_by": prev.text() if prev else None})
    return {
        "entry": entry,
        "instruction_count": len(ordered),
        "complete": not incomplete and not conflicts,
        "incomplete": incomplete,
        "overlap_conflicts": conflicts,
        "near_calls": near_calls,
        "far_calls": far_calls,
        "indirect": indirect,
        "returns": returns,
        "direct_refs": direct_refs,
        "bp_refs": bp_refs,
        "backedges": backedges,
        "listing": [{"at": i.off, "bytes": i.raw.hex(), "text": i.text(), "flow": i.flow}
                    for i in ordered],
    }


def dispatch_cases(data: bytes) -> dict:
    """Read the dispatcher's compare chain. Only the shapes proven by the retail
    bytes are reported: ``cmp al,imm8; jne next; push cs; call near; jmp end``
    (the case calls a near target) and ``cmp al,imm8; je group`` (grouped cases)."""
    head, err = linear(data, DISPATCH_ENTRY, MAX_DISPATCH, stop_on_ret=True)
    doc_match = len(head) == DISPATCH_DOC_COUNT
    key_index = next((k for k, ins in enumerate(head) if ins.op == 0xA0), None)
    key_load = head[key_index] if key_index is not None else None
    cases: list[dict] = []
    unstructured: list[int] = []
    for i, ins in enumerate(head):
        if not (ins.op == 0x3C and ins.imm is not None and ins.modrm is None and len(ins.raw) == 2):
            continue
        if i + 1 >= len(head):
            continue
        nxt = head[i + 1]
        if nxt.op == 0x75 and nxt.flow == "jcc" and i + 5 < len(head):
            blk = head[i + 2:i + 5]
            if (blk[0].op == 0x0E and blk[1].op == 0xE8 and blk[2].flow == "jmp"
                    and nxt.target == blk[2].end):
                cases.append({"case": ins.imm, "form": "jne-push-cs-call",
                              "call_target": blk[1].target, "at": ins.off})
                continue
        if nxt.op == 0x74 and nxt.flow == "jcc":
            cases.append({"case": ins.imm, "form": "je-group", "group_target": nxt.target,
                          "at": ins.off})
            continue
        unstructured.append(ins.off)
    case_map = {c["case"]: c for c in cases}
    target_case = case_map.get(OPCODE)
    path = _not_equal_path(data, key_load, OPCODE)
    return {
        "entry": DISPATCH_ENTRY,
        "linear_instruction_count": len(head),
        "doc_instruction_count": DISPATCH_DOC_COUNT,
        "doc_count_matches": doc_match,
        "sweep_stopped": err,
        "key_load_at": None if key_load is None else key_load.off,
        "key_source": (
            "mov al, [0x%04x]" % key_load.direct
            if key_load is not None and key_load.direct is not None else None),
        "case_count": len(cases),
        "unstructured_cmp_al_sites": unstructured,
        "cases": sorted(cases, key=lambda c: c["case"]),
        "opcode_0x37": target_case,
        "not_equal_path_to_0x37": path,
    }


def _not_equal_path(data: bytes, key_load: Optional[Insn], opcode: int) -> dict:
    """Follow the path on which AL != each earlier case value, from the key
    load to the compare for ``opcode``. Only cmp/jcc may run on it, so AL still
    holds the key at that compare. This is a path fact, not a claim about other
    entries into the chain."""
    if key_load is None:
        return {"reached": False, "reason": "no key load in dispatcher prefix"}
    addr = key_load.end
    clobber: list[str] = []
    steps = 0
    while steps < MAX_DISPATCH:
        steps += 1
        try:
            ins = decode(data, addr)
        except DecodeError as exc:
            return {"reached": False, "reason": exc.reason, "steps": steps, "clobber": clobber}
        if ins.op == 0x3C and ins.imm is not None and len(ins.raw) == 2:
            if ins.imm == opcode:
                return {"reached": True, "at": ins.off, "steps": steps, "clobber": clobber}
            try:
                nxt = decode(data, ins.end)
            except DecodeError as exc:
                return {"reached": False, "reason": exc.reason, "steps": steps, "clobber": clobber}
            if nxt.op == 0x75 and nxt.flow == "jcc":
                addr = nxt.target
                continue
            if nxt.op == 0x74 and nxt.flow == "jcc":
                addr = nxt.end
                continue
            clobber.append(nxt.text())
            return {"reached": False, "reason": "unexpected-branch", "steps": steps, "clobber": clobber}
        clobber.append(ins.text())
        return {"reached": False, "reason": "non-compare-on-path", "steps": steps, "clobber": clobber}
    return {"reached": False, "reason": "step-budget", "steps": steps, "clobber": clobber}


def near_call_candidates(data: bytes, target: int) -> list[dict]:
    """Byte-pattern candidates: ``E8 rel16`` whose exact target is ``target``.
    Not decoded-boundary checked; a random byte match is possible."""
    out = []
    for o in range(len(data) - 2):
        if data[o] == 0xE8:
            rel = _s16(data[o + 1:o + 3])
            if o + 3 + rel == target:
                out.append({"at": o, "push_cs_before": data[o - 1] == 0x0E if o > 0 else False})
    return out


def far_call_literal_candidates(data: bytes, offset: int) -> list[dict]:
    """Literal ``9A off16 seg16`` sites whose offset equals ``offset``."""
    out = []
    for o in range(len(data) - 4):
        if data[o] == 0x9A and _u16(data[o + 1:o + 3]) == offset:
            out.append({"at": o, "seg": _u16(data[o + 3:o + 5])})
    return out


def analyze(data: bytes) -> dict:
    handler = walk(data, HANDLER_0X37)
    parser = walk(data, PARSER_ENTRY)
    dispatch = dispatch_cases(data)
    header = data[:16]
    parser_callers = near_call_candidates(data, PARSER_ENTRY)
    handler_callers = near_call_candidates(data, HANDLER_0X37)
    handler_reaches_parser_near = any(c["target"] == PARSER_ENTRY for c in handler["near_calls"])
    handler_far_literal_segs = sorted({c["seg"] for c in handler["far_calls"]})
    return {
        "dispatcher": dispatch,
        "handler_0x37": {**handler, "address": HANDLER_0X37},
        "parser": {**parser, "address": PARSER_ENTRY,
                   "prologue_matches": data[PARSER_ENTRY:PARSER_ENTRY + 3] == PARSER_PROLOGUE},
        "callers": {
            "near_calls_to_handler_0x37": handler_callers,
            "near_calls_to_parser_0x74d3": parser_callers,
            "far_literal_sites_offset_parser": far_call_literal_candidates(data, PARSER_ENTRY),
        },
        "handler_reaches_parser_by_near_call": handler_reaches_parser_near,
        "handler_far_call_segments": handler_far_literal_segs,
        "overlay_header_first16_hex": header.hex(),
        "overlay_header_signature_ascii": header[:4].decode("ascii", "replace"),
    }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_game_ovr(install: Path) -> Optional[Path]:
    want = OVR_NAME.upper()
    found: list[Path] = []
    for folder in (install, install / "POOLRAD"):
        if not folder.is_dir():
            continue
        for entry in folder.iterdir():
            if entry.is_file() and entry.name.upper() == want:
                found.append(entry)
    if len(found) > 1:
        raise PorSourceError("ambiguous %s: more than one match" % OVR_NAME)
    return found[0] if found else None


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    if not install.is_dir():
        raise PorSourceError("install folder not found")
    out = validate_output_dir(install, out)
    path = find_game_ovr(install)
    if path is None:
        raise PorSourceError("GAME.OVR not found in install or POOLRAD subfolder")
    data = path.read_bytes()
    sha = _sha(data)
    pinned = len(data) == PINNED_SIZE and sha == PINNED_SHA256
    if not pinned and not allow_unpinned:
        raise PorSourceError("GAME.OVR does not match the pinned retail hash; "
                             "pass --allow-unpinned to probe it anyway (results are not retail evidence)")
    result = analyze(data)
    diagnostics: list[dict] = []
    d = result["dispatcher"]
    if not d["doc_count_matches"]:
        diagnostics.append({"code": "dispatch-count-differs",
                            "message": "linear dispatcher sweep gave %d instructions; docs claim %d"
                            % (d["linear_instruction_count"], DISPATCH_DOC_COUNT)})
    if d["opcode_0x37"] is None:
        diagnostics.append({"code": "no-0x37-case", "message": "no structured 0x37 case in dispatcher"})
    elif d["opcode_0x37"]["call_target"] != HANDLER_0X37:
        diagnostics.append({"code": "0x37-target-differs",
                            "message": "0x37 case calls 0x%05x, not 0x%05x"
                            % (d["opcode_0x37"]["call_target"], HANDLER_0X37)})
    if not d["not_equal_path_to_0x37"]["reached"]:
        diagnostics.append({"code": "0x37-path-unverified",
                            "message": "not-equal path to the 0x37 compare: %s"
                            % d["not_equal_path_to_0x37"].get("reason")})
    for name in ("handler_0x37", "parser"):
        w = result[name]
        if not w["complete"]:
            diagnostics.append({"code": name + "-walk-incomplete",
                                "message": "%d incomplete point(s), %d overlap conflict(s)"
                                % (len(w["incomplete"]), len(w["overlap_conflicts"]))})
    if not result["parser"]["prologue_matches"]:
        diagnostics.append({"code": "parser-prologue-differs",
                            "message": "bytes at 0x%05x are not push bp; mov bp, sp" % PARSER_ENTRY})
    checks_ok = not diagnostics
    out_doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "playable": False,
        "source": {
            "file": OVR_NAME,
            "size": len(data),
            "sha256": sha,
            "pinned_size": PINNED_SIZE,
            "pinned_sha256": PINNED_SHA256,
            "pin_match": pinned,
            "addresses": "GAME.OVR file offsets; near-call targets are assumed to share this offset space",
        },
        "analysis": result,
        "diagnostics": diagnostics,
        "established_by_bytes": [
            "GAME.OVR matches the pinned size and SHA-256 (see source.pin_match).",
            "The dispatcher's first instruction loads AL from DS:0x6f7f (analysis.dispatcher.key_source).",
            "The 0x37 case is `cmp al,0x37; jne; push cs; call near 0x19ba; jmp` and the not-equal path "
            "from the key load to that compare executes only cmp/jcc (analysis.dispatcher.opcode_0x37, "
            "not_equal_path_to_0x37).",
            "The 0x37 handler is a closed walk over its reachable instructions "
            "(analysis.handler_0x37.complete); its near calls are listed (none in the handler).",
            "The handler's far calls are literal seg:off operands; their segments are listed and are not "
            "resolved to any file offset.",
            "The parser entry starts with push bp; mov bp, sp and returns retf 2 (analysis.parser).",
            "Near-call sites that target 0x74d3 and 0x19ba are listed as byte-pattern candidates "
            "(analysis.callers).",
        ],
        "not_established": [
            "What opcode 0x37 means in PoR. The name LOAD_PIECES comes from the CoK schema; it is not PoR evidence.",
            "Which function the handler's far calls reach. Their segments are not file offsets and the overlay "
            "stub/fixup table is not parsed.",
            "Whether the handler reaches the operand parser at 0x74d3 at all. No near call in the handler "
            "targets it; far-call resolution is unknown.",
            "Whether the handler's 3-iteration loop reads three operand bytes, what those bytes mean, or "
            "what width they have under PoR.",
            "The meaning of the DGROUP fields the handler touches (0x6f7f, 0x4431, 0x4433, 0x4434 and the "
            "far-pointer loads from 0x49d2 and 0x49d6).",
            "Whether 0x19ba is reached at runtime for opcode 0x37. The bytes show a static path only.",
            "Completeness of the ECL walk, of the dispatcher for every opcode, and of any framing model.",
            "The overlay header format; the 16 header bytes are reported raw and not parsed.",
        ],
    }
    return out_doc, (0 if checks_ok else 1)


def _fmt_insn_rows(listing: list[dict]) -> list[str]:
    rows = ["| Address | Bytes | Flow | Text |", "| ---: | --- | --- | --- |"]
    for r in listing:
        rows.append("| `0x%05x` | `%s` | %s | `%s` |" % (r["at"], r["bytes"], r["flow"], r["text"]))
    return rows


def render_report(doc: dict) -> str:
    a = doc["analysis"]
    d = a["dispatcher"]
    h = a["handler_0x37"]
    p = a["parser"]
    s = doc["source"]
    L: list[str] = []
    add = L.append
    add("# Pool of Radiance GAME.OVR 0x37 handler probe")
    add("")
    add("> Generated by `%s`. Static probe only; playable: false. Not evidence of LOAD_PIECES semantics." % TOOL)
    add("")
    add("| Field | Value |")
    add("| --- | --- |")
    add("| File | `%s` (%d bytes) |" % (s["file"], s["size"]))
    add("| SHA-256 | `%s` |" % s["sha256"])
    add("| Pin match | %s |" % ("yes" if s["pin_match"] else "NO (unpinned, not retail evidence)"))
    add("")
    add("## Dispatcher `0x%x`" % DISPATCH_ENTRY)
    add("")
    add("- Linear instructions to first return: %d (docs claim %d; matches: %s)."
        % (d["linear_instruction_count"], d["doc_instruction_count"], d["doc_count_matches"]))
    add("- Key source: `%s`." % d["key_source"])
    add("- Structured case count: %d; unstructured `cmp al` sites: %d at %s."
        % (d["case_count"], len(d["unstructured_cmp_al_sites"]),
           ", ".join("0x%x" % x for x in d["unstructured_cmp_al_sites"]) or "none"))
    case37 = d["opcode_0x37"]
    add("- 0x37 case: %s." % ("absent" if case37 is None else
        "`cmp al, 0x37; jne; push cs; call near 0x%x` at `0x%x`" % (case37["call_target"], case37["at"])))
    add("- Not-equal path to the 0x37 compare: reached=%s, steps=%s, clobber=%s."
        % (d["not_equal_path_to_0x37"].get("reached"), d["not_equal_path_to_0x37"].get("steps"),
           d["not_equal_path_to_0x37"].get("clobber")))
    add("")
    add("## Handler `0x%x` (opcode 0x37)" % HANDLER_0X37)
    add("")
    add("- Reachable instructions: %d; complete: %s; returns: %s."
        % (h["instruction_count"], h["complete"], h["returns"]))
    add("- Near calls: %d (%s). Far calls: %d, literal segments %s."
        % (len(h["near_calls"]), h["near_calls"], len(h["far_calls"]), a["handler_far_call_segments"]))
    add("- Direct DGROUP references (DS-relative): %s."
        % ", ".join("0x%04x" % x for x in h["direct_refs"]))
    add("- BP-relative references: %s."
        % ", ".join("%+d" % x for x in h["bp_refs"]))
    add("- Backward branches: %s." % (h["backedges"],))
    add("- Handler reaches parser by near call: %s." % a["handler_reaches_parser_by_near_call"])
    add("")
    add("## Operand parser `0x%x`" % PARSER_ENTRY)
    add("")
    add("- Prologue `push bp; mov bp, sp`: %s."
        % p["prologue_matches"])
    add("- Reachable instructions: %d; complete: %s; returns: %s."
        % (p["instruction_count"], p["complete"], p["returns"]))
    add("- BP-relative references (positive = stack arguments): %s."
        % ", ".join("%+d" % x for x in p["bp_refs"]))
    add("- Near-call candidates targeting it (byte pattern, unverified boundary): %d, all `push cs`-preceded: %s."
        % (len(a["callers"]["near_calls_to_parser_0x74d3"]),
           all(c["push_cs_before"] for c in a["callers"]["near_calls_to_parser_0x74d3"])))
    add("- Literal far-call sites with this offset: %d."
        % len(a["callers"]["far_literal_sites_offset_parser"]))
    add("")
    add("## Overlay header")
    add("")
    add("- First 16 bytes (raw, not parsed): `%s`; signature ASCII `%s`."
        % (a["overlay_header_first16_hex"], a["overlay_header_signature_ascii"]))
    add("")
    add("## Established by bytes")
    add("")
    for line in doc["established_by_bytes"]:
        add("- " + line)
    add("")
    add("## Not established")
    add("")
    for line in doc["not_established"]:
        add("- " + line)
    add("")
    add("## Diagnostics")
    add("")
    if doc["diagnostics"]:
        for item in doc["diagnostics"]:
            add("- `%s`: %s" % (item["code"], item["message"]))
    else:
        add("- none")
    add("")
    add("## Annotated listing: handler 0x37 (coarse operand text)")
    add("")
    L.extend(_fmt_insn_rows(h["listing"]))
    add("")
    add("## Annotated listing: operand parser 0x74d3 (coarse operand text)")
    add("")
    L.extend(_fmt_insn_rows(p["listing"]))
    add("")
    return "\n".join(L) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_loadpieces_handler.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_loadpieces_handler_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance GAME.OVR 0x37 handler/dispatch/parser static probe (read-only).")
    ap.add_argument("--install", required=True,
                    help="PoR install folder (GAME.OVR here or in its POOLRAD subfolder)")
    ap.add_argument("-o", "--out", required=True,
                    help="output folder (outside the install; inside the repo only under data/)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="probe a GAME.OVR that does not match the pinned hash (results are not retail evidence)")
    args = ap.parse_args(argv)
    out = Path(args.out)
    try:
        doc, code = probe(Path(args.install), out, allow_unpinned=args.allow_unpinned)
        write_outputs(doc, out)
    except (PorSourceError, OSError) as exc:
        print("por_loadpieces_handler: error: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s and %s (%s, playable=false; dispatcher 0x37 case %s; handler complete=%s; "
          "parser complete=%s; %d diagnostics)"
          % (out / "por_loadpieces_handler.json", out / "por_loadpieces_handler_report.md", STATUS,
             "found" if doc["analysis"]["dispatcher"]["opcode_0x37"] else "absent",
             doc["analysis"]["handler_0x37"]["complete"], doc["analysis"]["parser"]["complete"],
             len(doc["diagnostics"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
