#!/usr/bin/env python3
"""Pool of Radiance: ECL handler cursor probe (DIAGNOSTIC ONLY).

STATUS: diagnostic-only. ``playable: false``. No events, no mappings, no module output.

Question. For a few ECL opcodes whose dispatcher case is in the pinned retail ``GAME.OVR``, does the
handler that the dispatcher calls consume or adjust the stream cursor ``[0x49ED]``, and is the
dispatcher key ``[0x6F7F]`` demonstrably the stream byte at the cursor? Only PoR bytes are used.
GoldBox opcode maps are not read and supply no meaning or cursor rule.

Method (static, bounded, read-only; no emulator, no runtime):

* Dispatch edge. The dispatcher at ``GAME.OVR:0x3C73`` is read with the existing decoder
  ``tools/por_loadpieces_handler.py`` (read-only import). For an opcode it finds the one
  ``cmp al,imm8`` for that value and follows its branch: either ``jnz next; push cs; call H; jmp exit``
  or ``jz group`` into a shared ``push cs; call H`` block. Every near branch target is recomputed from
  the raw bytes and must equal the decoded target.
* Handler paths. The handler is run as a bounded path walk. AL starts unknown. Reading the key cell
  ``[0x6F7F]`` sets AL to the opcode; this is the key-producer assumption, and it is recorded as an
  assumption on every path. Compares of AL against an immediate are decided; a memory compare or any
  flag-setter the walk cannot decide forks the path. A far call is recorded as unresolved and its
  cursor effect is unknown afterwards. Any instruction the walk does not model ends the path as
  ``unmodelled``. Nothing is inferred from a name.
* Caller path. The dispatcher's only near caller is the loop at ``GAME.OVR:0x3EB7``. The loop's key
  store (``es:[di+0x6700]`` with ``di = [0x49DE] + [0x49ED]``) and its call are matched as a decoded
  sequence. Other callers are found by a raw byte scan and marked as such.
* Cell census. Every byte-pattern reference to the key, cursor and guard cells is classified by the
  instruction it belongs to. Each reference is marked ``walk-reached`` (in a decoded walk),
  ``decodes-at-candidate-start`` (the decoder accepts the instruction at that offset), or
  ``byte-pattern`` (the pattern only).

Evidence labels. ``decoded`` = an instruction the decoder produced from a walk or path.
``byte-pattern`` = a raw-byte match not tied to a decoded walk. Every output says which.

Falsifiers (checked on synthetic bytes in the test suite and reported on retail): a wrong branch target
(a recomputed target that disagrees with the decoded one, or a shared group that calls a different
handler); a cursor mutation (a cursor write other than the one increment); an unknown helper (a far call
whose target is not decoded); and a key-producer assumption (a loop store that is not the stream byte at
the cursor, or a handler compare on a value that is not the key cell).

Retail block compare. After the byte chain fixes the field to inspect (the cursor after the opcode byte,
i.e. block offset ``at + 1``), the pinned ``ECL2.DAX`` block is read (read-only, via ``tools/por_ecl.py``).

Companions (read, not changed): docs/por-ecl-native-stream-probe.md, docs/por-ecl-native-framing-probe.md,
docs/por-ecl-decoder.md. This tool does not import or modify the stream probe.

Usage::

    python tools/por_ecl_handler_cursor_probe.py --install "PATH/TO/POOLRAD" --ecl 2 --block 20 \\
        -o data/work/por-ecl-handler-cursor/retail

Stdlib + the read-only modules above.
Exit: 0 every self-check passes; 1 a self-check failed; 2 a named refusal (missing or unpinned file,
output inside the install, output outside data/work/ on the CLI).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"

sys.path.insert(0, str(TOOLS_DIR))
import por_loadpieces_handler as h  # noqa: E402  (read-only decoder; not edited)
import por_ecl as ecl  # noqa: E402  (read-only container and header; not edited)
import por_ecl_native_framing_probe as framing  # noqa: E402  (read-only; classifier arms only)

SCHEMA = "openua.por-ecl-handler-cursor-probe"
SCHEMA_VERSION = 1
STATUS = "diagnostic-only"
TOOL = "tools/por_ecl_handler_cursor_probe.py"
RESULT_JSON = "por_ecl_handler_cursor_probe.json"
RESULT_MD = "por_ecl_handler_cursor_probe.md"

PINS = {
    "GAME.OVR": (206105, "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"),
    "START.EXE": (65231, "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"),
    "ECL2.DAX": (19968, "6ad6dc5aa53da82f4dba62dbc47d5a02a3f14c14071bec44e81a692615f08a3d"),
}
BLOCK_PIN = {"block_id": 20, "raw_size": 7679,
             "decoded_sha256": "a1e1dd7a7ffc07f6e3c3ce7fad25d373270c10edd06ec3fa1f1d0edc9a7297ec"}

DISPATCH_ENTRY = 0x3C73       # dispatcher: key load at +3, then a cmp/jcc chain
LOOP_ENTRY = 0x3EB7           # the dispatcher's only near caller: stream-reading loop
CELL_CURSOR = 0x49ED          # stream cursor (word)
CELL_STREAM_BASE = 0x49DE     # far pointer to the ECL block (les di,[0x49de])
CELL_KEY = 0x6F7F             # dispatch key byte
CELL_KEY_PREV = 0x6F7E        # previous key (written by the loop)
STREAM_DISP = 0x6700          # es:[di+0x6700] reads the stream
PRIMARY = 0x1B                # the opcode the request names
DEFAULT_OPCODES = (0x1B, 0x16, 0x15, 0x2B)
DEFAULT_AT = 34               # block offset of PRIMARY, as the stream probe records it (checked, not trusted)
MAX_DISPATCH = 400
MAX_STEPS = 600
MAX_PATHS = 64
TRACE_HEAD = 48               # per-path trace kept in the output (the step count is kept in full)
SENTINEL = object()

WRITE_OPS = {0x88, 0x89, 0xA2, 0xA3, 0xC6, 0xC7, 0x8F}
READ_OPS = {0x8A, 0x8B, 0xA0, 0xA1, 0x38, 0x39, 0x3A, 0x3B, 0x84, 0x85, 0xC4, 0xC5}
LOOP_SEQ = [("cursor-load", "a1ed49"), ("stream-base-les", "c43ede49"), ("index-add", "03f8"),
            ("es-stream-read", "268a850067"), ("key-store", "a27f6f"), ("push-cs", "0e")]
ENTRY_CURSOR_SEQ = ["8b4606", "a3ed49"]     # mov ax,[bp+6]; mov [0x49ed],ax


class ProbeRefusal(Exception):
    """A named refusal: the probe does not run on this input."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    """Address (file offset) in four hex digits."""
    return None if v is None else "0x%04X" % v


def _opx(v: Optional[int]) -> Optional[str]:
    """Opcode byte in two hex digits (never an address)."""
    return None if v is None else "0x%02X" % v


def _dumps(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _s8(b: int) -> int:
    return b - 256 if b >= 128 else b


def _s16(lo: int, hi: int) -> int:
    v = lo | (hi << 8)
    return v - 65536 if v >= 32768 else v


def _decode(data: bytes, off: int):
    """The decoder's instruction at ``off``, or None when it is not decodable there."""
    if not (0 <= off < len(data)):
        return None
    try:
        return h.decode(data, off)
    except (h.DecodeError, IndexError):
        return None


def raw_branch_target(data: bytes, off: int) -> Optional[int]:
    """Branch target recomputed from the raw bytes alone: rel8 jcc (70-7F), jmp EB, rel16 call E8 / jmp E9."""
    op = data[off]
    if 0x70 <= op <= 0x7F or op == 0xEB:
        return off + 2 + _s8(data[off + 1])
    if op in (0xE8, 0xE9):
        return off + 3 + _s16(data[off + 1], data[off + 2])
    return None


def _mem_direct(ins) -> Optional[int]:
    """DS-direct address of the instruction's memory operand (moffs or mod 00 rm 110), else None."""
    return ins.direct


def _role(ins) -> str:
    """How the instruction uses its memory operand: read, write, rmw, cmp, or unclassified."""
    op = ins.op
    reg = ins.modrm[1] if ins.modrm else None
    if op in (0xA2, 0xA3) or op in WRITE_OPS:
        return "write"
    if op in READ_OPS:
        return "read"
    if op == 0x8D:
        return "address-only"
    if op in (0x80, 0x81, 0x83):
        return "cmp" if reg == 7 else "rmw"
    if op in (0xFE, 0xFF):
        if reg in (0, 1):
            return "rmw"
        if reg == 6:
            return "read"
        return "unclassified"
    if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
        return "rmw"
    if op in (0xF6, 0xF7):
        return "read" if reg in (0, 1) else "rmw"
    if op < 0x40 and (op & 7) in (0, 1):
        return "rmw"
    if op < 0x40 and (op & 7) in (2, 3):
        return "read"
    return "unclassified"


# ---------------------------------------------------------------------------------------------
# Dispatcher edge (decoded): the cmp al,imm for one opcode and the call it reaches
# ---------------------------------------------------------------------------------------------

def dispatch_edge(data: bytes, opcode: int, entry: int = DISPATCH_ENTRY) -> dict:
    """Branch structure for one opcode in the dispatcher's cmp/jcc chain. Structure, not semantics."""
    head, err = h.linear(data, entry, MAX_DISPATCH, stop_on_ret=True)
    idx = [i for i, ins in enumerate(head) if ins.op == 0x3C and len(ins.raw) == 2 and ins.imm == opcode]
    rec: dict = {"opcode": _opx(opcode), "evidence": "decoded", "sweep_stopped": err}
    if len(idx) != 1:
        return dict(rec, status="refused", reason="compare count for opcode is %d" % len(idx))
    i = idx[0]
    cmp_ins = head[i]
    rec["compare_at"] = cmp_ins.off
    if i + 1 >= len(head):
        return dict(rec, status="refused", reason="no branch after compare")
    nxt = head[i + 1]
    if nxt.op == 0x75 and nxt.flow == "jcc":
        blk = head[i + 2:i + 5]
        shape = (len(blk) == 3 and blk[0].op == 0x0E and blk[1].flow == "call" and blk[2].flow == "jmp")
        rec.update({"form": "jne-push-cs-call", "jump_at": nxt.off, "jump_target": nxt.target,
                    "jump_target_raw": raw_branch_target(data, nxt.off),
                    "next_case_is_cmp": bool(_decode(data, nxt.target) and _decode(data, nxt.target).op == 0x3C)})
        if not shape:
            return dict(rec, status="refused", reason="case block is not push cs / call / jmp")
        call, jmp = blk[1], blk[2]
        rec.update({"push_cs_at": blk[0].off, "call_at": call.off, "call_target": call.target,
                    "call_target_raw": raw_branch_target(data, call.off),
                    "exit_target": jmp.target, "exit_target_raw": raw_branch_target(data, jmp.off),
                    "group_target": None, "group_members": []})
        consistent = (rec["jump_target"] == rec["jump_target_raw"] == blk[2].end
                      and rec["call_target"] == rec["call_target_raw"]
                      and rec["exit_target"] == rec["exit_target_raw"])
        rec["consistent"] = bool(consistent)
        rec["handler"] = call.target
        rec["status"] = "ok" if consistent else "refused"
        if not consistent:
            rec["reason"] = "decoded branch target disagrees with raw recomputation"
        return rec
    if nxt.op == 0x74 and nxt.flow == "jcc":
        group = nxt.target
        g0 = _decode(data, group)
        g1 = _decode(data, group + 1)
        shape = g0 is not None and g0.op == 0x0E and g1 is not None and g1.flow == "call"
        members = []
        for j in range(len(head) - 1):
            a, b = head[j], head[j + 1]
            if a.op == 0x3C and len(a.raw) == 2 and b.op == 0x74 and b.flow == "jcc" and b.target == group:
                members.append(a.imm)
        rec.update({"form": "je-group", "jump_at": nxt.off, "jump_target": group,
                    "jump_target_raw": raw_branch_target(data, nxt.off), "group_target": group,
                    "group_members": sorted(members), "next_case_is_cmp": None})
        if not shape:
            return dict(rec, status="refused", reason="group block is not push cs / call")
        rec.update({"push_cs_at": group, "call_at": group + 1, "call_target": g1.target,
                    "call_target_raw": raw_branch_target(data, group + 1), "handler": g1.target,
                    "exit_target": None, "exit_target_raw": None})
        consistent = rec["jump_target"] == rec["jump_target_raw"] and rec["call_target"] == rec["call_target_raw"]
        rec["consistent"] = bool(consistent)
        rec["status"] = "ok" if consistent else "refused"
        if not consistent:
            rec["reason"] = "decoded branch target disagrees with raw recomputation"
        return rec
    return dict(rec, status="refused", reason="compare is not followed by a jcc")


def dispatch_key_read(data: bytes, entry: int = DISPATCH_ENTRY) -> dict:
    """The dispatcher's first read of the key cell, and whether the key compare chain reaches the opcode."""
    head, _ = h.linear(data, entry, MAX_DISPATCH, stop_on_ret=True)
    key = next((ins for ins in head if _mem_direct(ins) == CELL_KEY and _role(ins) == "read"), None)
    if key is None:
        return {"found": False}
    return {"found": True, "at": key.off, "bytes": key.raw.hex(), "entry": entry,
            "after_prologue": key.off == entry + 3 and head[0].op == 0x55}


# ---------------------------------------------------------------------------------------------
# Handler path walk (bounded; AL = opcode via the key-cell read; forks on undecided branches)
# ---------------------------------------------------------------------------------------------

def _new_state(addr: int) -> dict:
    return {"addr": addr, "al": None, "al_src": None, "zf": None, "cur": 0, "cur_known": True,
            "cur_before_far": None, "incs": [], "decs": [], "far": [], "conds": [], "key_reads": [],
            "key_writes": [], "stream_reads": [], "compare_non_key": False, "unres": [], "trace": [],
            "steps": 0, "first_cur_step": None, "first_branch_step": None}


def _touch_cursor(st: dict) -> None:
    if st["first_cur_step"] is None:
        st["first_cur_step"] = st["steps"]


def _finalize(st: dict, terminal: str) -> dict:
    reasons = list(st["unres"])
    if terminal not in ("ret", "retf"):
        reasons.append("terminal:" + terminal)
    if st["far"]:
        reasons.append("far-call-unresolved")
    if not st["cur_known"]:
        reasons.append("cursor-delta-unknown")
    if st["compare_non_key"]:
        reasons.append("compare-on-non-key-value")
    before = st["first_branch_step"]
    cursor_first = st["first_cur_step"] is not None and (before is None or st["first_cur_step"] <= before)
    return {
        "terminal": terminal,
        "conditions": st["conds"],
        "cursor_delta_known": st["cur"] if st["cur_known"] else None,
        "cursor_delta_before_first_far_call": st["cur_before_far"],
        "cursor_increments": st["incs"],
        "cursor_decrements": st["decs"],
        "cursor_touch_before_first_branch": bool(cursor_first) if st["first_cur_step"] is not None else None,
        "key_reads": st["key_reads"],
        "key_writes": st["key_writes"],
        "far_calls": st["far"],
        "stream_reads": st["stream_reads"],
        "unresolved_reasons": sorted(set(reasons)),
        "steps": st["steps"],
        "trace_head": st["trace"][:TRACE_HEAD],
    }


def _apply(data: bytes, st: dict, ins, opcode: int, work: list) -> Optional[str]:
    """One decoded instruction against state ``st``. Returns a terminal name, or None to continue."""
    op, off = ins.op, ins.off
    reg = ins.modrm[1] if ins.modrm else None
    mod = ins.modrm[0] if ins.modrm else None
    rm = ins.modrm[2] if ins.modrm else None
    mem = _mem_direct(ins)
    role = _role(ins) if mem is not None else None
    al_new = SENTINEL
    zf_new = SENTINEL

    # Cursor and key cells (memory operand is the cell).
    if mem == CELL_CURSOR and role is not None and role != "address-only":
        if role in ("write", "rmw") and op == 0xFF and reg == 0 and role == "rmw":
            _touch_cursor(st)
            if st["cur_known"]:
                st["cur"] += 1
            st["incs"].append(off)
        elif role in ("write", "rmw") and op == 0xFF and reg == 1 and role == "rmw":
            _touch_cursor(st)
            if st["cur_known"]:
                st["cur"] -= 1
            st["decs"].append(off)
        elif role in ("write", "rmw"):
            _touch_cursor(st)
            st["cur_known"] = False
            st["unres"].append("cursor-write-other@%04x" % off)
        elif role == "unclassified":
            _touch_cursor(st)
            st["cur_known"] = False
            st["unres"].append("cursor-ref-unclassified@%04x" % off)
    if mem == CELL_KEY and role in ("write", "rmw"):
        st["key_writes"].append(off)
        st["unres"].append("key-cell-written@%04x" % off)
    if mem == CELL_KEY and role == "read" and ((op == 0xA0) or (op == 0x8A and reg == 0)):
        st["key_reads"].append(off)
    if ins.prefixes and 0x26 in ins.prefixes and ins.raw[-2:] == b"\x00\x67" and mem is None:
        st["stream_reads"].append(off)

    # Control flow.
    if 0x70 <= op <= 0x7F:
        st["first_branch_step"] = st["first_branch_step"] if st["first_branch_step"] is not None else st["steps"]
        if st["zf"] is not None and op in (0x74, 0x75):
            taken = st["zf"] if op == 0x74 else (not st["zf"])
            st["addr"] = ins.target if taken else ins.end
            return None
        child = copy.deepcopy(st)
        child["addr"] = ins.target
        child["conds"].append("taken@%04x" % off)
        work.append(child)
        st["conds"].append("not-taken@%04x" % off)
        st["addr"] = ins.end
        return None
    if op in (0xE9, 0xEB):
        st["first_branch_step"] = st["first_branch_step"] if st["first_branch_step"] is not None else st["steps"]
        if raw_branch_target(data, off) != ins.target:
            return "decoder-disagreement"
        st["addr"] = ins.target
        return None
    if op == 0x9A:
        st["first_branch_step"] = st["first_branch_step"] if st["first_branch_step"] is not None else st["steps"]
        seg, far_off = ins.far
        st["far"].append({"at": off, "seg": seg, "off": far_off, "resolved": False})
        if st["cur_before_far"] is None and st["cur_known"]:
            st["cur_before_far"] = st["cur"]
        st["cur_known"] = False
        st["al"], st["al_src"], st["zf"] = None, "other", None
        st["addr"] = ins.end
        return None
    if op in (0xC2, 0xC3):
        return "ret"
    if op in (0xCA, 0xCB):
        return "retf"
    if op == 0xE8:
        return "unmodelled-near-call"

    # AL and flags. Anything not listed resets what the walk cannot follow.
    if op == 0x3C:   # cmp al, imm8
        imm = ins.raw[1]
        if st["al"] is None or st["al_src"] != "key-cell":
            st["compare_non_key"] = True
        zf_new = (st["al"] == imm) if st["al"] is not None else None
    elif op == 0x3D:
        zf_new = None
    elif op == 0x80 and mod == 3 and rm == 0 and reg == 7:
        imm = ins.raw[-1]
        if st["al"] is None or st["al_src"] != "key-cell":
            st["compare_non_key"] = True
        zf_new = (st["al"] == imm) if st["al"] is not None else None
    elif op == 0xA0:                       # mov al, moffs8: the key cell is the only AL source the walk follows
        al_new = opcode if mem == CELL_KEY else None
    elif op == 0x8A:                       # mov r8, r/m8
        if reg == 0:
            al_new = opcode if (mem == CELL_KEY and role == "read") else None
    elif op in (0xB0, 0xB8):               # mov al, imm8 / mov ax, imm16 (low byte)
        al_new = ins.raw[1]
    elif op in (0x8B, 0xA1, 0x8D, 0xC4, 0xC5, 0x58, 0x40, 0x48) and (reg == 0 or op in (0xA1, 0x58, 0x40, 0x48)):
        al_new = None                      # writes AX / AL from an unmodelled source
    elif op in (0x88, 0x89, 0xC6, 0xC7, 0x8F, 0x80, 0x81, 0x83, 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3,
                0xF6, 0xF7, 0xFE, 0xFF) and mod == 3 and rm == 0 and not (op == 0x80 and reg == 7):
        al_new = None                      # register operand AL/AX/ax-class is the destination
    elif op == 0x84 or op == 0x85:
        zf_new = None
    elif op < 0x40 and (op & 7) in (0, 1, 2, 3, 4, 5):
        if op not in (0x38, 0x39, 0x3A, 0x3B):
            al_new = None                  # ALU forms: AL/AX may be the destination; cmp forms are read-only
        zf_new = None
    elif op in (0x80, 0x81, 0x83, 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF):
        zf_new = None
    elif 0x40 <= op <= 0x4F:
        zf_new = None
    elif op in (0x9C, 0x9D):
        zf_new = None
    elif op in (0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                0x57, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x90, 0x98, 0x99, 0x8C, 0x8E):
        pass
    elif op in (0x88, 0x89, 0x8A, 0x8B, 0x8D, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC4, 0xC5, 0xC6, 0xC7, 0x8F):
        pass
    else:
        return "unmodelled:" + ins.text()

    if al_new is not SENTINEL:
        st["al"] = al_new
        st["al_src"] = "key-cell" if (al_new == opcode and mem == CELL_KEY) else (None if al_new is None else "imm")
    if zf_new is not SENTINEL:
        st["zf"] = zf_new
    st["addr"] = ins.end
    return None


def handler_paths(data: bytes, entry: int, opcode: int) -> dict:
    """Bounded path walk of one handler for one opcode. Refuses only on a broken decoder, never guesses."""
    paths: list = []
    work = [_new_state(entry)]
    refusals: list = []
    while work:
        if len(paths) >= MAX_PATHS:
            refusals.append("path-budget")
            break
        st = work.pop()
        while True:
            if st["steps"] >= MAX_STEPS:
                paths.append(_finalize(st, "step-budget"))
                break
            ins = _decode(data, st["addr"])
            if ins is None:
                paths.append(_finalize(st, "undecodable@%04x" % st["addr"]))
                break
            st["steps"] += 1
            st["trace"].append(ins.off)
            term = _apply(data, st, ins, opcode, work)
            if term is not None:
                paths.append(_finalize(st, term))
                break
    paths.sort(key=lambda p: (p["trace_head"][:1], p["conditions"]))
    for i, p in enumerate(paths):
        p["id"] = i
    return {"entry": entry, "opcode": _opx(opcode), "paths": paths, "refusals": refusals}


def settlement(handler: dict) -> dict:
    """Settled only when every path ends in a return with no far call, no unknown cursor, no unmodelled step."""
    paths = handler["paths"]
    open_ = [p for p in paths if p["unresolved_reasons"]]
    settled = [p for p in paths if not p["unresolved_reasons"]]
    deltas = sorted({p["cursor_delta_known"] for p in settled})
    if handler["refusals"]:
        status = "open"
    elif not paths:
        status = "open"
    else:
        status = "settled" if not open_ else "open"
    reasons = sorted({r for p in open_ for r in p["unresolved_reasons"]})
    return {"status": status, "paths": len(paths), "settled_paths": len(settled), "open_paths": len(open_),
            "settled_cursor_delta": deltas[0] if len(deltas) == 1 else None,
            "open_reasons": reasons, "refusals": handler["refusals"]}


# ---------------------------------------------------------------------------------------------
# Caller path: the stream loop, decoded; other callers by byte pattern
# ---------------------------------------------------------------------------------------------

def loop_report(data: bytes, loop_entry: int = LOOP_ENTRY, dispatch_entry: int = DISPATCH_ENTRY) -> dict:
    w = h.walk(data, loop_entry)
    items = w["listing"]
    found = None
    for i in range(len(items)):
        match = []
        ok = True
        for k, (name, hexs) in enumerate(LOOP_SEQ):
            if i + k >= len(items):
                ok = False
                break
            it = items[i + k]
            b = bytes.fromhex(it["bytes"])
            if not b.startswith(bytes.fromhex(hexs)):
                ok = False
                break
            if k > 0:
                prev = items[i + k - 1]
                if prev["at"] + len(bytes.fromhex(prev["bytes"])) != it["at"]:
                    ok = False
                    break
            match.append({"name": name, "at": it["at"], "bytes": it["bytes"]})
        if ok:
            found = (i, match)
            break
    seq = found[1] if found else []
    call_at = None
    call_target = None
    store_at = seq[4]["at"] if len(seq) > 4 else None
    if found:
        j = found[0] + len(LOOP_SEQ)
        if j < len(items) and items[j]["bytes"].startswith("e8"):
            call_at = items[j]["at"]
            call_target = _decode(data, call_at).target
    # Entry cursor: mov ax,[bp+6] then mov [0x49ed],ax, as decoded instructions.
    entry_cursor = None
    for k, it in enumerate(items[:-1]):
        if it["bytes"].startswith(ENTRY_CURSOR_SEQ[0]) and items[k + 1]["bytes"] == ENTRY_CURSOR_SEQ[1]:
            entry_cursor = {"load_at": it["at"], "store_at": items[k + 1]["at"], "source": "argument [bp+6]"}
            break
    cursor_writes = []
    for it in items:
        ins = _decode(data, it["at"])
        if ins is not None and _mem_direct(ins) == CELL_CURSOR and _role(ins) in ("write", "rmw"):
            cursor_writes.append({"at": ins.off, "bytes": ins.raw.hex(), "role": _role(ins),
                                  "kind": "inc" if (ins.op == 0xFF and ins.modrm and ins.modrm[1] == 0)
                                  else ("dec" if (ins.op == 0xFF and ins.modrm and ins.modrm[1] == 1)
                                        else "store"),
                                  "evidence": "decoded"})
    return {
        "entry": loop_entry, "walk_complete": w["complete"], "walk_incomplete": w["incomplete"],
        "sequence_found": found is not None, "sequence": seq,
        "key_store_at": store_at,
        "dispatch_call_at": call_at, "dispatch_call_target": call_target,
        "dispatch_call_target_matches": call_target == dispatch_entry,
        "key_store_immediately_before_call": (found is not None and call_at is not None
                                              and seq[-1]["at"] + 1 == call_at),
        "entry_cursor": entry_cursor,
        "cursor_writes": cursor_writes,
        "loop_advances_cursor": any(w_["kind"] in ("inc", "dec") for w_ in cursor_writes),
        "backedges": w["backedges"],
        "near_calls": [{"at": x["at"], "target": x["target"]} for x in w["near_calls"]],
        "far_calls": [{"at": x["at"], "seg": x["seg"], "off": x["off"]} for x in w["far_calls"]],
    }


def callers_of(data: bytes, target: int, walk_starts: set) -> list:
    """Near E8 sites whose rel16 lands on ``target`` (raw scan), with the push context when present."""
    out = []
    for p in range(len(data) - 2):
        if data[p] != 0xE8:
            continue
        if p + 3 + _s16(data[p + 1], data[p + 2]) != target:
            continue
        rec = {"at": p, "evidence": "decoded" if p in walk_starts else "byte-pattern", "push_cell": None,
               "push_evidence": None}
        if p >= 5 and data[p - 5] == 0xFF and data[p - 4] == 0x36 and data[p - 1] == 0x0E:
            pushed = _decode(data, p - 5)
            if pushed is not None and pushed.op == 0xFF and pushed.length == 4 and pushed.direct is not None:
                rec["push_cell"] = pushed.direct
                rec["push_evidence"] = "decodes-at-candidate-start"
        out.append(rec)
    return out


def cell_census(data: bytes, cell: int, walk_starts: set) -> list:
    """Every byte-pattern reference to a DS cell, classified by the instruction it sits in."""
    pat = struct.pack("<H", cell)
    out = []
    i = data.find(pat)
    while i >= 0:
        rec = None
        for s in (i - 1, i - 2, i - 3):
            ins = _decode(data, s)
            if ins is None or not (s < i and i + 2 <= s + ins.length):
                continue
            if _mem_direct(ins) == cell:
                rec = {"at": i, "instruction": s, "op": "0x%02X" % ins.op, "text": ins.text(),
                       "role": _role(ins),
                       "evidence": "decoded" if s in walk_starts else "decodes-at-candidate-start"}
                break
        if rec is None:
            rec = {"at": i, "instruction": None, "op": None, "text": None, "role": "unclassified",
                   "evidence": "byte-pattern"}
        out.append(rec)
        i = data.find(pat, i + 1)
    return out


def _census_summary(hits: list) -> dict:
    roles: dict = {}
    for r in hits:
        roles[r["role"]] = roles.get(r["role"], 0) + 1
    return {"references": len(hits), "roles": dict(sorted(roles.items()))}


# ---------------------------------------------------------------------------------------------
# Block compare (retail only, read-only): the field the byte chain fixes, not the probe's stop
# ---------------------------------------------------------------------------------------------

def block_compare(block: bytes, at: int, primary_settlement: dict, primary_handler: dict) -> dict:
    byte = block[at] if 0 <= at < len(block) else None
    reads = sum(len(p["stream_reads"]) for p in primary_handler["paths"])
    return {
        "block_offset": at, "byte_at_offset": None if byte is None else "0x%02X" % byte,
        "matches_primary_opcode": byte == PRIMARY,
        "field_inspected": "cursor after the opcode byte (block offset %d)" % (at + 1),
        "next_bytes_from_offset": block[at:at + 8].hex(),
        "next_key_byte_at": at + 1,
        "next_key_byte": None if at + 1 >= len(block) else "0x%02X" % block[at + 1],
        "handler_stream_reads_on_all_paths": reads,
        "reads_operand_bytes_on_any_path": reads > 0,
        "far_path_guard": "[0x6F7D] == 0 selects the far call; its runtime value is not established",
        "supported_prefix_extends_past_opcode": primary_settlement["status"] == "settled",
    }


# ---------------------------------------------------------------------------------------------
# Analysis (pure: bytes in, dict out)
# ---------------------------------------------------------------------------------------------

def analyse(game: bytes, start: bytes, opcodes=DEFAULT_OPCODES, dax: Optional[bytes] = None,
            ecl_n: Optional[int] = None, block_id: Optional[int] = None, at: int = DEFAULT_AT,
            game_name: str = "GAME.OVR") -> dict:
    arms = framing.classifier_table(game)
    d_head, _ = h.linear(game, DISPATCH_ENTRY, MAX_DISPATCH, stop_on_ret=True)
    disp_walk = {ins.off for ins in d_head}
    loop = loop_report(game)
    loop_walk = {it["at"] for it in h.walk(game, LOOP_ENTRY)["listing"]}
    cls_walk = {it["at"] for it in h.walk(game, 0x9379)["listing"]}
    handler_walks = set()
    edges = {}
    for op in opcodes:
        edges[op] = dispatch_edge(game, op)
    for op in opcodes:
        if edges[op].get("status") == "ok":
            handler_walks |= {it["at"] for it in h.walk(game, edges[op]["handler"])["listing"]}
    walk_starts = disp_walk | loop_walk | cls_walk | handler_walks
    key_read = dispatch_key_read(game)
    chain = {}
    first_key = next((ins for ins in d_head if _mem_direct(ins) == CELL_KEY and _role(ins) == "read"), None)
    for op in opcodes:
        chain[_opx(op)] = (h._not_equal_path(game, first_key, op) if first_key is not None
                           else {"reached": False, "reason": "no key read"})
    handlers = {}
    for op in opcodes:
        e = edges[op]
        if e.get("status") != "ok":
            handlers[_opx(op)] = {"status": "refused", "reason": e.get("reason")}
            continue
        hp = handler_paths(game, e["handler"], op)
        handlers[_opx(op)] = {
            "handler_entry": _hex(e["handler"]),
            "classifier_arm": arms[op].get("arm"),
            "classifier_class": arms[op].get("class"),
            "group_members": e.get("group_members", []),
            "paths": hp["paths"],
            "refusals": hp["refusals"],
            "settlement": settlement(hp),
            "far_calls_on_paths": sorted({(f["at"], f["seg"], f["off"]) for p in hp["paths"]
                                          for f in p["far_calls"]}),
            "stream_reads_on_paths": sum(len(p["stream_reads"]) for p in hp["paths"]),
        }
    gw = cell_census(game, CELL_KEY, walk_starts)
    sw = cell_census(start, CELL_KEY, set())
    cw = cell_census(game, CELL_CURSOR, walk_starts)
    # Unclassified byte-pattern hits count as possible writers: the accounting check must not pass by default.
    key_writers = [r for r in gw if r["role"] in ("write", "rmw", "unclassified")]
    prim = handlers.get(_opx(PRIMARY), {})
    prim_paths = prim.get("paths", [])
    loop_callers = callers_of(game, LOOP_ENTRY, walk_starts)
    disp_callers = callers_of(game, DISPATCH_ENTRY, walk_starts)
    cls_callers = callers_of(game, 0x9379, walk_starts)
    dispatch_handler_callers = callers_of(game, edges[PRIMARY].get("handler", -1), walk_starts) \
        if edges.get(PRIMARY, {}).get("status") == "ok" else []
    # Compare instruction starts (the census 'at' is the displacement; 'instruction' is the opcode byte).
    accounted = {loop["key_store_at"], 0x938A}
    checks = {
        "dispatch_edge_primary_consistent": edges[PRIMARY].get("consistent") is True,
        "dispatch_group_0x16_shares_primary_handler": (
            edges.get(0x16, {}).get("status") == "ok" and edges.get(0x16, {}).get("handler")
            == edges[PRIMARY].get("handler") and edges[0x16].get("group_target") is not None
            and 0x16 in edges[0x16].get("group_members", [])),
        "dispatch_key_read_after_prologue": key_read.get("found") is True and key_read.get("after_prologue") is True,
        "dispatch_chain_reaches_primary_cmp_only": (chain[_opx(PRIMARY)].get("reached") is True
                                                    and chain[_opx(PRIMARY)].get("clobber") == []),
        "loop_sequence_found": loop["sequence_found"],
        "loop_key_store_immediately_before_dispatch_call": loop["key_store_immediately_before_call"],
        "loop_dispatch_call_target_is_dispatcher": loop["dispatch_call_target_matches"],
        "loop_entry_cursor_from_argument": loop["entry_cursor"] is not None,
        "loop_never_advances_cursor": (loop["walk_complete"] and not loop["loop_advances_cursor"]),
        "callers_of_loop_all_push_a_cell": bool(loop_callers) and all(c["push_cell"] is not None
                                                                      for c in loop_callers),
        "primary_handler_paths_enumerated": bool(prim_paths) and not prim.get("refusals"),
        "primary_cursor_touch_before_branch_on_all_paths": bool(prim_paths) and all(
            p["cursor_touch_before_first_branch"] is True for p in prim_paths),
        "primary_cursor_increments_once_on_all_paths": bool(prim_paths) and all(
            p["cursor_increments"] and len(p["cursor_increments"]) == 1 and not p["cursor_decrements"]
            for p in prim_paths),
        "primary_no_stream_reads_on_any_path": bool(prim_paths) and all(not p["stream_reads"] for p in prim_paths),
        "primary_compares_use_key_cell_only": bool(prim_paths) and all(
            "compare-on-non-key-value" not in p["unresolved_reasons"] for p in prim_paths),
        "key_cell_writers_accounted": {r["instruction"] for r in key_writers} <= accounted,
        "key_cell_writers_in_start_exe_none": not [r for r in sw if r["role"] in ("write", "rmw")],
    }
    if ecl_n is not None and dax is not None:
        entries, base = ecl.parse_dax(dax)
        entry = ecl.select_entry(entries, block_id, None)
        start_b = base + entry.data_offset
        block = ecl.rle_decode(dax[start_b:start_b + entry.comp_size], entry.raw_size)
        ecl.parse_header(block)                    # refuses a block that is not an ECL block
        blk_sha = hashlib.sha256(block).hexdigest()
        bc = block_compare(block, at, settlement(prim) if prim else {"status": "open"}, prim)
        bc.update({"block_id": entry.block_id, "raw_size": entry.raw_size,
                   "decoded_sha256": blk_sha,
                   "decoded_sha256_matches_pin": blk_sha == BLOCK_PIN["decoded_sha256"]})
        checks["block_decoded_sha_matches_pin"] = blk_sha == BLOCK_PIN["decoded_sha256"]
        checks["block_byte_at_offset_is_primary"] = bc["matches_primary_opcode"]
        ecl_info = bc
    else:
        ecl_info = None
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS, "tool": TOOL,
        "playable": False, "mappings": [], "events_emitted": 0,
        "question": ("Does the handler of each opcode consume or adjust the stream cursor [0x49ED]; "
                     "is the dispatch key [0x6F7F] demonstrably the stream byte at the cursor?"),
        "install_file": game_name,
        "pins": {n: {"size": len(b), "sha256": _sha(b)} for n, b in
                 ((game_name, game), ("START.EXE", start))},
        "dispatch": {"entry": DISPATCH_ENTRY, "key_read": key_read, "edges": {_opx(k): v for k, v in edges.items()},
                     "not_equal_chain": chain},
        "loop": loop,
        "callers": {"loop_0x3EB7": loop_callers, "dispatcher_0x3C73": disp_callers,
                    "classifier_0x9379": cls_callers,
                    "primary_handler": dispatch_handler_callers},
        "cells": {
            "key_0x6F7F_game": {"summary": _census_summary(gw), "references": gw},
            "key_0x6F7F_start": {"summary": _census_summary(sw), "references": sw},
            "cursor_0x49ED_game": {"summary": _census_summary(cw), "references": cw},
        },
        "handlers": handlers,
        "classifier_facts": {"0x9379_direct_callers": len(cls_callers),
                             "note": "no direct near or far caller of the classifier is in the scanned bytes"},
        "block": ecl_info,
        "checks": checks,
        "falsifiers": {
            "wrong_branch_target": {
                "claim": "the 0x1B compare reaches the handler by the decoded branch; raw recomputation agrees",
                "observed": {"consistent": edges[PRIMARY].get("consistent"),
                             "shared_group_handler": edges.get(0x16, {}).get("handler")},
                "triggered": edges[PRIMARY].get("consistent") is not True},
            "cursor_mutation": {
                "claim": "the handler changes the cursor only by one increment on every path",
                "observed": {"paths": len(prim_paths), "increments": [p["cursor_increments"] for p in prim_paths]},
                "triggered": not checks["primary_cursor_increments_once_on_all_paths"]},
            "unknown_helper": {
                "claim": "a far callee whose target is not decoded can move the cursor; the claim is limited to paths without it",
                "observed": {"far_calls_on_paths": [list(map(_hex_or, f)) for f in prim.get("far_calls_on_paths", [])]},
                "triggered": bool(prim.get("far_calls_on_paths"))},
            "key_producer": {
                "claim": "the handler's key compare reads the stream byte at the cursor (the loop store), before any far call",
                "observed": {"loop_store_at": loop["key_store_at"],
                             "key_writers_in_game": [r["instruction"] for r in key_writers],
                             "key_writers_in_start": [r["at"] for r in sw if r["role"] in ("write", "rmw")]},
                "triggered": not (checks["loop_key_store_immediately_before_dispatch_call"]
                                  and checks["key_cell_writers_accounted"]
                                  and checks["primary_compares_use_key_cell_only"])},
        },
        "not_established": [
            "run-time reachability of the stream loop: its nine near callers are byte patterns with run-time argument cells",
            "the run-time value of the entry cursor: the nine callers push [0x49E3]..[0x49EB]; the writers of those cells are not decoded here",
            "the far callee 0x002B:0x008E and its cursor effect (segment literal; overlay fixup not parsed)",
            "the guard [0x6F7D]: writers at 0x8DB3 and 0x8E1B store 1; their reachability and the initial value are not established",
            "whether far callees could write the loop exit flag [0x442E] (which would end the loop)",
            "other overlays and indirect callers: only GAME.OVR and START.EXE are scanned",
            "the meaning of any opcode, of any operand, and of the cursor; no opcode semantics are used",
        ],
        "legend": {"decoded": "instruction from a decoder walk or a bounded path walk",
                   "decodes-at-candidate-start": "raw pattern whose start the decoder accepts; not walk-reached",
                   "byte-pattern": "raw byte match only"},
    }
    if ecl_info is not None:
        doc["block"] = ecl_info
    return doc


def _hex_or(v):
    return _hex(v) if isinstance(v, int) else v


# ---------------------------------------------------------------------------------------------
# I/O, report, CLI
# ---------------------------------------------------------------------------------------------

def _check_pins(name: str, data: bytes) -> None:
    size, sha = PINS[name]
    if len(data) != size or _sha(data) != sha:
        raise ProbeRefusal("unpinned file: %s (size %d)" % (name, len(data)))


def probe(install: Path, out: Path, ecl_n: int = 2, block_id: Optional[int] = 20, at: int = DEFAULT_AT):
    install = Path(install)
    if not install.is_dir():
        raise ProbeRefusal("install folder not found: %s" % install)
    out_r, inst_r = Path(out).resolve(), install.resolve()
    if out_r == inst_r or inst_r in out_r.parents:
        raise ProbeRefusal("output folder is inside the install")
    blobs = {}
    for name in ("GAME.OVR", "START.EXE", "ECL%d.DAX" % ecl_n):
        p = install / name
        if not p.is_file():
            raise ProbeRefusal("missing file: %s" % name)
        blobs[name] = p.read_bytes()
    _check_pins("GAME.OVR", blobs["GAME.OVR"])
    _check_pins("START.EXE", blobs["START.EXE"])
    if ecl_n == 2:                                  # the only ECL file with a recorded pin
        _check_pins("ECL2.DAX", blobs["ECL2.DAX"])
    doc = analyse(blobs["GAME.OVR"], blobs["START.EXE"], dax=blobs["ECL%d.DAX" % ecl_n], ecl_n=ecl_n,
                  block_id=block_id, at=at)
    doc["checks"]["pins_match"] = True              # verified above, before any analysis ran
    doc["ecl"] = {"file": "ECL%d.DAX" % ecl_n, "block_id": block_id, "at": at}
    code = 0 if all(doc["checks"].values()) else 1
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(_dumps(doc), encoding="utf-8")
    (out / RESULT_MD).write_text(render_md(doc), encoding="utf-8")
    return doc, code


def _edge_row(e: dict) -> str:
    if e.get("status") != "ok":
        return "| %s | refused: %s | | | |" % (e.get("opcode"), e.get("reason"))
    return "| %s | %s | %s | %s | %s |" % (e["opcode"], e["form"], _hex(e["compare_at"]),
                                           _hex(e["handler"]), ", ".join(_opx(x) for x in e.get("group_members", [])) or "-")


def render_md(doc: dict) -> str:
    L = []
    L.append("# Pool of Radiance: ECL handler cursor probe (diagnostic only)")
    L.append("")
    L.append("Status: **%s**. `playable: false`. `mappings: []`. `events_emitted: 0`." % doc["status"])
    L.append("")
    L.append("Checks: %d of %d pass." % (sum(1 for v in doc["checks"].values() if v), len(doc["checks"])))
    L.append("")
    L.append("## Dispatch edges (decoded)")
    L.append("")
    L.append("| Opcode | Form | Compare at | Handler | Shared group members |")
    L.append("| --- | --- | --- | --- | --- |")
    for k in sorted(doc["dispatch"]["edges"], key=lambda x: int(x, 16)):
        L.append(_edge_row(doc["dispatch"]["edges"][k]))
    L.append("")
    L.append("## Handler paths and settlement")
    L.append("")
    L.append("| Opcode | Handler | Paths | Settled | Open | Settled cursor delta | Open reasons |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for k in sorted(doc["handlers"], key=lambda x: int(x, 16)):
        hd = doc["handlers"][k]
        if hd.get("status") == "refused":
            L.append("| %s | refused | | | | | %s |" % (k, hd.get("reason")))
            continue
        s = hd["settlement"]
        L.append("| %s | %s | %d | %d | %d | %s | %s |" % (
            k, hd["handler_entry"], s["paths"], s["settled_paths"], s["open_paths"],
            "-" if s["settled_cursor_delta"] is None else "%+d" % s["settled_cursor_delta"],
            ", ".join(s["open_reasons"]) or "-"))
    L.append("")
    L.append("## Caller path (loop at 0x3EB7)")
    L.append("")
    lp = doc["loop"]
    L.append("- Key store and dispatch call matched as decoded sequence: %s (store at %s, call at %s -> %s)."
             % (lp["sequence_found"], _hex(lp["key_store_at"]), _hex(lp["dispatch_call_at"]),
                _hex(lp["dispatch_call_target"])))
    L.append("- Entry cursor: argument `[bp+6]` stored to `[0x49ED]` at %s. Loop advances cursor: %s."
             % (_hex(lp["entry_cursor"]["store_at"]) if lp["entry_cursor"] else None, lp["loop_advances_cursor"]))
    L.append("- Loop near callers (byte pattern, push cell in the scan): %s." %
             ", ".join("%s push %s" % (_hex(c["at"]), _hex(c["push_cell"])) for c in doc["callers"]["loop_0x3EB7"]))
    L.append("- Classifier at 0x9379 direct callers in scanned bytes: %d." % doc["classifier_facts"]["0x9379_direct_callers"])
    L.append("")
    L.append("## Falsifiers")
    L.append("")
    for k, v in doc["falsifiers"].items():
        L.append("- **%s** — claim: %s. Triggered: %s." % (k, v["claim"], v["triggered"]))
    L.append("")
    if doc.get("block"):
        b = doc["block"]
        L.append("## Retail block compare")
        L.append("")
        L.append("- Byte at block offset %d: %s (matches %s: %s). Next bytes: `%s`."
                 % (b["block_offset"], b["byte_at_offset"], _opx(PRIMARY), b["matches_primary_opcode"],
                    b["next_bytes_from_offset"]))
        L.append("- Stream reads in the primary handler: %d. Supported prefix extends past the opcode: %s."
                 % (b["handler_stream_reads_on_all_paths"], b["supported_prefix_extends_past_opcode"]))
        L.append("")
    L.append("## Not established")
    L.append("")
    for x in doc["not_established"]:
        L.append("- " + x)
    L.append("")
    L.append("Evidence labels: `decoded` (walk or path), `decodes-at-candidate-start`, `byte-pattern`.")
    L.append("")
    return "\n".join(L)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="PoR install folder (POOLRAD); read-only")
    ap.add_argument("--ecl", type=int, default=2, help="ECL file number n (reads ECL<n>.DAX)")
    ap.add_argument("--block", type=int, default=20, help="TOC block id")
    ap.add_argument("--at", type=int, default=DEFAULT_AT, help="block offset of the opcode to compare")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder under data/work/")
    args = ap.parse_args(argv)
    out = Path(args.out).resolve()
    if not out.is_relative_to(DATA_WORK.resolve()):
        print("refused: output folder must be under data/work/ (git-ignored)", file=sys.stderr)
        return 2
    try:
        doc, code = probe(Path(args.install), args.out, ecl_n=args.ecl, block_id=args.block, at=args.at)
    except (ProbeRefusal, ecl.EclError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    for k, v in sorted(doc["checks"].items()):
        print("%-56s %s" % (k, "ok" if v else "FAIL"))
    print("primary %s settlement: %s (settled %d, open %d)" % (
        _opx(PRIMARY), doc["handlers"][_opx(PRIMARY)]["settlement"]["status"],
        doc["handlers"][_opx(PRIMARY)]["settlement"]["settled_paths"],
        doc["handlers"][_opx(PRIMARY)]["settlement"]["open_paths"]))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
