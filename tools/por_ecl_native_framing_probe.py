#!/usr/bin/env python3
"""Pool of Radiance: ECL operand framing, derived from the retail GAME.OVR and START.EXE bytes.

STATIC-PROBE-ONLY. ``playable: false``. Reads the pinned retail ``GAME.OVR`` and ``START.EXE``
read-only (hashes checked before and after) and derives, from PoR's own bytes only:

1. ``classifier``: for every ECL opcode value 0x00..0xFF, the arm the compare chain at
   ``GAME.OVR:0x9390`` takes (classifier entry ``0x9379``). An arm is a class (the class byte
   pushed for the operand parser ``0x74D3``), the default ``inc [0x49ED]`` arm (one byte, zero
   parser operands), or a named refusal. Instructions come from ``por_loadpieces_handler.decode``.
2. ``parser``: the per-operand body ``0x74F5..0x75F4``, walked as a bounded control/dataflow over
   decoder instructions. The walk tracks which cursor-relative byte each tag, value and extra read
   takes, which DS buffer it lands in, the cursor writes, the helper calls, and a symbolic domain
   for the tag and value bytes that the compare chains partition. Any unmodelled control transfer
   or unknown cursor write is a named refusal on that path, never a guess.
3. ``helpers``: byte census of the three helpers the body calls (``0x7B82`` value decode,
   ``0x8626`` string unpacker, ``0x87CE`` 0x81 post-step).
4. ``callers``: the parser's near callers (classifier arms, and the routine at ``0x7689``) and the
   menu helpers' independence from the parser and the classifier.
5. ``stub_model``: START.EXE stub run of the group whose header is at ``0x45B`` (fileofs
   ``0x74D3``). The zero-skew targets are a model; the probe checks their prologues only.

It does not give any operand or opcode a meaning, does not bind a module, and does not claim
that any path is reachable at run time. No opcode semantics from any other game are used.

Companions: docs/por-ecl-native-framing-probe.md (findings), docs/por-ecl-menu-framing-probe.md,
docs/por-ecl-opcode2d-probe.md, docs/por-ecl-decoder.md.

Usage::

    python tools/por_ecl_native_framing_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-ecl-native-framing/retail

Exit: 0 all checks pass, 1 a structural check failed, 2 a named refusal (missing or unpinned file,
output inside the install).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import por_loadpieces_handler as h  # noqa: E402  (read-only decoder; not edited)

SCHEMA = "openua.por-ecl-native-framing-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_ecl_native_framing_probe.py"

PINS = {
    "GAME.OVR": (206105, "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"),
    "START.EXE": (65231, "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"),
}

# GAME.OVR file offsets (the bytes, as the decoder places them)
KEY_LOAD = 0x9379            # classifier entry: reads stream[cursor] into the key byte
CHAIN_ENTRY = 0x9390         # first cmp al,imm of the classifier compare chain
PARSER = 0x74D3              # operand parser entry (retf 2)
BODY_HEAD = 0x74F5           # first instruction of the per-operand body
TAG_LOAD = 0x7539            # mov al,[di+0x7005]: tag of the operand, reloaded into AL
LOOP_TAIL = 0x75F4           # mov al,[bp-1] / cmp al,[bp-7] / jz exit / jmp loop
EXIT_HEAD = 0x75FF           # inc [cursor]; mov sp,bp; pop bp; retf 2
CALLER_ROUTINE = 0x7689      # routine with five class-1 parser calls (0x7724..0x7784)
HELPER_VALUE = 0x7B82        # value decode: (buf3 << 8) | buf2, pure
HELPER_STRING = 0x8626       # string unpacker (0x80 arm, count > 0): cursor direct, far calls
HELPER_81 = 0x87CE           # post-step of the 0x81 arm: far calls, no direct cursor ref
HELPER_81_NEAR = 0x7BCE      # near callee of 0x87CE: a range test on its argument (census: pure)
MENU_HELPER_19 = 0x9196      # zero-skew target of 2B:25 (START.EXE stub index 20)
MENU_HELPER_2A = 0x92C3      # zero-skew target of 2B:2A (START.EXE stub index 21)

CURSOR = 0x49ED              # stream cursor cell (word)
FAR_PTR = 0x49DE             # far pointer to the ECL block (les di,[0x49de])
STREAM_DISP = 0x6700         # es:[di+0x6700] reads the ECL stream
KEY = 0x6F7F
BUF_TAG = 0x7005             # DS:[0x7005 + i]: tag of operand i
BUF_EXTRA = 0x7045           # DS:[0x7045 + i]: third byte of operand i
BUF_VAL = 0x7085             # DS:[0x7085 + i]: value byte of operand i
BUF_NAMES = {BUF_TAG: "tag", BUF_EXTRA: "extra", BUF_VAL: "value"}
CALLEES = {HELPER_VALUE: "value-decode-0x7B82", HELPER_STRING: "string-0x8626",
           HELPER_81: "post-81-0x87CE"}
OPEN_CALLEES = {"string-0x8626", "post-81-0x87CE"}   # unresolved far calls inside
STUB_RUN = 0x471             # first stub of the group header at START.EXE:0x45B
STUB_RUN_LEN = 25
HEADER_START = 0x45B
HEADER_FILEOFS = 0x74D3
RESIDENT_BASE = 0x200        # START.EXE resident image: literal far (seg, off) -> 0x200 + seg*16 + off

MAX_CHAIN = 400
MAX_BODY = 600
JCC = {0x72: "jb", 0x73: "jnb", 0x74: "jz", 0x75: "jnz", 0x76: "jbe", 0x77: "ja"}
FULL = frozenset(range(256))
CURSOR_INC = bytes.fromhex("ff06ed49")      # inc [0x49ed]
CURSOR_LOAD = bytes.fromhex("a1ed49")       # mov ax,[0x49ed]
CURSOR_STORE = bytes.fromhex("a3ed49")      # mov [0x49ed],ax
LES_FAR = bytes.fromhex("c43ede49")         # les di,[0x49de]
ES_STREAM_READ_PREFIX = 0x26

# flag-neutral instructions: moves, pushes/pops, lea, mov moffs. Anything else clobbers the flags
# the next jcc would read (so a jcc after an unmodelled flag-setter is refused, not guessed).
FLAG_NEUTRAL = set(range(0x50, 0x60)) | {0x0E, 0x88, 0x89, 0x8A, 0x8B, 0x8D, 0xA0, 0xA1, 0xA2, 0xA3,
                                         0xC4, 0xC5, 0xC6, 0xC7} | set(range(0xB0, 0xC0))

# Byte sequences the walk is checked against (decoder-verified text is also recorded).
KEY_LOAD_SEQUENCE = [
    bytes.fromhex("a1ed49"),       # mov ax,[0x49ed]
    bytes.fromhex("c43ede49"),     # les di,[0x49de]
    bytes.fromhex("03f8"),         # add di,ax
    bytes.fromhex("268a850067"),   # es mov al,[di+0x6700]
    bytes.fromhex("a27f6f"),       # mov [0x6f7f],al
]
VALUE_DECODE_SEQUENCE = [
    bytes.fromhex("8a4608"),       # mov al,[bp+8]
    bytes.fromhex("8bd0"),         # mov dx,ax
    bytes.fromhex("8a4606"),       # mov al,[bp+6]
    bytes.fromhex("d3e0"),         # shl ax,cl
    bytes.fromhex("03c2"),         # add ax,dx
]


class ProbeRefusal(Exception):
    """A named refusal: the probe does not run on this input."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ranges(vals) -> list:
    out: list = []
    for v in sorted(vals):
        if out and out[-1][1] == v - 1:
            out[-1][1] = v
        else:
            out.append([v, v])
    return out


def _size(ranges) -> int:
    return sum(hi - lo + 1 for lo, hi in ranges)


def _rects_overlap(a: tuple, b: tuple) -> bool:
    def ov(x, y):
        return any(lo1 <= hi2 and lo2 <= hi1 for lo1, hi1 in x for lo2, hi2 in y)
    return ov(a[0], b[0]) and ov(a[1], b[1])


def _jcc_taken(name: str, v: int, imm: int) -> bool:
    """Taken predicate of a short jcc after ``cmp al,imm`` (or ``cmp word m,imm``) with value v."""
    return {"jb": v < imm, "jnb": v >= imm, "jz": v == imm, "jnz": v != imm,
            "jbe": v <= imm, "ja": v > imm}[name]


def _modrm_di_disp(core: bytes) -> Optional[tuple]:
    """(reg, disp16) for ``op modrm disp16`` with mod=10 rm=101, i.e. [di+disp16]; else None."""
    if len(core) < 4:
        return None
    modrm = core[1]
    if modrm & 0xC7 != 0x85:
        return None
    return (modrm >> 3) & 7, core[2] | (core[3] << 8)


# ---------------------------------------------------------------------------------------------
# 1. Classifier: concrete walk of the compare chain for one opcode value
# ---------------------------------------------------------------------------------------------

def classify_value(game: bytes, value: int, entry: int = CHAIN_ENTRY, parser: int = PARSER) -> dict:
    """Follow the classifier compare chain for one opcode value and report the arm it takes.

    Modelled: ``cmp al,imm8`` (0x3C), short jcc (0x72..0x77), jmp, ``mov al,imm8`` (0xB0),
    ``push ax`` (0x50), ``push cs`` (0x0E), near call, ``inc [0x49ED]``, ``pop bp``/``retf``.
    Anything else is a named refusal.
    """
    al = value & 0xFF
    flag: Optional[tuple] = None
    pushes: list = []
    pc = entry
    for _ in range(MAX_CHAIN):
        try:
            ins = h.decode(game, pc)
        except h.DecodeError as exc:
            return {"arm": "refusal", "reason": exc.reason, "at": pc}
        raw = ins.raw
        if raw[0] == 0x3C and len(raw) == 2:
            flag = (al, raw[1])
            pc = ins.end
            continue
        if raw[0] in JCC:
            if flag is None:
                return {"arm": "refusal", "reason": "jcc-without-compare", "at": pc}
            a, imm = flag
            pc = ins.target if _jcc_taken(JCC[raw[0]], a, imm) else ins.end
            continue
        if raw[0] in (0xEB, 0xE9) and ins.flow == "jmp":
            pc = ins.target
            continue
        if raw[0] == 0xB0 and len(raw) == 2:
            al = raw[1]
            pc = ins.end
            continue
        if raw[0] == 0x50 and len(raw) == 1:
            pushes.append(al)
            pc = ins.end
            continue
        if raw[0] == 0x0E and len(raw) == 1:
            pc = ins.end
            continue
        if raw[0] == 0xE8 and ins.flow == "call":
            if ins.target == parser:
                return {"arm": "push-cs-call", "class": pushes[-1] if pushes else None,
                        "call": ins.target, "at": ins.off, "pushed": list(pushes)}
            return {"arm": "other-call", "call": ins.target, "at": ins.off}
        if raw == CURSOR_INC:
            return {"arm": "inc-only", "at": ins.off, "inc": CURSOR, "operands_parsed": 0}
        if raw[0] in (0x5D, 0xCB) and len(raw) == 1:
            return {"arm": "exit-no-advance", "at": ins.off}
        return {"arm": "refusal", "reason": "unmodelled-byte", "at": pc, "byte": raw[0]}
    return {"arm": "refusal", "reason": "step-budget", "at": pc}


def classifier_table(game: bytes) -> dict:
    return {v: classify_value(game, v) for v in range(256)}


# ---------------------------------------------------------------------------------------------
# 2. Operand body: bounded control/dataflow over decoder instructions
# ---------------------------------------------------------------------------------------------

def _new_state(entry: int) -> dict:
    return {"pc": entry, "cur": 0, "ax": None, "di_mode": None, "di_off": None,
            "dl": None, "al": None, "flag": None, "bp6": None, "dom": {},
            "reads": [], "stores": [], "calls": [], "cursor_incs": [], "cursor_writes": [],
            "steps": 0, "refusal": None, "trace": []}


def _copy(st: dict) -> dict:
    out = dict(st)
    out["dom"] = dict(st["dom"])
    for k in ("reads", "stores", "calls", "cursor_incs", "cursor_writes", "trace"):
        out[k] = list(st[k])
    return out


def _finish(st: dict, terminal: str, imm: Optional[int] = None) -> dict:
    calls = list(st["calls"])
    dom = st["dom"]
    return {
        "terminal": terminal,
        "retf_imm": imm,
        "tag_set": None if dom.get("tag") is None else _ranges(dom["tag"]),
        "value_set": None if dom.get("value") is None else _ranges(dom["value"]),
        "extra_set": None if dom.get("extra") is None else _ranges(dom["extra"]),
        "cursor_delta": st["cur"],
        "reads": list(st["reads"]),
        "stores": list(st["stores"]),
        "calls": calls,
        "cursor_incs": list(st["cursor_incs"]),
        "cursor_writes": list(st["cursor_writes"]),
        "open": any(c["name"] in OPEN_CALLEES for c in calls),
        "steps": st["steps"],
        "refusal": st["refusal"],
        "trace_len": len(st["trace"]),
    }


def body_paths(game: bytes, entry: int, stop: Optional[int] = None,
               max_steps: int = MAX_BODY) -> list:
    """Enumerate the paths from ``entry`` to ``stop`` (or to a ``retf``), tracking symbols.

    Symbols: ``al`` names the buffer AL mirrors (``tag``, ``value``, ``extra``) so a compare on AL
    partitions that buffer's domain; ``bp6`` names what ``[bp-6]`` holds (the value, for the 0x80
    arm); ``cur`` is the cursor offset from its value at entry; ``ax`` is AX as cursor+offset, or
    ``None`` when unknown; ``di_mode``/``di_off`` track the stream base vs the operand index; ``flag``
    is the (symbol, imm) of the last compare, dropped by any flag-setting instruction that is not
    modelled, so a jcc never reads a stale compare.
    """
    paths: list = []
    work = [_new_state(entry)]
    while work:
        st = work.pop()
        while True:
            if st["refusal"] is not None:
                paths.append(_finish(st, "refused"))
                break
            if st["steps"] >= max_steps:
                st["refusal"] = "step-budget"
                paths.append(_finish(st, "refused"))
                break
            pc = st["pc"]
            if stop is not None and pc == stop:
                paths.append(_finish(st, "tail"))
                break
            st["steps"] += 1
            st["trace"].append(pc)
            try:
                ins = h.decode(game, pc)
            except h.DecodeError as exc:
                st["refusal"] = exc.reason
                continue
            raw = ins.raw
            es = raw[0] == ES_STREAM_READ_PREFIX
            core = raw[1:] if es else raw
            if ins.flow in ("ret", "retf"):
                paths.append(_finish(st, "return", ins.imm))
                break
            if ins.flow in ("call_far", "jmp_far", "indirect_call", "indirect_callf",
                            "indirect_jmp", "indirect_jmpf"):
                st["refusal"] = "far-or-indirect-transfer"
                continue
            if ins.flow == "jcc":
                if core[0] not in JCC:
                    st["refusal"] = "unmodelled-jcc"
                    continue
                if st["flag"] is None or st["flag"][0] is None or st["flag"][0] not in st["dom"]:
                    st["refusal"] = "jcc-on-unbound-flags"
                    continue
                sym, imm = st["flag"]
                dset = st["dom"][sym]
                name = JCC[core[0]]
                taken = {v for v in dset if _jcc_taken(name, v, imm)}
                nottaken = set(dset) - taken
                if taken and nottaken:
                    alt = _copy(st)
                    alt["dom"][sym] = frozenset(taken)
                    alt["pc"] = ins.target
                    work.append(alt)
                    st["dom"][sym] = frozenset(nottaken)
                    st["pc"] = ins.end
                elif taken:
                    st["dom"][sym] = frozenset(taken)
                    st["pc"] = ins.target
                else:
                    st["dom"][sym] = frozenset(nottaken)
                    st["pc"] = ins.end
                continue
            if ins.flow == "jmp":
                st["pc"] = ins.target
                continue
            if ins.flow == "call":
                name = CALLEES.get(ins.target)
                if name is None:
                    st["refusal"] = "unknown-near-callee"
                    continue
                st["calls"].append({"at": pc, "name": name, "open": name in OPEN_CALLEES})
                st["al"] = None
                st["ax"] = None
                st["flag"] = None
                st["pc"] = ins.end
                continue
            # --- straight-line instructions ---------------------------------------------------
            st["pc"] = ins.end
            if es:
                if core[0] != 0x8A:
                    st["refusal"] = "es-prefixed-non-read"
                    continue
                di = _modrm_di_disp(core)
                if di is None or di[1] != STREAM_DISP or st["di_mode"] != "stream" \
                        or st["di_off"] is None:
                    st["refusal"] = "stream-read-shape"
                    continue
                reg = di[0]
                st["reads"].append({"at": pc, "rel": st["di_off"], "reg": reg})
                if reg == 2:
                    st["dl"] = st["di_off"]
                elif reg == 0:
                    st["al"] = None
                continue
            if core[0] == 0x3C and len(core) == 2:          # cmp al,imm8
                st["flag"] = (st["al"], core[1])
                continue
            if core == b"\x83\x7e\xfa\x00":                  # cmp word [bp-6],0
                st["flag"] = (st["bp6"], 0)
                continue
            if core[0] == 0x8A:                              # mov r8, r/m8
                di = _modrm_di_disp(core)
                if di is not None and di[0] == 0 and di[1] in BUF_NAMES:
                    name = BUF_NAMES[di[1]]
                    st["al"] = name
                    st["dom"][name] = FULL
                elif ((core[1] >> 3) & 7) == 0:
                    st["al"] = None
                st["flag"] = None if core[0] not in FLAG_NEUTRAL else st["flag"]
                continue
            if core[0] == 0x88:                              # mov r/m8, r8
                di = _modrm_di_disp(core)
                if (core[1] & 0xC0) == 0xC0:
                    st["al"] = None
                    st["ax"] = None
                elif di is not None and ((core[1] >> 3) & 7) == 2 and st["dl"] is not None:
                    st["stores"].append({"at": pc, "buf": BUF_NAMES.get(di[1], hex(di[1])),
                                         "rel": st["dl"]})
                continue
            if core == b"\x89\x46\xfa":                      # mov [bp-6],ax
                st["bp6"] = st["al"]
                continue
            if core == CURSOR_LOAD:                          # mov ax,[0x49ed]
                st["ax"] = st["cur"]
                continue
            if core == CURSOR_STORE:                         # mov [0x49ed],ax
                if st["ax"] is None:
                    st["refusal"] = "cursor-write-of-unknown-ax"
                    continue
                st["cur"] = st["ax"]
                st["cursor_writes"].append({"at": pc, "cursor_after_rel": st["ax"]})
                continue
            if core == CURSOR_INC:                           # inc [0x49ed]
                st["cur"] += 1
                st["cursor_incs"].append(pc)
                st["flag"] = None
                continue
            if core == b"\x40":                              # inc ax
                if st["ax"] is not None:
                    st["ax"] += 1
                st["flag"] = None
                continue
            if core == LES_FAR:                              # les di,[0x49de]
                st["di_mode"] = "stream"
                st["di_off"] = None
                continue
            if core == b"\x03\xf8":                          # add di,ax
                if st["di_mode"] == "stream":
                    st["di_off"] = st["ax"]
                st["flag"] = None
                continue
            if core == b"\x8b\xf8":                          # mov di,ax (operand-index mode)
                st["di_mode"] = "index"
                st["di_off"] = None
                continue
            if core == b"\x30\xe4":                          # xor ah,ah
                st["ax"] = None
                st["flag"] = None
                continue
            if core == b"\xd3\xe7":                          # shl di,cl (DI only)
                st["flag"] = None
                continue
            if core[0] == 0x8B:                              # mov r16, r/m16
                if ((core[1] >> 3) & 7) == 0:
                    st["ax"] = None
                st["flag"] = st["flag"] if core[0] in FLAG_NEUTRAL else None
                continue
            if core[0] == 0xB0:                              # mov al,imm8
                st["al"] = None
                continue
            if core[0] in (0xC6, 0xC7) and (core[1] & 0xC0) != 0xC0:   # mov m,imm (non-AX)
                continue
            if core[0] in (0x80, 0x81, 0x83, 0xFE, 0xFF) and (core[1] & 0xC0) != 0xC0:
                st["flag"] = None                              # ALU/inc/dec on memory
                continue
            if core[0] in FLAG_NEUTRAL:
                if core[0] == 0x58:                          # pop ax writes AX
                    st["ax"] = None
                    continue
                if core[0] == 0xB1 or core[0] == 0x0E or 0x50 <= core[0] < 0x60:
                    continue
                if core[0] in (0x88, 0x89) and (core[1] & 0xC0) != 0xC0:
                    continue
                if core[0] in (0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
                               0xBC, 0xBD, 0xBE, 0xBF):
                    if core[0] == 0xB8:
                        st["ax"] = None
                    continue
            # anything else may write AX or AL or the flags: clobber, do not guess
            st["ax"] = None
            st["al"] = None
            st["flag"] = None
    return paths


def body_summary(paths: list) -> dict:
    """Group the terminal paths into operand kinds; check the (tag, value) space tiles exactly."""
    ok = [p for p in paths if p["refusal"] is None and p["terminal"] == "tail"]
    kinds = []
    for p in ok:
        if p["tag_set"] is None:
            continue
        kinds.append({
            "tag_set": p["tag_set"],
            "value_set": p["value_set"],
            "cursor_delta": p["cursor_delta"],
            "reads": [{"rel": r["rel"], "reg": r["reg"]} for r in p["reads"]],
            "stores": [{"buf": s["buf"], "rel": s["rel"]} for s in p["stores"]],
            "calls": [c["name"] for c in p["calls"]],
            "open": p["open"],
        })
    rects = []
    area = 0
    for p in ok:
        if p["tag_set"] is None:
            continue
        vset = p["value_set"] if p["value_set"] is not None else [[0, 255]]
        area += _size(p["tag_set"]) * _size(vset)
        rects.append((p["tag_set"], vset))
    disjoint = all(not _rects_overlap(rects[i], rects[j])
                   for i in range(len(rects)) for j in range(i + 1, len(rects)))
    return {
        "path_count": len(paths),
        "tail_paths": len(ok),
        "refused_paths": [p["refusal"] for p in paths if p["refusal"] is not None],
        "kinds": kinds,
        "tiling_area": area,
        "tiling_complete": area == 256 * 256,
        "tiling_disjoint": disjoint,
    }


# ---------------------------------------------------------------------------------------------
# 3. Helpers, 4. callers, 5. stub model
# ---------------------------------------------------------------------------------------------

def helper_census(game: bytes, entry: int) -> dict:
    w = h.walk(game, entry)
    direct = w["direct_refs"]
    return {
        "entry": entry,
        "complete": w["complete"],
        "instruction_count": w["instruction_count"],
        "far_call_count": len(w["far_calls"]),
        "near_call_targets": sorted({c["target"] for c in w["near_calls"]}),
        "direct_ds_refs": [hex(x) for x in direct],
        "touches_cursor_cell": CURSOR in direct,
        "returns": [r["imm"] for r in w["returns"]],
        "pure": bool(w["complete"] and not w["far_calls"] and not w["near_calls"]
                     and not w["indirect"] and not direct),
    }


def value_decode_anchor(game: bytes) -> dict:
    """The 0x7B82 arithmetic, checked as an in-order byte sequence in its listing."""
    w = h.walk(game, HELPER_VALUE)
    blob = b"".join(bytes.fromhex(r["bytes"]) for r in w["listing"])
    pos = 0
    found = []
    for seg in VALUE_DECODE_SEQUENCE:
        k = blob.find(seg, pos)
        found.append(k >= 0)
        if k >= 0:
            pos = k + len(seg)
    return {"sequence_found_in_order": all(found), "per_step": found,
            "formula": "((byte at [bp+6]) << 8) | (byte at [bp+8])"}


def _store_word(listing: list, at: int) -> Optional[str]:
    for row in listing:
        if row["at"] == at:
            raw = bytes.fromhex(row["bytes"])
            if len(raw) == 3 and raw[0] == 0xA3:
                return "0x%04x" % (raw[1] | (raw[2] << 8))
    return None


def parser_callers(game: bytes) -> dict:
    """Near callers of 0x74D3: the classifier arms, and the routine at 0x7689 (five class-1 calls)."""
    cls = h.walk(game, CHAIN_ENTRY)
    cls_sites = sorted(c["at"] for c in cls["near_calls"] if c["target"] == PARSER)
    w = h.walk(game, CALLER_ROUTINE)
    listing = w["listing"]
    sites = []
    for c in w["near_calls"]:
        if c["target"] != PARSER:
            continue
        at = c["at"]
        nxt = next((n for n in w["near_calls"]
                    if n["at"] > at and n["target"] == HELPER_VALUE and n["at"] - at <= 16), None)
        pushed = None
        for row in listing:
            if at - 4 <= row["at"] < at and row["bytes"].startswith("b0"):
                pushed = int(row["bytes"][2:4], 16)
        store = None
        if nxt is not None:
            for row in listing:
                if row["at"] > nxt["at"] and row["bytes"].startswith("a3"):
                    store = row["at"]
                    break
        sites.append({"at": at, "class_pushed": pushed,
                      "value_decode_at": None if nxt is None else nxt["at"],
                      "stored_at": store, "stored_word": None if store is None else _store_word(listing, store)})
    return {"classifier_arm_call_sites": cls_sites,
            "routine_entry": CALLER_ROUTINE, "routine_complete": w["complete"],
            "parser_near_calls_in_routine": len(sites), "sites": sites}


def stub_model(game: bytes, start: bytes) -> dict:
    fileofs = struct.unpack("<I", start[HEADER_START + 4:HEADER_START + 8])[0]
    header = {"at": HEADER_START, "bytes": start[HEADER_START:HEADER_START + 4].hex(" "),
              "fileofs": fileofs, "matches_0x74d3": fileofs == HEADER_FILEOFS}
    rows = []
    for i in range(STUB_RUN_LEN):
        b = start[STUB_RUN + 5 * i:STUB_RUN + 5 * i + 5]
        if b[:2] != b"\xcd\x3f":
            rows.append({"index": i, "stub": False})
            continue
        proc = struct.unpack("<H", b[2:4])[0]
        rows.append({"index": i, "stub": True, "proc_off": proc,
                     "zero_skew_game_target": HEADER_FILEOFS + proc,
                     "prologue": game[HEADER_FILEOFS + proc:HEADER_FILEOFS + proc + 3].hex(" ")})
    hits: dict = {}
    for i in range(len(game) - 4):
        if game[i] != 0x9A:
            continue
        off, seg = struct.unpack("<HH", game[i + 1:i + 5])
        addr = RESIDENT_BASE + seg * 16 + off
        if STUB_RUN <= addr < STUB_RUN + 5 * STUB_RUN_LEN and (addr - STUB_RUN) % 5 == 0:
            k = (addr - STUB_RUN) // 5
            hits[k] = hits.get(k, 0) + 1
    return {"header": header, "stubs": rows,
            "far_literal_candidates_by_index": {str(k): v for k, v in sorted(hits.items())},
            "index_2_zero_skew_is_parser": rows[2].get("zero_skew_game_target") == PARSER,
            "index_2_far_literal_candidates": hits.get(2, 0)}


def menu_helper_independence(game: bytes) -> dict:
    out = {}
    for name, entry in (("0x9196", MENU_HELPER_19), ("0x92C3", MENU_HELPER_2A)):
        w = h.walk(game, entry)
        out[name] = {
            "entry": entry,
            "complete": w["complete"],
            "near_call_targets": sorted({c["target"] for c in w["near_calls"]}),
            "calls_parser": any(c["target"] == PARSER for c in w["near_calls"]),
            "calls_classifier": any(c["target"] == KEY_LOAD for c in w["near_calls"]),
            "direct_ds_refs": [hex(x) for x in w["direct_refs"]],
            "touches_cursor_cell": CURSOR in w["direct_refs"],
            "far_call_count": len(w["far_calls"]),
        }
    return out


# ---------------------------------------------------------------------------------------------
# Probe driver
# ---------------------------------------------------------------------------------------------

def _in_order(blob: bytes, seqs: list) -> dict:
    pos = 0
    found = []
    for seg in seqs:
        k = blob.find(seg, pos)
        found.append(k >= 0)
        if k >= 0:
            pos = k + len(seg)
    return {"sequence_found_in_order": all(found), "per_step": found}


def _key_load_check(game: bytes) -> dict:
    out = _in_order(game[KEY_LOAD:KEY_LOAD + 0x16], KEY_LOAD_SEQUENCE)
    out["at"] = KEY_LOAD
    return out


def _parser_anchors(game: bytes) -> dict:
    return {
        "prologue_55_89_e5": game[PARSER:PARSER + 3] == b"\x55\x89\xe5",
        "mov_al_bp6_at_74dd": game[0x74DD:0x74DD + 3] == b"\x8a\x46\x06",
        "mov_bp7_al_at_74e0": game[0x74E0:0x74E0 + 3] == b"\x88\x46\xf9",
        "cmp_al_bp7_at_74e5": game[0x74E5:0x74E5 + 3] == b"\x3a\x46\xf9",
        "tag_load_at_7539": game[TAG_LOAD:TAG_LOAD + 4] == b"\x8a\x85\x05\x70",
        "loop_tail_mov_al_bp1_at_75f4": game[LOOP_TAIL:LOOP_TAIL + 3] == b"\x8a\x46\xff",
        "loop_tail_cmp_bp7_at_75f7": game[0x75F7:0x75F7 + 3] == b"\x3a\x46\xf9",
        "loop_tail_jz_exit_at_75fa": game[0x75FA:0x75FA + 2] == b"\x74\x03",
        "loop_back_jmp_at_75fc": game[0x75FC:0x75FC + 1] == b"\xe9",
        "exit_inc_cursor_at_75ff": game[EXIT_HEAD:EXIT_HEAD + 4] == CURSOR_INC,
        "retf_2_at_7606": game[0x7606:0x7606 + 3] == b"\xca\x02\x00",
    }


def _dispatch_cases(game: bytes) -> dict:
    """Structured dispatcher cases from PoR's own 0x3C73 chain (decoder reader; no other source)."""
    r = h.dispatch_cases(game)
    return {c["case"]: c for c in r.get("cases", []) if "case" in c}


def _per_opcode(arms: dict, cases: dict) -> dict:
    out = {}
    for v in range(256):
        a = arms[v]
        key = "0x%02X" % v
        if a["arm"] == "push-cs-call":
            c = a["class"]
            out[key] = {
                "arm": "class", "operands_parser": c,
                "framing_min": 1 + 2 * c, "framing_max_without_open_terms": 1 + 3 * c,
                "open_terms": (["0x80 operand with count>0: string unpacker 0x8626 (unresolved far calls)",
                                "0x81 operand: post-step 0x87CE (unresolved far calls)"] if c >= 1 else []),
            }
        elif a["arm"] == "inc-only":
            case = cases.get(v)
            out[key] = {"arm": "default", "operands_parser": 0, "framing_min": 1,
                        "framing_max_without_open_terms": 1, "open_terms": [],
                        "dispatch_case": None if case is None else case.get("form"),
                        "note": "classifier frames one byte; handler-level reads not established"}
        else:
            out[key] = {"arm": a["arm"], "reason": a.get("reason")}
    return out


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    install = Path(install)
    if not install.is_dir():
        raise ProbeRefusal("install folder not found: %s" % install)
    out_r, inst_r = out.resolve(), install.resolve()
    if out_r == inst_r or inst_r in out_r.parents:
        raise ProbeRefusal("output folder is inside the install")
    blobs: dict = {}
    for name, (size, sha) in PINS.items():
        p = install / name
        if not p.is_file():
            raise ProbeRefusal("missing file: %s" % name)
        data = p.read_bytes()
        if not allow_unpinned and (len(data) != size or _sha(data) != sha):
            raise ProbeRefusal("unpinned file: %s (size %d)" % (name, len(data)))
        blobs[name] = data
    game, start = blobs["GAME.OVR"], blobs["START.EXE"]
    pins_ok = all(len(blobs[n]) == PINS[n][0] and _sha(blobs[n]) == PINS[n][1] for n in PINS)

    arms = classifier_table(game)
    cases = _dispatch_cases(game)
    refused = sorted(v for v in range(256) if arms[v]["arm"] == "refusal")
    class_of = {v: arms[v]["class"] for v in range(256) if arms[v]["arm"] == "push-cs-call"}
    default_set = sorted(v for v in range(256) if arms[v]["arm"] == "inc-only")
    body = body_paths(game, BODY_HEAD, stop=LOOP_TAIL)
    summary = body_summary(body)
    exit_paths = body_paths(game, EXIT_HEAD, stop=None)
    helpers = {
        "0x7B82_value_decode": helper_census(game, HELPER_VALUE),
        "0x8626_string": helper_census(game, HELPER_STRING),
        "0x87CE_post_81": helper_census(game, HELPER_81),
        "0x7BCE_near_callee_of_0x87CE": helper_census(game, HELPER_81_NEAR),
    }
    callers = parser_callers(game)
    stubs = stub_model(game, start)
    menu = menu_helper_independence(game)
    value_anchor = value_decode_anchor(game)
    key_load = _key_load_check(game)
    anchors = _parser_anchors(game)

    checks = {
        "pins_match": pins_ok,
        "classifier_key_load_bytes": key_load["sequence_found_in_order"],
        "classifier_every_value_reaches_arm": not refused,
        "classifier_class_arms_call_parser": all(a.get("call") == PARSER for a in arms.values()
                                                  if a["arm"] == "push-cs-call"),
        "classifier_0x27_is_class_8": arms[0x27].get("class") == 8,
        "classifier_0x29_is_class_14": arms[0x29].get("class") == 14,
        "classifier_0x2D_is_class_1": arms[0x2D].get("class") == 1,
        "classifier_0x37_is_class_3": arms[0x37].get("class") == 3,
        "classifier_0x15_0x2B_default": arms[0x15]["arm"] == "inc-only" and arms[0x2B]["arm"] == "inc-only",
        "parser_anchors": all(anchors.values()),
        "body_refusal_free": not summary["refused_paths"],
        "body_tag_value_tiling_complete": summary["tiling_complete"],
        "body_tag_value_tiling_disjoint": summary["tiling_disjoint"],
        "body_exit_is_one_byte": bool(exit_paths) and all(
            p["cursor_delta"] == 1 and p["refusal"] is None for p in exit_paths if p["terminal"] == "return"),
        "value_decode_formula_anchored": value_anchor["sequence_found_in_order"],
        "helper_0x7B82_pure": helpers["0x7B82_value_decode"]["pure"],
        "helper_0x8626_far_calls_and_cursor_ref": (helpers["0x8626_string"]["far_call_count"] > 0
                                                   and helpers["0x8626_string"]["touches_cursor_cell"]),
        "helper_0x87CE_far_calls": helpers["0x87CE_post_81"]["far_call_count"] > 0,
        "helper_0x7BCE_near_callee_pure": helpers["0x7BCE_near_callee_of_0x87CE"]["pure"],
        "helper_0x87CE_near_targets_are_0x7BCE": helpers["0x87CE_post_81"]["near_call_targets"]
                                                  == [HELPER_81_NEAR],
        "caller_routine_five_class1_calls": (callers["parser_near_calls_in_routine"] == 5
                                             and all(s["value_decode_at"] is not None
                                                     and s["class_pushed"] == 1 for s in callers["sites"])),
        "classifier_has_eight_parser_arms": len(callers["classifier_arm_call_sites"]) == 8,
        "stub_header_is_group_0x74d3": stubs["header"]["matches_0x74d3"],
        "stub_zero_skew_prologues": all(
            game[t:t + 3] == b"\x55\x89\xe5" for t in (PARSER, KEY_LOAD, MENU_HELPER_2A, MENU_HELPER_19)),
        "menu_helpers_do_not_call_parser_or_classifier": all(
            not m["calls_parser"] and not m["calls_classifier"] for m in menu.values()),
    }

    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS,
        "tool": TOOL, "playable": False, "mappings": [], "events_emitted": 0,
        "pins": {n: {"size": len(blobs[n]), "sha256": _sha(blobs[n])} for n in PINS},
        "classifier": {
            "entry": CHAIN_ENTRY, "key_load": KEY_LOAD,
            "default_arm_opcodes": ["0x%02X" % v for v in default_set],
            "class_sets": {str(c): ["0x%02X" % v for v in sorted(class_of) if class_of[v] == c]
                           for c in sorted(set(class_of.values()))},
            "refused_values": ["0x%02X" % v for v in refused],
            "default_arm_with_dispatch_case": ["0x%02X" % v for v in default_set if v in cases],
            "per_opcode": _per_opcode(arms, cases),
        },
        "parser": {
            "entry": PARSER, "anchors": anchors, "body_range": [BODY_HEAD, LOOP_TAIL],
            "body": summary,
            "operand_kinds": summary["kinds"],
            "exit_paths": exit_paths,
        },
        "helpers": helpers,
        "value_decode_anchor": value_anchor,
        "callers": callers,
        "menu_helpers": menu,
        "stub_model": stubs,
        "key_load": key_load,
        "checks": checks,
        "not_established": [
            "run-time reachability of the classifier and of the 0x7689 routine",
            "the unresolved far callees 0x0AF8:xxxx called from 0x8626 and 0x87CE (their cursor effect)",
            "the handler-level operand reads of 0x15 and 0x2B (0x92C3 and 0x9196 are not the parser)",
            "the zero-skew stub mapping itself (prologues are consistent, not proof)",
            "the meaning of any operand value, of the 0x7B82 result, or of the cursor",
        ],
    }
    code = 0 if all(checks.values()) else 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_ecl_native_framing_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc, code


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="folder holding GAME.OVR and START.EXE (read-only)")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder (outside the install)")
    ap.add_argument("--allow-unpinned", action="store_true", help="accept unpinned bytes (not retail evidence)")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(Path(args.install), args.out, args.allow_unpinned)
    except ProbeRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    for k, v in sorted(doc["checks"].items()):
        print("%-48s %s" % (k, "ok" if v else "FAIL"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
