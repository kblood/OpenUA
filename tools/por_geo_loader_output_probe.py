#!/usr/bin/env python3
"""Observe-only probe: what does the GEO loader body write to its output far pointer, and what fixes it?

Follows tools/por_geo_loader_target_probe.py (identity of the loader target 0x0802:0x0716 as START.EXE
0x876D, conditional on the live segment) and tools/por_geo_loader_caller_frame_probe.py (caller frame).
The body's bytes are read here, and only read, to answer from bytes:

1. Output far pointer. Every write through the body's output-variable pointer ([bp+6]) is listed with its
   gate (a byte-verified branch) and the value's provenance (xor-zero, or the allocator's returned DX:AX).
2. Pointer escapes. Every place the body passes one of its pointer arguments to a callee is listed. The
   callees are then identified from their own bytes: DOS read wrapper 0x0AF8:0x14FB, allocator wrapper
   0x0AF8:0x023F, near allocator 0x8077, RLE decoder 0x8566 (each with byte checks, not names).
3. Archive and id. The body builds an archive name and compares a TOC id byte with the caller's id. The
   probe reports whether the bytes fix either one. They do not, so the probe reports the gap, not a block.
4. Control rule. The RLE decoder's control bytes (cmp immediates at fixed offsets) are read from the file,
   and the rule is cross-checked against tools/por_map.py rle_decode over the pinned GEO archives.
5. TOC order. The body reads a 9-byte TOC record as id (1), offset (4), u16 (status), u16 (comp). The probe
   checks the 8 pinned archives against that order: the status gate 0x402 is the raw size on every block.

Nothing here runs the code, reads a live register, or identifies a GEO block for a requested id. Helper
and near-callee placements are memory-present checks at an unknown instant. No plane 2 binding.

Usage:
    python tools/por_geo_loader_output_probe.py [--install PATH/TO/POOLRAD] \
        [--dump data/work/por-live-memory-pid34644/ram-000000-100000.bin ...] \
        [-o data/work/por-geo-loader-output-probe]

Exit: 0 the probe ran (its verdict may be unresolved; that is the result); 2 a named refusal
(unpinned input, bad dump, unidentified loader body, output outside data/work or inside the install).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_loadpieces_handler as lh  # noqa: E402
import por_geo_loader_target_probe as tp  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_map as pm  # noqa: E402

SCHEMA = "openua.por-geo-loader-output-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "loader-output-probe-only"
TOOL = "tools/por_geo_loader_output_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-loader-output-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMPS = tp.DEFAULT_DUMPS
Refusal = om.Refusal
OVR_NAME = tp.OVR_NAME
EXE_NAME = tp.EXE_NAME

BODY_FILE = 0x876D                  # conditional identity; re-checked against the target probe
BODY_OFF = 0x0716                   # the loader offset (raw 0x0802:0x0716)
LOADER_RAW_SEG = 0x0802             # raw segment word of the loader call
BODY_SEG_LOAD = 0x2068              # 0x0802 + load 0x1866 (target probe)
LOAD = 0x1866
MOD_SEG = 0x0AF8
MOD_BASE = 0xAC76                   # routine-B module base for segment 0x0AF8 (copy-helper probe)
DECODE_LIMIT = 400
HELPER_WINDOW = 48
GEO_RAW_GATE = 0x402                # the fill's status gate (1026 bytes)
TOC_CLAMP = 0x8CA0                  # the body's comp-size clamp
GEO_ARCHIVES = range(1, 9)
REG_NAMES = {0: "ax", 1: "cx", 2: "dx", 3: "bx"}

# Store census expected from the bytes (file offset, pointer var bp disp, pointer field disp, register).
EXPECTED_STORES = [
    (0x87D8, 10, 0, "ax"),   # status = 0, gate A (call 0x8624 returned 0)
    (0x87E0, 6, 0, "ax"),    # output offset = 0, gate A
    (0x87E3, 6, 2, "ax"),    # output segment = 0, gate A
    (0x88E8, 10, 0, "ax"),   # status = 0, gate B not taken (AL != id)
    (0x88F0, 6, 0, "ax"),    # output offset = 0, gate B not taken
    (0x88F3, 6, 2, "ax"),    # output segment = 0, gate B not taken
    (0x8924, 6, 0, "ax"),    # output offset = allocator AX, gate B taken
    (0x8927, 6, 2, "dx"),    # output segment = allocator DX, gate B taken
]
# Gates, verified by bytes: (compare off, branch off, branch op, target)
EXPECTED_GATES = {
    "A": {"test": 0x87CF, "branch": 0x87D1, "target": 0x87EA, "op": 0x75},   # or al,al; jnz 0x87EA
    "B": {"compare": 0x88DE, "branch": 0x88E1, "target": 0x890A, "op": 0x74},  # cmp al,[bp+14]; jz 0x890A
}
CLAMP_CMP = {"at": 0x8862, "bytes": bytes.fromhex("81 7e d4 a0 8c"), "text": "cmp [bp-44],0x8CA0"}
CLAMP_BRANCH = {"at": 0x8867, "op": 0x76, "target": 0x88A9}   # jbe 0x88A9: comp <= 0x8CA0 skips the clamp block
CLAMP_BLOCK = (0x8869, 0x88A9)                               # clamp, 'tempsize ' literal, far call 0x0899:0000
COMPARE_ID = bytes.fromhex("3a 46 0e")       # cmp al,[bp+14]
ALLOC_CALL = (MOD_SEG, 0x023F)
READ_CALL = (MOD_SEG, 0x14FB)
SEEK_CALL = (MOD_SEG, 0x1563)
RLE_CMP_OFFS = {0x858A: bytes.fromhex("3c 00 7c"), 0x858E: bytes.fromhex("3c 7e 7f"),
                0x85CB: bytes.fromhex("3c 81 7c"), 0x85CF: bytes.fromhex("3c ff 7f")}
NEAR_CALLEES = {"open_or_gate_8624": 0x8624, "alloc_near_8077": 0x8077,
                "rle_decode_8566": 0x8566, "free_or_release_8057": 0x8057}

NOT_ESTABLISHED = [
    "the archive name the body opens: the bytes build it from literal pieces, and no digit or archive selector is fixed",
    "the requested block id: the caller's byte at [bp+14] is not fixed by any caller bytes read here",
    "the TOC match that selects a block: AL is the id byte read by the DOS read wrapper, and the path from the body to the caller is not closed",
    "whether the seek offset is the block's file position: the body seeks to [bp-309] plus the TOC offset (32-bit add). "
    "[bp-309] has no store in the body; its address is passed to the near open routine 0x8624, so its value is that "
    "routine's output, not decoded here (a data-section base of 2 + TOC bytes is a hypothesis, not checked)",
    "whether the name buffer [bp-573] is the file name the open routine uses: it is built from the DS:0x547C literal "
    "(DS not established) and two 0x0AF8:0x0B98 appends of 'GEO' and '.dax' (the append semantics are not decoded)",
    "the clamp block 0x8869 to 0x88A8 (comp above 0x8CA0): its 'tempsize ' literal, the 0x0AF8:0x1366 field and the far "
    "call 0x0899:0x0000 are not decoded beyond their bytes; no PoR block takes it (the gate C and the comp maximum are checked)",
    "the contents of the output buffer at any instant: no dump holds a decoded GEO block (see the buffer-fill probe)",
    "whether any of this runs, and the live SP and register values at any call",
    "any GEO block identity, area mapping, descriptor, plane 2 binding, or playability",
]

DISCRIMINATORS = [
    "A live capture at the compare 0x88DE (cmp al,[bp+14]), for each record scanned: AL (the record id), [bp+14] "
    "(the requested id), [bp-44], [bp-48] and [bp-309]. This fixes the requested id and the seek term together.",
    "A live capture of the DOS open call's file name and handle (INT 21h reached through the open routine 0x8624), "
    "to fix which GEO archive the name selects.",
    "A live capture of the output far pointer, the status word and the decoded byte count after the return at "
    "0x899B, to see which of the three store paths ran and whether the output is non-NULL.",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


# ---- byte-level recognisers (pure; the synthetic tests exercise these) ------------------------

def is_les_bp_di(raw: bytes) -> Optional[int]:
    """`les di,[bp+d]` (C4 /r, reg=di, mod 01 or 10, rm=bp). Returns d, else None."""
    if len(raw) < 3 or raw[0] != 0xC4:
        return None
    modrm = raw[1]
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    if reg != 7 or rm != 6 or mod not in (1, 2):
        return None
    if mod == 1:
        return raw[2] - 256 if raw[2] >= 128 else raw[2]
    return int.from_bytes(raw[2:4], "little", signed=True)


def writes_di(raw: bytes) -> bool:
    """True when the instruction overwrites DI (so a pointer held in ES:DI is no longer valid)."""
    i = 1 if raw and raw[0] == 0x26 else 0
    if len(raw) <= i:
        return True
    op = raw[i]
    if op in (0xBF, 0x5F):                     # mov di,imm16 ; pop di
        return True
    if op in (0xC4, 0xC5, 0x8D, 0x8B) and len(raw) > i + 1 and ((raw[i + 1] >> 3) & 7) == 7:
        return True                            # les/lds/lea/mov with reg=di
    return False


def store_through_di(raw: bytes) -> Optional[dict]:
    """`[es:]mov [di+d],reg` (88/89) or `mov word [di+d],imm` (C7) with d 0 or a disp8. Else None."""
    i = 1 if raw and raw[0] == 0x26 else 0
    if len(raw) < i + 2 or raw[i] not in (0x88, 0x89, 0xC7):
        return None
    modrm = raw[i + 1]
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    if rm != 5 or mod not in (0, 1):
        return None
    disp = 0
    if mod == 1:
        if len(raw) < i + 3:
            return None
        disp = raw[i + 2] - 256 if raw[i + 2] >= 128 else raw[i + 2]
    if raw[i] == 0xC7:
        return {"reg": "imm", "disp": disp, "width": 2, "es": i == 1}
    return {"reg": REG_NAMES.get(reg, "?"), "disp": disp, "width": 2 if raw[i] == 0x89 else 1, "es": i == 1}


def is_escape_push(raw_a: bytes, raw_b: bytes) -> bool:
    """`push es ; push di`: a far pointer value passed to a callee."""
    return raw_a == b"\x06" and raw_b == b"\x57"


def provenance(ins: list, idx: int, reg: str, exe: bytes, depth: int = 0) -> dict:
    """The nearest preceding writer of the register, found by a linear scan (no CFG). A load of AX from a
    [bp+d] slot is followed to the nearest earlier store of AX into that slot (depth-limited)."""
    for j in range(idx - 1, max(-1, idx - 14), -1):
        raw = exe[ins[j].off:ins[j].off + ins[j].length]
        if reg == "ax" and raw[:2] == b"\x31\xc0":
            return {"kind": "xor-zero", "at": "0x%X" % ins[j].off}
        if reg == "dx" and raw[:2] == b"\x31\xd2":
            return {"kind": "xor-zero", "at": "0x%X" % ins[j].off}
        if raw[:1] == b"\x9a":
            seg = int.from_bytes(raw[3:5], "little")
            off = int.from_bytes(raw[1:3], "little")
            return {"kind": "far-call-return", "at": "0x%X" % ins[j].off, "target": "0x%04X:0x%04X" % (seg, off)}
        if reg == "ax" and raw[:1] == b"\xb8":
            return {"kind": "imm", "at": "0x%X" % ins[j].off, "value": int.from_bytes(raw[1:3], "little")}
        if reg == "ax" and raw[:1] == b"\x8b" and len(raw) >= 2 and ((raw[1] >> 3) & 7) == 0 and depth < 3:
            loc = _mem_operand(raw)
            if loc is not None and loc[0] == "bp":
                for m in range(j - 1, max(-1, j - 40), -1):
                    st = exe[ins[m].off:ins[m].off + ins[m].length]
                    if st[:1] == b"\x89" and len(st) >= 2 and ((st[1] >> 3) & 7) == 0 and _mem_operand(st) == loc:
                        return {"kind": "load-from-bp-slot", "at": "0x%X" % ins[j].off, "slot": loc[1],
                                "stored_at": "0x%X" % ins[m].off,
                                "via": provenance(ins, m, "ax", exe, depth + 1)}
                # No store in the body: the slot's address may be passed to a callee (its output).
                for m in range(j - 1, max(-1, j - 200), -1):
                    lea = exe[ins[m].off:ins[m].off + ins[m].length]
                    if lea[:1] == b"\x8d" and len(lea) >= 2 and _mem_operand(lea) == loc:
                        callee = None
                        for x in range(m + 1, min(len(ins), m + 14)):
                            if ins[x].flow in ("call", "call_far"):
                                callee = ("0x%04X:0x%04X" % ins[x].far) if ins[x].far else "0x%X" % ins[x].target
                                break
                        return {"kind": "load-from-bp-slot", "at": "0x%X" % ins[j].off, "slot": loc[1],
                                "stored_at": None, "address_passed_at": "0x%X" % ins[m].off,
                                "address_passed_to": callee}
                return {"kind": "load-from-bp-slot", "at": "0x%X" % ins[j].off, "slot": loc[1], "stored_at": None}
            return {"kind": "load", "at": "0x%X" % ins[j].off}
    return {"kind": "unknown", "at": None}


def body_census(ins: list, exe: bytes) -> dict:
    """Every store through a far pointer loaded from [bp+d], and every pointer passed to a callee."""
    stores, escapes = [], []
    ptr = None       # (index, bp disp) of the live `les di,[bp+d]`
    for k, i in enumerate(ins):
        raw = exe[i.off:i.off + i.length]
        d = is_les_bp_di(raw)
        if d is not None:
            ptr = (k, d)
            nxt = [exe[ins[k + x].off:ins[k + x].off + ins[k + x].length] for x in (1, 2) if k + x < len(ins)]
            if len(nxt) == 2 and is_escape_push(nxt[0], nxt[1]):
                callee = None
                for m in range(k + 3, min(len(ins), k + 12)):
                    if ins[m].flow in ("call", "call_far"):
                        callee = {"flow": ins[m].flow, "target": ("0x%04X:0x%04X" % ins[m].far)
                                  if ins[m].far else "0x%X" % ins[m].target}
                        break
                escapes.append({"at": "0x%X" % i.off, "pointer_var_bp": d, "callee": callee})
            continue
        if ptr is None:
            continue
        if i.flow != "seq" or writes_di(raw):
            ptr = None
            continue
        st = store_through_di(raw)
        if st is not None:
            stores.append({"at": "0x%X" % i.off, "pointer_var_bp": ptr[1], "field_disp": st["disp"],
                           "reg": st["reg"], "width": st["width"], "es_prefixed": st["es"], "index": k})
    for s in stores:
        if s["reg"] in ("ax", "dx"):
            s["provenance"] = provenance(ins, s.pop("index"), s["reg"], exe)
        else:
            s.pop("index", None)
            s["provenance"] = {"kind": "immediate" if s["reg"] == "imm" else "unknown", "at": None}
    return {"stores": stores, "escapes": escapes}


def gate_check(exe: bytes, expected: dict) -> dict:
    """Verify each branch's opcode and target from its bytes. Target = branch + 2 + signed rel8."""
    out = {}
    if "test" in expected:
        t = expected["test"]
        out["test_bytes"] = exe[t:t + 2].hex(" ")
        out["test_is_or_al_al"] = exe[t:t + 2] == b"\x08\xc0"
    b = expected["branch"]
    op = exe[b]
    rel = exe[b + 1] - 256 if exe[b + 1] >= 128 else exe[b + 1]
    tgt = b + 2 + rel
    out.update({"branch": "0x%X" % b, "op": "0x%02X" % op, "target": "0x%X" % tgt,
                "target_matches": tgt == expected["target"], "op_matches": op == expected["op"]})
    return out


def compare_gate(exe: bytes) -> dict:
    """`cmp al,[bp+14]` at 0x88DE and its jz at 0x88E1 (the record's id byte against the requested id)."""
    c = EXPECTED_GATES["B"]["compare"]
    return {"compare_bytes": exe[c:c + 3].hex(" "), "is_cmp_al_bp14": exe[c:c + 3] == COMPARE_ID,
            "branch": gate_check(exe, EXPECTED_GATES["B"])}


def clamp_gate(exe: bytes) -> dict:
    """`cmp [bp-44],0x8CA0` then `jbe 0x88A9`: a comp count at or below the clamp skips the clamp block."""
    a = CLAMP_CMP["at"]
    b = CLAMP_BRANCH["at"]
    rel = exe[b + 1] - 256 if exe[b + 1] >= 128 else exe[b + 1]
    tgt = b + 2 + rel
    return {"cmp_at": "0x%X" % a, "cmp_bytes": exe[a:a + 5].hex(" "), "cmp_matches": exe[a:a + 5] == CLAMP_CMP["bytes"],
            "branch_at": "0x%X" % b, "op": "0x%02X" % exe[b], "target": "0x%X" % tgt,
            "target_matches": tgt == CLAMP_BRANCH["target"] and exe[b] == CLAMP_BRANCH["op"],
            "clamp_block": ["0x%X" % CLAMP_BLOCK[0], "0x%X" % CLAMP_BLOCK[1]]}


def _mem_operand(raw: bytes) -> Optional[tuple]:
    """(kind, value) for a `[bp+d]` (mod 01/10, rm 110) or direct `[addr]` (mod 00, rm 110) ModRM operand."""
    if len(raw) < 3:
        return None
    mod, rm = raw[1] >> 6, raw[1] & 7
    if rm != 6:
        return None
    if mod == 1:
        return ("bp", raw[2] - 256 if raw[2] >= 128 else raw[2])
    if mod == 2:
        return ("bp", int.from_bytes(raw[2:4], "little", signed=True))
    if mod == 0:
        return ("direct", int.from_bytes(raw[2:4], "little"))
    return None


def read_args(ins: list, k: int, exe: bytes) -> Optional[dict]:
    """Arguments of the `call 0x0AF8:0x14FB` at ins[k], read from the pushes before it. Scanning backwards,
    the pointers are (result, destination, handle) and the count sits between the first two (an immediate
    `mov ax,imm`, or a `push [bp+d]`). Returns None unless three pointers are found."""
    ptrs, count = [], None
    for j in range(k - 1, max(-1, k - 22), -1):
        raw = exe[ins[j].off:ins[j].off + ins[j].length]
        if len(ptrs) < 3 and raw[:1] in (b"\xc4", b"\x8d") and len(raw) > 1 and ((raw[1] >> 3) & 7) == 7:
            loc = _mem_operand(raw)
            if loc is not None:
                ptrs.append({"op": "les" if raw[0] == 0xC4 else "lea", "kind": loc[0], "value": loc[1]})
            continue
        if count is None and len(ptrs) == 1 and raw[:1] == b"\xb8":
            count = int.from_bytes(raw[1:3], "little")
        elif count is None and len(ptrs) == 1 and raw[:2] == b"\xff\x76":
            count = {"push_mem_bp": raw[2] - 256 if raw[2] >= 128 else raw[2]}
    if len(ptrs) != 3:
        return None
    return {"result": ptrs[0], "dst": ptrs[1], "handle": ptrs[2], "count": count}


def helper_facts(exe: bytes, file_off: int) -> dict:
    """Decode a callee to its return and report its far calls, INT 21h sites and return pop."""
    ins, err = lh.linear(exe, file_off, DECODE_LIMIT, stop_on_ret=True)
    rets = [i for i in ins if i.flow in ("ret", "retf")]
    last = rets[0] if rets else None
    end = last.off + last.length if last else file_off
    return {
        "file": "0x%X" % file_off, "decode_error": err, "instructions": len(ins),
        "window": exe[file_off:end],
        "far_calls": sorted({"0x%04X:0x%04X" % i.far for i in ins if i.far is not None and i.flow == "call_far"}),
        "int21_sites": ["0x%X" % i.off for i in ins if exe[i.off:i.off + 2] == b"\xcd\x21"],
        "return": None if last is None else {"flow": last.flow, "pops": last.imm, "at": "0x%X" % last.off},
        "es_stores": ["0x%X" % i.off for i in ins if i.prefixes and 0x26 in i.prefixes and
                      exe[i.off + (1 if exe[i.off] == 0x26 else 0)] in (0x88, 0x89, 0xC6, 0xC7)],
        "_ins": ins,
    }


def rle_body_rule(comp: bytes) -> bytes:
    """The decoder's rule as read from 0x8566: c <= 0x7E copies c+1 bytes; c >= 0x81 repeats the next byte
    256-c times; 0x7F and 0x80 are not decoded (the body falls through to no-op). Raises on those."""
    out = bytearray()
    i, n = 0, len(comp)
    while i < n:
        c = comp[i]
        i += 1
        if c <= 0x7E:
            if i + c + 1 > n:
                raise ValueError("literal overruns the block")
            out += comp[i:i + c + 1]
            i += c + 1
        elif c >= 0x81:
            if i >= n:
                raise ValueError("repeat has no value byte")
            out += bytes((comp[i],)) * (256 - c)
            i += 1
        else:
            raise ValueError("undefined control 0x%02X" % c)
    return bytes(out)


def toc_record(raw9: bytes) -> dict:
    """The body's read order for one 9-byte TOC record: id (1), offset (4), status u16, comp u16."""
    return {"id": raw9[0], "offset": int.from_bytes(raw9[1:5], "little"),
            "status_word": int.from_bytes(raw9[5:7], "little"), "comp": int.from_bytes(raw9[7:9], "little")}


# ---- memory checks ---------------------------------------------------------------------------

def mem_check(start: bytes, dump: om.Dump, label: str, file_off: int, seg: int, off: int, load: int,
              n: int) -> dict:
    lin = (seg + load) * 16 + off
    if not dump.covers(lin, n):
        return {"dump": label, "covered": False}
    live = dump.read(lin, n)
    spans = tp.masked_match(start, file_off, live, load) if file_off + n <= len(start) else None
    pl = [p["file_offset"] for p in tp.placements(start, live, load)]
    return {"dump": label, "covered": True, "live_linear": "0x%X" % lin, "agrees_at_file": spans is not None,
            "placements": ["0x%X" % p for p in pl], "unique_at_file": pl == [file_off]}


def literal_census(exe: bytes, ins: list, dumps: list) -> list:
    """`mov di,imm16` followed by `push cs; push di` (or `push ds; push di`): a literal the body passes as a
    far pointer. A CS literal is mapped through the body's contiguous segment (file = body file + (imm - body
    offset)) and checked in each dump; the Pascal string is read from the file. A DS literal is not mapped:
    DS is not established by these bytes."""
    rows = []

    def raw_at(x: int) -> bytes:
        return exe[ins[x].off:ins[x].off + ins[x].length]

    for k in range(len(ins) - 2):
        a = raw_at(k)
        seg_push, di_push = raw_at(k + 1), raw_at(k + 2)
        if a[:1] != b"\xbf" or len(a) != 3 or di_push != b"\x57" or seg_push not in (b"\x0e", b"\x1e"):
            continue
        imm = int.from_bytes(a[1:3], "little")
        path = "clamp-block" if CLAMP_BLOCK[0] <= ins[k].off < CLAMP_BLOCK[1] else "normal"
        if seg_push == b"\x1e":
            rows.append({"at": "0x%X" % ins[k].off, "seg": "ds", "imm": "0x%04X" % imm, "path": path,
                         "state": "ds-not-established"})
            continue
        f = BODY_FILE + (imm - BODY_OFF)
        row = {"at": "0x%X" % ins[k].off, "seg": "cs", "imm": "0x%04X" % imm, "file_offset": "0x%X" % f,
               "path": path}
        if 0 <= f < len(exe):
            n = exe[f]
            text = exe[f + 1:f + 1 + n]
            row["pascal_length"] = n
            row["pascal_text"] = text.decode("ascii") if all(32 <= c < 127 for c in text) else None
        n = 1 + exe[f] if 0 <= f < len(exe) else 0
        row["memory"] = [_literal_mem(exe, d, lb, f, imm, n) for lb, d, _, _ in dumps]
        rows.append(row)
    return rows


def _read_order_fits(reads: list) -> dict:
    """The four TOC reads in body order: id (1 byte to [bp-49]), offset (4 to [bp-48]), status (2 into the
    caller's status variable, bp+10), comp (2 to [bp-44]). Returns each check and whether all hold."""
    want = [("lea", -49, 1), ("lea", -48, 4), ("les", 10, 2), ("lea", -44, 2)]
    got = []
    for r in reads:
        a = r.get("args") or {}
        d = a.get("dst") or {}
        got.append((d.get("op"), d.get("value"), a.get("count")))
    checks = {"sequence": got[:4] == want}
    return {"expected": want, "found": got[:4], "checks": checks, "all_hold": all(checks.values())}


def _literal_mem(exe: bytes, dump: om.Dump, label: str, f: int, imm: int, n: int) -> dict:
    lin = BODY_SEG_LOAD * 16 + imm
    if n <= 0 or not dump.covers(lin, n):
        return {"dump": label, "covered": False}
    live = dump.read(lin, n)
    return {"dump": label, "covered": True, "live_linear": "0x%X" % lin,
            "agrees_with_file_at_mapped_offset": live == exe[f:f + n]}


# ---- top level ----------------------------------------------------------------------------

def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = tp.check_pins(ovr, exe)
    tdoc = tp.probe(install, dump_paths)
    ident = tdoc["identity"]
    if ident.get("file_offset") != "0x%X" % BODY_FILE or not str(ident["verdict"]).startswith("identified"):
        raise Refusal("loader body is not identified at 0x%X: %s" % (BODY_FILE, ident))
    dumps = []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        base = om.resolve_dump_base(dp.name, len(raw), None)
        dumps.append(("%s/%s" % (dp.parent.name, dp.name), om.Dump(raw, base), len(raw), _sha(raw)[:16]))

    ins, err = lh.linear(exe, BODY_FILE, DECODE_LIMIT, stop_on_ret=True)
    census = body_census(ins, exe)
    body_reads = []
    for k, i in enumerate(ins):
        if i.flow == "call_far" and i.far == READ_CALL:
            body_reads.append({"at": "0x%X" % i.off, "args": read_args(ins, k, exe)})
    seeks = []
    for k, i in enumerate(ins):
        if not (i.flow == "call_far" and i.far == SEEK_CALL):
            continue
        row = {"at": "0x%X" % i.off, "preceding": [exe[ins[j].off:ins[j].off + ins[j].length].hex(" ")
                                                   for j in range(max(0, k - 6), k)]}
        # The offset term: `add ax,[bp+d]` (03 /r, reg=ax) before the call. AX is the value before the add.
        for j in range(k - 1, max(-1, k - 8), -1):
            raw = exe[ins[j].off:ins[j].off + ins[j].length]
            if raw[:1] == b"\x03" and len(raw) >= 2 and ((raw[1] >> 3) & 7) == 0:
                loc = _mem_operand(raw)
                row["offset_add"] = {"at": "0x%X" % ins[j].off, "operand": loc, "adds_to": "ax",
                                     "ax_before_add": provenance(ins, j, "ax", exe)}
                break
        seeks.append(row)
    alloc_calls = ["0x%X" % i.off for i in ins if i.flow == "call_far" and i.far == ALLOC_CALL]
    gates = {"A": gate_check(exe, EXPECTED_GATES["A"]), "B": compare_gate(exe), "C": clamp_gate(exe)}

    helpers = {}
    for name, off in (("0x0AF8:0x14FB", 0x14FB), ("0x0AF8:0x023F", 0x023F), ("0x0AF8:0x1563", 0x1563),
                      ("0x0AF8:0x1685", 0x1685), ("0x0AF8:0x16A8", 0x16A8)):
        f = MOD_BASE + off
        h = helper_facts(exe, f)
        h.pop("_ins")
        h["module_base"] = "0x%X" % MOD_BASE
        h["mem"] = [mem_check(exe, d, lb, f, MOD_SEG, off, LOAD, HELPER_WINDOW) for lb, d, _, _ in dumps]
        h["window_sha"] = _sha(h.pop("window"))[:16]
        helpers[name] = h
    near = {}
    for name, f in NEAR_CALLEES.items():
        h = helper_facts(exe, f)
        h.pop("_ins")
        h["window_sha"] = _sha(h.pop("window"))[:16]
        # A near target is file-contiguous with the body: its offset in the body's segment is the body offset
        # plus the file distance. The live segment is the raw 0x0802 plus the load.
        seg_off = BODY_OFF + (f - BODY_FILE)
        h["near_offset_in_body_segment"] = "0x%X" % seg_off
        h["mem"] = [mem_check(exe, d, lb, f, LOADER_RAW_SEG, seg_off, LOAD, HELPER_WINDOW) for lb, d, _, _ in dumps]
        near[name] = h

    rle_checks = {"cmp_bytes": {"0x%X" % o: exe[o:o + 3] == v for o, v in RLE_CMP_OFFS.items()}}
    rle_checks["decoder_es_stores"] = near["rle_decode_8566"]["es_stores"]
    rle_checks["decoder_calls"] = near["rle_decode_8566"]["far_calls"]

    archives, cross = [], {}
    all_ids: list[int] = []
    rle_mismatch, rle_equal, rle_undefined = [], 0, []
    for n in GEO_ARCHIVES:
        path = pm.resolve_geo(install, n)
        data = path.read_bytes()
        entries, base = pm.parse_dax(data)
        recs = []
        for e in entries:
            comp = data[base + e.data_offset:base + e.data_offset + e.comp_size]
            rec = {"id": e.block_id, "offset": e.data_offset, "raw": e.raw_size, "comp": e.comp_size,
                   "status_gate_holds": e.raw_size == GEO_RAW_GATE, "comp_under_clamp": e.comp_size <= TOC_CLAMP}
            recs.append(rec)
            all_ids.append(e.block_id)
            try:
                want = pm.rle_decode(comp, e.raw_size)
                try:
                    got = rle_body_rule(comp)
                    if got == want:
                        rle_equal += 1
                    else:
                        rle_mismatch.append("GEO%d id %d" % (n, e.block_id))
                except ValueError as exc:
                    rle_undefined.append("GEO%d id %d: %s" % (n, e.block_id, exc))
            except pm.PorMapError as exc:
                rle_mismatch.append("GEO%d id %d (por_map): %s" % (n, e.block_id, exc))
            cross.setdefault(e.block_id, []).append("GEO%d" % n)
        archives.append({"archive": "GEO%d.DAX" % n, "sha256_prefix": _sha(data)[:16], "size": len(data),
                         "toc_entries": len(entries), "records": recs,
                         "status_gate_all": all(r["status_gate_holds"] for r in recs)})
    comps = [r["comp"] for a in archives for r in a["records"]]
    toc = {"archives": archives, "ids_total": len(all_ids), "ids_distinct": len(set(all_ids)),
           "comp_max": max(comps), "comp_all_under_clamp": all(c <= TOC_CLAMP for c in comps),
           "id_archive_lookup": {str(k): v for k, v in sorted(cross.items())}}
    rle_summary = {"blocks": len(all_ids), "equal_to_por_map": rle_equal, "mismatch": rle_mismatch,
                   "undefined_control_hits": rle_undefined}

    body_stores = census["stores"]
    expected_set = list(EXPECTED_STORES)
    got_set = [(int(s["at"], 16), s["pointer_var_bp"], s["field_disp"], s["reg"]) for s in body_stores]
    out_stores = [s for s in body_stores if s["pointer_var_bp"] == 6]
    null_paths = {s["at"]: s["provenance"]["kind"] for s in out_stores}

    overall = {
        "status": "archive-and-id-not-established",
        "blocker": "the archive name, the requested id and the TOC seek are not fixed by the bytes read here",
        "geo_output": "not_established", "plane2_binding": "not claimed", "playable": False,
        "output_far_pointer_paths": null_paths,
        "non_null_path_gated_on": "the TOC id byte equal to the requested id, after the body's DOS read wrapper",
    }
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status_scope": STATUS_SCOPE, "tool": TOOL,
        "playable": False,
        "question": "What does the loader body write to its output far pointer, and what fixes the output?",
        "pins": pins,
        "target_identity": {"file_offset": "0x%X" % BODY_FILE, "verdict": ident["verdict"], "conditional": True},
        "dumps": [{"label": lb, "size": sz, "sha256_prefix": sh} for lb, _, sz, sh in dumps],
        "body": {"file": "0x%X" % BODY_FILE, "decode_error": err, "instructions": len(ins),
                 "stores": body_stores, "escapes": census["escapes"],
                 "expected_store_set_matches": sorted(expected_set) == sorted(got_set),
                 "unexpected_stores": [x for x in got_set if x not in expected_set],
                 "missing_stores": [x for x in expected_set if x not in got_set]},
        "gates": gates,
        "reads": body_reads,
        "read_order_fits_toc": _read_order_fits(body_reads),
        "literals": literal_census(exe, ins, dumps),
        "seeks": seeks,
        "alloc_calls": alloc_calls,
        "helpers": helpers,
        "near_callees": near,
        "rle_rule": rle_checks,
        "rle_cross_check": rle_summary,
        "toc": toc,
        "verdict": overall,
        "not_established": NOT_ESTABLISHED,
        "next_discriminating_observations": DISCRIMINATORS,
    }


# ---- report ---------------------------------------------------------------------------------

def render_report(doc: dict) -> str:
    v = doc["verdict"]
    b = doc["body"]
    lines = [
        "# Pool of Radiance: the loader body's output far pointer (observe-only)", "",
        "**Status: %s. `playable: false`. `geo_output: %s`. `plane2_binding: %s`.**" % (
            v["status"], v["geo_output"], v["plane2_binding"]), "",
        "Blocker: %s" % v["blocker"], "",
        "## Target identity (conditional)", "",
        "- body file `%s`, verdict `%s`" % (b["file"], doc["target_identity"]["verdict"]), "",
        "## Output far pointer (the body's `[bp+6]` variable)", "",
        "| Store | Pointer var | Field | Reg | Provenance |", "| --- | --- | --- | --- | --- |",
    ]
    for s in b["stores"]:
        p = s["provenance"]
        prov = p["kind"] + ((" " + p["target"]) if p.get("target") else "")
        lines.append("| %s | bp%+d | +%d | %s | %s |" % (s["at"], s["pointer_var_bp"], s["field_disp"], s["reg"], prov))
    lines += ["", "- store census equals the expected set: %s" % b["expected_store_set_matches"], "",
              "## Pointer escapes", ""]
    for e in b["escapes"]:
        lines.append("- %s: pointer var bp%+d passed to %s" % (e["at"], e["pointer_var_bp"], e["callee"]))
    lines += ["", "## Gates", ""]
    for k, g in doc["gates"].items():
        lines.append("- %s: %s" % (k, g))
    lines += ["", "## DOS read calls in the body (args: handle, destination, count, result)", ""]
    for r in doc["reads"]:
        lines.append("- %s: %s" % (r["at"], r["args"]))
    lines += ["", "- read order (id 1, offset 4, status 2, comp 2) fits: %s" % doc["read_order_fits_toc"]["all_hold"],
              "", "## Literals the body passes as far pointers", ""]
    for x in doc["literals"]:
        if x["seg"] == "cs":
            mem = ", ".join("%s: %s" % (m["dump"].split("/")[0], m.get("agrees_with_file_at_mapped_offset"))
                            for m in x["memory"])
            lines.append("- %s (%s): CS:0x%s, file %s, Pascal %r (length %s); memory agrees: %s" % (
                x["at"], x["path"], x["imm"][2:], x["file_offset"], x.get("pascal_text"), x.get("pascal_length"), mem))
        else:
            lines.append("- %s (%s): DS:%s, %s (DS is not established by these bytes)" % (
                x["at"], x["path"], x["imm"], x["state"]))
    lines += ["", "## Seek to the record (offset term)", ""]
    for s in doc["seeks"]:
        lines.append("- %s: offset term %s; AX before the add: %s" % (s["at"], s.get("offset_add", {}).get("operand"),
                                                                    s.get("offset_add", {}).get("ax_before_add")))
    lines += ["", "## Helpers (module base 0xAC76, placements in both dumps)", ""]
    for name, h in doc["helpers"].items():
        lines.append("- %s: far calls %s, INT 21h at %s, return %s, es-stores %s" % (
            name, h["far_calls"], h["int21_sites"], h["return"], h["es_stores"]))
        for m in h["mem"]:
            lines.append("  - mem: %s" % m)
    lines += ["", "## Near callees (body segment, memory-present)", ""]
    for name, h in doc["near_callees"].items():
        lines.append("- %s at %s: far calls %s, return %s" % (name, h["file"], h["far_calls"], h["return"]))
        for m in h["mem"]:
            lines.append("  - mem: %s" % m)
    r = doc["rle_cross_check"]
    lines += ["", "## Control rule (0x8566) against por_map.rle_decode", "",
              "- blocks %d, equal %d, mismatch %s, undefined hits %s" % (
                  r["blocks"], r["equal_to_por_map"], r["mismatch"], r["undefined_control_hits"]), ""]
    t = doc["toc"]
    lines += ["## TOC order (id, offset, status u16, comp u16) against the pinned archives", "",
              "| Archive | Entries | Status gate holds on all | SHA-256 (prefix) |", "| --- | ---: | --- | --- |"]
    for a in t["archives"]:
        lines.append("| %s | %d | %s | `%s` |" % (a["archive"], a["toc_entries"], a["status_gate_all"], a["sha256_prefix"]))
    lines += ["", "- ids total %d, distinct %d" % (t["ids_total"], t["ids_distinct"]), "",
              "## Not established", ""]
    lines += ["- " + x for x in doc["not_established"]]
    lines += ["", "## Next discriminating observations", ""]
    lines += ["%d. %s" % (i + 1, x) for i, x in enumerate(doc["next_discriminating_observations"])]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_loader_output_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_geo_loader_output_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only probe of the loader body's output far pointer.")
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
    except (Refusal, FileNotFoundError, pm.PorMapError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s (stores_match=%s, rle_equal=%d/%d, status=%s)" % (
        args.out, doc["body"]["expected_store_set_matches"], doc["rle_cross_check"]["equal_to_por_map"],
        doc["rle_cross_check"]["blocks"], doc["verdict"]["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
