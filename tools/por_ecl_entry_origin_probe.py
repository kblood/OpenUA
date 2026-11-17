#!/usr/bin/env python3
"""Pool of Radiance: what the pinned retail bytes establish about the ECL stream origin (STATIC, DIAGNOSTIC).

STATUS: static-probe-only. ``playable: false``. No events, mappings or module output.

Question. ``tools/por_ecl_native_stream_probe.py`` walks an ECL block from block offset 22 and labels
that origin as inherited from ``tools/por_ecl.py`` (``ECL_HEADER_LEN``). This probe asks what the pinned
retail ``GAME.OVR`` and ``START.EXE`` bytes establish instead, by following PoR's own code:

1. the far pointer slot ``DS:[0x49DE]:[0x49E0]`` read by the key load (classifier entry ``GAME.OVR:0x9379``, key load at ``0x937C``): every
   direct access to it, and the allocation that produces its value (``0x0E600``);
2. the initial stream cursor ``DS:[0x49ED]``: the literal stores, and the routine (``0x7689``) whose
   first parser call runs straight after the literal store;
3. the loader (``0x7814``): zero fill of the buffer, then a copy of ``len - 2`` bytes from ``record + 2``;
4. the operand parser (``0x74D3``): five class-1 calls, each consuming a tag-1 record of four bytes
   (leader, tag, value, extra), whose values are decoded (``0x7B82``) into the entry slots
   ``DS:[0x49E3..0x49EB]`` that the VM step (``0x3EB7``) is later called with;
5. a retail check (read-only): for every ECL block in the install, the five records parsed from the
   literal cursor must equal the vaddrs in the block's header table, and the parse must end at the
   vaddr of block byte 22 under the model below.

No GoldBox ECL framing is used. The DAX container (TOC and signed-byte RLE) comes from
``tools/por_ecl.py`` through ``parse_dax`` and ``rle_decode`` only. The header layout, ``ECL_HEADER_LEN``
and ``parse_header`` are not read. The cursor literal, the fetch displacement and the loader's copy skip
are read from the pinned bytes; the record size (four bytes) is the sum of the cursor steps on the tag-1/2/3
path, checked against those bytes. Each is checked against its expected instruction sequence; a mismatch is a
named failed check, never a silent default.

Model (the only one the checks support):

* fetch of vaddr ``v``: the buffer index is ``(v + DISP) & 0xFFFF`` from the pointer slot (``DISP``
  is the ``es mov [di+disp16]`` displacement, read from the bytes);
* loader: buffer index ``k`` holds block byte ``k + SKIP`` (``SKIP`` read from the ``add di,imm``
  before the copy call);
* parse: record ``k`` (``k = 0..4``) starts at cursor ``CURSOR0 + 4k``; its tag, value and extra are
  the bytes at cursor+1, +2, +3, and its value word is ``(extra << 8) | value``.

What the probe can and cannot settle is reported in ``verdict`` and ``not_established``. In short: the
vaddr origin ``0x9914`` follows from PoR's own bytes; block byte 22 follows only if the loader's source
record is the block from byte 0 and its copy is a byte copy, and two of those links (the record source at
``0x0802:0x0716`` and the copy call at ``0x0AF8:0x1685``) cannot be resolved statically here.

Refusals (exit 2, named): a missing or unpinned ``GAME.OVR``/``START.EXE``, output inside the install,
output outside ``data/work/`` (CLI only). Exit 1: a byte check or the retail consistency check failed.
Exit 0: every byte check and the retail consistency check pass, and the report is written.

Usage::

    python tools/por_ecl_entry_origin_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-ecl-entry-origin-probe/retail

Stdlib + the read-only decoder ``tools/por_loadpieces_handler.py`` and the DAX container in
``tools/por_ecl.py``. Neither is edited.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"

sys.path.insert(0, str(TOOLS_DIR))
import por_loadpieces_handler as h  # noqa: E402  (read-only x86 decoder; not edited)
import por_ecl as ecl  # noqa: E402  (read-only: DAX TOC and signed-byte RLE container only)

SCHEMA = "openua.por-ecl-entry-origin-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_ecl_entry_origin_probe.py"
RESULT_JSON = "por_ecl_entry_origin_probe.json"
RESULT_MD = "por_ecl_entry_origin_probe.md"

PINS = {
    "GAME.OVR": (206105, "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"),
    "START.EXE": (65231, "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"),
}

# GAME.OVR file offsets (locations of the instructions the checks name; each is also verified by bytes)
CLASSIFIER_ENTRY = 0x9379      # classifier prologue (55 89 e5); its key load follows at 0x937C
KEY_LOAD = 0x937C              # a1 ed 49 ... : key load, reads the opcode through [0x49DE] at [0x49ED]
VM_KEY_LOAD = 0x3ED9           # the same fetch inside the VM step (0x3EB7), before its call to the classifier
ALLOC_CALL = 0x0E63B           # call 0x0AF8:0x023F with AX = 0x1E00 pushed (allocator)
ALLOC_STORE = 0x0E640          # mov [0x49DE], ax  (offset of the block buffer)
ALLOC_STORE_SEG = 0x0E643      # mov [0x49E0], dx  (segment of the block buffer)
HEADER_ROUTINE = 0x7689        # resets the cursor, then five class-1 parser calls
HEADER_CURSOR_STORE = 0x76C8   # mov [0x49ED], 0x9900
HEADER_ROUTINE_END = 0x7814    # next routine (the loader)
PARSER = 0x74D3                # operand parser (class count at [bp+6])
PARSER_EXIT = 0x75FF           # inc [0x49ED] ; mov sp,bp ; pop bp ; retf 2
VALUE_DECODE = 0x7B82          # ((byte [bp+6]) << 8) | (byte [bp+8])
LOADER = 0x7814                # zero fill, record read, record copy from record+2
LOADER_ZERO = 0x781B           # les di,[0x49DE] ; push es ; push di ; mov ax,0x1e00 ; ...
LOADER_COPY = 0x78B1           # les di,[bp-12] ; add di,imm ; ... ; call 0x0AF8:0x1685
VM_STEP = 0x3EB7               # called with a vaddr pushed from an entry slot

CURSOR = 0x49ED                # stream cursor cell (word)
PTR_OFF = 0x49DE               # far pointer to the block: offset word (segment at 0x49E0)
PTR_SEG = 0x49E0
ENTRY_SLOTS = (0x49E3, 0x49E5, 0x49E7, 0x49E9, 0x49EB)   # written by the five value-decode stores
SLOT_SET = frozenset({PTR_OFF, PTR_SEG, CURSOR, *ENTRY_SLOTS})
ALLOC_SIZE = 0x1E00            # pushed before the allocator call that yields the block buffer
RECORD_COUNT = 5               # records in the header table (class-1 parser calls in 0x7689)
RECORD_BYTES_TAG123 = 4        # leader + tag + value + extra, from the tag-1/2/3 path (verified below)

# Byte sequences the checks compare against (spaces are ignored). Each is a PoR instruction run, read
# from the pinned GAME.OVR; the decoded text of each run is what the report prints.
ALLOC_ARGS = "b8001e50 9a3f02f80a a3de49 8916e049"          # at 0x0E637: mov ax,0x1e00; push; call; stores
KEY_LOAD_BYTES = "a1ed49 c43ede49 03f8 268a8500 67 a27f6f"   # at 0x937C (and 0x3ED9): key load via [0x49DE]
LOADER_ZERO_BYTES = "c43ede49 06 57 b8001e 50 b000 50 9aa816f80a"   # at 0x781B: zero fill 0x1E00
LOADER_COPY_BYTES = "c47ef4 81c7 0200 06 57 c43ede49 06 57 8b46f8 48 48 50 9a8516f80a"  # at 0x78B1
LOADER_GUARD_BYTES = "837ef802 72 81"                        # at 0x78AB: cmp [bp-8],2 ; jb
RECORD_READ_BYTES = "9a16070208"                             # call 0x0802:0x0716 (the record source)
TAG123_PATH_BYTES = "3c01 7408 3c02 7404 3c03 7520 ff06ed49 a1ed49"   # at 0x753D: tag 1/2/3 path
TAG123_STORE_BYTES = "a1ed49 4040 a3ed49"                    # at 0x752A: cursor := cursor+2 (stored)
PARSER_EXIT_BYTES = "ff06ed49 89ec 5d ca0200"                # at 0x75FF: inc cursor ; mov sp,bp ; pop bp ; retf 2
PARSER_CLASS_BYTES = "8a4606 8846f9 b001 3a46f9"             # at 0x74DD: class arg ; loop bound
VALUE_BODY_BYTES = "8a4608 30e4 8bd0 8a4606 30e4 b108 d3e0 03c2"    # at 0x7B88: (extra<<8)|value
VALUE_PUSH_BYTES = "a08670 50 a04670 50 0e"                  # value pushed, then extra, then push cs


class ProbeRefusal(Exception):
    """A named refusal: the probe does not run on this input."""


# ---------------------------------------------------------------------------------------------
# Byte helpers (every constant the model uses comes through here, from the bytes)
# ---------------------------------------------------------------------------------------------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int], width: int = 4) -> Optional[str]:
    return None if v is None else ("0x%0*X" % (width, v))


def _dumps(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def u16(data: bytes, off: int) -> int:
    return data[off] | (data[off + 1] << 8)


def hexseq(spec: str) -> bytes:
    return bytes.fromhex(spec.replace(" ", ""))


def seq_at(data: bytes, off: int, spec: str) -> bool:
    want = hexseq(spec)
    return 0 <= off and off + len(want) <= len(data) and data[off:off + len(want)] == want


def find_all(data: bytes, pattern: bytes, lo: int = 0, hi: Optional[int] = None) -> list:
    hi = len(data) if hi is None else hi
    out, i = [], data.find(pattern, lo)
    while i != -1 and i < hi:
        out.append(i)
        i = data.find(pattern, i + 1)
    return out


def decode_window(data: bytes, start: int, end: int) -> list:
    """Linear decode from ``start`` while the next instruction begins before ``end``."""
    out, p = [], start
    while p < end:
        ins = h.decode(data, p)
        out.append(ins)
        p = ins.end
    return out


def site(ins) -> dict:
    return {"off": _hex(ins.off, 5), "raw": ins.raw.hex(), "text": ins.text(), "flow": ins.flow}


# ---------------------------------------------------------------------------------------------
# Direct accesses to the cells the model depends on
# ---------------------------------------------------------------------------------------------

_ARITH = {0: "add", 1: "or", 2: "adc", 3: "sbb", 4: "and", 5: "sub", 6: "xor", 7: "cmp"}


def access_kind(ins) -> str:
    """Classify an instruction that names a DS-direct cell (direction and width from the opcode)."""
    op = ins.op
    reg = ins.modrm[1] if ins.modrm else None
    if op == 0xA1:
        return "load"
    if op == 0xA3:
        return "store"
    if op == 0xC4:
        return "les"
    if op in (0x88, 0x89):
        return "store"
    if op in (0x8A, 0x8B):
        return "load"
    if op in (0xC6, 0xC7) and reg == 0:
        return "store-imm"
    if op == 0xFF:
        return {0: "inc", 1: "dec", 6: "push"}.get(reg, "ff/%s" % reg)
    if op == 0xFE:
        return {0: "inc8", 1: "dec8"}.get(reg, "fe/%s" % reg)
    if op in (0x80, 0x81, 0x83):
        return "cmp" if reg == 7 else "rmw-%s" % _ARITH.get(reg, "?")
    if op in (0x38, 0x39, 0x3A, 0x3B):
        return "cmp"
    if op in (0x84, 0x85):
        return "test"
    return "other-%02x" % op


def cell_refs(data: bytes, cells: frozenset = SLOT_SET) -> list:
    """Every decoded instruction whose DS-direct operand is one of ``cells`` (byte scan, decode-checked)."""
    found, seen = [], set()
    n = len(data)
    for i in range(n - 2):
        b = data[i]
        if b & 0xC7 == 0x06:                       # ModRM mod=00 rm=110: disp16 follows
            disp = u16(data, i + 1)
            if disp in cells:
                start_candidates = range(max(0, i - 3), i)
                _accept(data, i, disp, start_candidates, found, seen)
        elif b in (0xA1, 0xA3):                    # moffs16 form: opcode then disp16
            disp = u16(data, i + 1)
            if disp in cells:
                _accept(data, i, disp, [i], found, seen)
    found.sort(key=lambda r: r["ins"].off)
    return [{"cell": _hex(r["ins"].direct), "kind": r["kind"], "ins": r["ins"]} for r in found]


def _accept(data, i, disp, starts, found, seen):
    for s in starts:
        try:
            ins = h.decode(data, s)
        except Exception:
            continue
        if ins.off == s and ins.end > i + 1 and ins.direct == disp and s not in seen:
            seen.add(s)
            found.append({"ins": ins, "kind": access_kind(ins)})
            return


def accesses_in(refs: list, lo: int, hi: int, cell: Optional[int] = None, kinds=None) -> list:
    out = []
    for r in refs:
        ins = r["ins"]
        if not (lo <= ins.off < hi):
            continue
        if cell is not None and r["cell"] != _hex(cell):
            continue
        if kinds is not None and r["kind"] not in kinds:
            continue
        out.append(r)
    return out


def near_calls_to(data: bytes, target: int, lo: int, hi: int) -> list:
    out = []
    for i in range(lo, min(hi, len(data) - 2)):
        if data[i] == 0xE8:
            rel = int.from_bytes(data[i + 1:i + 3], "little", signed=True)
            if (i + 3 + rel) == target:
                out.append(i)
    return out


# ---------------------------------------------------------------------------------------------
# Byte checks: each returns a dict {ok, facts, sites}. Facts carry values read from the bytes.
# ---------------------------------------------------------------------------------------------

def check_pointer_slot(data: bytes, refs: list) -> dict:
    """[0x49DE]:[0x49E0] is stored once, by the allocator's result, and read only through les."""
    st_off = accesses_in(refs, 0, len(data), PTR_OFF, {"store", "store-imm"})
    st_seg = accesses_in(refs, 0, len(data), PTR_SEG, {"store", "store-imm"})
    les_off = accesses_in(refs, 0, len(data), PTR_OFF, {"les"})
    push_off = accesses_in(refs, 0, len(data), PTR_OFF, {"push"})
    ok = ([r["ins"].off for r in st_off] == [ALLOC_STORE] and
          [r["ins"].off for r in st_seg] == [ALLOC_STORE_SEG] and not push_off)
    alloc_ok = seq_at(data, 0x0E637, ALLOC_ARGS)
    return {
        "ok": ok and alloc_ok,
        "facts": {
            "direct_stores_offset": [_hex(r["ins"].off, 5) for r in st_off],
            "direct_stores_segment": [_hex(r["ins"].off, 5) for r in st_seg],
            "les_loads": [_hex(r["ins"].off, 5) for r in les_off],
            "direct_pushes": [_hex(r["ins"].off, 5) for r in push_off],
            "alloc_sequence_bytes": alloc_ok,
            "alloc_size_pushed": _hex(ALLOC_SIZE),
        },
        "sites": [site(r["ins"]) for r in st_off + st_seg + les_off],
    }


def check_cursor_literals(data: bytes) -> dict:
    """Literal stores of the cursor cell ``c7 06 ed 49 imm16``."""
    pat = bytes.fromhex("c706ed49")
    hits = []
    for i in find_all(data, pat):
        if data[i:i + 4] == pat:
            hits.append({"off": _hex(i, 5), "value": _hex(u16(data, i + 4)), "raw": data[i:i + 6].hex()})
    values = sorted({u16(data, int(x["off"], 16) + 4) for x in hits})
    sites = [x["off"] for x in hits]
    ok = (sites == ["0x076C8", "0x0E993"] and values == [0x9900])
    return {"ok": ok, "facts": {"sites": hits, "values": [_hex(v) for v in values]},
            "sites": [{"off": x["off"], "raw": x["raw"], "text": "mov [0x49ed], %s" % x["value"]} for x in hits]}


def check_header_routine(data: bytes, refs: list) -> dict:
    """Routine 0x7689: the only cursor access in [0x7689, 0x7814) is the literal store; no branch between
    the store and the first parser call; five class-1 parser calls, each with ``push 1`` before it."""
    cur = accesses_in(refs, HEADER_ROUTINE, HEADER_ROUTINE_END, CURSOR)
    cur_offs = [r["ins"].off for r in cur]
    win = decode_window(data, HEADER_CURSOR_STORE, 0x7724)
    branches = [_hex(i.off, 5) for i in win if i.flow in ("jcc", "jmp", "ret", "retf", "jmp_far")]
    calls_between = [_hex(i.off, 5) for i in win if i.flow in ("call", "call_far")]
    parse_calls = near_calls_to(data, PARSER, HEADER_ROUTINE, HEADER_ROUTINE_END)
    class_args = [seq_at(data, c - 4, "b001500e") for c in parse_calls]
    ok = (cur_offs == [HEADER_CURSOR_STORE] and not branches and len(parse_calls) == RECORD_COUNT
          and all(class_args))
    return {
        "ok": ok,
        "facts": {
            "cursor_reads_in_routine": sum(1 for r in cur if r["kind"] == "load"),
            "cursor_accesses": [_hex(x, 5) for x in cur_offs],
            "branches_between_store_and_first_parse": branches,
            "calls_between_store_and_first_parse": calls_between,
            "parser_call_sites": [_hex(c, 5) for c in parse_calls],
            "class_pushed_all_one": all(class_args),
        },
        "sites": [site(i) for i in win[:6]] + [{"off": _hex(c, 5), "raw": data[c:c + 3].hex(),
                                                 "text": "call 0x074d3 (class 1 pushed)"} for c in parse_calls],
    }


def check_parser(data: bytes, refs: list) -> dict:
    """The operand parser: class arg, tag-1/2/3 path (cursor := c+2 at 0x752F, inc at 0x7549, exit inc
    at 0x75FF, so a record advances the cursor by 4), and the three stream fetches (tag, value, extra)."""
    body_les = accesses_in(refs, PARSER, PARSER_EXIT + 1, PTR_OFF, {"les"})
    body_cur = accesses_in(refs, PARSER, PARSER_EXIT + 1, CURSOR)
    reads = []
    for off in find_all(data, bytes.fromhex("268a95"), PARSER, PARSER_EXIT + 1):
        reads.append({"off": _hex(off, 5), "disp": _hex(u16(data, off + 3))})
    tag_path = seq_at(data, 0x753D, TAG123_PATH_BYTES)
    store_ok = seq_at(data, 0x752A, TAG123_STORE_BYTES)
    exit_ok = seq_at(data, PARSER_EXIT, PARSER_EXIT_BYTES)
    class_ok = seq_at(data, 0x74DD, PARSER_CLASS_BYTES)
    fetch_disps = sorted({r["disp"] for r in reads})
    # four stream fetches: tag 0x74FF, value 0x751A, extra 0x7556 (tag 1/2/3 path) and 0x75BA (other path)
    ok = (tag_path and store_ok and exit_ok and class_ok and len(reads) == 4
          and fetch_disps == ["0x6700"]
          and [r["ins"].off for r in body_les] == [0x74F9, 0x7514, 0x7550, 0x75B4]
          and all(r["cell"] == _hex(PTR_OFF) for r in body_les))
    return {
        "ok": ok,
        "facts": {
            "stream_fetch_displacements": fetch_disps,
            "stream_fetch_sites": reads,
            "far_pointer_loads_in_body": [_hex(r["ins"].off, 5) for r in body_les],
            "cursor_accesses_in_body": [_hex(r["ins"].off, 5) for r in body_cur],
            "tag123_path_bytes_ok": tag_path,
            "tag123_store_bytes_ok": store_ok,
            "exit_inc_bytes_ok": exit_ok,
            "class_arg_bytes_ok": class_ok,
            "record_bytes_tag123": RECORD_BYTES_TAG123,
        },
        "sites": [site(r["ins"]) for r in body_les] + [{"off": _hex(PARSER_EXIT, 5), "raw": "ff06ed49",
                                                         "text": "inc [0x49ed] (exit)"}],
    }


def check_value_decode(data: bytes, refs: list) -> dict:
    """0x7B82 computes (extra << 8) | value; each of the five call sites pushes value then extra, and the
    result is stored into the next entry slot in order."""
    body_ok = seq_at(data, VALUE_DECODE + 6, VALUE_BODY_BYTES)
    calls = near_calls_to(data, VALUE_DECODE, HEADER_ROUTINE, HEADER_ROUTINE_END)
    pushes_ok = [seq_at(data, c - 9, VALUE_PUSH_BYTES) for c in calls]
    store_cells = []
    for c in calls:
        nxt = h.decode(data, c + 3)
        store_cells.append(nxt.direct if nxt.op == 0xA3 else None)
    ok = body_ok and len(calls) == RECORD_COUNT and all(pushes_ok) and store_cells == list(ENTRY_SLOTS)
    return {
        "ok": ok,
        "facts": {
            "value_formula_bytes_ok": body_ok,
            "value_decode_call_sites": [_hex(c, 5) for c in calls],
            "push_order_value_then_extra_ok": pushes_ok,
            "stored_into": [_hex(s) for s in store_cells],
        },
        "sites": [{"off": _hex(c, 5), "raw": data[c:c + 3].hex(), "text": "call 0x07b82"} for c in calls],
    }


def check_loader(data: bytes, refs: list) -> dict:
    """0x7814: zero fill of the block buffer; record read at 0x0802:0x0716; copy of len-2 bytes from
    record+2 into [0x49DE]. The copy skip is read from the ``add di,imm16`` before the copy call."""
    zero_ok = seq_at(data, LOADER_ZERO, LOADER_ZERO_BYTES)
    rec_read = find_all(data, bytes.fromhex(RECORD_READ_BYTES), LOADER, LOADER + 0x100)
    guard_ok = seq_at(data, 0x78AB, LOADER_GUARD_BYTES)
    copy_ok = seq_at(data, LOADER_COPY, LOADER_COPY_BYTES)
    skip = u16(data, LOADER_COPY + 5) if copy_ok else None
    ok = zero_ok and bool(rec_read) and guard_ok and copy_ok and skip is not None
    return {
        "ok": ok,
        "facts": {
            "zero_fill_bytes_ok": zero_ok,
            "record_read_call_sites": [_hex(x, 5) for x in rec_read],
            "length_guard_len_ge_2_ok": guard_ok,
            "copy_bytes_ok": copy_ok,
            "copy_skip_from_bytes": _hex(skip) if skip is not None else None,
            "copy_destination_cell": "0x49DE (les di,[0x49de] before the copy call)",
            "copy_count": "len - 2 (dec ax twice)",
        },
        "sites": [{"off": _hex(LOADER_ZERO, 5), "raw": data[LOADER_ZERO:LOADER_ZERO + 6].hex(),
                   "text": "les di,[0x49de] ; push es ; push di ; mov ax,0x1e00 ; push ax ; ..."},
                  {"off": _hex(LOADER_COPY, 5), "raw": data[LOADER_COPY:LOADER_COPY + 9].hex(),
                   "text": "les di,[bp-12] ; add di,%s ; push es ; push di ; les di,[0x49de] ; ... ; call 0x0af8:0x1685"
                   % (_hex(skip) if skip is not None else "?")}],
    }


def check_key_load_and_dispatch(data: bytes, refs: list) -> dict:
    """The key load reads ES:[DI+disp] with DI = [0x49DE] + [0x49ED]; the entry slots are pushed to the VM."""
    key_ok = seq_at(data, KEY_LOAD, KEY_LOAD_BYTES)
    key_disp = _hex(u16(data, KEY_LOAD + 12)) if key_ok else None   # disp16 of 'es mov al,[di+disp16]' at +12
    vm_key_ok = seq_at(data, VM_KEY_LOAD, KEY_LOAD_BYTES)
    vm_key_disp = _hex(u16(data, VM_KEY_LOAD + 12)) if vm_key_ok else None
    entry_ok = seq_at(data, CLASSIFIER_ENTRY, "55 89e5")
    dispatch = {}
    for slot in ENTRY_SLOTS:
        sites = []
        for off in find_all(data, bytes([0xFF, 0x36]) + slot.to_bytes(2, "little")):
            # push word [slot] ; push cs ; call near VM_STEP  (the call is 3 bytes, starting at off+5)
            if data[off + 4:off + 6] == b"\x0e\xe8":
                tgt = off + 8 + int.from_bytes(data[off + 6:off + 8], "little", signed=True)
                if tgt == VM_STEP:
                    sites.append(_hex(off, 5))
        dispatch[_hex(slot)] = sites
    ok = (entry_ok and key_ok and vm_key_ok and key_disp == "0x6700" and vm_key_disp == "0x6700"
          and all(dispatch[_hex(s)] for s in ENTRY_SLOTS))
    return {
        "ok": ok,
        "facts": {"classifier_entry_0x9379_bytes_ok": entry_ok,
                  "key_load_0x937C_bytes_ok": key_ok, "key_load_displacement": key_disp,
                  "vm_key_load_0x3ED9_bytes_ok": vm_key_ok, "vm_key_load_displacement": vm_key_disp,
                  "vm_step_callers_by_entry_slot": dispatch},
        "sites": [{"off": _hex(CLASSIFIER_ENTRY, 5), "raw": data[CLASSIFIER_ENTRY:CLASSIFIER_ENTRY + 3].hex(),
                   "text": "push bp ; mov bp,sp (classifier entry)"},
                  {"off": _hex(KEY_LOAD, 5), "raw": data[KEY_LOAD:KEY_LOAD + 17].hex(),
                   "text": "mov ax,[0x49ed] ; les di,[0x49de] ; add di,ax ; es mov al,[di+0x6700] ; mov [0x6f7f],al"},
                  {"off": _hex(VM_KEY_LOAD, 5), "raw": data[VM_KEY_LOAD:VM_KEY_LOAD + 17].hex(),
                   "text": "same fetch inside the VM step (0x3EB7)"}],
    }


def byte_checks(data: bytes) -> dict:
    """Every byte-level check on GAME.OVR, keyed by name. ``ok`` on each is a structural pass."""
    refs = cell_refs(data)
    return {
        "pointer_slot": check_pointer_slot(data, refs),
        "cursor_literals": check_cursor_literals(data),
        "header_routine_0x7689": check_header_routine(data, refs),
        "operand_parser_0x74D3": check_parser(data, refs),
        "value_decode_0x7B82": check_value_decode(data, refs),
        "loader_0x7814": check_loader(data, refs),
        "key_load_and_dispatch": check_key_load_and_dispatch(data, refs),
    }


MODEL_CHECKS = ("cursor_literals", "header_routine_0x7689", "operand_parser_0x74D3", "loader_0x7814")


def model_from_bytes(checks: dict) -> Optional[dict]:
    """Constants the retail check uses, read from the checks' bytes. None unless every check the model rests
    on passes: a partial sequence never yields a constant."""
    if not all(checks[k]["ok"] for k in MODEL_CHECKS):
        return None
    lits = checks["cursor_literals"]["facts"]["values"]
    disp = checks["operand_parser_0x74D3"]["facts"]["stream_fetch_displacements"]
    skip = checks["loader_0x7814"]["facts"]["copy_skip_from_bytes"]
    if not lits or len(lits) != 1 or len(disp) != 1 or skip is None:
        return None
    return {"cursor0": int(lits[0], 16), "disp": int(disp[0], 16), "skip": int(skip, 16),
            "record_bytes": RECORD_BYTES_TAG123}


# ---------------------------------------------------------------------------------------------
# Retail consistency: the model against every ECL block (read-only container)
# ---------------------------------------------------------------------------------------------

def buffer_index(v: int, disp: int) -> int:
    return (v + disp) & 0xFFFF


def parse_model(block: bytes, model: dict, skip: Optional[int] = None) -> dict:
    """Run the five class-1 parser records from the literal cursor under the model."""
    sk = model["skip"] if skip is None else skip

    def byte_at(v: int, off: int = 0) -> Optional[int]:
        k = buffer_index(v + off, model["disp"]) + sk
        return block[k] if 0 <= k < len(block) else None

    c = model["cursor0"]
    recs = []
    for _ in range(RECORD_COUNT):
        leader, tag = byte_at(c), byte_at(c, 1)
        val, ext = byte_at(c, 2), byte_at(c, 3)
        if None in (leader, tag, val, ext):
            return {"ok": False, "reason": "out-of-block", "records": recs, "end": c}
        if tag not in (1, 2, 3):
            return {"ok": False, "reason": "tag-not-closed-123: 0x%02x" % tag, "records": recs, "end": c}
        recs.append({"cursor": c, "leader": leader, "tag": tag, "value": val, "extra": ext,
                     "word": (ext << 8) | val})
        c = (c + model["record_bytes"]) & 0xFFFF
    return {"ok": True, "records": recs, "end": c}


def block_rows(dax_path: Path, model: dict, skip: Optional[int] = None) -> list:
    rows = []
    sk = model["skip"] if skip is None else skip
    origin = (model["cursor0"] + RECORD_COUNT * model["record_bytes"]) & 0xFFFF
    dax = dax_path.read_bytes()
    entries, base = ecl.parse_dax(dax)
    for en in entries:
        comp = dax[base + en.data_offset: base + en.data_offset + en.comp_size]
        blk = ecl.rle_decode(comp, en.raw_size)
        segs = [u16(blk, 2 + 4 * k) for k in range(RECORD_COUNT)]
        vaddrs = [u16(blk, 4 + 4 * k) for k in range(RECORD_COUNT)]
        res = parse_model(blk, model, skip)
        words = [r["word"] for r in res["records"]] if res["ok"] else []
        tags = [r["tag"] for r in res["records"]]
        in_block = all(0 <= buffer_index(v, model["disp"]) + sk < en.raw_size for v in vaddrs)
        rows.append({
            "file": dax_path.name, "block_id": en.block_id, "raw_size": en.raw_size,
            "magic": _hex(u16(blk, 0)),
            "header_segments": sorted({_hex(s) for s in segs}),
            "header_vaddrs": [_hex(v) for v in vaddrs],
            "parsed_words": [_hex(w) for w in words],
            "parsed_tags": tags,
            "parse_ok": res["ok"],
            "parse_end_vaddr": _hex(res["end"]),
            "record_match": bool(res["ok"] and words == vaddrs and all(t == 1 for t in tags)
                                 and all(s == 0x0101 for s in segs)),
            "slot0_is_origin": vaddrs[0] == origin,
            "entry_slots_at_or_after_origin": all(v >= origin for v in vaddrs),
            "origin_block_offset": buffer_index(origin, model["disp"]) + sk,
            "vaddrs_in_block": in_block,
        })
    return rows


def decoded_blocks(dax_paths: list) -> list:
    """(block bytes, header vaddrs) for every ECL member, through the read-only container."""
    out = []
    for p in dax_paths:
        dax = p.read_bytes()
        entries, base = ecl.parse_dax(dax)
        for en in entries:
            comp = dax[base + en.data_offset: base + en.data_offset + en.comp_size]
            blk = ecl.rle_decode(comp, en.raw_size)
            out.append((blk, [u16(blk, 4 + 4 * k) for k in range(RECORD_COUNT)]))
    return out


def skip_grid(dax_paths: list, model: dict, skips=range(-4, 5)) -> list:
    """Pass count per candidate copy skip, with the fetch displacement fixed at the byte-read value."""
    decoded = decoded_blocks(dax_paths)
    out = []
    for s in skips:
        passed = 0
        for blk, vaddrs in decoded:
            res = parse_model(blk, model, skip=s)
            if res["ok"] and [r["word"] for r in res["records"]] == vaddrs:
                passed += 1
        out.append({"skip": s, "skip_hex": _hex(s & 0xFFFF) if s >= 0 else "-0x%X" % -s, "passes": passed,
                    "of": len(decoded)})
    return out


# ---------------------------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------------------------

def verdict_for(checks: dict, model: Optional[dict], grid: list, blocks: list) -> dict:
    byte_ok = all(c["ok"] for c in checks.values())
    full = [g["skip"] for g in grid if blocks and g["passes"] == g["of"]] if grid else []
    skip_from_bytes = model["skip"] if model else None
    skip_pinned = bool(full) and full == [2] and skip_from_bytes == 2
    origin_vaddr = (model["cursor0"] + RECORD_COUNT * model["record_bytes"]) & 0xFFFF if model else None
    return {
        "origin_vaddr": _hex(origin_vaddr),
        "origin_vaddr_status": ("the end of PoR's five-record table parse, from the literal cursor 0x9900 and four "
                                "bytes per record (bytes). The routine never reads the cursor after the parses, and the "
                                "VM step loads its own vaddr from the slots, so 0x9914 is the end of the table, not an "
                                "entry PoR's code is shown to start from. Retail entry slots at or after it: %d of %d "
                                "blocks") % (sum(1 for b in blocks if b["entry_slots_at_or_after_origin"]), len(blocks))
            if byte_ok else "not-established",
        "origin_buffer_index": (buffer_index(origin_vaddr, model["disp"]) if model and origin_vaddr is not None else None),
        "origin_buffer_index_status": ("established-by-bytes: fetch displacement 0x6700 read from the parser and "
                                       "key-load bytes") if model else "not-established",
        "origin_block_offset": (buffer_index(origin_vaddr, model["disp"]) + skip_from_bytes
                                if model and origin_vaddr is not None else None),
        "origin_block_offset_status": (
            "conditional: copy skip %s read from the loader bytes is the only skip the 29-block parse accepts "
            "(grid pins the sum with the displacement); still conditional on the loader source record "
            "being the block from byte 0 (record source 0x0802:0x0716 unresolved) and on the copy call "
            "0x0AF8:0x1685 being a byte copy (not resolved)" % (_hex(skip_from_bytes) if skip_from_bytes is not None else "?")
            if skip_pinned else "not-established: the retail parse does not accept the byte-read skip"),
        "retail_blocks_matching": sum(1 for b in blocks if b["record_match"]),
        "retail_blocks_total": len(blocks),
        "retail_blocks_entry_slots_at_or_after_origin": sum(1 for b in blocks if b["entry_slots_at_or_after_origin"]),
        "retail_blocks_slot0_is_origin": sum(1 for b in blocks if b["slot0_is_origin"]),
        "established": False,
        "conditional": bool(skip_pinned and byte_ok),
        "label_suggestion": ("replace 'inherited from por_ecl.py' with 'PoR-derived: 2-byte loader copy skip plus "
                             "five 4-byte class-1 records; block-offset link conditional on the loader source'"),
    }


# ---------------------------------------------------------------------------------------------
# Pins, install, and orchestration
# ---------------------------------------------------------------------------------------------

def load_pinned(install: Path, allow_unpinned: bool = False) -> dict:
    out = {}
    for name, (size, sha) in PINS.items():
        path = install / name
        if not path.is_file():
            raise ProbeRefusal("missing install file: %s" % path)
        data = path.read_bytes()
        if (len(data) != size or _sha(data) != sha) and not allow_unpinned:
            raise ProbeRefusal("unpinned install file: %s (size %d, sha %s)" % (name, len(data), _sha(data)[:16]))
        out[name] = data
    return out


def validate_output_dir(install: Path, out: Path, cli: bool = False) -> Path:
    out = out.resolve()
    if out == install.resolve() or install.resolve() in out.parents:
        raise ProbeRefusal("output inside the install: %s" % out)
    if cli and DATA_WORK.resolve() not in out.parents and out != DATA_WORK.resolve():
        raise ProbeRefusal("output outside data/work/: %s" % out)
    return out


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    install = Path(install)
    files = load_pinned(install, allow_unpinned)
    validate_output_dir(install, Path(out), cli=False)
    before = {k: _sha(v) for k, v in files.items()}
    ovr = files["GAME.OVR"]
    checks = byte_checks(ovr)
    model = model_from_bytes(checks)
    dax_paths = sorted(install.glob("ECL*.DAX"), key=lambda p: int(p.stem[3:]) if p.stem[3:].isdigit() else 0)
    blocks, grid = [], []
    consistency = {"ran": False}
    if model and dax_paths:
        for p in dax_paths:
            blocks.extend(block_rows(p, model))
        grid = skip_grid(dax_paths, model)
        consistency = {"ran": True, "blocks": len(blocks), "all_match": all(b["record_match"] for b in blocks)}
    after = {k: _sha(v) for k, v in files.items()}
    byte_ok = all(c["ok"] for c in checks.values())
    self_checks = {
        "inputs_unchanged": before == after,
        "byte_checks_pass": byte_ok,
        "model_read_from_bytes": model is not None,
        "retail_blocks_ran": consistency["ran"],
        "retail_all_blocks_match": bool(consistency.get("all_match")),
        "copy_skip_pinned_by_retail": bool(grid) and [g["skip"] for g in grid if g["passes"] == g["of"]] == [2],
    }
    verdict = verdict_for(checks, model, grid, blocks)
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS, "playable": False,
        "tool": TOOL,
        "pins": {k: {"size": len(v), "sha256": _sha(v)} for k, v in files.items()},
        "model": {k: _hex(v) if isinstance(v, int) else v for k, v in (model or {}).items()},
        "checks": {k: {"ok": v["ok"], "facts": v["facts"], "sites": v["sites"]} for k, v in checks.items()},
        "skip_grid": grid,
        "blocks": blocks,
        "verdict": verdict,
        "self_checks": self_checks,
        "not_established": [
            "the record source R that the loader reads: 0x0AF8:0x0716 via 0x0802 (the record read at 0x78A6) is not resolved",
            "whether the copy call 0x0AF8:0x1685 is a byte copy or a transform (its body is not located; its "
            "arguments are (R+2, [0x49DE], len-2))",
            "the zero fill 0x0AF8:0x16A8 is inferred from its pushes (dest, 0x1E00, 0), not from its body",
            "the allocator 0x0AF8:0x023F: its return in AX:DX is assumed (the caller stores AX and DX to the cell)",
            "reachability: no GAME.OVR near call reaches 0x0E600, 0x7689 or 0x7814; the far or INT 3Fh entry is not traced",
            "the cursor effect of the far callees in 0x7689 (0x0AF8:0x16A8 at 0x76EF) on DS:[0x49ED] is assumed nil",
            "the meaning of any operand value or of the second cursor-literal site 0x0E993 (its consumer is not located)",
            "that the header's five entry slots are the only entry points used by the event loop",
        ],
        "assumptions": [
            "the stream buffer is the block buffer whose pointer is [0x49DE]:[0x49E0] (checked by the key-load and parser accesses)",
            "the record read at R returns the decoded block bytes from byte 0 (the copy skip in the model is 2)",
            "a far callee does not write DS:[0x49ED] between the literal store and the first parser call",
        ],
        "not_claimed": "no GoldBox framing, no opcode meaning, no module, no event, no playable path",
    }
    return doc, (0 if all(self_checks.values()) else 1)


def render_report(doc: dict) -> str:
    lines = ["# Pool of Radiance ECL entry origin probe", "",
             "**Status: static-probe-only. `playable: false`.** Tool: `%s`." % doc["tool"], "",
             "## Verdict", ""]
    v = doc["verdict"]
    for k in ("origin_vaddr", "origin_vaddr_status", "origin_buffer_index", "origin_buffer_index_status",
              "origin_block_offset", "origin_block_offset_status", "retail_blocks_matching", "retail_blocks_total",
              "established", "conditional"):
        lines.append("- **%s**: %s" % (k, v.get(k)))
    lines += ["", "## Model (read from the bytes)", ""]
    for k, val in doc["model"].items():
        lines.append("- %s: %s" % (k, val))
    lines += ["", "## Byte checks", "", "| check | ok | key facts |", "| --- | --- | --- |"]
    for name, c in doc["checks"].items():
        facts = "; ".join("%s=%s" % (k, v) for k, v in c["facts"].items() if not isinstance(v, (dict, list)))
        lines.append("| %s | %s | %s |" % (name, c["ok"], facts))
    lines += ["", "## Decoded call and access sites", ""]
    for name, c in doc["checks"].items():
        lines.append("### %s" % name)
        for s in c["sites"]:
            if "text" in s:
                lines.append("- `%s` `%s` %s" % (s.get("off"), s.get("raw", ""), s.get("text")))
        lines.append("")
    lines += ["## Copy-skip grid (fetch displacement fixed at the byte-read value)", "",
              "| skip | passes | of |", "| --- | --- | --- |"]
    for g in doc["skip_grid"]:
        lines.append("| %s | %d | %d |" % (g["skip_hex"], g["passes"], g["of"]))
    lines += ["", "## Retail blocks", "", "| file | id | raw | header vaddrs | parsed words | match | origin block offset |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for b in doc["blocks"]:
        lines.append("| %s | %d | %d | %s | %s | %s | %s |" % (
            b["file"], b["block_id"], b["raw_size"], " ".join(b["header_vaddrs"]),
            " ".join(b["parsed_words"]) if b["parsed_words"] else "-", b["record_match"], b["origin_block_offset"]))
    lines += ["", "## Not established", ""]
    lines += ["- %s" % x for x in doc["not_established"]]
    lines += ["", "## Assumptions", ""]
    lines += ["- %s" % x for x in doc["assumptions"]]
    lines += ["", "## Self checks", ""]
    for k, val in doc["self_checks"].items():
        lines.append("- %s: %s" % (k, val))
    lines += ["", "Reproduce:", "", "```sh",
              "python tools/por_ecl_entry_origin_probe.py --install \"PATH/TO/POOLRAD\" -o data/work/por-ecl-entry-origin-probe/retail",
              "```", ""]
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(_dumps(doc), encoding="utf-8")
    (out / RESULT_MD).write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Pool of Radiance ECL entry origin probe (read-only, static).")
    ap.add_argument("--install", required=True, help="POOLRAD folder (GAME.OVR, START.EXE and ECL*.DAX, pinned)")
    ap.add_argument("-o", "--out", required=True, help="output folder (under data/work/)")
    ap.add_argument("--allow-unpinned", action="store_true", help="accept unpinned files; the report is not evidence")
    args = ap.parse_args(argv)
    try:
        out = validate_output_dir(Path(args.install), Path(args.out), cli=True)
        doc, rc = probe(Path(args.install), out, args.allow_unpinned)
    except ProbeRefusal as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, out)
    print("wrote %s and %s" % (RESULT_JSON, RESULT_MD))
    print("byte checks: %s" % {k: v["ok"] for k, v in doc["checks"].items()})
    print("retail blocks matching: %d of %d" % (doc["verdict"]["retail_blocks_matching"], doc["verdict"]["retail_blocks_total"]))
    print("origin: vaddr %s, buffer index %s, block offset %s (%s)" % (
        doc["verdict"]["origin_vaddr"], doc["verdict"]["origin_buffer_index"],
        doc["verdict"]["origin_block_offset"], "conditional" if doc["verdict"]["conditional"] else "not established"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
