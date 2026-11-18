#!/usr/bin/env python3
"""Pool of Radiance ECL decoder, slice 3: read-only, decode-only.

Status: DECODE ONLY. This tool reads one ECL block from an explicit PoR DAX
(``ECL<n>.DAX``), validates the DAX container, decompresses the block, checks
the 22-byte ECL header and walks the instruction stream from the header end.
It does not map anything to FRUA events and does not produce a module. Every
output says so (``"playable": false``).

Evidence basis (read the doc before trusting a field):
  * DAX container and signed-byte RLE: GoldBox ``docs/dax-format.md`` (sections
    1 and 2). Validated on the local retail ``ECL2.DAX`` (see
    ``docs/por-ecl-decoder.md``).
  * Opcode table (wordSet and mnemonics): GoldBox
    ``docs/engine/research/ecl-krynn-gen1-opcodes.md`` section 2, as recovered
    from the COAB dumper's table. Reproduced here as data, not as code.
  * Operand framing (2 or 3 bytes; code 0x80 inline string; count-driven
    ON_GOTO/ON_GOSUB): ``docs/engine/research/ecl-krynn-gen1-opcodes.md`` 3.4 and
    ``docs/engine/research/ecl-opcode-spec-for-asm.md`` 2.2-2.4.
  * The two menu opcodes (0x15 VERTICAL_MENU, 0x2B HORIZONTAL_MENU) are framed
    differently by the two GoldBox sources. The default ``conservative`` mode
    stops at them and keeps the rest of the block as raw bytes. The
    ``spec-menus`` mode uses the count-driven framing of the second source; its
    coverage is a census result, not proof, and its output says so.

What it does
  * Opens the DAX read-only (``"rb"``); never writes under the source.
  * Walks the instruction stream from byte 22. Each decoded instruction keeps its
    offset, raw numeric operands and the source-table name. An unknown opcode,
    an ambiguous framing, a truncated operand or a count that is not a literal
    stops the walk; the remaining bytes are kept as raw numeric data and marked
    unsupported. It never guesses a length.
  * Lists control-flow edges (GOTO, GOSUB, ON_GOTO, ON_GOSUB) with their raw
    vaddr targets. Targets are resolved to instruction offsets only when the
    user supplies ``--vbase``, or the opt-in ``--por-vbase`` (PoR-derived,
    CONDITIONAL, not promoted; see docs/por-ecl-decoder.md). Otherwise they stay
    ``unresolved-no-base``. The two options cannot be combined.
  * Prints a candidate-base diagnostic (which vbase values would make the
    header pointers and edge targets land on decoded instruction starts). It is
    diagnostic only and never changes the decode.
  * Writes deterministic ``por_ecl.json`` and ``por_ecl_report.md`` into an
    explicit output folder. Nothing is timestamped and no absolute paths appear.
    Output refused unless it is outside the source and, inside this repository,
    under ``data/`` (git-ignored).

  * Opt-in ``--por-decode-strings`` (default off): for each complete ``0x80``
    operand, decodes its payload bytes with the PoR 6-bit codec (GAME.OVR
    0x8626 / 0x7BA6; docs/por-ecl-codec-static-probe.md) into CANDIDATE character
    codes and text, tagged ``accepted: false``, ``runtime_verified: false``,
    ``playable: false``. Only the ``count`` bytes named by the operand are read,
    and malformed or truncated payloads yield ``status: refused`` with no text.
    It never changes framing, opcode semantics or control flow. Without the flag
    the JSON and report are byte-identical to the flagless tool.

What it refuses (exit 2, named error)
  * A DAX whose TOC size is not a positive multiple of 9, whose TOC runs past EOF,
    whose data chain is not contiguous, or whose data does not end at EOF.
  * An RLE block that overruns, is missing a repeat value, or does not produce
    exactly the TOC ``raw_size`` bytes.
  * An ambiguous block id (repeated in the TOC) without ``--index``.
  * A block that is not an ECL block (magic word 0x1388) or is shorter than the
    22-byte header.

Usage
  python3 tools/por_ecl.py --dax PATH/TO/ECL2.DAX --list
  python3 tools/por_ecl.py --dax PATH/TO/ECL2.DAX --block 20 -o data/work/por-ecl/ecl2-20
  python3 tools/por_ecl.py --install "D:/PoR" --ecl 2 --index 2 -o data/work/por-ecl/ecl2-2 \
      --framing spec-menus --vbase 0x98FE

Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCHEMA = "openua.por-ecl"
SCHEMA_VERSION = 1
STATUS = "decode-only"
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"

DAX_TOC_ENTRY = 9
ECL_HEADER_LEN = 22
ECL_MAGIC = 0x1388
ECL_SEGMENT_EXPECTED = 0x0101
CONTROL_BYTE_LITERAL_MAX = 0x7F  # control < 0x80 -> literal run

# Opt-in PoR-derived base (--por-vbase). EVIDENCE LEVEL: CONDITIONAL, NOT PROMOTED.
# block_offset = (vaddr - 0x98FE) mod 65536. Basis and open links:
# docs/por-ecl-decoder.md, docs/por-ecl-base-probe.md, docs/por-ecl-entry-origin-probe.md.
POR_VBASE = 0x98FE
POR_TABLE_END = POR_VBASE + ECL_HEADER_LEN  # vaddr 0x9914 = block byte 22
POR_VBASE_RULE = "block_offset = (vaddr - 0x98FE) mod 65536"

# Operand codes whose third byte (val) is present: word = (val << 8) | high.
THREE_BYTE_CODES = (0x01, 0x02, 0x03, 0x81)
STRING_CODE = 0x80

# PoR 0x80 payload codec, used only by --por-decode-strings. Retail evidence (static
# plus an 8086-subset execution of the unpacker; not runtime): the MSB-first 6-bit
# unpacker at GAME.OVR:0x08626, the char map at GAME.OVR:0x07BA6, and the count
# writer at GAME.OVR:0x07526. Sources: docs/por-ecl-codec-static-probe.md and
# docs/por-ecl-length-xref.md. Evidence level: pinned-retail static, NOT accepted text.
POR_CHAR_MAP_LIMIT = 0x1F      # v <= 0x1F -> v + 0x40, else v (GAME.OVR:0x07BA6)
POR_ASCII_MAX = 0x7E           # codes outside printable ASCII are escaped, never printed raw
POR_STRING_PROVENANCE = {
    "mode": "por-decode-strings",
    "scope": "complete 0x80 inline-string operands only; the payload is the 'high' byte count "
             "of bytes that follow the 0x80 code byte",
    "codec": "MSB-first 6-bit split, 4 values per 3 bytes; a tail of n bytes gives floor(8n/6) "
             "values (leftover bits dropped); value 0 is skipped, not a terminator; "
             "char = v + 0x40 for v <= 0x1F, else v",
    "evidence_level": "pinned-retail-static",
    "sources": [
        "GAME.OVR:0x08626 unpacker, 0x07BA6 char map (docs/por-ecl-codec-static-probe.md)",
        "GAME.OVR:0x07526 count writer, 0x07577 read, payload at p+3 (docs/por-ecl-length-xref.md)",
    ],
    "framing_basis": "operand boundaries come from this decoder's framing, which is GoldBox-derived "
                     "and not changed here; the PoR 0x80 arm agrees on the count and payload "
                     "offset, but the walk-to-parser alignment is not shown",
    "accepted": False,
    "runtime_verified": False,
    "playable": False,
    "not_established": [
        "that the ECL walk reaches the operand parser GAME.OVR:0x074D3 at run time",
        "that a decoded run is the text the game shows, or any text is accepted",
        "that the decoder's block offsets and the parser's stream offsets index the same bytes",
        "the meaning of the surrounding opcode (names and framing are GoldBox-derived hypotheses)",
    ],
    "not_claimed": [
        "no accepted or playable text, no FRUA event mapping, no module generation",
        "no runtime reachability or on-screen match",
    ],
}

# Opcode table: op -> (mnemonic, wordSet, countAt or None).
# Source: GoldBox ecl-krynn-gen1-opcodes.md section 2 (EclDump-derived table).
# 0x1F keeps its framing but has no known semantics.
OPCODES: dict[int, tuple[str, int, Optional[int]]] = {
    0x00: ("EXIT", 0, None), 0x01: ("GOTO", 1, None), 0x02: ("GOSUB", 1, None),
    0x03: ("COMPARE", 2, None), 0x04: ("ADD", 3, None), 0x05: ("SUBTRACT", 3, None),
    0x06: ("DIVIDE", 3, None), 0x07: ("MULTIPLY", 3, None), 0x08: ("RANDOM", 2, None),
    0x09: ("SAVE", 2, None), 0x0A: ("LOAD_CHARACTER", 1, None), 0x0B: ("LOAD_MONSTER", 3, None),
    0x0C: ("SETUP_MONSTER", 3, None), 0x0D: ("APPROACH", 0, None), 0x0E: ("PICTURE", 1, None),
    0x0F: ("INPUT_NUMBER", 2, None), 0x10: ("INPUT_STRING", 2, None), 0x11: ("PRINT", 1, None),
    0x12: ("PRINTCLEAR", 1, None), 0x13: ("RETURN", 0, None), 0x14: ("COMPARE_AND", 4, None),
    0x15: ("VERTICAL_MENU", 0, None), 0x16: ("IF_EQ", 0, None), 0x17: ("IF_NE", 0, None),
    0x18: ("IF_LT", 0, None), 0x19: ("IF_GT", 0, None), 0x1A: ("IF_LE", 0, None),
    0x1B: ("IF_GE", 0, None), 0x1C: ("CLEARMONSTERS", 0, None), 0x1D: ("PARTYSTRENGTH", 1, None),
    0x1E: ("CHECKPARTY", 6, None), 0x1F: ("UNKNOWN_1F", 2, None), 0x20: ("NEWECL", 1, None),
    0x21: ("LOAD_FILES", 3, None), 0x22: ("PARTY_SURPRISE", 2, None), 0x23: ("SURPRISE", 4, None),
    0x24: ("COMBAT", 0, None), 0x25: ("ON_GOTO", 2, 1), 0x26: ("ON_GOSUB", 2, 1),
    0x27: ("TREASURE", 8, None), 0x28: ("ROB", 3, None), 0x29: ("ENCOUNTER_MENU", 14, None),
    0x2A: ("GETTABLE", 3, None), 0x2B: ("HORIZONTAL_MENU", 0, None), 0x2C: ("PARLAY", 6, None),
    0x2D: ("CALL", 1, None), 0x2E: ("DAMAGE", 5, None), 0x2F: ("AND", 3, None),
    0x30: ("OR", 3, None), 0x31: ("SPRITE_OFF", 0, None), 0x32: ("FIND_ITEM", 1, None),
    0x33: ("PRINT_RETURN", 0, None), 0x34: ("ECL_CLOCK", 2, None), 0x35: ("SAVE_TABLE", 3, None),
    0x36: ("ADD_NPC", 1, None), 0x37: ("LOAD_PIECES", 3, None), 0x38: ("PROGRAM", 1, None),
    0x39: ("WHO", 1, None), 0x3A: ("DELAY", 0, None), 0x3B: ("SPELL", 3, None),
    0x3C: ("PROTECTION", 1, None), 0x3D: ("CLEAR_BOX", 0, None), 0x3E: ("DUMP", 0, None),
    0x3F: ("FIND_SPECIAL", 1, None), 0x40: ("DESTROY_ITEMS", 1, None),
}

# The two menu opcodes whose framing the two GoldBox sources disagree on.
# "spec-menus" framing (ecl-opcode-spec-for-asm.md 2.4): 0x15 has 3 fixed
# operands with the count at operand 2; 0x2B has 2 fixed operands with the count
# at operand 1. Both are followed by that many operands.
MENU_OPCODES = {0x15, 0x2B}
SPEC_MENU_FRAMING: dict[int, tuple[str, int, Optional[int]]] = {
    0x15: ("VERTICAL_MENU", 3, 2),
    0x2B: ("HORIZONTAL_MENU", 2, 1),
}
FRAMINGS = ("conservative", "spec-menus")
CONTROL_TERMINAL = {0x00, 0x13}  # EXIT / RETURN end a subroutine; linear walk goes on
JUMP_KINDS = {0x01: "goto", 0x02: "gosub", 0x25: "on_goto", 0x26: "on_gosub"}


class EclError(Exception):
    """A named refusal: bad source, malformed block, or unsafe output."""


# --------------------------------------------------------------------------
# DAX container (GoldBox docs/dax-format.md sections 1-2)
# --------------------------------------------------------------------------


@dataclass
class TocEntry:
    index: int
    block_id: int
    data_offset: int
    raw_size: int
    comp_size: int


def parse_dax(data: bytes) -> tuple[list[TocEntry], int]:
    """Validate the container. Returns (entries, data_base)."""
    if len(data) < 2:
        raise EclError("DAX too short for a TOC size word")
    toc_bytes = int.from_bytes(data[0:2], "little")
    if toc_bytes == 0 or toc_bytes % DAX_TOC_ENTRY != 0:
        raise EclError("DAX TOC size %d is not a positive multiple of 9" % toc_bytes)
    data_base = 2 + toc_bytes
    if data_base > len(data):
        raise EclError("DAX TOC runs past end of file")
    count = toc_bytes // DAX_TOC_ENTRY
    entries: list[TocEntry] = []
    expected_offset = 0
    for i in range(count):
        base = 2 + DAX_TOC_ENTRY * i
        block_id = data[base]
        data_offset = int.from_bytes(data[base + 1:base + 5], "little")
        raw_size = int.from_bytes(data[base + 5:base + 7], "little")
        comp_size = int.from_bytes(data[base + 7:base + 9], "little")
        if data_offset != expected_offset:
            raise EclError("DAX data chain is not contiguous at TOC index %d" % i)
        if data_base + data_offset + comp_size > len(data):
            raise EclError("DAX block %d at TOC index %d runs past end of file" % (block_id, i))
        entries.append(TocEntry(i, block_id, data_offset, raw_size, comp_size))
        expected_offset += comp_size
    if data_base + expected_offset != len(data):
        raise EclError("DAX data section does not end exactly at end of file")
    return entries, data_base


def rle_decode(comp: bytes, raw_size: int) -> bytes:
    """Signed-byte RLE: control < 0x80 copies control+1 literals; else repeat next byte 256-control times."""
    out = bytearray()
    i = 0
    n = len(comp)
    while i < n:
        c = comp[i]
        i += 1
        if c < 0x80:
            run = c + 1
            if i + run > n:
                raise EclError("RLE literal run overruns its block")
            out += comp[i:i + run]
            i += run
        else:
            if i >= n:
                raise EclError("RLE repeat run has no value byte")
            out += bytes([comp[i]]) * (256 - c)
            i += 1
        if len(out) > raw_size:
            raise EclError("RLE output exceeds the TOC raw_size")
    if len(out) != raw_size:
        raise EclError("RLE output is %d bytes; TOC raw_size is %d" % (len(out), raw_size))
    return bytes(out)


def select_entry(entries: list[TocEntry], block_id: Optional[int], index: Optional[int]) -> TocEntry:
    if index is not None:
        if not (0 <= index < len(entries)):
            raise EclError("TOC index %d out of range (0..%d)" % (index, len(entries) - 1))
        entry = entries[index]
        if block_id is not None and entry.block_id != block_id:
            raise EclError("TOC index %d has block id %d, not requested id %d"
                           % (index, entry.block_id, block_id))
        return entry
    if block_id is None:
        raise EclError("choose a block with --block ID or --index I")
    matches = [e for e in entries if e.block_id == block_id]
    if not matches:
        raise EclError("no TOC entry with block id %d" % block_id)
    if len(matches) > 1:
        raise EclError("block id %d is ambiguous (TOC indices %s); use --index"
                       % (block_id, ", ".join(str(e.index) for e in matches)))
    return matches[0]


# --------------------------------------------------------------------------
# ECL header and instruction walk
# --------------------------------------------------------------------------


def parse_header(block: bytes) -> dict:
    if len(block) < ECL_HEADER_LEN:
        raise EclError("block is %d bytes; the ECL header is %d" % (len(block), ECL_HEADER_LEN))
    magic = int.from_bytes(block[0:2], "little")
    if magic != ECL_MAGIC:
        raise EclError("block does not start with the ECL magic word 0x1388 (got 0x%04x)" % magic)
    pointers = []
    for k in range(5):
        base = 2 + 4 * k
        segment = int.from_bytes(block[base:base + 2], "little")
        vaddr = int.from_bytes(block[base + 2:base + 4], "little")
        pointers.append({"slot": k, "segment": segment, "vaddr": vaddr})
    return {
        "magic": magic,
        "header_length": ECL_HEADER_LEN,
        "pointers": pointers,
        "segment_all_expected": all(p["segment"] == ECL_SEGMENT_EXPECTED for p in pointers),
    }


@dataclass
class Operand:
    code: int
    high: int
    val: Optional[int]
    word: Optional[int]
    size: int
    string_len: Optional[int] = None
    string_sha256: Optional[str] = None
    offset: int = 0


def read_operand(block: bytes, pos: int) -> Operand:
    if pos + 2 > len(block):
        raise EclError("operand truncated at offset %d" % pos)
    code = block[pos]
    high = block[pos + 1]
    if code in THREE_BYTE_CODES:
        if pos + 3 > len(block):
            raise EclError("operand truncated at offset %d" % pos)
        val = block[pos + 2]
        word = (val << 8) | high
        size = 3
        op = Operand(code, high, val, word, size, offset=pos)
    else:
        op = Operand(code, high, None, high, 2, offset=pos)
    if code == STRING_CODE:
        # high = number of packed string bytes that follow the operand (the
        # GoldBox spec's reading). Only length and hash are kept, never text.
        n = high
        if pos + op.size + n > len(block):
            raise EclError("inline string at offset %d overruns the block" % pos)
        packed = block[pos + op.size:pos + op.size + n]
        op.string_len = n
        op.string_sha256 = hashlib.sha256(packed).hexdigest()
        op.size += n
    return op


def operand_dict(op: Operand) -> dict:
    d = {"offset": op.offset, "code": op.code, "high": op.high, "size": op.size}
    if op.val is not None:
        d["val"] = op.val
        d["word"] = op.word
    if op.string_len is not None:
        d["string_len"] = op.string_len
        d["string_sha256"] = op.string_sha256
    return d


def por_6bit_values(payload: bytes) -> list[int]:
    """MSB-first 6-bit split (PoR GAME.OVR:0x08626). floor(8n/6) values; leftover bits dropped."""
    total = 8 * len(payload)
    big = int.from_bytes(payload, "big") if payload else 0
    return [(big >> (total - 6 * (k + 1))) & 0x3F for k in range(total // 6)]


def por_char(v: int) -> int:
    """PoR char map (GAME.OVR:0x07BA6): v + 0x40 for v <= 0x1F, else v."""
    return v + 0x40 if v <= POR_CHAR_MAP_LIMIT else v


def por_string_record(block: bytes, op: Operand) -> dict:
    """Candidate decode of one complete 0x80 operand. Fails closed: anything that is not a
    complete 0x80 string with its full payload present yields status "refused" and no text.
    Reads exactly ``op.string_len`` bytes, starting at the payload offset (operand + 2)."""
    base = {"accepted": False, "runtime_verified": False, "playable": False}
    if op.code != STRING_CODE or op.string_len is None:
        return dict(base, status="refused", reason="operand is not a 0x80 inline string")
    n = op.string_len
    start = op.offset + 2
    if start + n > len(block):
        return dict(base, status="refused", reason="payload truncated",
                    count=n, present=max(0, len(block) - start))
    if n == 0:
        return dict(base, status="empty", payload_offset=start, count=0, bytes_used=0,
                    values=0, zero_values_skipped=0, char_codes=[], candidate_text="")
    payload = block[start:start + n]
    vals = por_6bit_values(payload)
    kept = [v for v in vals if v != 0]
    codes = [por_char(v) for v in kept]
    text = "".join(chr(c) if 0x20 <= c <= POR_ASCII_MAX else "\\x%02X" % c for c in codes)
    return dict(base, status="candidate", payload_offset=start, count=n, bytes_used=n,
                values=len(vals), zero_values_skipped=len(vals) - len(kept),
                char_codes=["0x%02X" % c for c in codes], candidate_text=text)


def _operand_out(block: bytes, ops: list, por_strings: bool) -> list:
    out = []
    for o in ops:
        d = operand_dict(o)
        if por_strings and o.code == STRING_CODE:
            d["por_decoded"] = por_string_record(block, o)
        out.append(d)
    return out


def por_string_summary(insts: list, walk_stop: str) -> dict:
    """Counts over the complete instructions only. Operands past a walk stop are not counted."""
    seen = {"candidate": 0, "empty": 0, "refused": 0}
    codes = 0
    for i in insts:
        for d in i.operands + i.count_operands:
            rec = d.get("por_decoded")
            if rec is None:
                continue
            seen[rec["status"]] = seen.get(rec["status"], 0) + 1
            codes += len(rec.get("char_codes", []))
    return dict(POR_STRING_PROVENANCE, walk_stop=walk_stop,
                operands_0x80=sum(seen.values()), candidate=seen["candidate"],
                empty=seen["empty"], refused=seen["refused"], char_codes_total=codes,
                status="candidate-only")


@dataclass
class Instruction:
    offset: int
    opcode: int
    mnemonic: str
    operands: list = field(default_factory=list)
    count_operands: list = field(default_factory=list)
    length: int = 0
    semantics_known: bool = True


@dataclass
class Edge:
    source: int
    kind: str
    target_vaddr: Optional[int]
    indirect: bool
    operand_offset: int


@dataclass
class Stop:
    kind: str
    offset: int
    opcode: Optional[int]
    detail: str


def walk_block(block: bytes, framing: str,
               por_strings: bool = False) -> tuple[list[Instruction], list[Edge], Stop]:
    if framing not in FRAMINGS:
        raise EclError("unknown framing %r" % framing)
    insts: list[Instruction] = []
    edges: list[Edge] = []
    pos = ECL_HEADER_LEN
    n = len(block)
    while pos < n:
        op = block[pos]
        start = pos
        if op not in OPCODES:
            return insts, edges, Stop("unknown-opcode", start, op,
                                      "opcode 0x%02x is not in the table" % op)
        if op in MENU_OPCODES and framing == "conservative":
            return insts, edges, Stop("ambiguous-framing", start, op,
                                      "menu framing differs between the two GoldBox sources; "
                                      "conservative mode stops here")
        mnemonic, wordset, count_at = OPCODES[op]
        if op in MENU_OPCODES:
            mnemonic, wordset, count_at = SPEC_MENU_FRAMING[op]
        pos += 1
        try:
            ops: list[Operand] = []
            for k in range(wordset):
                o = read_operand(block, pos)
                ops.append(o)
                pos += o.size
            count_ops: list[Operand] = []
            if count_at is not None:
                cnt_src = ops[count_at]
                if cnt_src.code != 0x00 and cnt_src.code != 0x02:
                    return insts, edges, Stop("ambiguous-count", start, op,
                                              "count operand has non-literal code 0x%02x"
                                              % cnt_src.code)
                count = cnt_src.word if cnt_src.code == 0x02 else cnt_src.high
                for _ in range(count):
                    o = read_operand(block, pos)
                    count_ops.append(o)
                    pos += o.size
        except EclError as exc:
            return insts, edges, Stop("truncated-operand", start, op, str(exc))
        inst = Instruction(start, op, mnemonic, _operand_out(block, ops, por_strings),
                           _operand_out(block, count_ops, por_strings), pos - start,
                           semantics_known=(op != 0x1F))
        insts.append(inst)
        if op in JUMP_KINDS:
            kind = JUMP_KINDS[op]
            targets = ([ops[0]] if op in (0x01, 0x02) else count_ops)
            for t in targets:
                if t.code in (0x01, 0x02, 0x81):
                    edges.append(Edge(start, kind, t.word, False, t.offset))
                else:
                    edges.append(Edge(start, kind, None, True, t.offset))
    return insts, edges, Stop("end-of-block", n, None, "walk reached the end of the block")


# --------------------------------------------------------------------------
# Resolution and diagnostics
# --------------------------------------------------------------------------


def resolve_edges(edges: list[Edge], vbase: Optional[int], block_len: int,
                  starts: set[int], decoded_end: int, wrap16: bool = False) -> list[dict]:
    """wrap16=False is the default (plain vaddr - vbase). wrap16=True is the PoR
    address form (--por-vbase): the offset is taken mod 65536 and a target that
    falls inside the 22-byte header is labelled ``in-header``."""
    out = []
    for e in edges:
        rec = {"source": e.source, "kind": e.kind, "operand_offset": e.operand_offset,
               "indirect": e.indirect, "target_vaddr": e.target_vaddr}
        if e.indirect:
            rec["resolution"] = "indirect-operand"
        elif vbase is None:
            rec["resolution"] = "unresolved-no-base"
        else:
            idx = e.target_vaddr - vbase
            if wrap16:
                idx &= 0xFFFF
            rec["target_offset"] = idx
            if idx < 0 or idx >= block_len:
                rec["resolution"] = "out-of-block"
            elif wrap16 and idx < ECL_HEADER_LEN:
                rec["resolution"] = "in-header"
            elif idx in starts:
                rec["resolution"] = "instruction-start"
            elif idx < decoded_end:
                rec["resolution"] = "mid-instruction"
            else:
                rec["resolution"] = "beyond-decoded-region"
        out.append(rec)
    return out


def candidate_base_diagnostic(block: bytes, header: dict, edges: list[Edge],
                              starts: set[int]) -> dict:
    """Which vbase values would put the header pointers and literal edge targets
    on decoded instruction starts. Diagnostic only: it never changes the decode.
    """
    vaddrs = [p["vaddr"] for p in header["pointers"]]
    vaddrs += [e.target_vaddr for e in edges if e.target_vaddr is not None]
    n = len(block)
    if not vaddrs:
        return {"targets": 0, "candidates": [], "note": "no vaddrs to test"}

    def hits(base: int) -> int:
        return sum(1 for v in vaddrs if 0 <= v - base < n and (v - base) in starts)

    cok_base = 0x7FFE
    ptr0_base = header["pointers"][0]["vaddr"] - ECL_HEADER_LEN
    # A base is worth scoring when the largest vaddr falls inside the block.
    # Small literals (for example a code-2 operand 0x0098) must not bound the window.
    lo = max(0, max(vaddrs) - n + 1)
    hi = max(vaddrs)
    scored = []
    for base in range(lo, hi + 1):
        h = hits(base)
        if h:
            scored.append((h, base))
    scored.sort(key=lambda t: (-t[0], t[1]))
    top = [{"vbase": "0x%04X" % b, "hits": h} for h, b in scored[:3]]
    return {
        "targets": len(vaddrs),
        "candidates": top,
        "named_candidates": [
            {"name": "coab-gen1-0x7FFE", "vbase": "0x%04X" % cok_base,
             "hits": hits(cok_base)},
            {"name": "header-ptr0-minus-22",
             "vbase": "0x%04X" % ptr0_base if ptr0_base >= 0 else None,
             "hits": hits(ptr0_base) if ptr0_base >= 0 else 0},
        ],
        "note": "diagnostic only; a best fit is not proof of a vbase",
    }


def decoded_coverage(insts: list[Instruction], block_len: int) -> dict:
    decoded = sum(i.length for i in insts)
    body = max(0, block_len - ECL_HEADER_LEN)
    return {"body_bytes": body, "decoded_bytes": decoded,
            "instructions": len(insts),
            "fraction": round(decoded / body, 6) if body else 1.0}


# --------------------------------------------------------------------------
# Top-level decode
# --------------------------------------------------------------------------


def parse_vbase(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    try:
        v = int(text, 0)
    except ValueError as exc:
        raise EclError("--vbase must be a hex or decimal vaddr, got %r" % text) from exc
    if not (0 <= v <= 0xFFFF):
        raise EclError("--vbase out of 16-bit range")
    return v


def check_vbase_options(vbase: Optional[int], por_vbase: bool) -> None:
    """--vbase and --por-vbase are alternatives. Naming both is refused, never merged."""
    if por_vbase and vbase is not None:
        raise EclError("--por-vbase and --vbase cannot be combined; choose one "
                       "(--por-vbase is the conditional PoR-derived base 0x98FE)")


def por_vbase_evidence(block: bytes, header: dict) -> dict:
    """Evidence metadata for the opt-in base. Written only in --por-vbase mode.

    The checks below are structural, per block. They do not promote the base:
    ``promoted`` is always false. A failed check is recorded, not refused.
    """
    vaddrs = [p["vaddr"] for p in header["pointers"]]
    checks = {
        "segments_0101": bool(header["segment_all_expected"]),
        "pointer_min_vaddr": "0x%04X" % min(vaddrs),
        "pointers_at_or_after_table_end": min(vaddrs) >= POR_TABLE_END,
        "pointers_inside_block": all(0 <= v - POR_VBASE < len(block) for v in vaddrs),
        "table_end_block_offset": ECL_HEADER_LEN,
    }
    ok = (checks["segments_0101"] and checks["pointers_at_or_after_table_end"]
          and checks["pointers_inside_block"])
    return {
        "mode": "por-vbase",
        "vbase": "0x%04X" % POR_VBASE,
        "rule": POR_VBASE_RULE,
        "wrap16": True,
        "evidence_level": "conditional",
        "promoted": False,
        "status": "conditional-checks-pass" if ok else "conditional-checks-fail",
        "header_table_check": checks,
        "basis": [
            "fetch arithmetic in GAME.OVR: buffer index = (vaddr + 0x6700) mod 65536 from [0x49DE] (bytes 0x3EDC..0x3EE2)",
            "loader copies len-2 bytes from record+2 (add di,2 at 0x78B4; callee bodies not located)",
            "retail: five header records parse to block bytes 2..21 and end at vaddr 0x9914 (29 of 29 ECL1-8 blocks, pinned GAME.OVR)",
            "retail diagnostic over ECL1-8, 29 blocks (not proof): 2899 of 3260 header and literal targets land on decoded starts under 0x98FE, against 68 under 0x9900 and 17 under 0x7FFE",
        ],
        "not_established": [
            "that the supplied game files match the pinned GOG revision used for this evidence; other PoR revisions are not checked by this mode",
            "that the loader source R starts at block byte 0 (the record source callee 0x0802:0x0716 is not located)",
            "that the copy is a byte copy of the block (callee 0x0AF8:0x1685 is not located)",
            "that block byte 22 is an instruction start (PoR never reads the cursor after the table parse)",
            "that every target lands on an instruction start (not so across ECL1-8; see the doc)",
            "runtime reachability, event semantics, playable conversion",
        ],
        "docs": [
            "docs/por-ecl-decoder.md",
            "docs/por-ecl-base-probe.md",
            "docs/por-ecl-entry-origin-probe.md",
        ],
    }


def decode_block(dax_bytes: bytes, block_id: Optional[int], index: Optional[int],
                 framing: str, vbase: Optional[int], por_vbase: bool = False,
                 por_strings: bool = False) -> dict:
    check_vbase_options(vbase, por_vbase)
    if por_vbase:
        vbase = POR_VBASE
    entries, data_base = parse_dax(dax_bytes)
    entry = select_entry(entries, block_id, index)
    comp = dax_bytes[data_base + entry.data_offset:data_base + entry.data_offset + entry.comp_size]
    block = rle_decode(comp, entry.raw_size)
    header = parse_header(block)
    insts, edges, stop = walk_block(block, framing, por_strings=por_strings)
    starts = {i.offset for i in insts}
    decoded_end = ECL_HEADER_LEN + sum(i.length for i in insts)
    tail = block[decoded_end:]
    resolved = resolve_edges(edges, vbase, len(block), starts, decoded_end, wrap16=por_vbase)
    return {
        "entry": entry,
        "block": block,
        "header": header,
        "instructions": insts,
        "stop": stop,
        "decoded_end": decoded_end,
        "tail": tail,
        "edges": resolved,
        "framing": framing,
        "vbase": vbase,
        "por_vbase": por_vbase,
        "por_strings": por_strings,
        "coverage": decoded_coverage(insts, len(block)),
        "diagnostic": candidate_base_diagnostic(block, header, edges, starts),
    }


def build_result(source_name: str, source_sha: str, res: dict) -> dict:
    e = res["entry"]
    block = res["block"]
    tail = res["tail"]
    instructions = []
    for i in res["instructions"]:
        instructions.append({
            "offset": i.offset,
            "opcode": "0x%02X" % i.opcode,
            "mnemonic": i.mnemonic,
            "length": i.length,
            "semantics_known": i.semantics_known,
            "operands": i.operands,
            "count_operands": i.count_operands,
        })
    edge_counts: dict[str, int] = {}
    for ed in res["edges"]:
        edge_counts[ed["resolution"]] = edge_counts.get(ed["resolution"], 0) + 1
    not_claimed = [
        "no FRUA event mapping",
        "no module generation",
        "no reachability or route claim",
        "control-flow targets are raw vaddrs; resolved only with --vbase",
        "instruction semantics are not implemented; only framing is tested",
    ]
    if res["por_vbase"]:
        not_claimed[3] = ("control-flow targets are raw vaddrs; resolved with --por-vbase only "
                          "under the conditional PoR-derived base 0x98FE (not promoted)")
    out = {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "source": {
            "file": source_name,
            "file_sha256": source_sha,
            "toc_index": e.index,
            "block_id": e.block_id,
            "data_offset": e.data_offset,
            "raw_size": e.raw_size,
            "comp_size": e.comp_size,
            "decoded_sha256": hashlib.sha256(block).hexdigest(),
        },
        "framing": res["framing"],
        "vbase": None if res["vbase"] is None else "0x%04X" % res["vbase"],
        "header": res["header"],
        "coverage": res["coverage"],
        "stop": {"kind": res["stop"].kind, "offset": res["stop"].offset,
                 "opcode": None if res["stop"].opcode is None else "0x%02X" % res["stop"].opcode,
                 "detail": res["stop"].detail},
        "instructions": instructions,
        "edges": res["edges"],
        "edge_resolution_counts": dict(sorted(edge_counts.items())),
        "unsupported_tail": {
            "offset": res["decoded_end"],
            "length": len(tail),
            "sha256": hashlib.sha256(tail).hexdigest(),
            "raw_hex": tail.hex(),
            "note": "raw numeric bytes; not decoded (no length or semantics guessed)",
        },
        "diagnostic_candidate_bases": res["diagnostic"],
        "not_claimed": not_claimed,
    }
    if res["por_vbase"]:
        # Present only in the opt-in mode, so default output is byte-identical.
        out["vbase_evidence"] = por_vbase_evidence(res["block"], res["header"])
    if res["por_strings"]:
        # Present only in the opt-in mode, so default output is byte-identical.
        out["por_string_decode"] = por_string_summary(res["instructions"], res["stop"].kind)
    return out


def render_report(result: dict) -> str:
    s = result["source"]
    h = result["header"]
    cov = result["coverage"]
    stop = result["stop"]
    diag = result["diagnostic_candidate_bases"]
    lines = []
    a = lines.append
    a("# Pool of Radiance ECL decode: block %d (TOC index %d)" % (s["block_id"], s["toc_index"]))
    a("")
    a("**Status: DECODE ONLY. `playable: false`.** Framing and control flow are")
    a("decoded only as far as the evidence supports. Nothing here is a FRUA event,")
    a("module or route claim. See `docs/por-ecl-decoder.md` for the evidence levels.")
    a("")
    a("## Source")
    a("")
    a("| Field | Value |")
    a("|---|---|")
    a("| File | %s |" % s["file"])
    a("| File SHA-256 | `%s` |" % s["file_sha256"])
    a("| TOC index / block id | %d / %d |" % (s["toc_index"], s["block_id"]))
    a("| Data offset (relative to data section) | %d |" % s["data_offset"])
    a("| Raw / compressed size | %d / %d |" % (s["raw_size"], s["comp_size"]))
    a("| Decoded SHA-256 | `%s` |" % s["decoded_sha256"])
    a("")
    a("## Header")
    a("")
    a("- magic: `0x%04X` (expected 0x1388)" % h["magic"])
    a("- header length: %d bytes" % h["header_length"])
    a("- segments all 0x0101: %s" % ("yes" if h["segment_all_expected"] else "NO"))
    a("")
    a("| Slot | Segment | vaddr |")
    a("|---|---|---|")
    for p in h["pointers"]:
        a("| %d | 0x%04X | 0x%04X |" % (p["slot"], p["segment"], p["vaddr"]))
    a("")
    a("## Decode coverage")
    a("")
    a("- framing mode: `%s`" % result["framing"])
    a("- instructions decoded: %d" % cov["instructions"])
    a("- body bytes decoded: %d of %d (%.1f%%)"
      % (cov["decoded_bytes"], cov["body_bytes"], 100.0 * cov["fraction"]))
    a("- stop: `%s` at offset %d (opcode %s): %s"
      % (stop["kind"], stop["offset"], stop["opcode"] or "-", stop["detail"]))
    tail = result["unsupported_tail"]
    a("- unsupported tail: %d bytes at offset %d (raw numeric data, not decoded)"
      % (tail["length"], tail["offset"]))
    a("")
    a("## Control-flow edges")
    a("")
    por = result.get("vbase_evidence")
    if not result["edges"]:
        a("No jump edges were decoded.")
    else:
        for kind, count in sorted(result["edge_resolution_counts"].items()):
            a("- `%s`: %d" % (kind, count))
        a("")
        if por:
            a("Edges resolved with the opt-in conditional base `0x98FE` (`--por-vbase`); see below.")
        else:
            a("Edges store raw vaddr targets. They resolve to offsets only with `--vbase`.")
    a("")
    if por:
        hc = por["header_table_check"]
        a("## PoR-derived vbase (opt-in, CONDITIONAL, not promoted)")
        a("")
        a("- vbase `%s`, rule `%s`, wrap16 on" % (por["vbase"], por["rule"]))
        a("- evidence level: `%s`; promoted: %s" % (por["evidence_level"],
                                                  "yes" if por["promoted"] else "no"))
        a("- structural check: `%s` (segments 0x0101: %s; pointers at or after 0x%04X: %s; "
          "pointers inside block: %s; minimum pointer %s)"
          % (por["status"], "yes" if hc["segments_0101"] else "NO", POR_TABLE_END,
             "yes" if hc["pointers_at_or_after_table_end"] else "NO",
             "yes" if hc["pointers_inside_block"] else "NO", hc["pointer_min_vaddr"]))
        a("- basis: see `vbase_evidence.basis` in the JSON and `docs/por-ecl-decoder.md`")
        a("- not established:")
        for item in por["not_established"]:
            a("  - %s" % item)
        a("")
    sd = result.get("por_string_decode")
    if sd:
        a("## PoR 0x80 candidate decode (opt-in, NOT accepted text)")
        a("")
        a("- candidates are tagged `accepted: false`, `runtime_verified: false`, `playable: false`")
        a("- codec and evidence: GAME.OVR 0x08626 / 0x07BA6 / 0x07526, pinned-retail static; "
          "see `docs/por-ecl-decoder.md`")
        a("- 0x80 operands: %d (candidate %d, empty %d, refused %d); walk stop: `%s`"
          % (sd["operands_0x80"], sd["candidate"], sd["empty"], sd["refused"], sd["walk_stop"]))
        a("- not established:")
        for item in sd["not_established"]:
            a("  - %s" % item)
        a("")
        rows = []
        for ins_ in result["instructions"]:
            for key in ("operands", "count_operands"):
                for d in ins_[key]:
                    rec = d.get("por_decoded")
                    if rec is not None and rec["status"] != "refused":
                        rows.append((ins_["offset"], d["offset"], rec))
        if rows:
            a("| Instruction offset | Operand offset | Count | Candidate text |")
            a("|---|---|---|---|")
            for ioff, ooff, rec in rows:
                a("| %d | %d | %d | `%s` |" % (ioff, ooff, rec["count"], rec["candidate_text"]))
            a("")
        else:
            a("No candidate payloads were decoded.")
            a("")
    a("## Candidate vbase diagnostic (not proof)")
    a("")
    a("Targets tested: %d (header pointers and literal jump targets)." % diag["targets"])
    a("")
    for c in diag["named_candidates"]:
        a("- %s `%s`: %d hits" % (c["name"], c["vbase"] or "n/a", c["hits"]))
    a("")
    a("Best fits: " + ", ".join("`%s` (%d)" % (c["vbase"], c["hits"]) for c in diag["candidates"]))
    a("")
    a("## Not claimed")
    a("")
    for item in result["not_claimed"]:
        a("- %s" % item)
    a("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Output and CLI
# --------------------------------------------------------------------------


def validate_output_dir(source: Path, out: Path) -> Path:
    src = Path(source).resolve()
    dst = Path(out).resolve()
    if dst == src or dst.is_relative_to(src):
        raise EclError("output folder must not be inside the source folder")
    repo = REPO_ROOT.resolve()
    if dst.is_relative_to(repo) and not dst.is_relative_to(DATA_DIR.resolve()):
        raise EclError("output folder inside the repository must be under data/ "
                       "(git-ignored); choose another location")
    return dst


def write_outputs(result: dict, report: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_ecl.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_ecl_report.md").write_text(report, encoding="utf-8", newline="\n")


def resolve_source(dax: Optional[str], install: Optional[str], ecl: Optional[int]) -> Path:
    if dax:
        p = Path(dax)
        if not p.is_file():
            raise EclError("DAX file not found")
        return p
    if install and ecl is not None:
        root = Path(install)
        for cand in (root / ("ECL%d.DAX" % ecl), root / "POOLRAD" / ("ECL%d.DAX" % ecl)):
            if cand.is_file():
                return cand
        raise EclError("ECL%d.DAX not found in the install folder or its POOLRAD subfolder" % ecl)
    raise EclError("give --dax PATH or --install DIR --ecl N")


def list_toc(dax_bytes: bytes) -> str:
    entries, _ = parse_dax(dax_bytes)
    lines = ["index  block_id  data_offset  raw_size  comp_size"]
    for e in entries:
        lines.append("%5d  %8d  %11d  %8d  %9d" % (e.index, e.block_id, e.data_offset,
                                                   e.raw_size, e.comp_size))
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Pool of Radiance ECL decoder (decode only).")
    ap.add_argument("--dax", help="explicit path to an ECL DAX file")
    ap.add_argument("--install", help="PoR install folder (ECL<n>.DAX here or in POOLRAD/)")
    ap.add_argument("--ecl", type=int, help="ECL archive number with --install (1..8)")
    ap.add_argument("--block", type=int, help="block id (must be unique in the TOC)")
    ap.add_argument("--index", type=int, help="TOC index (required when the id repeats)")
    ap.add_argument("--list", action="store_true", help="print the TOC and exit")
    ap.add_argument("--framing", choices=FRAMINGS, default="conservative",
                    help="menu framing: conservative stops at 0x15/0x2B; spec-menus decodes them")
    ap.add_argument("--vbase", help="resolve jump targets: target offset = vaddr - vbase (hex or decimal)")
    ap.add_argument("--por-vbase", action="store_true",
                    help="opt-in, CONDITIONAL: resolve jump targets with the PoR-derived base 0x98FE "
                         "(offset = (vaddr - 0x98FE) mod 65536). Not promoted. Cannot be combined with --vbase")
    ap.add_argument("--por-decode-strings", action="store_true",
                    help="opt-in: decode each 0x80 operand payload with the PoR 6-bit codec into "
                         "CANDIDATE text (accepted: false, runtime_verified: false). Default off")
    ap.add_argument("-o", "--out", help="output folder (required unless --list)")
    args = ap.parse_args(argv)
    try:
        src = resolve_source(args.dax, args.install, args.ecl)
        data = src.read_bytes()
        if args.list:
            print(list_toc(data))
            return 0
        if not args.out:
            raise EclError("-o OUT is required unless --list")
        out = validate_output_dir(src, Path(args.out))
        vbase = parse_vbase(args.vbase)
        check_vbase_options(vbase, args.por_vbase)
        res = decode_block(data, args.block, args.index, args.framing, vbase,
                           por_vbase=args.por_vbase, por_strings=args.por_decode_strings)
        result = build_result(src.name, hashlib.sha256(data).hexdigest(), res)
        report = render_report(result)
        write_outputs(result, report, out)
    except EclError as exc:
        print("por_ecl: error: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s and %s (%s, playable=false)"
          % (out / "por_ecl.json", out / "por_ecl_report.md", STATUS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
