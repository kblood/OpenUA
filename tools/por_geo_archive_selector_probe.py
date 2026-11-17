#!/usr/bin/env python3
"""Bounded static trace of the PoR GEO archive selector (DS:[0x5376]) and its save slot.

Pins GAME.OVR and START.EXE, then uses the repository's 16-bit decoder to:

1. Find every decoded access to the far-pointer slot DS:[0x49D6] (and its segment word
   DS:[0x49D8]) and check the producer of each store (an allocator call and its argument).
2. Find every decoded access to the displacement 0x624 on any base register, and check
   whether each ES-prefixed access takes its base from DS:[0x49D6] (the instruction
   immediately before it).
3. Find every decoded write to the selector DS:[0x5376] and classify its value source from
   the instruction immediately before it (constant, parameter, the one-byte save slot
   DS:[0x5377], or the field copy). Unclassified writes stay unclassified.
4. Classify every decoded read of DS:[0x5376] by the instructions that follow it.
5. Record address-immediate passes of 0x5376 (callee may write through the pointer; the
   callee is not entered) and the direct call sites of the two START procedures that
   touch the selector (byte scan of E8 and 9A operands, plus decoded near calls).

Output is static. Every number is a count of decoded or byte-matched sites, not a runtime
value. Nothing is executed, no emulator is run, and the pinned inputs are read only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import por_loadpieces_handler as decoder  # noqa: E402
import por_overlay_group_map as groups  # noqa: E402

SCHEMA = "openua.por-geo-archive-selector-probe"
VERSION = 1
TOOL = "tools/por_geo_archive_selector_probe.py"
DATA_WORK = ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-archive-selector-probe"
INSTALL_ENV = "OPENUA_POR_INSTALL"
DEFAULT_INSTALL = Path(r"G:\Games\Pool of Radiance\POOLRAD")
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"
PROLOGUE = b"\x55\x89\xE5"

SLOT_OFF = 0x49D6          # far pointer, offset word
SLOT_SEG = 0x49D8          # far pointer, segment word
SELECTOR = 0x5376          # GEO archive selector byte (DS)
SELECTOR_PREV = 0x5377     # one-byte save slot written by START 0x89A1 / read by 0x89B4
FIELD = 0x624              # displacement read/written through the slot's far pointer
ROW_STRIDE = 0x1E
ALLOC = (0x0AF8, 0x023F)   # far allocator called with a byte count (unit not established)
FORMATTER = (0x0AF8, 0x1366)  # consumer call receiving the zero-extended selector (unresolved)

# Anchors fixed by the earlier committed probes (not re-derived here).
OVR_INIT_ROOT = 0xE600     # slot allocation block (far pointers from calls with arguments 0x800/0x800/0x400/0x1E00)
OVR_SAVE_ROOT = 0x1FD3E    # stores the zero-extended selector into the field (ES:[DI+0x624])
OVR_RESTORE_ROOT = 0x1F5E8  # loads the field low byte back into the selector (GAME.OVR 0x1FBB0)
OVR_SAVE_SITE = 0x1FEFE
OVR_RESTORE_SITE = 0x1FBAB
START_SET_ROOT = 0x89A1    # retf 2: saves selector to 0x5377, sets it from [bp+6]
START_RESTORE_ROOT = 0x89B4  # restores selector from 0x5377

WRITE_MOFFS = (0xA2, 0xA3)
WRITE_MODRM = (0x88, 0x89)
WRITE_CONST = (0xC6, 0xC7)
READ_MOFFS = (0xA0, 0xA1)
READ_MODRM = (0x8A, 0x8B)
MEM_RE = re.compile(r"^\[(bx|bp|si|di)\+(\d+)\]$")


class Refusal(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: Optional[int]) -> Optional[str]:
    return None if value is None else "0x%05X" % value


# ---------------------------------------------------------------- decoding helpers

def is_memory(ins: decoder.Insn) -> bool:
    if ins.op in WRITE_MOFFS + READ_MOFFS:
        return True
    return bool(ins.modrm) and ins.modrm[0] != 3


def access_kind(ins: decoder.Insn) -> Optional[str]:
    """Memory-access kind of one decoded instruction, by opcode. None when it touches no memory."""
    op = ins.op
    if not is_memory(ins) and op not in (0xC4, 0xC5):
        return None
    if op in (0xC4, 0xC5):
        return "pointer-load"
    if op == 0x8D:
        return None
    if op in WRITE_MOFFS + WRITE_MODRM:
        return "write"
    if op in WRITE_CONST:
        return "write-const"
    if op in READ_MOFFS + READ_MODRM:
        return "read"
    if op in (0x80, 0x81, 0x83) and ins.modrm:
        return "read" if ins.modrm[1] == 7 else "read-modify-write"
    if op in (0xFE, 0xFF) and ins.modrm:
        return {0: "read-modify-write", 1: "read-modify-write", 6: "read"}.get(ins.modrm[1], "other")
    return "other"


def field_hit(ins: decoder.Insn) -> Optional[dict]:
    """A memory operand whose displacement is FIELD on any base register."""
    if not ins.mem:
        return None
    m = MEM_RE.match(ins.mem)
    if not m or int(m.group(2)) != FIELD:
        return None
    es = 0x26 in ins.prefixes
    return {"base": m.group(1), "segment": "ES" if es else "default"}


class Image:
    """One pinned image: its walked prologue roots and an instruction table over them."""

    def __init__(self, name: str, data: bytes, roots: list[int]):
        self.name = name
        self.data = data
        self.roots = list(roots)
        self.walks = {r: decoder.walk(data, r) for r in self.roots}
        self.sites: dict[int, dict] = {}
        for root in self.roots:
            if not self.walks[root]["complete"]:
                continue  # a partial walk (for example a false prologue match) contributes no sites
            for row in self.walks[root]["listing"]:
                at = row["at"]
                site = self.sites.get(at)
                if site is None:
                    site = {"image": name, "at": at, "ins": decoder.decode(data, at), "roots": []}
                    self.sites[at] = site
                if root not in site["roots"]:
                    site["roots"].append(root)
        self.by_end: dict[int, list[int]] = defaultdict(list)
        for at, site in self.sites.items():
            self.by_end[site["ins"].end].append(at)

    def prev(self, at: int) -> Optional[dict]:
        """The decoded instruction that ends exactly at `at`, if it is unique."""
        cands = self.by_end.get(at, [])
        return self.sites[cands[0]] if len(cands) == 1 else None

    def nxt(self, at: int, count: int) -> list[dict]:
        out: list[dict] = []
        cur = at
        for _ in range(count):
            site = self.sites.get(cur)
            if site is None:
                break
            out.append(site)
            cur = site["ins"].end
        return out

    def back(self, at: int, count: int) -> list[dict]:
        out: list[dict] = []
        cur = at
        for _ in range(count):
            site = self.prev(cur)
            if site is None:
                break
            out.append(site)
            cur = site["at"]
        return list(reversed(out))

    def text(self, at: int) -> str:
        return self.sites[at]["ins"].text() if at in self.sites else "?"


def describe(site: dict) -> dict:
    ins = site["ins"]
    return {"image": site["image"], "at": hx(site["at"]), "bytes": ins.raw.hex(" "),
            "text": ins.text(), "roots": [hx(r) for r in site["roots"]]}


def chain_text(img: Image, sites: list[dict]) -> list[str]:
    return [("%s %s" % (hx(s["at"]), s["ins"].text())) for s in sites]


# ---------------------------------------------------------------- census

def slot_census(img: Image, offset: int) -> dict:
    """Direct (decoded) accesses to a DS slot at `offset`, with the producer of each store."""
    rows = []
    for at in sorted(img.sites):
        site = img.sites[at]
        ins = site["ins"]
        if ins.direct != offset:
            continue
        kind = access_kind(ins)
        if kind is None:
            continue
        row = describe(site)
        row["access"] = kind
        if kind in ("write", "write-const"):
            prev = img.prev(at)
            row["producer"] = None
            if prev is not None and prev["ins"].flow == "call_far":
                row["producer"] = {"call": hx(prev["at"]), "far": list(prev["ins"].far),
                                   "is_allocator": tuple(prev["ins"].far) == ALLOC,
                                   "argument": None}
                arg_chain = img.back(prev["at"], 2)  # oldest first: mov ax,imm ; push ax
                if len(arg_chain) == 2 and arg_chain[0]["ins"].name == "mov ax" and \
                        arg_chain[1]["ins"].name.startswith("push"):
                    row["producer"]["argument"] = arg_chain[0]["ins"].imm
                    row["producer"]["argument_chain"] = chain_text(img, arg_chain)
        rows.append(row)
    return {"rows": rows, "count_pointer_loads": sum(1 for r in rows if r["access"] == "pointer-load")}


def pointer_loads_of_slot(img: Image) -> int:
    return sum(1 for s in img.sites.values() if s["ins"].direct == SLOT_OFF and
               access_kind(s["ins"]) == "pointer-load")


def field_census(img: Image) -> dict:
    """Every decoded access to displacement FIELD on any base register, with its DI source."""
    rows = []
    for at in sorted(img.sites):
        site = img.sites[at]
        ins = site["ins"]
        hit = field_hit(ins)
        if hit is None:
            continue
        kind = access_kind(ins) or "address-only"
        row = describe(site)
        row.update({"access": kind, "base": hit["base"], "segment": hit["segment"]})
        if hit["segment"] == "ES" and hit["base"] == "di":
            src = img.prev(at)
            row["base_loaded_by"] = None
            if src is not None and src["ins"].op == 0xC4 and src["ins"].direct == SLOT_OFF:
                row["base_loaded_by"] = describe(src)
                row["base_source"] = "far-pointer slot DS:[0x49D6] (contiguous les)"
            else:
                row["base_source"] = "not established (previous instruction is not the slot load)"
            if kind == "write":
                # Value chain: the store uses AX here (modrm reg 0). Check the three-instruction
                # run `mov al,[0x5376]; xor ah,ah; les di,[0x49D6]; mov es:[di+FIELD],ax`.
                if ins.modrm and ins.modrm[1] == 0 and ins.op == 0x89:
                    back = img.back(at, 3)
                    row["value_chain"] = chain_text(img, back)
                    row["value_source"] = _zero_extended_selector_copy(back)
                else:
                    row["value_source"] = "not_ax_word_store"
            if kind == "read":
                nxt = img.nxt(ins.end, 1)
                row["value_sink"] = ("copy_low_byte_to_selector"
                                     if nxt and nxt[0]["ins"].op == WRITE_MOFFS[0] and nxt[0]["ins"].direct == SELECTOR
                                     else "not_established")
                row["value_sink_text"] = chain_text(img, nxt)
        else:
            row["base_source"] = "not_es_or_not_di"
        rows.append(row)
    return {"rows": rows}


def _zero_extended_selector_copy(back: list[dict]) -> str:
    """Match the three instructions before a `mov es:[di+FIELD],ax` against the zero-extended copy."""
    if len(back) != 3:
        return "chain_not_contiguous"
    a, b, c = back
    ok_load = a["ins"].op == READ_MOFFS[0] and a["ins"].direct == SELECTOR
    ok_zero = b["ins"].op == 0x30 and b["ins"].modrm == (3, 4, 4)
    ok_les = c["ins"].op == 0xC4 and c["ins"].direct == SLOT_OFF
    if ok_load and ok_zero and ok_les:
        return "zero_extended_selector_copy"
    return "unclassified"


def selector_writes(img: Image, offset: int) -> list[dict]:
    rows = []
    for at in sorted(img.sites):
        site = img.sites[at]
        ins = site["ins"]
        if ins.direct != offset or access_kind(ins) not in ("write", "write-const"):
            continue
        row = describe(site)
        if ins.op in WRITE_CONST:
            row.update({"source_class": "constant", "value": ins.imm})
        else:
            prev = img.prev(at)
            cls = "unclassified"
            detail = None
            if prev is not None:
                p = prev["ins"]
                detail = chain_text(img, [prev])[0]
                if p.op == READ_MODRM[0] and p.bp_disp == 6 and p.modrm and p.modrm[1] == 0:
                    cls = "parameter_bp+6"
                elif p.op == READ_MOFFS[0] and p.direct == SELECTOR_PREV:
                    cls = "copy_of_save_slot_0x5377"
                elif p.op == READ_MOFFS[0] and p.direct == SELECTOR:
                    cls = "copy_of_selector"
                elif p.op == READ_MODRM[0] and field_hit(p) is not None and field_hit(p)["base"] == "di":
                    cls = "field_low_byte"
            row.update({"source_class": cls, "previous": detail})
        rows.append(row)
    return rows


def selector_reads(img: Image) -> list[dict]:
    """Classify every decoded read of DS:[0x5376] by the instructions that follow it."""
    rows = []
    for at in sorted(img.sites):
        site = img.sites[at]
        ins = site["ins"]
        if ins.direct != SELECTOR or access_kind(ins) not in ("read", "read-modify-write"):
            continue
        after = img.nxt(ins.end, 16)
        cls = "other"
        # A window association, not an argument proof: the selector's register must reach the call.
        if any(s["ins"].flow == "call_far" and s["ins"].far is not None and
               tuple(s["ins"].far) == FORMATTER for s in after):
            cls = "formatter_call_within_16_insns"
        if cls == "other" and _row_stride_after(after):
            cls = "row_select_stride_0x1E"
        if cls == "other" and any(field_hit(s["ins"]) is not None and access_kind(s["ins"]) == "write"
                                  for s in after):
            cls = "copied_to_field_0x624"
        if cls == "other" and ins.op == 0x80 and ins.imm is not None:
            cls = "compare_immediate"
        row = describe(site)
        row["access"] = access_kind(ins)
        row["consumer_class"] = cls
        rows.append(row)
    return rows


def _row_stride_after(after: list[dict]) -> bool:
    for i, s in enumerate(after):
        if s["ins"].op == 0xBA and s["ins"].imm == ROW_STRIDE:
            return any(t["ins"].name == "mul" for t in after[i + 1:i + 3])
    return False


def pointer_passes(img: Image, targets: tuple[int, ...]) -> list[dict]:
    """Address-immediate moves (mov reg,imm16) of selector addresses; the next call is recorded."""
    rows = []
    for at in sorted(img.sites):
        site = img.sites[at]
        ins = site["ins"]
        if 0xB8 <= ins.op <= 0xBF and ins.imm in targets:
            call = None
            for s in img.nxt(ins.end, 12):
                if s["ins"].flow in ("call", "call_far"):
                    call = s
                    break
            row = describe(site)
            row["address"] = hx(ins.imm)
            row["next_call"] = (describe(call) if call else None)
            row["next_call_target"] = (
                ("0x%04X:0x%04X" % tuple(call["ins"].far)) if call and call["ins"].far else
                (hx(call["ins"].target) if call else None))
            rows.append(row)
    return rows


def displacement_immediates(img: Image) -> list[dict]:
    rows = []
    for at in sorted(img.sites):
        ins = img.sites[at]["ins"]
        if ins.imm == FIELD and ins.op in (0x81, 0x83, 0x05, 0x25, 0x2D, 0x35, 0x3D, 0xBF, 0xBE, 0xBB):
            rows.append(describe(img.sites[at]))
    return rows


def callers(images: list[Image], entry: int, image_name: str, data_by_name: dict) -> dict:
    """Direct call sites of `entry` (a procedure in `image_name`): decoded near calls and byte scans."""
    decoded = []
    for img in images:
        for root in img.roots:
            if not img.walks[root]["complete"]:
                continue
            for nc in img.walks[root]["near_calls"]:
                if nc["target"] == entry:
                    decoded.append({"image": img.name, "site": hx(nc["at"]), "walk_root": hx(root)})
    raw_near = []
    raw_far = []
    for name, data in data_by_name.items():
        for i in range(len(data) - 2):
            if data[i] == 0xE8 and i + 3 + int.from_bytes(data[i + 1:i + 3], "little", signed=True) == entry:
                raw_near.append({"image": name, "site": hx(i)})
        # A far call carries a segment-relative offset word. The file offset equals that word only
        # if the segment base is the file start, which is not established; so a match here is a
        # candidate, and entries above 0xFFFF cannot be far-call offsets at all.
        if entry <= 0xFFFF:
            lo = entry.to_bytes(2, "little")
            for i in range(len(data) - 4):
                if data[i] == 0x9A and data[i + 1:i + 3] == lo:
                    raw_far.append({"image": name, "site": hx(i), "segment_word": data[i + 3:i + 5].hex(),
                                    "status": "candidate_offset_word_equals_file_offset"})
    return {"decoded_near_calls": decoded, "raw_near_e8": raw_near,
            "raw_far_offset_matches": raw_far,
            "raw_far_scan": "candidate offset-word scan" if entry <= 0xFFFF else "not_applicable_above_0xFFFF",
            "image": image_name, "entry": hx(entry)}


# ---------------------------------------------------------------- analysis

def analyze(ovr: bytes, exe: bytes) -> dict:
    groups.check_pin(OVR_NAME, ovr, groups.PINS)
    groups.check_pin(EXE_NAME, exe, groups.PINS)

    group_list = []
    for pos in range(0, len(exe) - groups.DESC_MIN + 1):
        if exe[pos:pos + 4] != groups.DESC_MAGIC:
            continue
        try:
            group_list.append(groups.parse_descriptor(exe, ovr, pos))
        except groups.Refusal:
            continue
    ovr_roots = []
    for g in group_list:
        lo, hi = g["fileofs"], g["fileofs"] + g["codesz"]
        for entry in range(lo, hi - len(PROLOGUE) + 1):
            if ovr[entry:entry + len(PROLOGUE)] == PROLOGUE:
                ovr_roots.append(entry)
    exe_roots = [i for i in range(len(exe) - len(PROLOGUE) + 1) if exe[i:i + len(PROLOGUE)] == PROLOGUE]

    ovr_img = Image(OVR_NAME, ovr, ovr_roots)
    exe_img = Image(EXE_NAME, exe, exe_roots)
    images = [ovr_img, exe_img]
    data_by_name = {OVR_NAME: ovr, EXE_NAME: exe}

    slot_ovr = slot_census(ovr_img, SLOT_OFF)
    slot_seg_ovr = slot_census(ovr_img, SLOT_SEG)
    slot_exe = slot_census(exe_img, SLOT_OFF)
    field_ovr = field_census(ovr_img)
    field_exe = field_census(exe_img)
    sel_writes = {OVR_NAME: selector_writes(ovr_img, SELECTOR), EXE_NAME: selector_writes(exe_img, SELECTOR)}
    prev_writes = {OVR_NAME: selector_writes(ovr_img, SELECTOR_PREV), EXE_NAME: selector_writes(exe_img, SELECTOR_PREV)}
    sel_reads = {OVR_NAME: selector_reads(ovr_img), EXE_NAME: selector_reads(exe_img)}
    passes = {OVR_NAME: pointer_passes(ovr_img, (SELECTOR, SELECTOR_PREV, SLOT_OFF)),
              EXE_NAME: pointer_passes(exe_img, (SELECTOR, SELECTOR_PREV, SLOT_OFF))}
    disp_imm = {OVR_NAME: displacement_immediates(ovr_img), EXE_NAME: displacement_immediates(exe_img)}

    call_census = {}
    for label, entry, image_name in (
            ("set_selector_0x89A1", START_SET_ROOT, EXE_NAME),
            ("restore_selector_0x89B4", START_RESTORE_ROOT, EXE_NAME),
            ("save_field_0x1FD3E", OVR_SAVE_ROOT, OVR_NAME),
            ("restore_field_0x1F5E8", OVR_RESTORE_ROOT, OVR_NAME),
            ("slot_init_0xE600", OVR_INIT_ROOT, OVR_NAME)):
        call_census[label] = callers(images, entry, image_name, data_by_name)

    # Chain checks, all derived from the decoded sites above.
    slot_writes = [r for r in slot_ovr["rows"] if r["access"] in ("write", "write-const")]
    slot_seg_writes = [r for r in slot_seg_ovr["rows"] if r["access"] in ("write", "write-const")]
    slot_exe_writes = [r for r in slot_exe["rows"] if r["access"] in ("write", "write-const")]
    field_writes = [r for r in field_ovr["rows"] + field_exe["rows"] if r["access"] == "write" and r["segment"] == "ES"]
    field_reads = [r for r in field_ovr["rows"] + field_exe["rows"] if r["access"] == "read" and r["segment"] == "ES"]
    field_other = [r for r in field_ovr["rows"] + field_exe["rows"]
                   if not (r["segment"] == "ES" and r["base"] == "di")]

    init_site = next((r for r in slot_writes if r["at"] == "0x0E620"), None)
    init_ok = bool(init_site and len(slot_writes) == 1 and init_site["producer"] and
                   init_site["producer"]["is_allocator"] and init_site["producer"]["argument"] == 0x800)
    field_ok = (len(field_writes) == 1 and len(field_reads) == 1 and
                field_writes[0]["at"] == hx(OVR_SAVE_SITE) and field_reads[0]["at"] == hx(OVR_RESTORE_SITE) and
                field_writes[0]["value_source"] == "zero_extended_selector_copy" and
                field_reads[0].get("value_sink") == "copy_low_byte_to_selector" and
                field_writes[0]["base_source"].startswith("far-pointer slot") and
                field_reads[0]["base_source"].startswith("far-pointer slot"))
    sel_classes = defaultdict(list)
    for name in (OVR_NAME, EXE_NAME):
        for w in sel_writes[name]:
            sel_classes[w["source_class"]].append("%s %s" % (w["image"], w["at"]))
    selector_origin_unique = len(sel_classes) == 1 and sum(len(v) for v in sel_classes.values()) == 1
    start_direct = (call_census["set_selector_0x89A1"]["decoded_near_calls"] == [] and
                    call_census["set_selector_0x89A1"]["raw_near_e8"] == [] and
                    call_census["set_selector_0x89A1"]["raw_far_offset_matches"] == [] and
                    call_census["restore_selector_0x89B4"]["decoded_near_calls"] == [] and
                    call_census["restore_selector_0x89B4"]["raw_near_e8"] == [] and
                    call_census["restore_selector_0x89B4"]["raw_far_offset_matches"] == [])

    doc = {
        "schema": SCHEMA,
        "schema_version": VERSION,
        "tool": TOOL,
        "playable": False,
        "status": "bounded-static-selector-trace",
        "pins": {
            OVR_NAME: {"size": len(ovr), "sha256": sha(ovr), "match": True},
            EXE_NAME: {"size": len(exe), "sha256": sha(exe), "match": True},
        },
        "coverage": {
            "ovr_candidate_descriptors": len(group_list),
            "ovr_prologue_roots": len(ovr_roots),
            "ovr_complete_walks": sum(bool(ovr_img.walks[r]["complete"]) for r in ovr_roots),
            "exe_prologue_roots": len(exe_roots),
            "exe_complete_walks": sum(bool(exe_img.walks[r]["complete"]) for r in exe_roots),
            "method": "prologue roots (55 89 E5) inside GAME.OVR group bodies and anywhere in START.EXE; "
                      "decoder branch/fallthrough walks; call edges recorded, not entered",
            "not_exhaustive": True,
        },
        "slot_49D6": {"ovr": slot_ovr, "exe": slot_exe, "pointer_loads_in_ovr": pointer_loads_of_slot(ovr_img)},
        "slot_49D8": {"ovr": slot_seg_ovr},
        "field_0x624": {"ovr": field_ovr, "exe": field_exe, "immediate_0x624": disp_imm},
        "selector_0x5376": {
            "writes": sel_writes,
            "reads": sel_reads,
            "address_passes": passes,
        },
        "save_slot_0x5377": {"writes": prev_writes},
        "callers": call_census,
        "consumers": {
            "formatter_call_within_16": [r for img in (OVR_NAME, EXE_NAME) for r in sel_reads[img]
                                         if r["consumer_class"] == "formatter_call_within_16_insns"],
            "row_select": [r for img in (OVR_NAME, EXE_NAME) for r in sel_reads[img]
                           if r["consumer_class"] == "row_select_stride_0x1E"],
        },
        "conclusion": {
            "slot_49D6_single_initializer_from_allocator": init_ok,
            "field_0x624_single_save_and_restore": field_ok,
            "selector_writer_classes": {k: v for k, v in sorted(sel_classes.items())},
            "selector_origin_unique": selector_origin_unique,
            "set_and_restore_procedures_have_no_direct_call_sites": start_direct,
            "archive_digit": "not_established",
            "area_mapping": "not_established",
            "runtime_values_or_execution": "not_established",
        },
    }
    doc["verdict"] = verdict(doc)
    if sha(ovr) != doc["pins"][OVR_NAME]["sha256"] or sha(exe) != doc["pins"][EXE_NAME]["sha256"]:
        raise Refusal("a pinned input changed during analysis")
    return doc


def verdict(doc: dict) -> dict:
    c = doc["conclusion"]
    claims = [
        {"id": "A1", "claim": "DS:[0x49D6] has exactly one decoded store, after an allocator call with argument 0x800 (GAME.OVR 0xE620)",
         "status": "bytes_established_decoded" if c["slot_49D6_single_initializer_from_allocator"] else "not_validated",
         "note": "the allocator's unit and return convention are not established"},
        {"id": "A2", "claim": "The only decoded accesses to displacement 0x624 are one ES store (GAME.OVR 0x1FEFE) and one ES load (0x1FBAB), both based on DS:[0x49D6]",
         "status": "bytes_established_decoded" if c["field_0x624_single_save_and_restore"] else "not_validated",
         "note": "complete decoded walks only; a displacement built in a register at run time is not seen as 0x624"},
        {"id": "A3", "claim": "The value stored into the field is the zero-extended DS:[0x5376] (save), and the field's low byte is stored back into DS:[0x5376] (restore)",
         "status": "bytes_established_decoded" if c["field_0x624_single_save_and_restore"] else "not_validated",
         "note": "decoded-only: the field's sole writer copies the selector, so the cycle has no independent source"},
        {"id": "A4", "claim": "DS:[0x5376] has a unique decoded origin",
         "status": "not_established_not_unique" if not c["selector_origin_unique"] else "bytes_established_decoded",
         "note": "writer classes: %s" % ", ".join(sorted(c["selector_writer_classes"]))},
        {"id": "A5", "claim": "The set and restore procedures START 0x89A1 and 0x89B4 have no direct call sites in either image",
         "status": "bytes_established_no_direct_sites" if c["set_and_restore_procedures_have_no_direct_call_sites"] else "not_validated",
         "note": "indirect calls (function pointer, table) are not excluded"},
        {"id": "A6", "claim": "The archive digit or area id equals the selector value",
         "status": "not_established", "note": "no mapping from selector value to a DAX digit is in the bytes"},
        {"id": "A7", "claim": "The field's content before its first save (allocator-provided memory) is zero or known",
         "status": "not_established", "note": "allocator zeroing is not established"},
        {"id": "A8", "claim": "The formatter at 0x0AF8:0x1366 turns the selector into a decimal digit",
         "status": "not_established", "note": "callee not entered; only the argument shape is decoded"},
    ]
    return {
        "claims": claims,
        "handoff_status": ("no_unique_selector_origin" if not c["selector_origin_unique"] else "unique_origin_candidate"),
        "archive": "not_established",
        "requested_block": "not_established",
        "playable": False,
    }


# ---------------------------------------------------------------- report

def render_report(doc: dict) -> str:
    c = doc["conclusion"]
    v = doc["verdict"]
    lines = [
        "# PoR GEO archive selector trace (static, bounded)", "",
        "**Status: `playable: false`. The archive, the requested block and the origin of the selector are not established.**", "",
        "## Coverage", "",
        "- GAME.OVR: %d candidate descriptors; %d prologue roots; %d complete walks."
        % (doc["coverage"]["ovr_candidate_descriptors"], doc["coverage"]["ovr_prologue_roots"],
           doc["coverage"]["ovr_complete_walks"]),
        "- START.EXE: %d prologue roots; %d complete walks." % (
            doc["coverage"]["exe_prologue_roots"], doc["coverage"]["exe_complete_walks"]),
        "- Method: " + doc["coverage"]["method"] + ".", "",
        "## Far-pointer slot DS:[0x49D6]", "",
    ]
    for r in doc["slot_49D6"]["ovr"]["rows"]:
        if r["access"] in ("write", "write-const"):
            p = r["producer"] or {}
            lines.append("- %s `%s` (%s): preceded by allocator call `%s`, argument %s." % (
                r["at"], r["text"], r["access"], p.get("call", "-"),
                ("0x%X" % p["argument"]) if p.get("argument") is not None else "not established"))
    for r in doc["slot_49D8"]["ovr"]["rows"]:
        if r["access"].startswith("write"):
            lines.append("- %s `%s` (segment word, %s)." % (r["at"], r["text"], r["access"]))
    lines.append("- Pointer loads (`les` of the slot) in GAME.OVR: %d." % doc["slot_49D6"]["pointer_loads_in_ovr"])
    lines += ["", "## Field at displacement 0x624", ""]
    for r in doc["field_0x624"]["ovr"]["rows"] + doc["field_0x624"]["exe"]["rows"]:
        extra = ""
        if r["access"] == "write":
            extra = "; value %s" % r.get("value_source")
        if r["access"] == "read":
            extra = "; sink %s" % r.get("value_sink")
        lines.append("- %s `%s` (%s, %s base `%s`)%s" % (
            r["at"], r["text"], r["access"], r["segment"], r["base"], extra))
    lines += ["", "## Writers of DS:[0x5376]", ""]
    for img in ("GAME.OVR", "START.EXE"):
        for w in doc["selector_0x5376"]["writes"][img]:
            val = (" value 0x%X" % w["value"]) if "value" in w else ""
            lines.append("- %s `%s` (%s, class `%s`)%s" % (w["at"], w["text"], img, w["source_class"], val))
    lines.append("- Address-immediate passes of the selector (callee not entered):")
    for img in ("GAME.OVR", "START.EXE"):
        for p in doc["selector_0x5376"]["address_passes"][img]:
            lines.append("  - %s `%s` (%s) next call `%s`" % (p["at"], p["text"], img, p["next_call_target"]))
    lines += ["", "## Save slot DS:[0x5377]", ""]
    for img in ("GAME.OVR", "START.EXE"):
        for w in doc["save_slot_0x5377"]["writes"][img]:
            lines.append("- %s `%s` (%s, class `%s`)" % (w["at"], w["text"], img, w["source_class"]))
    lines += ["", "## START procedures that touch the selector (decoded, not entered from callers)", ""]
    lines.append("- Set procedure at 0x089A1 (`retf 2`): stores DS:[0x5376] into DS:[0x5377], then stores its "
                 "byte parameter `[bp+6]` into DS:[0x5376].")
    lines.append("- Restore procedure at 0x089B4 (`retf`): stores DS:[0x5377] into DS:[0x5376].")
    lines.append("- Neither procedure has a direct call site in either image (see the callers table).")
    lines += ["", "## Readers of DS:[0x5376] (classes)", ""]
    counts = defaultdict(int)
    for img in ("GAME.OVR", "START.EXE"):
        for r in doc["selector_0x5376"]["reads"][img]:
            counts[r["consumer_class"]] += 1
    for k, n in sorted(counts.items()):
        lines.append("- `%s`: %d" % (k, n))
    lines += ["", "## Direct call sites of the set / restore procedures", ""]
    for label, row in doc["callers"].items():
        lines.append("- %s at %s: decoded near calls %d; raw E8 %d; raw far offset matches %d." % (
            label, row["entry"], len(row["decoded_near_calls"]), len(row["raw_near_e8"]),
            len(row["raw_far_offset_matches"])))
    lines += ["", "## Claims", ""]
    for claim in v["claims"]:
        lines.append("- %s %s — `%s` (%s)" % (claim["id"], claim["claim"], claim["status"], claim["note"]))
    lines += ["", "## Verdict", "",
              "- Handoff status: `%s`." % v["handoff_status"],
              "- Writer classes: %s." % (", ".join("%s (%d)" % (k, len(vv))
                                                   for k, vv in sorted(c["selector_writer_classes"].items()))),
              "- Archive: `%s`; requested block: `%s`; playable: %s." % (
                  v["archive"], v["requested_block"], str(v["playable"]).lower()), "",
              "## Limits", "",
              "- Decoded prologue roots only; accesses reached only from non-prologue entries are not counted.",
              "- Call edges are recorded but not entered. Callee writes through a passed pointer are not traced.",
              "- The allocator's unit, return convention and zeroing, the DS value, and the table at DS:0x2614 are not established.",
              "- Byte-scan call sites (E8, 9A) are not instruction-aligned; they show absence of a direct operand, not a call graph.",
              "- Nothing was executed; no emulator or DOSBox run was made.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- main

def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def find_install(arg: Optional[Path]) -> Path:
    if arg is not None:
        return arg
    env = os.environ.get(INSTALL_ENV)
    return Path(env) if env else DEFAULT_INSTALL


def probe(install: Path) -> dict:
    paths = {name: install / name for name in (OVR_NAME, EXE_NAME)}
    if not all(p.is_file() for p in paths.values()):
        raise Refusal("missing pinned GAME.OVR or START.EXE in %s" % install)
    before = {name: p.read_bytes() for name, p in paths.items()}
    doc = analyze(before[OVR_NAME], before[EXE_NAME])
    after = {name: p.read_bytes() for name, p in paths.items()}
    if any(sha(after[n]) != sha(before[n]) for n in before):
        raise Refusal("pinned inputs changed during the probe")
    doc["input_unchanged"] = True
    return doc


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--install", type=Path, default=None,
                        help="install folder with GAME.OVR and START.EXE (default: $%s or the reference path)"
                        % INSTALL_ENV)
    parser.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if not _inside(out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    install = find_install(args.install)
    try:
        doc = probe(install)
    except (OSError, Refusal, groups.Refusal) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_archive_selector_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_geo_archive_selector_probe.md").write_text(render_report(doc), encoding="utf-8")
    print("wrote %s (handoff_status=%s, archive=%s, playable=false)" % (
        out, doc["verdict"]["handoff_status"], doc["verdict"]["archive"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
