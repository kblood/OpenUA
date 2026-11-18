#!/usr/bin/env python3
"""Pool of Radiance inline-string operand census (ECL code 0x80): read-only.

Status: CENSUS-ONLY. This tool does NOT interpret string payloads (no charset,
no text, no dictionary), does NOT map any string to a FRUA event or message,
and does NOT claim a playable module. It reads an explicit, user-supplied PoR
DOS install read-only and records every inline-string operand (operand code
0x80) that the existing ECL framing decoder (``tools/por_ecl.py``) reaches in
ECL1.DAX through ECL8.DAX, with its raw payload bytes preserved as hex and
base64.

What it does, for every TOC entry of every ECL archive:
  * decodes the block with the existing DAX/RLE code and checks the ECL header
    (``por_ecl.parse_dax``, ``rle_decode`` and ``parse_header``, reused);
  * walks the instruction stream from byte 22 in BOTH framings that
    ``por_ecl`` supports (``conservative`` and ``spec-menus``), reported side by
    side. Each walk is the authoritative ``por_ecl.walk_block`` walk;
  * for every decoded instruction, records every operand (fixed and count-driven)
    whose code is 0x80, with: source archive and its SHA-256, TOC index, block
    id, decoded-block offset of the operand (the "decompressed offset"), the
    instruction offset and mnemonic, the operand slot, the declared length (the
    operand ``high`` byte), the payload offset and length, the total operand
    length (2 + declared), the raw payload as hex and base64, and the payload
    SHA-256;
  * probes the one instruction where a walk stopped (truncated operand or
    ambiguous count) operand by operand, so a string that is valid before the
    failure is kept (marked ``instruction_complete: false``) and a string that
    overruns the block is recorded as a malformed frame with the bytes that were
    actually available, as hex. A malformed frame is never completed or guessed;
  * records every incomplete walk as one skipped/ambiguous entry with its reason
    (unknown opcode, ambiguous menu framing, ambiguous count, truncated operand,
    or string overrun) and the undecoded tail's length and SHA-256.

Byte-count reading of code 0x80 (the decoder's reading, from
``docs/engine/research/ecl-opcode-spec-for-asm.md`` 2.2): ``high`` is the number
of packed payload bytes that follow the two-byte operand. This census inherits
that reading. The GoldBox wording is ambiguous, and ``docs/por-ecl-decoder.md``
records that a 6-bit reading stops much earlier. The census states this and does
not test the alternative.

Framing status of each string (mechanical):
  * ``before-first-menu``: the instruction precedes the first menu opcode in the
    walk. Both framings agree on this prefix.
  * ``spec-menu-frame``: the string belongs to a menu instruction (0x15 or 0x2B)
    decoded under ``spec-menus``. Its framing is the census-supported, not proven,
    reading from the second GoldBox source.
  * ``after-spec-menu``: the instruction follows a menu decoded under
    ``spec-menus``, so its boundaries depend on that unproven framing.

Duplicate block ids: several TOC entries can share one block id. Every TOC entry
is walked and recorded by TOC index. Duplicates are flagged, never merged, and
never selected by id.

Usage
  python3 tools/por_ecl_strings.py --install "G:/Games/Pool of Radiance/POOLRAD" \
      -o data/work/por-ecl-strings/retail

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_ecl_strings.json        schema openua.por-ecl-strings, playable: false
  por_ecl_strings_report.md   human-readable coverage, skipped frames and limits

Exit codes
  0  census written; every ECL archive present and every block decoded
  1  census written, but at least one archive is absent or a container, RLE,
     header or magic check failed (see "diagnostics"). Coverage is still
     reported; an incomplete walk is never read as an absence of strings.
  2  named refusal: bad install folder, ambiguous archive, unsafe output location

The source is opened "rb" and never written. Stdlib only, plus the helpers in
``tools/por_ecl.py``, ``tools/por_walls.py`` (archive lookup) and
``tools/por_convert.py`` (output guard).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

import por_ecl as pe
from por_convert import PorSourceError, validate_output_dir
from por_map import PorMapError
from por_walls import resolve_archive

SCHEMA = "openua.por-ecl-strings"
SCHEMA_VERSION = 1
STATUS = "census-only"
TOOL = "tools/por_ecl_strings.py"

ARCHIVE_STEM = "ECL"
ARCHIVES = tuple(range(1, 9))
FRAMINGS = pe.FRAMINGS
END_OF_BLOCK = "end-of-block"
STRING_CODE = 0x80
MENU_OPCODES = pe.MENU_OPCODES
PROBE_KINDS = ("truncated-operand", "ambiguous-count")

FS_BEFORE_MENU = "before-first-menu"
FS_SPEC_MENU = "spec-menu-frame"
FS_AFTER_SPEC_MENU = "after-spec-menu"

CLASSIFICATION_BASIS = (
    "string = operand code 0x80. The decoder's byte-count reading is kept: "
    "high = number of packed payload bytes after the two-byte operand "
    "(docs/engine/research/ecl-opcode-spec-for-asm.md 2.2; wording ambiguous). "
    "Payload bytes are preserved raw (hex and base64). No charset or text "
    "semantics are applied."
)
NOT_CLAIMED = [
    "no string is decoded as text, no charset or dictionary is applied",
    "no string is mapped to a FRUA message, event, or STRG resource",
    "no playable module, conversion, or route is produced",
    "string payloads are raw bytes; their meaning is not established",
    "a string not reached by a walk does not mean that no string exists there",
    "the 0x80 byte-count reading matches the retail 0x80 arm's count by static code reading "
    "(docs/por-ecl-length-xref.md); the walk's run-time reach of that code is not shown",
    "spec-menus framing is a census result, not proof; frames after it are flagged",
    "tail bytes after a stop are raw bytes and are never counted as strings",
    "a malformed string frame is recorded with the bytes available, never completed",
]


class StringCensusError(Exception):
    """A named refusal for the whole census (bad install or arguments)."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%02X" % v


# --------------------------------------------------------------------------
# Frames (raw payload preserved; no text semantics)
# --------------------------------------------------------------------------


def make_frame(block: bytes, operand_offset: int, declared: int) -> dict:
    """Describe one complete inline-string frame. The caller has checked that the
    declared payload lies inside the block; this re-checks it as an invariant."""
    p0 = operand_offset + 2
    payload = block[p0:p0 + declared]
    if block[operand_offset] != STRING_CODE or len(payload) != declared:
        raise pe.EclError("internal: string frame at %d does not match the block"
                          % operand_offset)
    return {
        "operand_offset": operand_offset,
        "declared_length": declared,
        "operand_total_length": 2 + declared,
        "payload_offset": p0,
        "payload_length": declared,
        "zero_length": declared == 0,
        "payload_hex": payload.hex(),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": _sha(payload),
    }


def _string_slots(inst: pe.Instruction):
    for slot, od in enumerate(inst.operands):
        if od["code"] == STRING_CODE:
            yield "operand", slot, od
    for k, od in enumerate(inst.count_operands):
        if od["code"] == STRING_CODE:
            yield "count", k, od


def _probe_read(block: bytes, pos: int, kind: str, slot: int, frames: list,
                failure: dict) -> Optional[pe.Operand]:
    """Read one operand inside a stopped instruction. Returns the parsed operand,
    or None after recording the failure in ``failure`` (first failure only).
    A valid string operand is appended to ``frames``."""
    try:
        o = pe.read_operand(block, pos)
    except pe.EclError as exc:
        if not failure:
            if pos + 2 <= len(block) and block[pos] == STRING_CODE:
                failure.update({
                    "reason": "string-overrun",
                    "block_offset": pos,
                    "slot_kind": kind,
                    "slot": slot,
                    "declared_length": block[pos + 1],
                    "available_bytes": len(block) - (pos + 2),
                    "partial_payload_hex": block[pos + 2:].hex(),
                    "detail": str(exc),
                })
            else:
                failure.update({
                    "reason": "truncated-fixed-operand",
                    "block_offset": pos,
                    "slot_kind": kind,
                    "slot": slot,
                    "detail": str(exc),
                })
        return None
    if o.code == STRING_CODE:
        fr = make_frame(block, o.offset, o.string_len)
        fr.update({"operand_kind": kind, "operand_slot": slot})
        frames.append(fr)
    return o


def probe_stop_instruction(block: bytes, stop: pe.Stop, framing: str) -> dict:
    """Walk, operand by operand, the one instruction where the walk stopped.

    Only truncated-operand and ambiguous-count stops are probed. The reads mirror
    ``por_ecl.walk_block`` so the failure point agrees with the walk. Valid
    strings read before the failure are returned (the caller marks them
    ``instruction_complete: false``). Nothing after the failure is read.
    """
    out: dict = {"frames": [], "failure": {}, "ambiguous_count": None, "mnemonic": None}
    if stop.kind not in PROBE_KINDS:
        return out
    op = block[stop.offset]
    mnemonic, wordset, count_at = pe.OPCODES[op]
    if op in MENU_OPCODES and framing == "spec-menus":
        mnemonic, wordset, count_at = pe.SPEC_MENU_FRAMING[op]
    out["mnemonic"] = mnemonic
    pos = stop.offset + 1
    fixed: list[pe.Operand] = []
    for slot in range(wordset):
        o = _probe_read(block, pos, "operand", slot, out["frames"], out["failure"])
        if o is None:
            return out
        fixed.append(o)
        pos += o.size
    if count_at is None:
        return out
    cnt_src = fixed[count_at]
    if cnt_src.code not in (0x00, 0x02):
        out["ambiguous_count"] = {"block_offset": stop.offset,
                                  "count_operand_code": "0x%02X" % cnt_src.code}
        out["failure"] = {"reason": "ambiguous-count", "block_offset": stop.offset,
                          "slot_kind": "operand", "slot": count_at,
                          "detail": "count operand has non-literal code 0x%02X" % cnt_src.code}
        return out
    count = cnt_src.word if cnt_src.code == 0x02 else cnt_src.high
    for k in range(count):
        o = _probe_read(block, pos, "count", k, out["frames"], out["failure"])
        if o is None:
            return out
        pos += o.size
    return out


# --------------------------------------------------------------------------
# One walk of one block in one framing
# --------------------------------------------------------------------------


def walk_frames(block: bytes, framing: str) -> tuple[dict, list[dict], list[dict]]:
    """Return (walk record, complete frames, skipped records) for one framing.

    Frames are the strings of decoded instructions (instruction_complete True) and
    the valid strings of the instruction where the walk stopped (False).
    """
    insts, _edges, stop = pe.walk_block(block, framing)
    decoded_end = pe.ECL_HEADER_LEN + sum(i.length for i in insts)
    tail = block[decoded_end:]
    complete = stop.kind == END_OF_BLOCK
    first_menu = next((k for k, i in enumerate(insts) if i.opcode in MENU_OPCODES), None)

    frames: list[dict] = []
    for k, inst in enumerate(insts):
        if inst.opcode in MENU_OPCODES:
            status = FS_SPEC_MENU
        elif first_menu is not None and k > first_menu:
            status = FS_AFTER_SPEC_MENU
        else:
            status = FS_BEFORE_MENU
        for kind, slot, od in _string_slots(inst):
            fr = make_frame(block, od["offset"], od["string_len"])
            fr.update({
                "operand_kind": kind,
                "operand_slot": slot,
                "framing_status": status,
                "instruction_index": k,
                "instruction_offset": inst.offset,
                "instruction_complete": True,
                "opcode": "0x%02X" % inst.opcode,
                "mnemonic": inst.mnemonic,
            })
            frames.append(fr)

    probe = probe_stop_instruction(block, stop, framing)
    for fr in probe["frames"]:
        stopped_is_menu = stop.opcode in MENU_OPCODES
        fr.update({
            "framing_status": (FS_SPEC_MENU if stopped_is_menu else
                               FS_AFTER_SPEC_MENU if first_menu is not None else FS_BEFORE_MENU),
            "instruction_index": len(insts),
            "instruction_offset": stop.offset,
            "instruction_complete": False,
            "opcode": _hex(stop.opcode),
            "mnemonic": probe["mnemonic"],
        })
        frames.append(fr)

    for fr in frames:
        fr["framing"] = framing

    skipped: list[dict] = []
    if not complete:
        reason = stop.kind
        detail = stop.detail
        malformed = probe["failure"].get("reason") == "string-overrun"
        if probe["failure"]:
            reason = probe["failure"]["reason"]
            detail = probe["failure"].get("detail", detail)
        rec = {
            "framing": framing,
            "reason": reason,
            "walk_stop_kind": stop.kind,
            "block_offset": stop.offset,
            "opcode": _hex(stop.opcode),
            "detail": detail,
            "string_frames_before_failure": len(probe["frames"]),
            "malformed_string_frame": malformed,
            "tail": {"offset": decoded_end, "length": len(tail), "sha256": _sha(tail),
                     "note": "raw bytes; not decoded; never counted as strings"},
        }
        if malformed:
            rec["malformed"] = {k: probe["failure"][k] for k in (
                "block_offset", "slot_kind", "slot", "declared_length",
                "available_bytes", "partial_payload_hex")}
        if probe["ambiguous_count"]:
            rec["ambiguous_count"] = probe["ambiguous_count"]
        skipped.append(rec)

    walk = {
        "framing": framing,
        "instructions": len(insts),
        "body_bytes": len(block) - pe.ECL_HEADER_LEN,
        "decoded_end": decoded_end,
        "complete": complete,
        "stop": {"kind": stop.kind, "offset": stop.offset, "opcode": _hex(stop.opcode),
                 "detail": stop.detail},
        "string_frames": sum(1 for f in frames if f["instruction_complete"]),
        "string_frames_incomplete_instruction": sum(
            1 for f in frames if not f["instruction_complete"]),
        "zero_length_frames": sum(1 for f in frames if f["zero_length"]),
        "malformed_string_frames": 1 if skipped and skipped[0]["malformed_string_frame"] else 0,
        "tail_bytes": len(tail),
    }
    return walk, frames, skipped


# --------------------------------------------------------------------------
# Archive and whole census
# --------------------------------------------------------------------------


def census_archive(path: Path, name: str) -> tuple[dict, list[dict], list[dict], list[dict]]:
    """Return (archive record, frames, skipped records, diagnostics) for one DAX."""
    data = path.read_bytes()
    file_sha = _sha(data)
    rec: dict = {"archive": name, "present": True, "file_bytes": len(data),
                 "file_sha256": file_sha, "container": "ok", "blocks": []}
    diags: list[dict] = []
    frames_all: list[dict] = []
    skipped_all: list[dict] = []
    try:
        entries, base = pe.parse_dax(data)
    except pe.EclError as exc:
        rec["container"] = "error"
        rec["container_error"] = str(exc)
        diags.append({"archive": name, "code": "container-error", "message": str(exc)})
        return rec, frames_all, skipped_all, diags

    ids: dict[int, list[int]] = {}
    for e in entries:
        ids.setdefault(e.block_id, []).append(e.index)

    for e in entries:
        start = base + e.data_offset
        comp = data[start:start + e.comp_size]
        same = sorted(ids[e.block_id])
        brec: dict = {"toc_index": e.index, "block_id": e.block_id,
                      "block_id_repeated": len(same) > 1,
                      "indices_with_block_id": same,
                      "data_offset": e.data_offset, "raw_size": e.raw_size,
                      "comp_size": e.comp_size}
        rec["blocks"].append(brec)
        try:
            block = pe.rle_decode(comp, e.raw_size)
        except pe.EclError as exc:
            brec["status"] = "rle-error"
            brec["error"] = str(exc)
            diags.append({"archive": name, "toc_index": e.index, "code": "rle-error",
                          "message": str(exc)})
            continue
        brec["decoded_sha256"] = _sha(block)
        if len(block) < 2 or int.from_bytes(block[0:2], "little") != pe.ECL_MAGIC:
            brec["status"] = "non-ecl"
            diags.append({"archive": name, "toc_index": e.index, "code": "non-ecl-block",
                          "message": "block does not start with the ECL magic word"})
            continue
        try:
            header = pe.parse_header(block)
        except pe.EclError as exc:
            brec["status"] = "header-error"
            brec["error"] = str(exc)
            diags.append({"archive": name, "toc_index": e.index, "code": "header-error",
                          "message": str(exc)})
            continue
        brec["status"] = "ok"
        brec["header_segments_all_expected"] = header["segment_all_expected"]
        brec["walks"] = {}
        for framing in FRAMINGS:
            walk, frames, skipped = walk_frames(block, framing)
            brec["walks"][framing] = walk
            for fr in frames:
                fr.update(_frame_provenance(name, file_sha, e, block))
            frames_all.extend(frames)
            for s in skipped:
                s.update(_frame_provenance(name, file_sha, e, block))
                s["frame_id"] = _skip_id(name, e.index, framing, s["block_offset"])
            skipped_all.extend(skipped)
    for fr in frames_all:
        fr["frame_id"] = "%s/toc%d/%s/0x%04X" % (name, fr["toc_index"], fr["framing"],
                                                fr["operand_offset"])
    return rec, frames_all, skipped_all, diags


def _frame_provenance(name: str, file_sha: str, e: pe.TocEntry, block: bytes) -> dict:
    return {"archive": name, "source_sha256": file_sha, "toc_index": e.index,
            "block_id": e.block_id, "data_offset": e.data_offset,
            "raw_size": e.raw_size, "comp_size": e.comp_size,
            "decoded_sha256": _sha(block)}


def _skip_id(name: str, toc_index: int, framing: str, offset: int) -> str:
    return "%s/toc%d/%s/0x%04X" % (name, toc_index, framing, offset)


def summarize(archives: list[dict], frames: list[dict], skipped: list[dict]) -> dict:
    per_framing: dict = {}
    for framing in FRAMINGS:
        walks = [b["walks"][framing] for a in archives for b in a["blocks"]
                 if b.get("status") == "ok" and framing in b.get("walks", {})]
        fr = [f for f in frames if f["framing"] == framing]
        sk = [s for s in skipped if s["framing"] == framing]
        per_framing[framing] = {
            "blocks_walked": len(walks),
            "complete_walks": sum(1 for w in walks if w["complete"]),
            "incomplete_walks": sum(1 for w in walks if not w["complete"]),
            "decoded_body_bytes": sum(w["decoded_end"] - pe.ECL_HEADER_LEN for w in walks),
            "body_bytes": sum(w["body_bytes"] for w in walks),
            "string_frames": sum(1 for f in fr if f["instruction_complete"]),
            "string_frames_incomplete_instruction": sum(
                1 for f in fr if not f["instruction_complete"]),
            "blocks_with_string_frames": len({(f["archive"], f["toc_index"]) for f in fr}),
            "zero_length_frames": sum(1 for f in fr if f["zero_length"]),
            "frames_before_first_menu": sum(1 for f in fr if f.get("framing_status") == FS_BEFORE_MENU),
            "frames_spec_menu": sum(1 for f in fr if f.get("framing_status") == FS_SPEC_MENU),
            "frames_after_spec_menu": sum(1 for f in fr if f.get("framing_status") == FS_AFTER_SPEC_MENU),
            "malformed_string_frames": sum(1 for s in sk if s["malformed_string_frame"]),
            "skipped_by_reason": _count_by(sk, "reason"),
            "tail_bytes": sum(w["tail_bytes"] for w in walks),
        }
    return {
        "archives_present": sum(1 for a in archives if a["present"]),
        "archives_absent": [a["archive"] for a in archives if not a["present"]],
        "blocks_total": sum(len(a["blocks"]) for a in archives),
        "blocks_ok": sum(1 for a in archives for b in a["blocks"] if b.get("status") == "ok"),
        "blocks_with_repeated_id": sum(1 for a in archives for b in a["blocks"]
                                       if b.get("block_id_repeated")),
        "per_framing": per_framing,
        "absence_rule": ("No string frame in a block is evidence of no strings there only when "
                         "its walk is complete. An incomplete walk is never evidence of absence."),
    }


def _count_by(items: list[dict], key: str) -> dict:
    out: dict = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return dict(sorted(out.items()))


def census(install: Path, out: Path) -> tuple[dict, int]:
    if not install.is_dir():
        raise StringCensusError("install folder not found")
    out = validate_output_dir(install, out)
    archives: list[dict] = []
    frames: list[dict] = []
    skipped: list[dict] = []
    diagnostics: list[dict] = []
    for n in ARCHIVES:
        name = "%s%d.DAX" % (ARCHIVE_STEM, n)
        path = resolve_archive(install, ARCHIVE_STEM, n)
        if path is None:
            archives.append({"archive": name, "present": False, "blocks": []})
            diagnostics.append({"archive": name, "code": "archive-absent",
                                "message": "archive not found in install or POOLRAD"})
            continue
        rec, frs, sks, diags = census_archive(path, name)
        archives.append(rec)
        frames.extend(frs)
        skipped.extend(sks)
        diagnostics.extend(diags)
    frames.sort(key=lambda f: (f["archive"], f["toc_index"], f["framing"], f["operand_offset"]))
    skipped.sort(key=lambda s: (s["archive"], s["toc_index"], s["framing"], s["block_offset"]))
    result = {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "tool": TOOL,
        "scope": {"operand_code": "0x%02X" % STRING_CODE,
                  "archives": ["%s%d.DAX" % (ARCHIVE_STEM, n) for n in ARCHIVES],
                  "framings": list(FRAMINGS),
                  "payload_encoding": "hex and base64, raw bytes; no text decoding"},
        "classification_basis": CLASSIFICATION_BASIS,
        "summary": summarize(archives, frames, skipped),
        "archives": archives,
        "string_frames": frames,
        "skipped_frames": skipped,
        "diagnostics": diagnostics,
        "not_claimed": NOT_CLAIMED,
    }
    return result, (1 if diagnostics else 0)


# --------------------------------------------------------------------------
# Markdown report (no payload bytes; counts and hashes only)
# --------------------------------------------------------------------------


def render_report(result: dict) -> str:
    s = result["summary"]
    lines: list[str] = []
    a = lines.append
    a("# Pool of Radiance inline-string (0x80) census")
    a("")
    a("**Status: CENSUS-ONLY. `playable: false`.** Raw string payloads are recorded in")
    a("`por_ecl_strings.json` as hex and base64. They are not decoded as text, and no")
    a("string is mapped to a FRUA message or event. This report has counts only.")
    a("")
    a("## Archives")
    a("")
    a("| Archive | Present | Bytes | SHA-256 | Container | Blocks | Blocks ok |")
    a("|---|---|---|---|---|---|---|")
    for ar in result["archives"]:
        if not ar["present"]:
            a("| %s | no | - | - | - | - | - |" % ar["archive"])
            continue
        ok = sum(1 for b in ar["blocks"] if b.get("status") == "ok")
        a("| %s | yes | %d | `%s` | %s | %d | %d |" % (
            ar["archive"], ar["file_bytes"], ar["file_sha256"], ar["container"],
            len(ar["blocks"]), ok))
    a("")
    a("## Coverage per framing")
    a("")
    a("| Framing | Blocks walked | Complete | Incomplete | Body bytes decoded / total | "
      "String frames | In stopped instruction | Zero-length | Malformed | Tail bytes |")
    a("|---|---|---|---|---|---|---|---|---|---|")
    for fr in result["scope"]["framings"]:
        p = s["per_framing"][fr]
        a("| %s | %d | %d | %d | %d / %d | %d | %d | %d | %d | %d |" % (
            fr, p["blocks_walked"], p["complete_walks"], p["incomplete_walks"],
            p["decoded_body_bytes"], p["body_bytes"], p["string_frames"],
            p["string_frames_incomplete_instruction"], p["zero_length_frames"],
            p["malformed_string_frames"], p["tail_bytes"]))
    a("")
    a("String frames by framing status:")
    a("")
    a("| Framing | Before first menu | Spec menu frame | After spec menu |")
    a("|---|---|---|---|")
    for fr in result["scope"]["framings"]:
        p = s["per_framing"][fr]
        a("| %s | %d | %d | %d |" % (fr, p["frames_before_first_menu"],
                                    p["frames_spec_menu"], p["frames_after_spec_menu"]))
    a("")
    a("## Duplicate block ids")
    a("")
    a("Blocks sharing an id within one archive are all walked and recorded by TOC index.")
    a("")
    dups = [(ar["archive"], b) for ar in result["archives"] for b in ar.get("blocks", [])
            if b.get("block_id_repeated")]
    if not dups:
        a("None.")
    else:
        a("| Archive | Block id | TOC indices |")
        a("|---|---|---|")
        seen = set()
        for arch, b in dups:
            key = (arch, b["block_id"])
            if key in seen:
                continue
            seen.add(key)
            a("| %s | %d | %s |" % (arch, b["block_id"],
                                   ", ".join(str(i) for i in b["indices_with_block_id"])))
    a("")
    a("## Skipped and ambiguous frames")
    a("")
    if not result["skipped_frames"]:
        a("None. Every walk reached end-of-block.")
    else:
        a("| Frame | Framing | Reason | Walk stop | Offset | Opcode | Strings before failure | Malformed |")
        a("|---|---|---|---|---|---|---|---|")
        for sk in result["skipped_frames"]:
            a("| %s | %s | %s | %s | %d | %s | %d | %s |" % (
                "%s toc %d block %d" % (sk["archive"], sk["toc_index"], sk["block_id"]),
                sk["framing"], sk["reason"], sk["walk_stop_kind"], sk["block_offset"],
                sk["opcode"] or "-", sk["string_frames_before_failure"],
                "yes" if sk["malformed_string_frame"] else "no"))
    a("")
    a("## Diagnostics")
    a("")
    if not result["diagnostics"]:
        a("None.")
    else:
        for d in result["diagnostics"]:
            where = d["archive"] + ("" if "toc_index" not in d else " TOC %d" % d["toc_index"])
            a("- %s: `%s`: %s" % (where, d["code"], d["message"]))
    a("")
    a("## Basis")
    a("")
    a("- %s" % result["classification_basis"])
    a("- Absence rule: %s" % s["absence_rule"])
    a("")
    a("## Not claimed")
    a("")
    for item in result["not_claimed"]:
        a("- %s" % item)
    a("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def write_outputs(result: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_ecl_strings.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_ecl_strings_report.md").write_text(
        render_report(result), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance inline-string (0x80) census across ECL1..ECL8 (read-only).")
    ap.add_argument("--install", required=True,
                    help="PoR install folder (ECL<n>.DAX here or in its POOLRAD subfolder)")
    ap.add_argument("-o", "--out", required=True,
                    help="output folder (outside the install; inside the repo only under data/)")
    args = ap.parse_args(argv)
    out = Path(args.out)
    try:
        result, code = census(Path(args.install), out)
        write_outputs(result, out)
    except (StringCensusError, PorSourceError, PorMapError, pe.EclError) as exc:
        print("por_ecl_strings: error: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s and %s (%s, playable=false; %d string frames; %d skipped; %d diagnostics)"
          % (out / "por_ecl_strings.json", out / "por_ecl_strings_report.md", STATUS,
             len(result["string_frames"]), len(result["skipped_frames"]),
             len(result["diagnostics"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
