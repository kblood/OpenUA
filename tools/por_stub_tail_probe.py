#!/usr/bin/env python3
"""Pool of Radiance: the fifth byte of each VROOMM stub slot (static, observe-only).

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only, playable: false.

A stub slot is ``CD 3F <proc lo> <proc hi> <tail>``. The resolver (tools/por_farcall_resolve.py)
treats only a zero tail as well-formed, which makes a group "partial" when a slot's tail is nonzero.
This probe asks what the tail byte is doing, keeping the evidence classes apart:

  raw pattern          bytes at a fixed place (slot tails, group pre/gap/trailer blocks, the
                       INT 3Fh vector install in START.EXE)
  decoded reference    a call_far that a complete walk from a prologue decodes, read under the
                       zero-skew image model (phys = header + seg*16 + off), landing on a
                       stub start or a stub tail
  structural           placement of nonzero tails in the group layout and the alignment test
  runtime unknown      whether INT 3Fh reads or advances past the tail. Not decidable here.

It does NOT decide whether a nonzero tail is malformed. It reports the placement, the tested
relations and the decoded references, and states what is still open.

Usage
  tools/.venv/Scripts/python.exe -I tools/por_stub_tail_probe.py \
      --install "PATH/TO/POOLRAD" -o data/work/por-stub-tail-byte

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_stub_tail_byte.json
  por_stub_tail_byte_report.md

Exit codes
  0  the probe ran and wrote its outputs
  2  named refusal: bad install, a file not matching its pin, or unsafe output location
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

SCHEMA = "openua.por-stub-tail-byte"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_stub_tail_probe.py"
PRO = fr.PROLOGUES
STUB_LEN = fr.STUB_LEN
# Pre-stub block, 5 bytes at header+0x11, keyed by the stub delta it belongs to.
PRE_BLOCK = {0x16: bytes([0xB2, 0x00, 0x11, 0x00, 0xB0]), 0x17: bytes([0xB2, 0x00, 0x10, 0x00, 0xB0])}
# The INT 3Fh vector install in START.EXE: mov dx,0x2e6 ; push cs ; pop ds ; mov ax,0x253f ; int 21h
VEC_DX_OFF = 0xA7E9
VEC_AX_OFF = 0xA7EE
VEC_INT21_OFF = 0xA7F1
HANDLER_OFF = 0x02E6
GAME_NAME_LEN_BYTE = 0x08


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_install(install: Path, allow_unpinned: bool = False) -> tuple[bytes, bytes, dict]:
    ovr_p = fr.find_file(install, fr.OVR_NAME)
    exe_p = fr.find_file(install, fr.EXE_NAME)
    ovr = ovr_p.read_bytes()
    start = exe_p.read_bytes()
    pins = {}
    for name, data in ((fr.OVR_NAME, ovr), (fr.EXE_NAME, start)):
        size, sha = fr.PINNED[name]
        ok = len(data) == size and _sha(data) == sha
        pins[name] = {"size": len(data), "sha256": _sha(data), "pin_match": ok}
        if not ok and not allow_unpinned:
            raise PorSourceError("%s does not match its pinned size and SHA-256 "
                                 "(use --allow-unpinned; the output is not retail evidence)" % name)
    return ovr, start, pins


def _trailer_class(b: bytes) -> str:
    if b == bytes(5):
        return "zero"
    if len(b) == 5 and b[0] == 0xB2 and b[1] == 0x00 and b[3] == 0x00 and b[4] == 0xB0:
        return "b2-00-XX-00-b0"
    return "other"


def all_groups(start: bytes, ovr: bytes) -> tuple[list[dict], dict]:
    """Accepted then partial groups, each with a status, sorted by header offset."""
    s = fr.scan_all(start, ovr)
    groups = []
    for g in s["groups"] + s["partial_groups"]:
        g = dict(g)
        g["is_partial"] = g["status"] == "partial"
        groups.append(g)
    groups.sort(key=lambda g: g["header_offset"])
    return groups, s


def _post_block(start: bytes, se: int) -> dict:
    """What follows a group's stub run (raw pattern). A 5-byte ``b2 00 XX 00 b0`` trailer may sit
    at the stub end (gap 0) or one byte later (gap 1, that byte recorded). Otherwise the stub end
    holds zero padding and then a header magic or other bytes."""
    if _trailer_class(start[se:se + 5]) == "b2-00-XX-00-b0":
        return {"kind": "b2-trailer", "gap_bytes": "", "gap_len": 0, "trailer": start[se:se + 5]}
    if _trailer_class(start[se + 1:se + 6]) == "b2-00-XX-00-b0":
        return {"kind": "b2-trailer", "gap_bytes": "%02x" % start[se], "gap_len": 1,
                "trailer": start[se + 1:se + 6]}
    z = 0
    while z < 16 and start[se + z] == 0:
        z += 1
    if start[se + z:se + z + 4] == fr.DESC_MAGIC:
        return {"kind": "zero-run-then-header" if z else "header-direct", "gap_bytes": "00 " * z,
                "gap_len": z, "trailer": b""}
    return {"kind": "other", "gap_bytes": "", "gap_len": 0, "trailer": b""}


def layout(start: bytes, ovr: bytes, groups: list[dict]) -> list[dict]:
    """Per-group raw pattern: pre-block, what follows the stub run, alignment scores."""
    headers = [g["header_offset"] for g in groups]
    rows = []
    for i, g in enumerate(groups):
        h = g["header_offset"]
        delta = g["stub_delta"]
        pre = start[g["stub_start"] - 5:g["stub_start"]]   # 5 bytes just before the stub run
        post = _post_block(start, g["stub_end"])
        nxt = headers[i + 1] if i + 1 < len(headers) else None
        trailer = post["trailer"]
        rows.append({
            "header_offset": h,
            "status": g["status"],
            "fileofs": g["fileofs"],
            "stub_count": g["stub_count"],
            "stub_delta": delta,
            "stub_start": g["stub_start"],
            "stub_end": g["stub_end"],
            "pre_block": pre.hex(" "),
            "pre_block_matches_delta": pre == PRE_BLOCK[delta],
            "post_kind": post["kind"],
            "gap_bytes": post["gap_bytes"].strip(),
            "gap_len": post["gap_len"],
            "trailer": trailer.hex(" ") if trailer else "",
            "trailer_xx": trailer[2] if trailer else None,
            "next_header": nxt,
            # Both alignments scored for every group (the resolver scores both and keeps the better).
            "alignment_scores": {str(d): _alignment_score(start, h, d, ovr) for d in fr.STUB_DELTAS},
        })
    return rows


def _alignment_score(start: bytes, h: int, delta: int, ovr: bytes) -> Optional[int]:
    """Well-formed slot count of the run at header+delta, using the group's own jmpcnt."""
    fields = fr._header_fields(start, ovr, h, 8 if ovr[:4] == b"FBOV" else 4)
    if fields is None:
        return None
    cand = fr._alignment_candidate(start, ovr, h, delta, fields)
    return None if cand is None else cand["valid_stub_count"]


def slot_table(start: bytes, ovr: bytes, groups: list[dict]) -> list[dict]:
    rows = []
    for g in groups:
        n = g["stub_count"]
        for k in range(n):
            base = g["stub_start"] + STUB_LEN * k
            tail = start[base + 4]
            proc = g["procs"][k]
            target = g["fileofs"] + proc
            rows.append({
                "header_offset": g["header_offset"],
                "status": g["status"],
                "index": k,
                "stub_start": base,
                "stub_image_addr": base,
                "is_last": k == n - 1,
                "valid": bool(g["stub_valid"][k]),
                "proc": proc,
                "target": target,
                "target_prologue": ovr[target:target + 3] in PRO if target + 3 <= len(ovr) else False,
                "target_fourth_byte": ovr[target + 3] if target + 3 <= len(ovr) else None,
                "tail": tail,
                "tail_nonzero": tail != 0,
                "tail_phys": base + 4,
                "group_fileofs": g["fileofs"],
                "group_codesz": g["codesz"],
                "group_fixupsz": g["fixupsz"],
                "group_stub_count": n,
                "group_stub_delta": g["stub_delta"],
            })
    return rows


def tail_summary(slots: list[dict]) -> dict:
    nz = [s for s in slots if s["tail_nonzero"]]
    return {
        "slots": len(slots),
        "nonzero_tails": len(nz),
        "nonzero_tails_at_last_slot": sum(1 for s in nz if s["is_last"]),
        "nonzero_tails_in_partial_groups": sum(1 for s in nz if s["status"] == "partial"),
        "nonzero_tails_in_accepted_groups": sum(1 for s in nz if s["status"] == "well-formed"),
        "nonzero_non_last_slots": sum(1 for s in nz if not s["is_last"]),
        "accepted_last_slots": sum(1 for s in slots if s["status"] == "well-formed" and s["is_last"]),
        "accepted_last_slots_tail_zero": sum(1 for s in slots if s["status"] == "well-formed"
                                             and s["is_last"] and not s["tail_nonzero"]),
        "partial_last_slots": sum(1 for s in slots if s["status"] == "partial" and s["is_last"]),
        "partial_last_slots_tail_nonzero": sum(1 for s in slots if s["status"] == "partial"
                                               and s["is_last"] and s["tail_nonzero"]),
        "nonzero_values": sorted("0x%02x" % s["tail"] for s in nz),
        "nonzero_tail_slots": [
            {"header_offset": s["header_offset"], "index": s["index"], "n": s["group_stub_count"],
             "tail": "0x%02x" % s["tail"], "tail_phys": "0x%x" % s["tail_phys"],
             "proc": "0x%04x" % s["proc"], "target": "0x%x" % s["target"],
             "target_prologue": s["target_prologue"]} for s in nz],
    }


def relations(slots: list[dict], lay: list[dict]) -> list[dict]:
    """Does each nonzero tail equal some simple per-slot or per-group byte? Each row is a
    one-in-256 coincidence per slot, so zero hits is weak evidence either way."""
    nz = [s for s in slots if s["tail_nonzero"]]
    by_h = {r["header_offset"]: r for r in lay}
    tests = {
        "proc lo": lambda s: s["proc"] & 0xFF,
        "proc hi": lambda s: s["proc"] >> 8,
        "stub count": lambda s: s["group_stub_count"],
        "slot index": lambda s: s["index"],
        "codesz lo": lambda s: s["group_codesz"] & 0xFF,
        "fixupsz lo": lambda s: s["group_fixupsz"] & 0xFF,
        "fileofs lo": lambda s: s["group_fileofs"] & 0xFF,
        "fileofs hi": lambda s: (s["group_fileofs"] >> 8) & 0xFF,
        "target byte +3": lambda s: s["target_fourth_byte"],
        "trailer XX": lambda s: by_h[s["header_offset"]]["trailer_xx"],
    }
    out = []
    for name, f in tests.items():
        eq = 0
        for s in nz:
            v = f(s)
            if v is not None and v == s["tail"]:
                eq += 1
        out.append({"relation": name, "equal": eq, "of": len(nz)})
    return out


def prologue_by_class(slots: list[dict]) -> dict:
    def pick(pred):
        xs = [s for s in slots if pred(s)]
        return {"slots": len(xs), "prologue_at_fo_plus_proc": sum(1 for s in xs if s["target_prologue"])}
    return {
        "accepted_zero_tail": pick(lambda s: s["status"] == "well-formed" and not s["tail_nonzero"]),
        "partial_zero_tail": pick(lambda s: s["status"] == "partial" and not s["tail_nonzero"]),
        "partial_nonzero_tail": pick(lambda s: s["status"] == "partial" and s["tail_nonzero"]),
    }


def prologue_density(ovr: bytes, groups: list[dict]) -> dict:
    bodies = [(g["fileofs"], g["fileofs"] + g["codesz"]) for g in groups]
    total = sum(hi - lo for lo, hi in bodies)
    hits = sum(1 for lo, hi in bodies for o in range(lo, max(lo, hi - 3))
               if ovr[o:o + 3] in PRO)
    return {"prologues": hits, "body_bytes": total, "density": hits / total if total else None}


def decoded_refs(ovr: bytes, start: bytes, slots: list[dict], hdr: int) -> dict:
    """call_far sites decoded by lh.walk from each slot's prologue target (complete walks only).
    Each site is classified under the zero-skew image model: phys = hdr + seg*16 + off."""
    stub_start = {s["stub_start"]: s for s in slots}
    stub_tail = {s["stub_start"] + 4: s for s in slots}
    sites: dict[int, dict] = {}
    walks_complete = 0
    walks = 0
    targets = sorted({s["target"] for s in slots if s["target_prologue"]})
    for tgt in targets:
        w = lh.walk(ovr, tgt)
        walks += 1
        if w["complete"]:
            walks_complete += 1
        for c in w["far_calls"]:
            at = c["at"]
            phys = hdr + c["seg"] * 16 + c["off"]
            if at in sites:
                sites[at]["walk_entries"].append(tgt)
                continue
            if phys in stub_start:
                cls, s = "stub-start", stub_start[phys]
            elif phys in stub_tail:
                cls, s = "stub-tail", stub_tail[phys]
            else:
                cls, s = "other", None
            rec = {"at": at, "seg": c["seg"], "off": c["off"], "phys": phys, "class": cls,
                   "walk_entries": [tgt], "walk_complete": w["complete"]}
            if s is not None:
                rec.update({"group_header": s["header_offset"], "group_status": s["status"],
                            "slot_index": s["index"], "slot_tail": s["tail"],
                            "slot_tail_nonzero": s["tail_nonzero"]})
            sites[at] = rec
    per_class = collections.Counter(r["class"] for r in sites.values())
    tail_hits = [r for r in sites.values() if r["class"] == "stub-tail"]
    start_hits = [r for r in sites.values() if r["class"] == "stub-start"]
    return {
        "walk_targets": walks,
        "complete_walks": walks_complete,
        "unique_call_far_sites": len(sites),
        "by_class": dict(sorted(per_class.items())),
        "stub_start_hits": sorted(({"at": "0x%x" % r["at"], "phys": "0x%x" % r["phys"],
                                    "group_header": "0x%x" % r["group_header"], "slot_index": r["slot_index"],
                                    "group_status": r["group_status"]} for r in start_hits),
                                  key=lambda x: x["at"]),
        "stub_tail_hits": sorted(({"at": "0x%x" % r["at"], "phys": "0x%x" % r["phys"],
                                   "group_header": "0x%x" % r["group_header"], "slot_index": r["slot_index"],
                                   "group_status": r["group_status"], "slot_tail": "0x%02x" % r["slot_tail"],
                                   "slot_tail_nonzero": r["slot_tail_nonzero"]} for r in tail_hits),
                                 key=lambda x: x["at"]),
        "stub_tail_hits_on_nonzero_tails": sum(1 for r in tail_hits if r["slot_tail_nonzero"]),
    }


def handler_evidence(start: bytes, hdr: int) -> dict:
    """Raw pattern only. The handler's code segment is not recovered, so no read is attributed."""
    ok_setup = (start[VEC_DX_OFF:VEC_DX_OFF + 3] == b"\xba\xe6\x02"
                and start[VEC_AX_OFF:VEC_AX_OFF + 3] == b"\xb8\x3f\x25"
                and start[VEC_INT21_OFF:VEC_INT21_OFF + 2] == b"\xcd\x21")
    f = struct.unpack_from("<14H", start, 2)
    relocs = f[2]
    cs_ip = (f[10], f[9])
    forms = {"mov al,[si+2]": b"\x8a\x44\x02", "mov al,[si+4]": b"\x8a\x44\x04",
             "mov al,[bx+2]": b"\x8a\x47\x02", "mov al,[bx+4]": b"\x8a\x47\x04",
             "mov al,[di+2]": b"\x8a\x45\x02", "mov al,[di+4]": b"\x8a\x45\x04",
             "lodsw": b"\xad", "lodsb": b"\xac", "mov reg,[bp+2]": None}
    counts = {}
    for name, pat in forms.items():
        if pat is None:
            counts[name] = sum(start.count(bytes([0x8B, r, 0x02])) for r in (0x76, 0x5E, 0x56, 0x46, 0x7E, 0x4E))
        else:
            counts[name] = start.count(pat)
    return {
        "setup_pattern_matches": ok_setup,
        "setup_file_offsets": {"mov_dx_handler": "0x%x" % VEC_DX_OFF, "mov_ax_253f": "0x%x" % VEC_AX_OFF,
                               "int21": "0x%x" % VEC_INT21_OFF},
        "handler_offset_cs_relative": "0x%x" % HANDLER_OFF,
        "mz_relocation_count": relocs,
        "mz_entry_cs_ip": {"cs": "0x%x" % cs_ip[0], "ip": "0x%x" % cs_ip[1]},
        "code_segment_of_setup": "unresolved",
        "byte_load_forms_in_START_EXE": counts,
        "attributed_to_tail_read": None,
    }


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    ovr, start, pins = load_install(install, allow_unpinned)
    hdr = fr.mz_image_base(start)
    groups, scan = all_groups(start, ovr)
    lay = layout(start, ovr, groups)
    slots = slot_table(start, ovr, groups)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "source": {"pins": pins, "all_pins_match": all(v["pin_match"] for v in pins.values()),
                   "image_base": hdr},
        "assumptions": [
            "Far-call seg:off resolves to hdr + seg*16 + off (zero-skew image model, as in the resolver).",
            "A stub's proc is relative to its group's fileofs (prologue-checked, as in the resolver).",
        ],
        "evidence_classes": {
            "raw_pattern": ["tail bytes", "pre-stub block", "gap and trailer bytes", "INT 3Fh vector install bytes"],
            "decoded_reference": ["call_far from complete walks (lh.walk), zero-skew classification"],
            "structural": ["nonzero-tail placement", "alignment scores", "trailer family", "relations tested"],
            "runtime_unknown": ["whether INT 3Fh reads or advances past the tail"],
        },
        "groups": {"count": len(groups),
                   "accepted": sum(1 for g in groups if not g["is_partial"]),
                   "partial": sum(1 for g in groups if g["is_partial"]),
                   "pre_block_matches_delta": sum(1 for r in lay if r["pre_block_matches_delta"]),
                   "post_kind_counts": dict(sorted(collections.Counter(
                       "%s|%s|gap%d" % (r["status"], r["post_kind"], r["gap_len"]) for r in lay).items())),
                   "layout": lay},
        "tail_summary": tail_summary(slots),
        "prologue_by_class": prologue_by_class(slots),
        "prologue_density_in_group_bodies": prologue_density(ovr, groups),
        "relations_tested_on_nonzero_tails": relations(slots, lay),
        "decoded_references": decoded_refs(ovr, start, slots, hdr),
        "handler": handler_evidence(start, hdr),
        "scan_notes": scan["notes"],
        "not_established": [
            "Whether a nonzero tail is a genuine malformed marker or a real field. Placement and prologue targets do not decide it.",
            "The meaning of the tail byte. None of the tested relations (proc bytes, counts, fileofs/codesz/fixupsz bytes, target byte, trailer XX) matches.",
            "Whether INT 3Fh reads the tail. The handler's code segment is not recovered, so no read is attributed.",
            "Whether the zero-skew image model holds for every far-call segment. The decoded stub-tail hits depend on it.",
        ],
    }
    write_outputs(doc, out)
    return doc, 0


def render_report(doc: dict) -> str:
    ts = doc["tail_summary"]
    dr = doc["decoded_references"]
    lines = [
        "# PoR stub slot tail byte (static probe)",
        "",
        "Status: %s, playable: %s." % (doc["status"], str(doc["playable"]).lower()),
        "",
        "## Pins",
        "",
    ]
    for name, v in sorted(doc["source"]["pins"].items()):
        lines.append("- `%s`: %d bytes, sha256 `%s`, pin match %s" % (name, v["size"], v["sha256"], str(v["pin_match"]).lower()))
    lines += ["", "## Raw pattern: tail bytes", "",
              "- slots: %d; nonzero tails: %d (values %s)" % (ts["slots"], ts["nonzero_tails"], ", ".join(ts["nonzero_values"]) or "-"),
              "- nonzero tails at the last slot of a group: %d of %d" % (ts["nonzero_tails_at_last_slot"], ts["nonzero_tails"]),
              "- nonzero tails in partial groups: %d; in accepted groups: %d; non-last nonzero: %d"
              % (ts["nonzero_tails_in_partial_groups"], ts["nonzero_tails_in_accepted_groups"], ts["nonzero_non_last_slots"]),
              "- accepted last slots with tail zero: %d of %d; partial last slots with tail nonzero: %d of %d"
              % (ts["accepted_last_slots_tail_zero"], ts["accepted_last_slots"],
                 ts["partial_last_slots_tail_nonzero"], ts["partial_last_slots"]),
              "", "| header | slot | stubs | tail | tail image addr | proc | target | target prologue |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in ts["nonzero_tail_slots"]:
        lines.append("| %s | %d | %d | %s | %s | %s | %s | %s |" % (
            "0x%x" % r["header_offset"], r["index"], r["n"], r["tail"], r["tail_phys"], r["proc"], r["target"],
            str(r["target_prologue"]).lower()))
    pc = doc["prologue_by_class"]
    lines += ["", "## Structural: prologue hits by class", "",
              "| class | slots | prologue at fileofs+proc |", "| --- | --- | --- |"]
    for k in ("accepted_zero_tail", "partial_zero_tail", "partial_nonzero_tail"):
        lines.append("| %s | %d | %d |" % (k, pc[k]["slots"], pc[k]["prologue_at_fo_plus_proc"]))
    pd = doc["prologue_density_in_group_bodies"]
    lines += ["", "Prologue density in group bodies: %d of %d bytes (%.4f)." % (pd["prologues"], pd["body_bytes"], pd["density"] or 0)]
    lines += ["", "## Structural: relations tested on nonzero tails", "",
              "| relation | equal | of |", "| --- | --- | --- |"]
    for r in doc["relations_tested_on_nonzero_tails"]:
        lines.append("| %s | %d | %d |" % (r["relation"], r["equal"], r["of"]))
    lines += ["", "## Decoded reference (zero-skew model)", "",
              "- walk targets: %d; complete walks: %d; unique call_far sites: %d; by class: %s"
              % (dr["walk_targets"], dr["complete_walks"], dr["unique_call_far_sites"], dr["by_class"]),
              "- stub-start hits: %d; stub-tail hits: %d; stub-tail hits on NONZERO tails: %d"
              % (len(dr["stub_start_hits"]), len(dr["stub_tail_hits"]), dr["stub_tail_hits_on_nonzero_tails"]),
              "", "| site | phys | class | group | slot | group status | tail |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in dr["stub_tail_hits"]:
        lines.append("| %s | %s | stub-tail | %s | %d | %s | %s |" % (
            r["at"], r["phys"], r["group_header"], r["slot_index"], r["group_status"], r["slot_tail"]))
    hd = doc["handler"]
    lines += ["", "## Raw pattern: INT 3Fh vector install and handler", "",
              "- setup bytes match at 0x%x / 0x%x / 0x%x: %s" % (
                  VEC_DX_OFF, VEC_AX_OFF, VEC_INT21_OFF, str(hd["setup_pattern_matches"]).lower()),
              "- handler CS:0x%s; code segment of setup: %s; MZ relocations: %d; entry CS:IP %s:%s"
              % (hd["handler_offset_cs_relative"][2:], hd["code_segment_of_setup"], hd["mz_relocation_count"],
                 hd["mz_entry_cs_ip"]["cs"], hd["mz_entry_cs_ip"]["ip"]),
              "- byte-load forms in START.EXE (raw count): %s" % hd["byte_load_forms_in_START_EXE"],
              "- attributed tail read: none", "", "## Not established", ""]
    lines += ["- %s" % x for x in doc["not_established"]]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_stub_tail_byte.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_stub_tail_byte_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="user-supplied PoR install folder (read-only)")
    ap.add_argument("-o", "--out", required=True, help="output folder (outside the install)")
    ap.add_argument("--allow-unpinned", action="store_true")
    args = ap.parse_args(argv)
    try:
        out = validate_output_dir(Path(args.install), Path(args.out))
        doc, code = probe(Path(args.install), out, allow_unpinned=args.allow_unpinned)
    except PorSourceError as exc:
        print("por_stub_tail_probe: error: %s" % exc, file=sys.stderr)
        return 2
    ts = doc["tail_summary"]
    print("wrote %s and %s (static-probe-only, playable=false; slots %d, nonzero tails %d, "
          "all at last slot of partial groups: %s)" % (
              out / "por_stub_tail_byte.json", out / "por_stub_tail_byte_report.md", ts["slots"],
              ts["nonzero_tails"], ts["nonzero_tails_at_last_slot"] == ts["nonzero_tails"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
