#!/usr/bin/env python3
"""Read-only identity and bounded-consumer probe for the PoR far call 03D5:0034.

Five writers of DGROUP 0x6AB1 in GAME.OVR each call the literal 9A 34 00 D5 03
(seg 0x03D5, off 0x0034) and store AL. This probe asks what that call reaches.

Static part: finds every literal site, the overlay group that holds it, and whether
its segment word is fixup-listed. The loader patches that word, so the file alone
cannot name the target.

Dump part (optional, read-only): maps each caller group uniquely into a raw RAM dump
(tools/por_overlay_group_map.py), reads the live segment word at each mapped site,
and asks which START.EXE bytes the live target equals. A target is named only when
its 16 bytes occur exactly once in START.EXE, and that offset lies in a VROOMM stub
run. The stub names the overlay group and procedure; the procedure is decoded with
tools/por_loadpieces_handler.py. No segment-base model is fitted or promoted.

Output: one JSON report and one Markdown summary under data/work/. The probe does
not start an emulator, does not write to the install, and states playable: false and
consumer_established: false.

Usage:
    python tools/por_geo_callee_identity_probe.py --install PATH/TO/POOLRAD \
        [--dump data/work/por-live-memory-pid34644/ram-000000-100000.bin] \
        [-o data/work/por-geo-callee-identity-probe]

Exit: 0 identity established by live bytes and callee decoded; 1 a check did not hold
(reported in the JSON); 2 named refusal (unpinned input, bad dump, output outside
data/work, output inside the install).
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

import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
from por_convert import PorSourceError  # noqa: E402

SCHEMA = "openua.por-geo-callee-identity-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "callee-identity-probe-only"
TOOL = "tools/por_geo_callee_identity_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-callee-identity-probe"

OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME
PINS = om.PINS

CALL_SEG = 0x03D5
CALL_OFF = 0x0034
LITERAL = bytes([0x9A, CALL_OFF & 0xFF, CALL_OFF >> 8, CALL_SEG & 0xFF, CALL_SEG >> 8])
WINDOW = 16                     # bytes compared for identity (the 32-byte window is reported too)
WINDOW_WIDE = 32
STUB_LEN = 5
STUB_MAGIC = b"\xcd\x3f"
DGROUP_PTR = 0x6A5C             # far pointer read by the callee and its helper (les di,[6a5c])
GUARD_FLAG = 0x84DC             # byte gate read by the helper; 0 or 0x0A forces a zero return
GUARD_VALUES = (0x00, 0x0A)
CLAMP_MAX = 0x0F
PLANE_READ_DISP = 0x200         # callee: es:[di+0x200] with di = 16*y + x
HELPER_WALK = 300
CALLEE_WALK = 400

NOT_ESTABLISHED = [
    "that the value at DGROUP 0x6A5C (the far pointer) is the GEO block base, or block base + 2",
    "the DGROUP segment in the dump, and so the live value of 0x6A5C",
    "that the guard flag at DGROUP 0x84DC has the value the callee sees at any instant",
    "that any caller group or the callee was executed, or reached by control flow",
    "that the dump is an atomic snapshot (the GameLink client declares it non-atomic)",
    "that the live segment word equals the loader's rewrite rule at any instant after the dump",
    "the meaning of the guard flag at DGROUP 0x84DC (only its 0 and 0x0A cases are decoded)",
    "the meaning of ECL opcode 0x2D, which reaches the writers through the dispatcher",
    "the GAME.OVR group that holds file 0x2DD22: its containment in the accepted +0x17 group 0x2DB87 "
    "is a range check, not a verified descriptor",
    "any GEO plane-2 link: the callee's return value is not compared with plane 2 of any block",
]


Refusal = om.Refusal          # a named refusal: no output is produced for this input


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def check_pins(ovr: bytes, exe: bytes, pins: dict) -> dict:
    """Refuse unless both files match their pins. There is no override in this tool."""
    rows = {}
    for name, data in ((OVR_NAME, ovr), (EXE_NAME, exe)):
        pin = pins[name]
        ok = len(data) == pin["size"] and _sha(data) == pin["sha256"]
        if not ok:
            raise Refusal("%s does not match its pin (size %d); refusing unpinned input" % (name, len(data)))
        rows[name] = {"size": len(data), "sha256": _sha(data), "pinned": True}
    return rows


def all_groups(exe: bytes, ovr: bytes) -> list[dict]:
    """Accepted and partial VROOMM groups from the farcall resolver (candidates, not verdicts)."""
    groups = [dict(g, status="well-formed") for g in fr.scan_groups(exe, ovr)]
    groups += [dict(g) for g in fr.scan_partial_groups(exe, ovr)]
    return groups


def find_literal_sites(ovr: bytes) -> list[int]:
    sites, pos = [], ovr.find(LITERAL)
    while pos != -1:
        sites.append(pos)
        pos = ovr.find(LITERAL, pos + 1)
    return sites


def owner_group(groups: list[dict], file_off: int) -> Optional[dict]:
    """The group whose code range [fileofs, fileofs+codesz) holds a GAME.OVR file offset."""
    hits = [g for g in groups if g["fileofs"] <= file_off < g["fileofs"] + g["codesz"]]
    if len(hits) > 1:
        raise Refusal("file offset 0x%X lies in %d groups; ambiguous" % (file_off, len(hits)))
    return hits[0] if hits else None


def site_rows(ovr: bytes, groups: list[dict]) -> list[dict]:
    rows = []
    for s in find_literal_sites(ovr):
        g = owner_group(groups, s)
        row = {"file_offset": s, "file_offset_hex": "0x%X" % s,
               "literal": LITERAL.hex(" "), "group": None, "body_offset": None,
               "seg_word_fixup_listed": None}
        if g is not None:
            body = s - g["fileofs"]
            fixups = om.read_fixups(ovr, {"fileofs": g["fileofs"], "codesz": g["codesz"],
                                          "fixupsz": g["fixupsz"]})
            row.update({
                "group": {"fileofs": g["fileofs"], "codesz": g["codesz"],
                          "header_offset": g["header_offset"], "status": g["status"]},
                "body_offset": body,
                "seg_word_fixup_listed": (body + 3) in fixups,
            })
        rows.append(row)
    return rows


def map_caller_group(ovr: bytes, group: dict, dump: om.Dump) -> dict:
    code = ovr[group["fileofs"]:group["fileofs"] + group["codesz"]]
    fixups = om.read_fixups(ovr, {"fileofs": group["fileofs"], "codesz": group["codesz"],
                                  "fixupsz": group["fixupsz"]})
    return om.map_group({"fileofs": group["fileofs"]}, code, fixups, dump)


def read_live_site(dump: om.Dump, base: int, body: int) -> dict:
    """Live operand words of a 9A site: the offset word and the segment word."""
    raw = dump.read(base + body + 1, 2)
    seg = dump.read(base + body + 3, 2)
    return {"live_off": int.from_bytes(raw, "little"), "live_seg": int.from_bytes(seg, "little")}


def stub_owner(groups: list[dict], exe: bytes, start_off: int) -> Optional[dict]:
    """The stub run that holds START.EXE offset start_off, if the offset is a stub start."""
    hits = []
    for g in groups:
        st, en = g.get("stub_start"), g.get("stub_end")
        if st is None or en is None or not (st <= start_off < en):
            continue
        if (start_off - st) % STUB_LEN:
            continue
        k = (start_off - st) // STUB_LEN
        hits.append((g, k))
    if len(hits) != 1:
        return None
    g, k = hits[0]
    if exe[start_off:start_off + 2] != STUB_MAGIC:
        return None
    proc = _u16(exe, start_off + 2)
    valid = g.get("stub_valid", [None] * (k + 1))[k] if g.get("stub_valid") else None
    return {"header_offset": g["header_offset"], "fileofs": g["fileofs"], "codesz": g["codesz"],
            "group_status": g["status"], "stub_index": k, "stub_offset_file": start_off,
            "proc": proc, "stub_well_formed": valid, "stub_trailer": exe[start_off + 4],
            "proc_file": g["fileofs"] + proc}


def common_prefix(a: bytes, b: bytes) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def identity_from_dump(dump: om.Dump, exe: bytes, groups: list[dict], target_linear: int) -> dict:
    """Name a live target by its bytes. Established only on a unique START window and a stub owner."""
    if not dump.covers(target_linear, WINDOW_WIDE):
        return {"status": "not-established", "reason": "target outside the dump",
                "target_linear": "0x%X" % target_linear}
    live = dump.read(target_linear, WINDOW_WIDE)
    win = live[:WINDOW]
    start_hits = []
    pos = exe.find(win)
    while pos != -1:
        start_hits.append(pos)
        pos = exe.find(win, pos + 1)
    dump_hits = dump.find_all(win)
    row = {"target_linear": "0x%X" % target_linear, "live_bytes_16": win.hex(" "),
           "live_bytes_32": live.hex(" "), "dump_hits_16": len(dump_hits),
           "start_hits_16": ["0x%X" % h for h in start_hits],
           "start_common_prefix_32": None}
    if len(start_hits) != 1:
        row.update({"status": "not-established",
                    "reason": "16-byte target window matches %d places in START.EXE" % len(start_hits)})
        return row
    f = start_hits[0]
    row["start_common_prefix_32"] = common_prefix(live, exe[f:f + WINDOW_WIDE])
    owner = stub_owner(groups, exe, f)
    row["stub_owner"] = owner
    if owner is None:
        row.update({"status": "not-established",
                    "reason": "the unique START offset is not a stub start of a single stub run"})
        return row
    if not owner["stub_well_formed"]:
        row.update({"status": "not-established", "reason": "the matched stub is not well-formed"})
        return row
    row.update({"status": "established-by-live-bytes",
                "reason": "live target bytes equal START.EXE at one offset that is a stub start "
                          "of one stub run"})
    return row


def decode_proc(ovr: bytes, entry: int, limit: int) -> tuple[list, Optional[str]]:
    return lh.linear(ovr, entry, limit, stop_on_ret=True)


def insn_row(i) -> dict:
    return {"off": "0x%X" % (i.off), "bytes": i.raw.hex(" "), "text": i.text(),
            "flow": i.flow, "mem": i.mem, "imm": i.imm, "target": i.target,
            "es_prefix": 0x26 in i.prefixes}


def proc_facts(ovr: bytes, group: dict, entry: int) -> dict:
    """Named skeleton checks on one procedure, read off its decoded instructions."""
    insns, why = decode_proc(ovr, entry, CALLEE_WALK)
    facts = {"entry": "0x%X" % entry, "walk_stop": why, "instruction_count": len(insns),
             "prologue": ovr[entry:entry + 3].hex(" ") in ("55 89 e5", "55 8b ec"),
             "wrap_bp6": False, "wrap_bp8": False, "guard_flag_cmps": [],
             "shl_cl4_offsets": [], "far_ptr_les": [], "es_reads": [], "near_calls": [],
             "ret": None, "listing": [insn_row(i) for i in insns]}
    for idx, i in enumerate(insns):
        if i.name == "cmp" and i.mem == "[bp+6]" and i.imm in (0, CLAMP_MAX):
            facts["wrap_bp6"] = True
        if i.name == "cmp" and i.mem == "[bp+8]" and i.imm in (0, CLAMP_MAX):
            facts["wrap_bp8"] = True
        if i.name == "cmp" and i.mem == "[0x%x]" % GUARD_FLAG:
            facts["guard_flag_cmps"].append({"off": "0x%X" % i.off, "imm": i.imm})
        if i.raw == b"\xd3\xe0":                       # shl ax, cl
            facts["shl_cl4_offsets"].append("0x%X" % i.off)
        if i.name.startswith("les") and i.mem == "[0x%x]" % DGROUP_PTR:
            facts["far_ptr_les"].append("0x%X" % i.off)
        if 0x26 in i.prefixes and i.mem is not None and i.name == "mov":
            nxt = insns[idx + 1].text() if idx + 1 < len(insns) else None
            facts["es_reads"].append({"off": "0x%X" % i.off, "mem": i.mem, "next": nxt})
        if i.flow == "call" and i.target is not None:
            facts["near_calls"].append("0x%X" % i.target)
        if i.flow in ("retf", "ret"):
            facts["ret"] = i.text()
    return facts


def range_gate_shape(ovr: bytes, entry: int) -> dict:
    """True when a procedure is the 0..15 range test on [bp+8] (X) and [bp+6] (Y): it
    compares each against 15 and 0 in that order and returns 1 inside, 0 outside."""
    insns, why = decode_proc(ovr, entry, HELPER_WALK)
    cmps = [(i.mem, i.imm) for i in insns if i.name == "cmp" and i.mem in ("[bp+8]", "[bp+6]")]
    want = [("[bp+8]", CLAMP_MAX), ("[bp+8]", 0), ("[bp+6]", CLAMP_MAX), ("[bp+6]", 0)]
    movs = [i.imm for i in insns if i.name == "mov" and i.mem == "[bp-1]" and i.imm is not None]
    ok = cmps == want and movs == [0, 1] and why is None
    return {"entry": "0x%X" % entry, "compares": [list(c) for c in cmps],
            "result_moves": movs, "range_test_shape": ok}


def arg_push_order(ovr: bytes, site: int) -> dict:
    """The four instructions before a 9A site must push [0x6AAD] then [0x6AAE] (X then Y)."""
    seq, off = [], max(0, site - 12)
    while off < site:
        i = lh.decode(ovr, off)
        seq.append(i)
        off += i.length
    tail = seq[-4:] if len(seq) >= 4 else seq
    want = [("mov", "[0x6aad]"), ("push", None), ("mov", "[0x6aae]"), ("push", None)]
    got = [(i.name.split(" ")[0], i.mem) for i in tail]
    ok = off == site and len(tail) == 4 and got == want
    return {"site": "0x%X" % site, "tail": [i.text() for i in tail], "push_order_ok": ok}


def callee_report(ovr: bytes, group: dict, proc_file: int) -> dict:
    """The callee and each procedure it calls inside the same group (one level).

    The skeleton checks are read off the decoded listing; they name the shape the
    probe expects. They do not prove the semantics of the GEO data the pointer reaches.
    """
    top = proc_facts(ovr, group, proc_file)
    helpers, gate = [], None
    for t in sorted(set(top["near_calls"])):
        target = int(t, 16)
        if group["fileofs"] <= target < group["fileofs"] + group["codesz"]:
            h = proc_facts(ovr, group, target)
            h.pop("listing", None)
            h["range_gate"] = range_gate_shape(ovr, target)
            helpers.append(h)
            if h["range_gate"]["range_test_shape"]:
                gate = target
    top["helpers"] = helpers
    top["range_gate_entry"] = "0x%X" % gate if gate is not None else None
    checks = {
        "prologue": top["prologue"],
        "wrap_bp6_and_bp8": top["wrap_bp6"] and top["wrap_bp8"],
        "single_far_ptr_load": len(top["far_ptr_les"]) == 1,
        "shl_cl4_before_ptr_load": bool(top["shl_cl4_offsets"]) and bool(top["far_ptr_les"])
        and int(top["shl_cl4_offsets"][0], 16) < int(top["far_ptr_les"][0], 16),
        "single_es_read_disp_0x200": (len(top["es_reads"]) == 1
                                      and top["es_reads"][0]["mem"] == "[di+512]"),
        "guard_flag_values_0_and_0a": sorted(g["imm"] for g in top["guard_flag_cmps"]) == [0, 10],
        "retf_4": top["ret"] is not None and top["ret"].startswith("retf"),
        "range_gate_shape": gate is not None,
    }
    top["checks"] = checks
    top["checks_ok"] = all(checks.values())
    return top


def store_context(ovr: bytes, pos: int, before: int = 14, after: int = 12) -> list[str]:
    """Instructions decoded forward around a store site (heuristic window, not a CFG)."""
    out, off = [], pos - before
    while off < pos + after:
        i = lh.decode(ovr, off)
        out.append("0x%X %s" % (i.off, i.text()))
        off += i.length
    return out


def classify_ptr_refs(ovr: bytes, groups: list[dict]) -> list[dict]:
    """Byte-led classification of each DGROUP 0x6A5C reference (heuristic, not reachability)."""
    pat = DGROUP_PTR.to_bytes(2, "little")
    rows, pos = [], ovr.find(pat)
    while pos != -1:
        cls = "unclassified"
        if pos >= 1 and ovr[pos - 1] == 0xA3:
            cls = "store AX to [disp16]"
        elif pos >= 1 and ovr[pos - 1] == 0xA1:
            cls = "load AX from [disp16]"
        elif pos >= 2 and ovr[pos - 2:pos] == b"\xc4\x3e":
            cls = "les DI (far pointer load)"
        elif pos >= 2 and ovr[pos - 2:pos] == b"\xc5\x3e":
            cls = "lds DI (far pointer load)"
        elif pos >= 3 and ovr[pos - 2] & 0xC7 == 0x06:
            op, reg = ovr[pos - 3], (ovr[pos - 2] >> 3) & 7
            if op in (0x89, 0x88):
                cls = "store reg to [disp16]"
            elif op in (0x8B, 0x8A):
                cls = "load reg from [disp16]"
            elif op in (0xC7, 0xC6):
                cls = "store immediate to [disp16]"
            elif op in (0x80, 0x81, 0x83):
                cls = "alu/cmp immediate on [disp16] (reg %d)" % reg
        g = owner_group(groups, pos)
        rows.append({"file_offset": "0x%X" % pos, "class": cls,
                     "group_fileofs": g["fileofs"] if g else None})
        pos = ovr.find(pat, pos + 1)
    return rows


def probe(install: Path, out: Path, dump_path: Optional[Path], *,
          pins: dict = PINS) -> tuple[dict, int]:
    ovr_path = fr.find_file(install, OVR_NAME)
    exe_path = fr.find_file(install, EXE_NAME)
    ovr, exe = ovr_path.read_bytes(), exe_path.read_bytes()
    inputs = check_pins(ovr, exe, pins)
    groups = all_groups(exe, ovr)
    sites = site_rows(ovr, groups)

    doc = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL,
           "status_scope": STATUS_SCOPE, "playable": False, "consumer_established": False,
           "question": "What does the far call 03D5:0034 reach, and can its return be read as a "
                       "bounded consumer?",
           "inputs": {"install_folder_name": install.name, **inputs}}
    doc["literal"] = {"bytes": LITERAL.hex(" "), "sites": sites,
                      "static_identity": "not-established: the segment word is loader-patched"}

    dump: Optional[om.Dump] = None
    if dump_path is not None:
        data = dump_path.read_bytes()
        base = om.resolve_dump_base(dump_path.name, len(data), None)
        dump = om.Dump(data, base)
        doc["inputs"]["dump"] = {"name": dump_path.name, "size": len(data),
                                 "sha256": _sha(data), "base": "0x%X" % base}

    identity = {"status": "not-established", "reason": "no RAM dump supplied"}
    callers = []
    if dump is not None:
        mapped_targets = set()
        for row in sites:
            if row["group"] is None:
                callers.append({"file_offset": row["file_offset_hex"], "map_status": "no group"})
                continue
            g = owner_group(groups, row["file_offset"])
            m = map_caller_group(ovr, g, dump)
            entry = {"file_offset": row["file_offset_hex"], "group_fileofs": "0x%X" % g["fileofs"],
                     "map_status": m["status"], "map_base": (
                         "0x%X" % m["base_linear"] if m["base_linear"] is not None else None)}
            if m["status"] == "unique":
                live = read_live_site(dump, m["base_linear"], row["body_offset"])
                tlin = live["live_seg"] * 16 + live["live_off"]
                entry.update({"live_seg": "0x%04X" % live["live_seg"],
                              "live_off": "0x%04X" % live["live_off"],
                              "raw_seg": "0x%04X" % CALL_SEG,
                              "delta_observed": "0x%04X" % ((live["live_seg"] - CALL_SEG) & 0xFFFF),
                              "target_linear": "0x%X" % tlin})
                entry["arg_push_order"] = arg_push_order(ovr, row["file_offset"])
                mapped_targets.add(tlin)
            callers.append(entry)
        doc["callers"] = callers
        if len(mapped_targets) == 1:
            tlin = mapped_targets.pop()
            identity = identity_from_dump(dump, exe, groups, tlin)
        elif mapped_targets:
            identity = {"status": "not-established",
                        "reason": "mapped callers disagree on the live target",
                        "targets": sorted("0x%X" % t for t in mapped_targets)}
        else:
            identity = {"status": "not-established", "reason": "no caller group mapped uniquely"}
    doc["identity"] = identity

    callee = None
    if identity.get("status") == "established-by-live-bytes":
        owner = identity["stub_owner"]
        grp = next(g for g in groups if g["fileofs"] == owner["fileofs"])
        callee = callee_report(ovr, grp, owner["proc_file"])
        callee["group"] = {"fileofs": grp["fileofs"], "codesz": grp["codesz"],
                           "header_offset": grp["header_offset"], "status": grp["status"]}
        callee["proc"] = owner["proc"]
    doc["callee"] = callee
    doc["pointer_refs"] = classify_ptr_refs(ovr, groups)
    stores = [r for r in doc["pointer_refs"] if r["class"] == "store AX to [disp16]"]
    doc["pointer_store_context"] = [
        dict(s, context=store_context(ovr, int(s["file_offset"], 16))) for s in stores]
    doc["not_established"] = list(NOT_ESTABLISHED)

    pushed = [c["arg_push_order"]["push_order_ok"] for c in doc.get("callers", [])
              if "arg_push_order" in c]
    ok = (identity.get("status") == "established-by-live-bytes" and callee is not None
          and callee["checks_ok"] and bool(pushed) and all(pushed))
    doc["status"] = "ok" if ok else "diagnostic"
    out.mkdir(parents=True, exist_ok=True)
    return doc, (0 if ok else 1)


def render_report(doc: dict) -> str:
    lines = ["# PoR far call 03D5:0034: callee identity probe", "",
             "**Status: observe-only. `playable: false`. `consumer_established: false`.**", "",
             "## Literal sites (GAME.OVR)", ""]
    for s in doc["literal"]["sites"]:
        g = s["group"]
        lines.append("- %s, group %s, body %s, seg word fixup-listed: %s"
                     % (s["file_offset_hex"], ("0x%X" % g["fileofs"]) if g else "none",
                        hex(s["body_offset"]) if s["body_offset"] is not None else "-",
                        s["seg_word_fixup_listed"]))
    lines += ["", "## Identity", "", "- status: `%s`" % doc["identity"]["status"],
              "- reason: %s" % doc["identity"].get("reason", "")]
    if doc["identity"].get("stub_owner"):
        o = doc["identity"]["stub_owner"]
        lines.append("- stub owner: header 0x%X, fileofs 0x%X, stub %d, proc 0x%04X, "
                     "group status %s" % (o["header_offset"], o["fileofs"], o["stub_index"],
                                          o["proc"], o["group_status"]))
    if doc.get("callee"):
        c = doc["callee"]
        lines += ["", "## Callee (decoded, one helper level)", "",
                  "- entry `%s`, range gate `%s`, return `%s`" %
                  (c["entry"], c["range_gate_entry"], c["ret"]),
                  "- far pointer load (les di) at %s; ES read at %s" %
                  (c["far_ptr_les"], [e["off"] for e in c["es_reads"]]),
                  "- guard flag compares at %s" % [g["off"] for g in c["guard_flag_cmps"]],
                  "- checks: " + ", ".join("%s=%s" % kv for kv in sorted(c["checks"].items()))]
    for c in doc.get("callers", []):
        if "arg_push_order" in c:
            lines.append("- caller %s: push order ok = %s" %
                         (c["file_offset"], c["arg_push_order"]["push_order_ok"]))
    lines += ["", "## Not established", ""] + ["- " + x for x in doc["not_established"]]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    (out / "por_geo_callee_identity_probe.json").write_text(
        json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    (out / "por_geo_callee_identity_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", required=True, type=Path)
    ap.add_argument("--dump", type=Path, default=None,
                    help="optional raw RAM dump named ram-LO-HI.bin (read-only)")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    try:
        if not _inside(args.out, DATA_WORK):
            raise Refusal("output must be a folder under data/work/")
        if _inside(args.out, args.install):
            raise Refusal("output must not be inside the install")
        doc, code = probe(args.install, args.out, args.dump)
    except (Refusal, PorSourceError) as e:
        print("refused: %s" % e, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("status: %s (identity %s)" % (doc["status"], doc["identity"]["status"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
