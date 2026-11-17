#!/usr/bin/env python3
"""Observe-only probe: what does the GEO loader call 0x0802:0x0716 reach, and does its contract fit?

The buffer-fill probe (tools/por_geo_buffer_fill_probe.py) and the copy-helper probe
(tools/por_geo_copy_helper_probe.py) left one target open: the loader 0x0802:0x0716, whose returned
far pointer (written to the fill's [bp-6]) would be the GEO block the copy reads. This probe asks:

1. Which bytes does the target reach? The live operand segment is read from the resident call sites
   that map uniquely to a pinned overlay group in each pinned dump. The live target bytes are then
   placed in the pinned START.EXE by a masked match: the only allowed difference is a 16-bit segment
   literal rewritten by the START load segment (file word + load). A placement must be unique.
2. Does the body's stack contract fit the ten static call sites? Every call site's pre-call pushes are
   read from the bytes (id word, status far pointer, output far pointer). A body whose `retf` pops a
   different count, or which reads parameters above the pushed region, is a prototype conflict.
3. Positive control: the same masked match, run on the copy helper's live body at 0x0AF8:0x1685,
   must place it at START 0xC2FB (the copy-helper probe's identity).

Nothing here says the target runs, that the fill or any caller runs, or what the loader returns. A
body's stack contract is read as bytes; a memory dump is memory-present evidence at an unknown
instant. The probe never promotes the output pointer to a GEO block and never binds plane 2.

Usage:
    python tools/por_geo_loader_target_probe.py [--install PATH/TO/POOLRAD] \
        [--dump data/work/por-live-memory-pid34644/ram-000000-100000.bin ...] \
        [-o data/work/por-geo-loader-target-probe]

Exit: 0 the probe ran (its verdict may be `unresolved`; that is the result); 2 a named refusal
(unpinned input, bad dump, output outside data/work or inside the install).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_farcall_resolve as fr  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_geo_callee_identity_probe as gcp  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

SCHEMA = "openua.por-geo-loader-target-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "loader-target-probe-only"
TOOL = "tools/por_geo_loader_target_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-loader-target-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMPS = [
    DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
    DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin",
]
Refusal = om.Refusal
OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME

LOADER_SEG = 0x0802                 # raw segment word in the call (GAME.OVR and START.EXE)
LOADER_OFF = 0x0716                 # offset word in the call
LOADER_CALL = bytes.fromhex("9a 16 07 02 08")
HDR = 0x200                         # START.EXE MZ header bytes (cparhdr * 16)
WINDOW = 256                        # live bytes compared at the target
CONTROL_SEG, CONTROL_OFF = 0x0AF8, 0x1685   # copy helper (positive control)
CONTROL_WINDOW = 64
CONTROL_FILE = 0xC2FB               # copy helper's identified START offset (its own probe)
CONTIG_FILE = HDR + LOADER_SEG * 16 + LOADER_OFF      # zero-skew MZ map (0x8936)
ROUTINE_B_BASE = 0xAC76             # routine-B module base (copy-helper probe), a segment-0x0AF8 fact
MAX_DECODE = 400

# Pre-call pushes for the loader, read from the bytes:
#   push ax after `mov al,[bp+X]` or `mov al,imm` (the id word, 2 bytes),
#   then `lea di,[bp+Y]; push ss; push di` (status far pointer, 4 bytes),
#   then `lea di,[bp+Z]; push ss; push di` (output far pointer, 4 bytes).
CALLER_RE = re.compile(
    rb"(?:\x8a\x46.\x50|\xb0.\x50)\x8d(?:\x7e.|\xbe..)\x16\x57\x8d(?:\x7e.|\xbe..)\x16\x57\Z", re.S)
CALLER_PUSH_BYTES = 2 + 4 + 4
PARAM_READ_NAMES = {"les", "lds", "mov", "cmp", "push", "add", "adc"}
POINTER_NAMES = {"les", "lds"}
BRANCH_FLOWS = {"jcc", "jmp"}

NOT_ESTABLISHED = [
    "that the target 0x0802:0x0716 runs, or that the fill or any caller runs, at any instant",
    "that the identified body is the loader: its stack contract conflicts with every static caller",
    "what the output far pointer holds at any instant, and whether it is a decoded GEO block",
    "the status 0x402 meaning beyond the fill's gate, and the id byte's meaning",
    "that the live segment word is the one the CPU uses at call time (the dumps are of unknown instant)",
    "any PoR meaning of the body's helper calls (0x0AF8:0x0B25 and the others)",
    "plane 2 binding, any consumer of the buffer, or any area/descriptor mapping",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def _positions(data: bytes, pat: bytes) -> list[int]:
    out, pos = [], data.find(pat)
    while pos != -1:
        out.append(pos)
        pos = data.find(pat, pos + 1)
    return out


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def check_pins(ovr: bytes, exe: bytes) -> dict:
    return gcp.check_pins(ovr, exe, om.PINS)


# ---- masked placement -----------------------------------------------------------------

def masked_match(start: bytes, p: int, live: bytes, load: int) -> Optional[list[int]]:
    """Compare live[] with START at p. The only allowed differences are 16-bit segment literals:
    a word whose live value is the file value plus `load` (mod 0x10000). Returns the span offsets
    used, or None on any other difference. `load` has a nonzero low byte in this use, so a rewritten
    word always differs at its first byte; the scan can therefore start a span at the first mismatch."""
    n = len(live)
    if p < 0 or p + n > len(start):
        return None
    spans: list[int] = []
    i = 0
    while i < n:
        if start[p + i] == live[i]:
            i += 1
            continue
        if i + 1 >= n:
            return None
        fw = start[p + i] | (start[p + i + 1] << 8)
        lw = live[i] | (live[i + 1] << 8)
        if fw == lw or (fw + load) & 0xFFFF != lw:
            return None
        spans.append(i)
        i += 2
    return spans


def placements(start: bytes, live: bytes, load: int) -> list[dict]:
    """Every START offset where the live window matches under the masked rule."""
    out = []
    for p in range(0, len(start) - len(live) + 1):
        spans = masked_match(start, p, live, load)
        if spans is not None:
            out.append({"file_offset": p, "segment_literal_spans": len(spans)})
    return out


# ---- static call sites --------------------------------------------------------------------

def call_sites(image: bytes) -> list[int]:
    return _positions(image, LOADER_CALL)


def caller_shape(image: bytes, site: int) -> dict:
    before = image[max(0, site - 20):site]
    m = CALLER_RE.search(before)
    return {"shape_matched": m is not None,
            "pushed_bytes": CALLER_PUSH_BYTES if m is not None else None}


def static_call_rows(ovr: bytes, exe: bytes, groups: list[dict]) -> list[dict]:
    rows = []
    for name, image in ((OVR_NAME, ovr), (EXE_NAME, exe)):
        for s in call_sites(image):
            row = {"image": name, "file_offset": "0x%X" % s, **caller_shape(image, s)}
            if name == OVR_NAME:
                g = gcp.owner_group(groups, s)
                if g is None:
                    row["owner_group"] = None
                    row["seg_word_fixup_listed"] = None
                else:
                    row["owner_group"] = "0x%X" % g["fileofs"]
                    row["seg_word_fixup_listed"] = (s + 3 - g["fileofs"]) in fr.fixup_table(ovr, g)
            rows.append(row)
    return rows


# ---- live segment rewrite at uniquely-mapped GAME.OVR sites ----------------------------------

def live_seg_rows(ovr: bytes, groups: list[dict], dump: om.Dump, sites: list[int]) -> list[dict]:
    out = []
    for s in sites:
        g = gcp.owner_group(groups, s)
        if g is None:
            continue
        code = ovr[g["fileofs"]:g["fileofs"] + g["codesz"]]
        if len(code) < g["codesz"]:
            continue
        fx = sorted(fr.fixup_table(ovr, g))
        try:
            r = om.map_group(g, code, fx, dump)
        except Refusal as exc:
            r = {"status": "refused", "reason": str(exc)}
        row = {"site": "0x%X" % s, "group": "0x%X" % g["fileofs"], "map_status": r["status"]}
        if r["status"] == "unique":
            rel = s + 3 - g["fileofs"]
            live = _u16(dump.read(r["base_linear"] + rel, 2), 0)
            row["live_seg"] = "0x%04X" % live
            row["live_seg_minus_raw"] = "0x%04X" % ((live - LOADER_SEG) & 0xFFFF)
            row["live_seg_value"] = live
        out.append(row)
    return out


def load_from_rewrite(rows: list[dict]) -> Optional[int]:
    """The START load implied by the rewritten call sites. None unless all unique rows agree."""
    vals = {r["live_seg_minus_raw"] for r in rows if r.get("map_status") == "unique"}
    if len(vals) != 1:
        return None
    return int(next(iter(vals)), 16)


# ---- the body's stack contract, read from its bytes ------------------------------------------

def contract(exe: bytes, entry: int) -> dict:
    ins, err = lh.linear(exe, entry, MAX_DECODE, stop_on_ret=True)
    rets = [i for i in ins if i.flow in ("ret", "retf")]
    first_branch = next((k for k, i in enumerate(ins) if i.flow in BRANCH_FLOWS), len(ins))
    pointer_loads = sorted({i.bp_disp for i in ins if i.name in POINTER_NAMES and i.bp_disp is not None
                            and i.bp_disp > 0})
    params_used = sorted({i.bp_disp for i in ins if i.bp_disp is not None and i.bp_disp > 0
                          and i.name in PARAM_READ_NAMES})
    uncond = sorted({i.bp_disp for k, i in enumerate(ins) if k < first_branch and i.bp_disp is not None
                     and i.bp_disp > 0 and i.name in PARAM_READ_NAMES})
    far = sorted({"0x%04X:0x%04X" % i.far for i in ins if i.far is not None})
    stores = []                       # ES-prefixed moves after a far-pointer load from bp+d
    cur = None
    for i in ins:
        if i.name in POINTER_NAMES and i.bp_disp is not None:
            cur = i.bp_disp
        elif cur is not None and i.name == "mov" and 0x26 in i.prefixes and i.flow == "seq":
            stores.append({"at": "0x%X" % i.off, "text": i.text(), "via_bp_pointer": cur})
    last = rets[0] if rets else None
    retf_imm = last.imm if (last is not None and last.flow == "retf") else None
    return {
        "entry_file": "0x%X" % entry,
        "entry_bytes": exe[entry:entry + 8].hex(" "),
        "decode_error": err,
        "instructions_to_first_return": len(ins),
        "first_return": None if last is None else {"file_offset": "0x%X" % last.off, "text": last.text(),
                                                   "flow": last.flow},
        "return_count": len(rets),
        "retf_pops_bytes": retf_imm,
        "pointer_params_loaded_far": pointer_loads,
        "bp_params_read": params_used,
        "bp_params_read_before_first_branch": uncond,
        "far_call_targets": far,
        "pointer_stores": stores,
        "first_branch_index": first_branch,
    }


def contract_vs_callers(contr: dict, callers: list[dict]) -> dict:
    """The body's declared pop against the bytes every caller pushes. A parameter read above the
    pushed region is a conflict: it reads the caller's own frame, not an argument."""
    pushed = {c["pushed_bytes"] for c in callers if c.get("shape_matched")}
    pushed_region_end = 6 + (next(iter(pushed)) if len(pushed) == 1 else 0)   # bp+6 is the last push
    beyond = [d for d in contr["bp_params_read"] if d >= pushed_region_end]
    reasons = []
    if not pushed:
        reasons.append("no caller shape matched")
    elif len(pushed) > 1:
        reasons.append("callers push different byte counts: %s" % sorted(pushed))
    elif contr["retf_pops_bytes"] != next(iter(pushed)):
        reasons.append("body pops %s bytes; every caller pushes %d" % (contr["retf_pops_bytes"], next(iter(pushed))))
    if beyond:
        reasons.append("body reads parameters above the pushed region: bp+%s" % ", bp+".join(str(d) for d in beyond))
    return {
        "callers_matched": sum(1 for c in callers if c.get("shape_matched")),
        "callers_total": len(callers),
        "caller_pushed_bytes": sorted(pushed),
        "body_pops_bytes": contr["retf_pops_bytes"],
        "params_read_above_pushed_region": beyond,
        "prototype_match": not reasons,
        "reasons": reasons,
    }


# ---- per-dump evidence -------------------------------------------------------------------

def dump_window(dump: om.Dump, lin: int, n: int) -> Optional[bytes]:
    return dump.read(lin, n) if dump.covers(lin, n) else None


def contiguous_row(start: bytes, live: Optional[bytes], load: int) -> dict:
    row = {"candidate": "contiguous-mz", "file_offset": "0x%X" % CONTIG_FILE,
           "file_bytes": start[CONTIG_FILE:CONTIG_FILE + 16].hex(" ")}
    head = start[CONTIG_FILE:CONTIG_FILE + 3]
    row["file_prologue"] = head in (b"\x55\x89\xe5", b"\x55\x8b\xec")
    if live is None:
        row["state"] = "memory-not-covered"
        return row
    spans = masked_match(start, CONTIG_FILE, live, load)
    row["state"] = "memory-agrees" if spans is not None else "memory-disagrees"
    return row


def dump_rows(start: bytes, dump: om.Dump, load: int, label: str) -> dict:
    lin = (LOADER_SEG + load) * 16 + LOADER_OFF
    live = dump_window(dump, lin, WINDOW)
    rec = {"dump": label, "base": "0x%X" % dump.base, "live_linear": "0x%X" % lin,
           "live_seg": "0x%04X" % (LOADER_SEG + load), "covered": live is not None}
    if live is None:
        rec["placements"] = []
        rec["contiguous_candidate"] = None
        return rec
    rec["live_first16"] = live[:16].hex(" ")
    rec["placements"] = placements(start, live, load)
    rec["contiguous_candidate"] = contiguous_row(start, live, load)
    rec["routine_b_base_candidate"] = {
        "candidate": "routine-b-module-base", "file_offset": "0x%X" % (ROUTINE_B_BASE + LOADER_OFF),
        "state": "not-applicable",
        "reason": "the routine-B base is established for segment 0x0AF8 only; it is not byte-supported "
                  "for segment 0x%04X" % (LOADER_SEG)}
    return rec


def control_row(start: bytes, dump: om.Dump, load: int, label: str) -> dict:
    """Positive control: the copy helper's live body must place at its identified START offset."""
    lin = (CONTROL_SEG + load) * 16 + CONTROL_OFF
    live = dump_window(dump, lin, CONTROL_WINDOW)
    if live is None:
        return {"dump": label, "covered": False}
    pl = placements(start, live, load)
    return {"dump": label, "covered": True, "live_linear": "0x%X" % lin,
            "placements": pl, "expected_file_offset": "0x%X" % CONTROL_FILE,
            "control_passes": [p["file_offset"] for p in pl] == [CONTROL_FILE]}


# ---- verdict -----------------------------------------------------------------------------

def identity_verdict(rows: list[dict], seg_rows_by_dump: dict, load: Optional[int]) -> dict:
    covering = [r for r in rows if r["covered"]]
    if not covering:
        return {"verdict": "not-covered", "file_offset": None}
    if load is None:
        return {"verdict": "unresolved", "file_offset": None, "reason": "rewritten call sites disagree"}
    for r in covering:
        seg_ok = sum(1 for s in seg_rows_by_dump.get(r["dump"], []) if s.get("map_status") == "unique"
                     and s.get("live_seg_value") == LOADER_SEG + load)
        if seg_ok < 2:
            return {"verdict": "unresolved", "file_offset": None,
                    "reason": "fewer than two uniquely-mapped call sites show the rewritten segment"}
    offs = {tuple(p["file_offset"] for p in r["placements"]) for r in covering}
    if len(offs) != 1:
        return {"verdict": "unresolved", "file_offset": None, "reason": "dumps disagree on placement"}
    (places,) = offs
    if len(places) == 0:
        return {"verdict": "unresolved", "file_offset": None, "reason": "no START placement"}
    if len(places) > 1:
        return {"verdict": "ambiguous", "file_offset": ["0x%X" % p for p in places]}
    return {"verdict": "identified-by-memory-bytes-conditional-on-live-segment",
            "file_offset": "0x%X" % places[0], "covering_dumps": len(covering),
            "rewritten_call_sites_per_dump": {k: sum(1 for s in v if s.get("map_status") == "unique")
                                               for k, v in seg_rows_by_dump.items()}}


def overall(identity: dict, prototype: dict) -> dict:
    if identity["verdict"] != "identified-by-memory-bytes-conditional-on-live-segment":
        status = "unresolved"
        blocker = "target placement not identified: %s" % identity.get("reason", identity["verdict"])
    elif not prototype["prototype_match"]:
        status = "unresolved-prototype-conflict"
        blocker = "; ".join(prototype["reasons"])
    else:
        status = "contract-consistent-output-unproven"
        blocker = "the output pointer is not traced; no GEO block is established"
    return {"status": status, "blocker": blocker, "geo_output": "not_established",
            "plane2_binding": "not claimed", "playable": False}


DISCRIMINATORS = [
    "A live capture at the fill's loader call (GAME.OVR 0x2FA17, or the START sites at 0x47E0 and 0x7276): "
    "SP before the call, then CS:IP at entry (expect 2068:0716), and the words at entry SP+6 to SP+23. "
    "A read of SP+16 and SP+20 that the body uses for pointers would show the conflict in action.",
    "A byte capture of linear 0x20D96 (2068:0716) taken at the moment of that call, to exclude a later "
    "overwrite of the resident image. The dumps are of unknown instant.",
    "A capture of the status word and the output far pointer after the call returns, to see which "
    "return path (the body writes zero on one path) the fill takes.",
]


# ---- top level ----------------------------------------------------------------------------

def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = check_pins(ovr, exe)
    groups = gcp.all_groups(exe, ovr)
    ovr_sites = call_sites(ovr)
    callers = static_call_rows(ovr, exe, groups)
    contr_rows = []
    dumps_meta, seg_rows_by_dump, rows = [], {}, []
    dumps = []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        label = "%s/%s" % (dp.parent.name, dp.name)
        base = om.resolve_dump_base(dp.name, len(raw), None)
        dump = om.Dump(raw, base)
        dumps.append((label, dump))
        dumps_meta.append({"label": label, "size": len(raw), "sha256_prefix": _sha(raw)[:16],
                           "base": "0x%X" % base})
        seg_rows_by_dump[label] = live_seg_rows(ovr, groups, dump, ovr_sites)
    load = None
    all_seg = [r for v in seg_rows_by_dump.values() for r in v]
    load = load_from_rewrite(all_seg)
    if load is None:
        raise Refusal("rewritten loader call sites do not agree on one START load segment")
    # Body bytes: the placement is searched in START for each covering dump's live window.
    target_rows = []
    controls = []
    for label, dump in dumps:
        target_rows.append(dump_rows(exe, dump, load, label))
        controls.append(control_row(exe, dump, load, label))
    entry = None
    identity = identity_verdict(target_rows, seg_rows_by_dump, load)
    if identity.get("file_offset") and identity["verdict"].startswith("identified"):
        entry = int(identity["file_offset"], 16)
    else:
        entry = target_rows[0]["placements"][0]["file_offset"] if target_rows and target_rows[0]["placements"] else None
    contr = contract(exe, entry) if entry is not None else None
    proto = contract_vs_callers(contr, callers) if contr is not None else {
        "prototype_match": False, "reasons": ["no identified body to read a contract from"],
        "callers_matched": sum(1 for c in callers if c.get("shape_matched")), "callers_total": len(callers)}
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status_scope": STATUS_SCOPE,
        "tool": TOOL, "playable": False,
        "question": "What does the loader 0x0802:0x0716 reach, and does its contract fit the callers?",
        "pins": pins,
        "dumps": dumps_meta,
        "loader": {"seg": "0x%04X" % LOADER_SEG, "off": "0x%04X" % LOADER_OFF,
                   "call_bytes": LOADER_CALL.hex(" ")},
        "call_sites": callers,
        "caller_shape_matched": sum(1 for c in callers if c.get("shape_matched")),
        "caller_shape_total": len(callers),
        "live_seg_rewrite": seg_rows_by_dump,
        "start_load_from_rewrite": "0x%04X" % load,
        "target": target_rows,
        "contiguous_candidate_file": "0x%X" % CONTIG_FILE,
        "positive_control": {"target": "0x%04X:0x%04X" % (CONTROL_SEG, CONTROL_OFF),
                             "expected_file_offset": "0x%X" % CONTROL_FILE, "dumps": controls,
                             "passes_all": bool(controls) and all(c.get("control_passes", False) for c in controls
                                                                  if c.get("covered"))},
        "identity": identity,
        "body_contract": contr,
        "prototype": proto,
        "verdict": overall(identity, proto),
        "not_established": NOT_ESTABLISHED,
        "next_discriminating_observations": DISCRIMINATORS,
    }


# ---- report ------------------------------------------------------------------------------

def render_report(doc: dict) -> str:
    v = doc["verdict"]
    ident = doc["identity"]
    pr = doc["prototype"]
    lines = [
        "# Pool of Radiance: loader target 0x0802:0x0716 (observe-only)", "",
        "**Status: %s. `playable: false`. `geo_output: %s`. `plane2_binding: %s`.**" % (
            v["status"], v["geo_output"], v["plane2_binding"]), "",
        "Blocker: %s" % v["blocker"], "",
        "## Pins and dumps", "",
        "| File | Size | SHA-256 |", "| --- | ---: | --- |",
    ]
    for name, p in doc["pins"].items():
        lines.append("| `%s` | %d | `%s` |" % (name, p["size"], p["sha256"]))
    lines += ["", "| Dump | Size | Base | SHA-256 (prefix) |", "| --- | ---: | --- | --- |"]
    for d in doc["dumps"]:
        lines.append("| `%s` | %d | %s | `%s` |" % (d["label"], d["size"], d["base"], d["sha256_prefix"]))
    lines += ["", "## Call sites (static bytes)", "",
              "Caller shape matched: %d of %d sites. Each pushes the id word and two far pointers (%d bytes)." % (
                  doc["caller_shape_matched"], doc["caller_shape_total"], CALLER_PUSH_BYTES), "",
              "| Image | File offset | Shape | Owner group | Seg word fixup-listed |",
              "| --- | --- | --- | --- | --- |"]
    for c in doc["call_sites"]:
        lines.append("| %s | %s | %s | %s | %s |" % (c["image"], c["file_offset"], c["shape_matched"],
                                                   c.get("owner_group", "-"), c.get("seg_word_fixup_listed", "-")))
    lines += ["", "## Live segment at uniquely-mapped GAME.OVR call sites", "",
              "START load from the rewrite: %s (raw %s plus load = live)." % (doc["start_load_from_rewrite"],
                                                                             doc["loader"]["seg"]), ""]
    for label, rows in doc["live_seg_rewrite"].items():
        for r in rows:
            lines.append("- %s: site %s group %s map %s live %s" % (label, r["site"], r["group"],
                                                                 r["map_status"], r.get("live_seg", "-")))
    lines += ["", "## Target placement in START.EXE (masked match)", "",
              "The allowed difference is a 16-bit segment literal rewritten by the load (file word + load).", ""]
    for t in doc["target"]:
        if not t["covered"]:
            lines.append("- %s: not covered" % t["dump"])
            continue
        lines.append("- %s: live %s, placements %s" % (t["dump"], t["live_linear"],
                                                       [hex(p["file_offset"]) for p in t["placements"]]))
        c = t.get("contiguous_candidate")
        if c:
            lines.append("  - contiguous MZ candidate %s: %s (prologue %s)" % (
                c["file_offset"], c.get("state"), c.get("file_prologue")))
    lines += ["", "## Positive control (copy helper 0x0AF8:0x1685)", "",
              "Expected START %s. Passes: %s." % (doc["positive_control"]["expected_file_offset"],
                                                  doc["positive_control"]["passes_all"]), ""]
    lines += ["## Identity", "", "- verdict: `%s`" % ident["verdict"]]
    if ident.get("file_offset"):
        lines.append("- file offset: %s" % (ident["file_offset"],))
    if ident.get("reason"):
        lines.append("- reason: %s" % ident["reason"])
    lines += ["", "## Body contract versus callers", ""]
    if doc["body_contract"]:
        bc = doc["body_contract"]
        lines += [
            "- entry %s, bytes `%s`" % (bc["entry_file"], bc["entry_bytes"]),
            "- first return: %s (%s), pops %s bytes" % (bc["first_return"]["text"], bc["first_return"]["file_offset"],
                                                         bc["retf_pops_bytes"]),
            "- bp parameters read: %s; before the first branch: %s" % (bc["bp_params_read"],
                                                                      bc["bp_params_read_before_first_branch"]),
            "- far pointers loaded from bp: %s" % (bc["pointer_params_loaded_far"],),
            "- far calls: %s" % (", ".join(bc["far_call_targets"]) or "none"),
        ]
    lines += ["- prototype match: %s" % pr["prototype_match"]]
    for reason in pr.get("reasons", []):
        lines.append("  - %s" % reason)
    lines += ["", "## Not established", ""]
    lines += ["- " + x for x in doc["not_established"]]
    lines += ["", "## Next discriminating observations", ""]
    lines += ["%d. %s" % (i + 1, x) for i, x in enumerate(doc["next_discriminating_observations"])]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_loader_target_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_geo_loader_target_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only probe of the loader target 0x0802:0x0716.")
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
    except (Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s (identity=%s, prototype_match=%s, status=%s)" % (
        args.out, doc["identity"]["verdict"], doc["prototype"]["prototype_match"], doc["verdict"]["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
