#!/usr/bin/env python3
"""Pool of Radiance: static census of indirect calls that could enter stub 1 (START.EXE 0x089C).

Observe-only and diagnostic. The lead (docs/por-door-caller-probe.md) is that group 0x166CB is
entered through its stub 1 (START file 0x0089C, proc 0x0D6D = file 0x17438), which is the only stub
whose closure reaches the plane-3 writer 0x167D4 and clearer 0x166CB, and that no literal far call
(9A) reaches it. This probe asks whether an INDIRECT call can reach it: FF /2 (call near r/m16) or
FF /3 (call far m16:16).

Evidence classes, kept separate in the output:
  I  instruction-start evidence: an FF /2 or FF /3 whose site is a decoded instruction start of a
     walk (tools/por_loadpieces_handler.py walk, reached from a stub closure, a prologue sweep, or the
     START.EXE entry point). Only class I rows are census rows.
  R  raw byte-pattern candidate: a byte pattern (FF with reg 2/3, a near word, or a far pair) that is
     not a decoded instruction start. Never counted as a caller and never as a table.
  T  table resolution: a decoded indirect operand whose table address is resolved through a DS base
     that the caller states. No DS base is established by this probe for any site, so no table is
     resolved on the retail run; the resolver exists so the falsifiers can be tested.

Address models for the target 0x0089C (neither promoted):
  M0  image = hdr + seg*16 + off (zero-skew; hdr = MZ header size). Target value seg*16+off = 0x069C.
  M1  file  = seg*16 + off + 0x7E (dump-anchored, docs/por-door-caller-probe.md). Value = 0x081E.
Near indirect words are offsets within a code segment whose base is NOT established; the near-word
candidates below assume base 0 (M0 value 0x069C, M1 value 0x081E) and are raw candidates only.

Read-only. Refuses an unpinned GAME.OVR or START.EXE (no override), re-hashes both files after the
run and refuses if either changed, and writes only under data/work outside the install.

Usage:
    python tools/por_door_indirect_probe.py --install PATH/TO/POOLRAD -o data/work/por-door-indirect-probe

Exit: 0 probe ran; 2 named refusal.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_door_caller_probe as dc  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

SCHEMA = "openua.por-door-indirect-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_door_indirect_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-door-indirect-probe"

STUB1_FILE = 0x0089C          # START.EXE file offset of stub 1 (group 0x166CB, stub index 1)
STUB1_PROC_REL = 0x0D6D       # proc named by stub 1; bytes are cd 3f 6d 0d 00
STUB1_BYTES = bytes.fromhex("cd3f6d0d00")
GROUP_FILE = 0x166CB
PROC1_FILE = GROUP_FILE + STUB1_PROC_REL   # 0x17438
M1_DELTA = dc.M1_DELTA        # 0x7E
MAX_CONTEXT_WORDS = 5
MAX_EXAMPLES = 24

OPERAND_CLASSES = ("register", "direct-ds", "bp-based", "base-index", "invalid-far-register")


class Refusal(Exception):
    pass


def operand_class(ins: lh.Insn) -> dict:
    """Classify the operand of a decoded FF /2 or FF /3. Does not resolve any address."""
    mod, reg, rm = ins.modrm
    kind = "near" if reg == 2 else "far"
    if mod == 3:
        cls = "invalid-far-register" if reg == 3 else "register"
        return {"kind": kind, "operand": cls, "rm": rm, "direct_ds_disp": None, "bp_disp": None}
    if mod == 0 and rm == 6:
        return {"kind": kind, "operand": "direct-ds", "rm": rm,
                "direct_ds_disp": ins.direct, "bp_disp": None}
    if rm in (2, 3) or (rm == 6 and mod != 0):
        return {"kind": kind, "operand": "bp-based", "rm": rm,
                "direct_ds_disp": None, "bp_disp": ins.bp_disp}
    return {"kind": kind, "operand": "base-index", "rm": rm, "direct_ds_disp": None, "bp_disp": None}


def resolve_table(data: bytes, ds_base_file: Optional[int], disp: Optional[int], word_index: int = 0) -> Optional[int]:
    """Read the word at DS:disp, given a caller-stated DS base (file offset of DS:0). None if unknown."""
    if ds_base_file is None or disp is None:
        return None
    at = ds_base_file + disp + 2 * word_index
    if not 0 <= at <= len(data) - 2:
        return None
    return struct.unpack_from("<H", data, at)[0]


def decoded_ind_sites(data: bytes, walks: list[tuple[str, int, dict]], domain: str) -> list[dict]:
    """Class I rows: FF /2 and FF /3 that a walk reached as an instruction start."""
    rows = []
    seen = set()
    for tier, caller, w in walks:
        for ind in w["indirect"]:
            at = ind["at"]
            if at in seen or ind["kind"] not in ("indirect_call", "indirect_callf"):
                continue
            seen.add(at)
            ins = lh.decode(data, at)
            if ins.op != 0xFF:
                continue
            row = operand_class(ins)
            row.update({"site": "0x%05X" % at, "domain": domain, "tier": tier,
                        "caller_entry": "0x%05X" % caller, "walk_complete": w["complete"],
                        "bytes": ins.raw.hex(), "text": ins.text(), "context": dc._context(w, at)})
            rows.append(row)
    rows.sort(key=lambda r: int(r["site"], 16))
    return rows


def covered_map(walks: list[dict], lo: int, hi: int) -> tuple[bytearray, set[int]]:
    """Bytes inside [lo, hi) covered by a decoded instruction, and the set of instruction starts."""
    cov = bytearray(hi - lo)
    starts: set[int] = set()
    for w in walks:
        for r in w["listing"]:
            n = len(r["bytes"]) // 2
            starts.add(r["at"])
            for b in range(r["at"], r["at"] + n):
                if lo <= b < hi:
                    cov[b - lo] = 1
    return cov, starts


def domain_coverage(walks: list[dict], lo: int, hi: int, out_of_range_targets: int) -> dict:
    cov, starts = covered_map(walks, lo, hi)
    inc = Counter(i["code"] for w in walks for i in w["incomplete"])
    return {
        "size": hi - lo,
        "covered_bytes": sum(cov),
        "covered_fraction": round(sum(cov) / (hi - lo), 4) if hi > lo else None,
        "walks": len(walks),
        "walks_complete": sum(1 for w in walks if w["complete"]),
        "incomplete_codes": dict(sorted(inc.items())),
        "near_targets_outside_domain": out_of_range_targets,
    }


def ff_byte_census(data: bytes, lo: int, hi: int, cov: bytearray, starts: set[int]) -> dict:
    """FF bytes with ModRM reg 2 or 3 in [lo, hi): instruction start, inside a decoded instruction, or raw."""
    counts = Counter()
    raw_examples = []
    for p in range(lo, min(hi, len(data) - 1)):
        if data[p] != 0xFF or ((data[p + 1] >> 3) & 7) not in (2, 3):
            continue
        if p in starts:
            counts["decoded-start"] += 1
        elif cov[p - lo]:
            counts["inside-decoded-insn"] += 1
        else:
            counts["raw-uncovered"] += 1
            if len(raw_examples) < MAX_EXAMPLES:
                raw_examples.append({"site": "0x%05X" % p, "modrm": "%02X" % data[p + 1],
                                     "bytes": data[p:p + 4].hex(" ")})
    return {"counts": dict(sorted(counts.items())), "raw_examples": raw_examples}


def closure_range(data: bytes, entries: list[int], lo: int, hi: int) -> dict[int, dict]:
    """Walk each entry; follow near calls whose target lies in [lo, hi)."""
    fns: dict[int, dict] = {}
    q = deque(entries)
    while q:
        e = q.popleft()
        if e in fns:
            continue
        w = lh.walk(data, e)
        fns[e] = w
        for c in w["near_calls"]:
            t = c["target"]
            if t is not None and lo <= t < hi and t not in fns:
                q.append(t)
    return fns


def start_census(start: bytes, hdr: int) -> dict:
    """START.EXE image: closure from the MZ entry point, then a prologue sweep of the rest."""
    e_ip, e_cs = struct.unpack_from("<HH", start, 0x14)
    entry = hdr + e_cs * 16 + e_ip
    lo, hi = hdr, len(start)
    closure = closure_range(start, [entry], lo, hi)
    reached_starts = {r["at"] for w in closure.values() for r in w["listing"]}
    sweep: dict[int, dict] = {}
    for p in range(lo, hi - 3):
        if start[p:p + 3] in dc.PROLOGUES and p not in reached_starts:
            sweep[p] = lh.walk(start, p)
    walks = [("START-entry-closure", e, w) for e, w in closure.items()] + \
            [("START-prologue-sweep", p, w) for p, w in sweep.items()]
    out_targets = sum(1 for _, _, w in walks for c in w["near_calls"]
                      if c["target"] is not None and not lo <= c["target"] < hi)
    cov_walks = [w for _, _, w in walks]
    cov, starts = covered_map(cov_walks, lo, hi)
    return {
        "entry_file": "0x%05X" % entry,
        "entry_cs_ip": "%04X:%04X" % (e_cs, e_ip),
        "image_range": ["0x%05X" % lo, "0x%05X" % hi],
        "coverage": domain_coverage(cov_walks, lo, hi, out_targets),
        "walks": walks,
        "byte_census_ff": ff_byte_census(start, lo, hi, cov, starts),
        "starts": starts,
    }


def ovr_census(ovr: bytes, allg: list[dict], cache: dc.GroupCache) -> dict:
    """GAME.OVR: every owner group's stub closure and prologue sweep, plus raw FF census per group."""
    groups = []
    all_walks: list[dict] = []
    body_ranges = []
    for g in allg:
        fo, cs = g["fileofs"], g["codesz"]
        body_ranges.append((fo, fo + cs))
        gw = cache.get(g)
        walks = [("A-stub-closure", e, w) for e, w in sorted(gw.reached.items())] + \
                [("B-prologue-unreached", e, w) for e, w in sorted(gw.swept.items())]
        out_targets = sum(1 for _, _, w in walks for c in w["near_calls"]
                          if c["target"] is not None and not fo <= c["target"] < fo + cs)
        wl = [w for _, _, w in walks]
        cov, starts = covered_map(wl, fo, fo + cs)
        groups.append({
            "fileofs": fo, "codesz": cs, "status": g["status"],
            "valid_stubs": len(gw.valid_entries),
            "coverage": domain_coverage(wl, fo, fo + cs, out_targets),
            "byte_census_ff": ff_byte_census(ovr, fo, fo + cs, cov, starts),
            "ind_sites": decoded_ind_sites(ovr, walks, "0x%05X" % fo),
            "far_calls_decoded": sum(len(w["far_calls"]) for w in wl),
        })
        all_walks.extend(wl)
    # Outside all owner-group bodies: raw FF census only (no walks here; not a decoded domain).
    in_body = bytearray(len(ovr))
    for lo, hi in body_ranges:
        for p in range(lo, min(hi, len(ovr))):
            in_body[p] = 1
    outside = Counter()
    outside_examples = []
    for p in range(len(ovr) - 1):
        if not in_body[p] and ovr[p] == 0xFF and ((ovr[p + 1] >> 3) & 7) in (2, 3):
            outside["outside-group-body"] += 1
            if len(outside_examples) < MAX_EXAMPLES:
                outside_examples.append({"site": "0x%05X" % p, "modrm": "%02X" % ovr[p + 1]})
    return {
        "groups": groups,
        "outside_group_bytes": in_body.count(0),
        "outside_group_ff": {"counts": dict(outside), "examples": outside_examples},
        "all_walks": all_walks,
    }


def stub1_decoded_reach(hdr: int, walks_by_file: dict[str, list[dict]]) -> dict:
    """Decoded direct calls that name stub 1 (near E8 to 0x089C; far 9A under M0 or M1). Instruction starts only."""
    near = []
    far_m0 = []
    far_m1 = []
    for fname, walks in walks_by_file.items():
        for w in walks:
            for c in w["near_calls"]:
                if c["target"] == STUB1_FILE:
                    near.append({"file": fname, "site": "0x%05X" % c["at"]})
            for c in w["far_calls"]:
                v = c["seg"] * 16 + c["off"]
                if hdr + v == STUB1_FILE:
                    far_m0.append({"file": fname, "site": "0x%05X" % c["at"], "literal": "%04X:%04X" % (c["seg"], c["off"])})
                if v + M1_DELTA == STUB1_FILE:
                    far_m1.append({"file": fname, "site": "0x%05X" % c["at"], "literal": "%04X:%04X" % (c["seg"], c["off"])})
    return {"near_E8_to_stub1": near, "far_M0_to_stub1": far_m0, "far_M1_to_stub1": far_m1}


def raw_pattern_hits(files: dict[str, bytes], pat: bytes) -> dict:
    out = {}
    for fname, data in files.items():
        hits = [m.start() for m in re.finditer(re.escape(pat), data)]
        out[fname] = ["0x%05X" % h for h in hits]
    return out


def raw_candidates(hdr: int, files: dict[str, bytes]) -> dict:
    """Byte-pattern candidates for the target, by model. Raw only: never counted as a caller or table."""
    near = {
        "M0_value_0x069C": STUB1_FILE - hdr,
        "M1_value_0x081E": STUB1_FILE - M1_DELTA,
        "group_rel_proc_0x0D6D": STUB1_PROC_REL,
    }
    near_hits = {}
    for label, w in near.items():
        if 0 <= w <= 0xFFFF:
            near_hits[label] = {"word": "0x%04X" % w, "hits": raw_pattern_hits(files, struct.pack("<H", w))}
    far_hits = {}
    for model, value in (("M0", STUB1_FILE - hdr), ("M1", STUB1_FILE - M1_DELTA)):
        pairs = []
        for seg in range(0, value // 16 + 1):
            off = value - seg * 16
            if 0 <= off <= 0xFFFF:
                pairs.append((seg, off))
        per = {}
        total = 0
        for seg, off in pairs:
            h = raw_pattern_hits(files, struct.pack("<HH", off, seg))
            n = sum(len(v) for v in h.values())
            if n:
                per["%04X:%04X" % (seg, off)] = h
                total += n
        far_hits[model] = {"value": "0x%04X" % value, "pairs_tested": len(pairs),
                           "pairs_with_hits": per, "total_hits": total}
    return {"near_words": near_hits, "far_pairs": far_hits,
            "stub1_identity_bytes": raw_pattern_hits(files, STUB1_BYTES)}


def table_candidates(data: bytes, ind_rows: list[dict], ds_bases: list[int], hdr: int) -> dict:
    """T: resolve each decoded direct-DS operand through each caller-stated DS base. Empty on retail.

    The table word is compared with the stub-1 near value under the M0 model (0x089C - hdr, base 0).
    That is one stated model, not a proof that the table is a near pointer."""
    resolved = []
    m0_near = STUB1_FILE - hdr
    for base in ds_bases:
        for r in ind_rows:
            if r["operand"] != "direct-ds":
                continue
            word = resolve_table(data, base, r["direct_ds_disp"])
            if word is None:
                continue
            resolved.append({"site": r["site"], "ds_base_file": "0x%05X" % base,
                             "table_word": "0x%04X" % word, "model": "M0-near-base0",
                             "points_to_stub1": word == m0_near})
    return {"ds_bases_stated": ["0x%05X" % b for b in ds_bases], "resolved": resolved}


def analyse(ovr: bytes, start: bytes, ds_bases: Optional[list[int]] = None) -> dict:
    hdr = fr.mz_image_base(start)
    scan = fr.scan_all(start, ovr)
    allg = scan["groups"] + scan["partial_groups"]
    cache = dc.GroupCache(ovr)
    st = start_census(start, hdr)
    ov = ovr_census(ovr, allg, cache)
    start_ind = decoded_ind_sites(start, st["walks"], "START.EXE")
    ind_all = start_ind + [r for g in ov["groups"] for r in g["ind_sites"]]
    reach = stub1_decoded_reach(hdr, {"START.EXE": [w for _, _, w in st["walks"]],
                                      "GAME.OVR": ov["all_walks"]})
    files = {"START.EXE": start, "GAME.OVR": ovr}
    return {
        "image_base": "0x%03X" % hdr,
        "m1_delta": "0x%02X" % M1_DELTA,
        "target": {"stub1_file": "0x%05X" % STUB1_FILE, "stub1_proc_rel": "0x%04X" % STUB1_PROC_REL,
                   "proc_file": "0x%05X" % PROC1_FILE, "group_file": "0x%05X" % GROUP_FILE,
                   "stub1_bytes": STUB1_BYTES.hex(" ")},
        "start": {k: v for k, v in st.items() if k not in ("walks", "starts")},
        "ovr": {"groups": ov["groups"], "outside_group_bytes": ov["outside_group_bytes"],
                "outside_group_ff": ov["outside_group_ff"]},
        "decoded_indirect_sites": ind_all,
        "decoded_indirect_counts": {
            "FF_2_near": sum(1 for r in ind_all if r["kind"] == "near"),
            "FF_3_far": sum(1 for r in ind_all if r["kind"] == "far"),
            "by_operand": dict(sorted(Counter(r["operand"] for r in ind_all).items())),
        },
        "stub1_decoded_reach": reach,
        "raw_candidates": raw_candidates(hdr, files),
        "table_resolution": table_candidates(start, ind_all, ds_bases or [], hdr),
    }


def verdict(result: dict) -> dict:
    """Trigger established only if a decoded indirect site resolves through a stated DS base to stub 1."""
    reach = result["stub1_decoded_reach"]
    direct_decoded = bool(reach["near_E8_to_stub1"] or reach["far_M0_to_stub1"] or reach["far_M1_to_stub1"])
    table_hit = [x for x in result["table_resolution"]["resolved"] if x["points_to_stub1"]]
    established = direct_decoded or bool(table_hit)
    return {
        "trigger_established": established,
        "reason": ("a decoded direct or resolved indirect call reaches stub 1" if established else
                   "no decoded direct call reaches stub 1 and no decoded indirect operand resolves to it; "
                   "table addresses need a caller-stated DS base, which the bytes here do not establish"),
    }


def recheck_pins(install: Path, pins: dict) -> dict:
    """Re-hash both pinned files after the run. A change is a refusal (pins before/after)."""
    after = {}
    for name in (fr.OVR_NAME, fr.EXE_NAME):
        raw = (install / name).read_bytes()
        after[name] = {"size": len(raw), "sha256": fr._sha(raw), "pin_match": True}
        if after[name]["sha256"] != pins[name]["sha256"] or after[name]["size"] != pins[name]["size"]:
            raise Refusal("%s changed during the run; refusing" % name)
    return after


def probe(install: Path, ds_bases: Optional[list[int]] = None) -> dict:
    ovr, start, pins_before = dc.load_pinned(install)
    result = analyse(ovr, start, ds_bases)
    pins_after = recheck_pins(install, pins_before)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "pins": {"before": pins_before, "after": pins_after,
                 "unchanged": True},
        "models": {
            "M0": "zero-skew: hdr + seg*16 + off (unproven)",
            "M1": "dump-anchored: seg*16 + off + 0x7E (conditional on one dump's stub-4 identity; unproven)",
        },
        "evidence_classes": {
            "I": "decoded instruction start (walk reached); the only class that is a census row",
            "R": "raw byte-pattern candidate; not a caller, not a table",
            "T": "table resolved through a caller-stated DS base; none on retail",
        },
        "analysis": result,
        "verdict": verdict(result),
        "open_edges": [
            "The trigger for stub 1 is not established by any decoded direct or indirect call here.",
            "DS base of each indirect caller is not established; direct-DS tables cannot be read.",
            "Segment-to-file mapping at run time: the entry copies the image (rep movsb) and far-returns into it; "
            "M0 and M1 remain unproven hypotheses.",
            "Runtime execution is not observed: every row is a static decode.",
        ],
    }


def render_report(doc: dict) -> str:
    a = doc["analysis"]
    L = ["# PoR indirect callers of stub 1 (static, observe-only)", "",
         "**Status: static-probe-only. `playable: false`.** Tool: `%s`." % TOOL, "",
         "## Verdict", "", "- trigger_established: **%s**" % doc["verdict"]["trigger_established"],
         "- %s" % doc["verdict"]["reason"], "",
         "## Pins (before and after the run)", ""]
    for k in doc["pins"]["before"]:
        b = doc["pins"]["before"][k]
        L.append("- `%s` size %d sha256 `%s` (after: sha `%s`, unchanged)" % (
            k, b["size"], b["sha256"], doc["pins"]["after"][k]["sha256"]))
    L += ["", "## Evidence classes", ""] + ["- %s: %s" % (k, v) for k, v in doc["evidence_classes"].items()]
    L += ["", "## Coverage", ""]
    s = a["start"]["coverage"]
    L.append("- START.EXE image (entry `%s`, %s): covered %d of %d bytes (%s), walks %d (complete %d), incomplete %s"
             % (a["start"]["entry_file"], a["start"]["entry_cs_ip"], s["covered_bytes"], s["size"],
                s["covered_fraction"], s["walks"], s["walks_complete"], s["incomplete_codes"]))
    for g in a["ovr"]["groups"]:
        c = g["coverage"]
        L.append("- group `0x%05X` (%s, codesz 0x%04X, valid stubs %d): covered %d/%d (%s), walks %d (complete %d), "
                 "incomplete %s, out-of-group near targets %d"
                 % (g["fileofs"], g["status"], g["codesz"], g["valid_stubs"], c["covered_bytes"], c["size"],
                    c["covered_fraction"], c["walks"], c["walks_complete"], c["incomplete_codes"],
                    c["near_targets_outside_domain"]))
    L.append("- GAME.OVR bytes outside every owner-group body: %d (raw FF census only: %s)"
             % (a["ovr"]["outside_group_bytes"], a["ovr"]["outside_group_ff"]["counts"]))
    L += ["", "## Class I: decoded FF /2 and FF /3 (instruction starts)", ""]
    dc_ = a["decoded_indirect_counts"]
    L.append("- FF /2 near: %d; FF /3 far: %d; by operand: %s" % (dc_["FF_2_near"], dc_["FF_3_far"], dc_["by_operand"]))
    for r in a["decoded_indirect_sites"]:
        L.append("  - `%s` %s %s operand `%s` (%s) in fn `%s` [%s] `%s`" % (
            r["site"], r["kind"], r["bytes"], r["operand"], r["domain"], r["caller_entry"], r["tier"], r["text"]))
    L += ["", "### Raw FF byte census (class R; FF with ModRM reg 2 or 3)", ""]
    L.append("- START.EXE: %s" % a["start"]["byte_census_ff"]["counts"])
    for g in a["ovr"]["groups"]:
        L.append("- group `0x%05X`: %s" % (g["fileofs"], g["byte_census_ff"]["counts"]))
    L += ["", "## Stub 1 reach (decoded instruction starts only)", ""]
    for k, v in a["stub1_decoded_reach"].items():
        L.append("- %s: %d" % (k, len(v)))
    L += ["", "## Raw byte-pattern candidates (class R; not callers, not tables)", ""]
    rc = a["raw_candidates"]
    L.append("- stub 1 identity bytes `cd 3f 6d 0d 00`: %s" % {k: len(v) for k, v in rc["stub1_identity_bytes"].items()})
    for label, v in rc["near_words"].items():
        L.append("- near word %s = `%s`: %s" % (label, v["word"], {k: len(x) for k, x in v["hits"].items()}))
    for model, v in rc["far_pairs"].items():
        L.append("- far pairs %s (value `%s`): %d pairs tested, %d hits" % (model, v["value"], v["pairs_tested"], v["total_hits"]))
    L += ["", "## Table resolution (class T)", ""]
    tr = a["table_resolution"]
    L.append("- DS bases stated: %s; resolved decoded operands: %d" % (tr["ds_bases_stated"], len(tr["resolved"])))
    L += ["", "## Open edges", ""] + ["- " + x for x in doc["open_edges"]] + [""]
    return "\n".join(L)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_door_indirect_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_door_indirect_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def _inside(child: Path, parent: Path) -> bool:
    return dc._inside(child, parent)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only static census of indirect calls into PoR stub 1.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL,
                    help="folder with the pinned GAME.OVR and START.EXE")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    try:
        doc = probe(args.install)
    except (Refusal, dc.Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
