#!/usr/bin/env python3
"""Pool of Radiance: resolve the owner closure's far pointers through the overlay fixup/group evidence.

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only, playable: false.

Input question. The wall-callee probe (tools/por_wall_callee_probe.py) found eight far calls in the
seven-procedure closure rooted at GAME.OVR 0x2EEF4. They reach three raw ``seg:off`` pairs
(0x0428:0x002A, 0x0464:0x2632, 0x0464:0x1B52). Their segment words sit in the owning group's fixup
table, so the loader rewrites them. This probe asks whether any of the three can be mapped to one exact
START.EXE or GAME.OVR file offset using only the evidence already in OpenUA: the pinned bytes, the
VROOMM descriptors and fixup tables, and optional RAM dumps.

What it does (each step's output is labelled, never merged):

  1. Descriptors. Every ``CD 3F 00 00`` header in START.EXE is parsed with the overlay group map's
     parser and bound-checked against GAME.OVR. The owner is the one group whose code span holds the
     owner offset; zero or more than one is a named refusal.
  2. Far-call sites. The owner's far calls are taken from the callee probe's closure. For each, the
     segment word (site+3) is checked against the owner's fixup table.
  3. Sibling deltas, per RAM dump. Every descriptor is mapped into the dump with the group map's
     stable-byte rule. For each uniquely mapped group, every fixup word's live-minus-raw delta is
     recorded. The owner group is reported as mapped or not in each dump. An owner measurement is
     possible only if the owner itself maps uniquely.
  4. Consensus delta. The set of sibling deltas across all dumps. A single value is a CONSENSUS, not a
     measurement of the owner's delta; the owner's own delta is only measured if step 3 maps it.
  5. Target resolution, under each candidate delta (the consensus, if one exists). For raw target
     ``seg:off`` and delta D, the live linear address is ``((seg + D) & 0xFFFF) * 16 + off``. The 32
     live bytes there are classified as:
       * jmp-stub-to-mapped-group: the live bytes begin ``EA off16 seg16`` (a far JMP over a VROOMM
         ``CD 3F`` stub, the way the overlay manager patches a resident stub), seg16 equals the base
         of a uniquely mapped group, and off16 lies inside that group's code. The group body offset
         maps to a GAME.OVR file offset. The stub's START.EXE position is found by byte match.
       * exact-file: the 32 live bytes occur exactly once in the pinned files.
       * masked-file: the live bytes equal one pinned file window except a single 16-bit word that sits
         after a 9A opcode and differs by exactly D. That is the loader's rewrite of a far-call operand.
       * no-match.
  6. Delta sweep (sensitivity only). Every D in 0..0xFFFF is tried for each target. The counts show how
     many deltas would also give a stub or exact match. Many do, so bytes alone do not single out one
     delta. The sweep never establishes a delta; it only records the ambiguity.
  7. Bounded closure. Only at a target resolved under the consensus delta, the callee probe's closure
     is decoded from the resolved file offset. Reported as CONDITIONAL on the consensus delta.

Kept apart in every output:
  * owner evidence       the owner group's own bytes and fixups (static);
  * sibling evidence     the other groups' deltas in RAM (measured in those groups only);
  * consensus            a model: one delta applied to the owner (not measured for the owner);
  * conditional result   a resolution or closure under the consensus, not a runtime fact.

Not established by this tool (recorded in the output): the owner group's own delta; that any target was
executed or reached; the owner's caller; any WALLDEF/8X8D/DAX binding or record-selection table.

Usage
  python3 tools/por_wall_far_target_probe.py --install "PATH/TO/POOLRAD" \
      --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
      --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
      -o data/work/por-wall-far-target-probe/retail

Exit codes
  0  every target resolves to one file offset under a MEASURED owner delta (not reached on retail bytes)
  1  output written; the question is not closed (the expected result on retail bytes)
  2  named refusal: bad install, unpinned file, missing dump, owner not in exactly one group, or unsafe
     output location
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_callee_probe as wcp  # noqa: E402

SCHEMA = "openua.por-wall-far-target-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_wall_far_target_probe.py"
OWNER = 0x2EEF4
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"
WINDOW = 32
PARA = 16
DELTA_SPACE = 0x10000
JMP_FAR = 0xEA
FAR_CALL = 0x9A
DESC_MAGIC = b"\xCD\x3F\x00\x00"
INT3F = b"\xCD\x3F"
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
MAX_DEPTH = wcp.DEFAULT_MAX_DEPTH
MAX_PROCS = wcp.DEFAULT_MAX_PROCS
MAX_INSNS = wcp.DEFAULT_MAX_INSNS
SWEEP_EXAMPLES = 8
STUB_DISTS = (0x16, 0x17)            # header -> first stub, both scored (por_farcall_resolve model)
STUB_LEN = 5

CLAIMS = {
    "owner_delta": "not_established unless the owner group maps uniquely in a dump",
    "consensus_delta": "a model: sibling-group agreement, applied to the owner, not measured for it",
    "conditional_resolution": "a target resolution or closure under the consensus delta only",
    "reached_or_executed": "not_established",
}
NOT_ESTABLISHED = [
    "the owner group's own load delta, unless the owner maps uniquely in a dump",
    "that any far target was executed, called, or reached by control flow",
    "the caller of the owner at 0x2EEF4",
    "which of the candidate deltas is the true delta for any target (the sweep is ambiguous)",
    "any WALLDEF, 8X8D or DAX binding, or a record-selection table, for any target",
]


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def descriptor_table(exe: bytes, ovr: bytes) -> list[dict]:
    """Every CD 3F 00 00 header in START.EXE, parsed; refused headers are kept with the reason."""
    rows: list[dict] = []
    p = exe.find(ogm.DESC_MAGIC)
    while p != -1:
        try:
            grp = ogm.parse_descriptor(exe, ovr, p)
            grp["fixups"] = ogm.read_fixups(ovr, grp)
            grp["code"] = ovr[grp["fileofs"]:grp["fileofs"] + grp["codesz"]]
            rows.append(grp)
        except ogm.Refusal as exc:
            rows.append({"descriptor_offset": p, "refused": str(exc)})
        p = exe.find(ogm.DESC_MAGIC, p + 1)
    return rows


def owner_group(rows: list[dict], owner: int) -> dict:
    cands = [r for r in rows if "refused" not in r
             and r["fileofs"] <= owner < r["fileofs"] + r["codesz"]]
    if len(cands) != 1:
        raise ogm.Refusal("owner 0x%X lies in %d descriptor groups (need exactly one)"
                          % (owner, len(cands)))
    return cands[0]


def wall_far_sites(ovr: bytes, owner: int) -> dict:
    """Far calls left unfollowed by the callee probe's closure from the owner."""
    trav = wcp.analyse(ovr, owner, MAX_DEPTH, MAX_PROCS, MAX_INSNS)
    v = trav["verdict"]
    sites = []
    for f in v["far_calls_not_followed"]:
        sites.append({"site": f["at"], "proc": f["proc"], "seg": f["seg"], "off": f["off"],
                      "bytes": f["bytes"]})
    sites.sort(key=lambda s: s["site"])
    return {"verdict_answer": v["answer"], "closure_complete": v["closure_complete"],
            "procs_explored": v["procs_explored"], "instructions_decoded": v["instructions_decoded"],
            "int21_file_hits": len(v["dos_file_function_hits"]),
            "string_token_candidates": len(v["string_token_candidates"]), "sites": sites,
            "_raw": v}


def owner_site_rows(og: dict, sites: list[dict]) -> list[dict]:
    """Each far site's segment word must be listed in the owner group's fixup table."""
    listed = set(og["fixups"])
    out = []
    for s in sites:
        body = s["site"] - og["fileofs"]
        seg_body = body + 3
        out.append({"site_file": _hex(s["site"]), "site_group": _hex(body),
                    "seg_word_group": _hex(seg_body),
                    "seg_word_fixup_listed": seg_body in listed,
                    "raw_target": "%04X:%04X" % (s["seg"], s["off"]),
                    "in_owner_span": 0 <= body < og["codesz"]})
    return out


def map_siblings(rows: list[dict], dump: ogm.Dump) -> list[dict]:
    """Map every descriptor into one dump; record each uniquely mapped group's fixup deltas."""
    out = []
    for r in rows:
        if "refused" in r:
            continue
        row = {"descriptor_offset": _hex(r["descriptor_offset"]), "fileofs": _hex(r["fileofs"]),
               "codesz": _hex(r["codesz"]), "fixup_count": len(r["fixups"])}
        try:
            m = ogm.map_group(r, r["code"], r["fixups"], dump)
        except ogm.Refusal as exc:
            row["mapping_status"] = "refused"
            row["reason"] = str(exc)
            out.append(row)
            continue
        row["mapping_status"] = m["status"]
        if m["status"] == "unique" and r["fixups"]:
            base = m["base_linear"]
            deltas = sorted({(u16(dump.read(base + w, 2), 0) - u16(r["code"], w)) & 0xFFFF
                             for w in r["fixups"]})
            row.update({"base_linear": _hex(base), "base_paragraph_aligned": base % PARA == 0,
                        "deltas": deltas})
        out.append(row)
    return out


def consensus(sib_rows: list[dict]) -> dict:
    unique = [r for r in sib_rows if r.get("deltas")]
    vals = sorted({d for r in unique for d in r["deltas"]})
    uniform_groups = all(len(r["deltas"]) == 1 for r in unique)
    return {"groups_with_deltas": len(unique),
            "delta_values": ["0x%04X" % v for v in vals],
            "each_group_uniform": uniform_groups,
            "consensus_delta": ("0x%04X" % vals[0]) if (len(vals) == 1 and uniform_groups) else None}


def mapped_segments(sib_rows: list[dict], rows: list[dict]) -> dict:
    """Group base segment -> descriptor row, for uniquely mapped, paragraph-aligned groups."""
    by_desc = {"0x%X" % r["descriptor_offset"]: r for r in rows if "refused" not in r}
    out = {}
    for s in sib_rows:
        if s.get("mapping_status") != "unique" or not s.get("base_paragraph_aligned"):
            continue
        base = int(s["base_linear"], 16)
        g = by_desc[s["descriptor_offset"]]
        out[base // PARA] = {"descriptor_offset": s["descriptor_offset"], "fileofs": g["fileofs"],
                             "codesz": g["codesz"], "base_linear": base}   # ints
    return out


def stub_file_hits(start: bytes, w: bytes) -> list[int]:
    """START.EXE offsets of a VROOMM stub that matches the live (JMP-patched) window.

    A patched stub keeps the file's ``CD 3F`` operand bytes at +2..+3 and the file's tail from +5 on.
    The live bytes at +0 (EA) and +3..+4 (the segment) differ from the file, so they are not compared.
    """
    hits = []
    p = start.find(INT3F)
    while p != -1:
        if p + WINDOW <= len(start) and start[p + 2:p + 4] == w[1:3] and start[p + 5:p + WINDOW] == w[5:WINDOW]:
            hits.append(p)
        p = start.find(INT3F, p + 1)
    return hits


def stub_run_hits(start: bytes, rows: list[dict], w: bytes) -> list[dict]:
    """File stub hits that also sit at a valid stub-run slot of a descriptor (header+0x16/0x17, stride 5).

    This is a layout check against the descriptors' own jmpcnt, using the stub-run model that
    tools/por_farcall_resolve.py documents. It is a model, recorded as such.
    """
    out = []
    for p in stub_file_hits(start, w):
        for r in rows:
            if "refused" in r:
                continue
            h = r["descriptor_offset"]
            for dist in STUB_DISTS:
                s0 = h + dist
                if s0 <= p < s0 + STUB_LEN * r["jmpcnt"] and (p - s0) % STUB_LEN == 0:
                    out.append({"stub_file": "0x%X" % p, "header": "0x%X" % h, "dist": dist,
                                "index": (p - s0) // STUB_LEN, "proc_off": "0x%04X" % u16(start, p + 2)})
    return out


def _jmp_target(w: bytes) -> tuple[int, int]:
    return u16(w, 1), u16(w, 3)


def classify_at(raw: int, off: int, delta: int, dump: ogm.Dump, files: dict[str, bytes],
                segs: dict, ovr: bytes, rows: list[dict]) -> dict:
    seg = (raw + delta) & 0xFFFF
    lin = seg * PARA + off
    out = {"delta": "0x%04X" % delta, "live_seg": "%04X" % seg, "linear": "0x%05X" % lin}
    if not dump.covers(lin, WINDOW):
        out["status"] = "out-of-dump"
        return out
    w = dump.read(lin, WINDOW)
    out["live_bytes"] = w[:8].hex(" ")
    if w[0] == JMP_FAR:
        o2, s2 = _jmp_target(w)
        g = segs.get(s2)
        if g is not None and o2 < g["codesz"]:
            file_off = g["fileofs"] + o2
            out["status"] = "jmp-stub-to-mapped-group"
            out["jmp_target"] = "%04X:%04X" % (s2, o2)
            out["group"] = {"descriptor_offset": g["descriptor_offset"], "group_body": _hex(o2),
                            "gameovr_offset": _hex(file_off),
                            "prologue_ok": ovr[file_off:file_off + 3] in PROLOGUES}
            out["start_stub_hits"] = ["0x%X" % p for p in stub_file_hits(files[EXE_NAME], w)]
            out["start_stub_runs"] = stub_run_hits(files[EXE_NAME], rows, w)
            return out
    exact = ogm.classify_target(w, files)
    out["exact"] = {"status": exact["status"], "hits": exact["hits"]}
    out["status"] = exact["status"] if exact["status"].startswith("unique-") else "no-exact-match"
    return out


def masked_hits(w: bytes, files: dict[str, bytes], delta: int) -> list[dict]:
    """Pinned windows equal to w except one 16-bit far-call operand word differing by exactly delta."""
    hits = []
    for name, data in files.items():
        for q in range(len(data) - WINDOW + 1):
            seg = data[q:q + WINDOW]
            diff = [i for i in range(WINDOW) if seg[i] != w[i]]
            if not diff:
                continue                      # an exact match is classify_target's job
            lo = diff[0]
            # the differing bytes must lie inside one 16-bit word that follows a 9A opcode
            for k in sorted({lo - 1, lo}):
                if k < 3 or k + 1 >= WINDOW or any(i < k or i > k + 1 for i in diff):
                    continue
                if seg[k - 3] != FAR_CALL or ((u16(w, k) - u16(seg, k)) & 0xFFFF) != delta:
                    continue
                hits.append({"file": name, "offset": "0x%X" % q, "word_at": k,
                             "file_word": "%04X" % u16(seg, k), "live_word": "%04X" % u16(w, k)})
                break
    return hits


def resolve_masked(raw: int, off: int, delta: int, dump: ogm.Dump, files: dict[str, bytes]) -> dict:
    seg = (raw + delta) & 0xFFFF
    lin = seg * PARA + off
    if not dump.covers(lin, WINDOW):
        return {"status": "out-of-dump", "hits": []}
    hits = masked_hits(dump.read(lin, WINDOW), files, delta)
    status = "masked-unique" if len(hits) == 1 else ("masked-absent" if not hits else "masked-ambiguous")
    return {"status": status, "hits": hits}


def sweep(raw: int, off: int, dump: ogm.Dump, files: dict[str, bytes], segs: dict,
          rows: list[dict], candidate: Optional[int]) -> dict:
    """Sensitivity: how many deltas also give a stub or an exact-unique window, and of the stub
    matches, which also sit at a valid stub-run slot (the discriminator)."""
    covered = jmp = exact_unique = 0
    jmp_ex, exact_ex, run_ok = [], [], []
    for d in range(DELTA_SPACE):
        seg = (raw + d) & 0xFFFF
        lin = seg * PARA + off
        if not dump.covers(lin, WINDOW):
            continue
        covered += 1
        w = dump.read(lin, WINDOW)
        if w[0] == JMP_FAR:
            o2, s2 = _jmp_target(w)
            g = segs.get(s2)
            if g is not None and o2 < g["codesz"]:
                jmp += 1
                if len(jmp_ex) < SWEEP_EXAMPLES:
                    jmp_ex.append("0x%04X" % d)
                if stub_run_hits(files[EXE_NAME], rows, w):
                    run_ok.append("0x%04X" % d)
        ex = ogm.classify_target(w, files)
        if ex["status"].startswith("unique-"):
            exact_unique += 1
            if len(exact_ex) < SWEEP_EXAMPLES:
                exact_ex.append("0x%04X" % d)
    cand = None if candidate is None else "0x%04X" % candidate
    return {"deltas_covered": covered, "jmp_stub_to_mapped_group": jmp,
            "exact_unique": exact_unique, "jmp_examples": jmp_ex, "exact_examples": exact_ex,
            "jmp_with_stub_run_slot": run_ok, "candidate": cand,
            "candidate_is_only_stub_run_delta": (run_ok == [cand]) if cand else None}


def closure_at(data: bytes, root: int) -> dict:
    trav = wcp.analyse(data, root, MAX_DEPTH, MAX_PROCS, MAX_INSNS)
    v = trav["verdict"]
    return {"root": _hex(root), "answer": v["answer"], "closure_complete": v["closure_complete"],
            "procs_explored": v["procs_explored"], "instructions_decoded": v["instructions_decoded"],
            "int21_file_hits": len(v["dos_file_function_hits"]),
            "int21_ah_unknown": len(v["int21_ah_unknown"]),
            "far_calls_not_followed": len(v["far_calls_not_followed"]),
            "indirect_calls_not_followed": len(v["indirect_calls_not_followed"]),
            "string_token_candidates": len(v["string_token_candidates"]),
            "selector_candidate_count": v["selector_candidate_count"],
            "selection_reached": v["selection_reached"]}


def analyse(ovr: bytes, exe: bytes, dumps: list[tuple[str, bytes, int]], owner: int = OWNER, *,
            pins: dict = ogm.PINS, run_sweep: bool = True) -> dict:
    ogm.check_pin(OVR_NAME, ovr, pins)
    ogm.check_pin(EXE_NAME, exe, pins)
    if not dumps:
        raise ogm.Refusal("at least one RAM dump is required to measure segment deltas")
    rows = descriptor_table(exe, ovr)
    og = owner_group(rows, owner)
    wall = wall_far_sites(ovr, owner)
    site_rows = owner_site_rows(og, wall["sites"])
    targets = sorted({(s["seg"], s["off"]) for s in wall["sites"]})
    files = {OVR_NAME: ovr, EXE_NAME: exe}

    per_dump, all_deltas, owner_measured = [], set(), False
    dump_objs = []
    for name, data, base in dumps:
        dump = ogm.Dump(data, base)
        dump_objs.append((name, dump))
        sib = map_siblings(rows, dump)
        owner_row = next(s for s in sib if s["descriptor_offset"] == "0x%X" % og["descriptor_offset"])
        cons = consensus([s for s in sib if s is not owner_row])
        if owner_row.get("deltas") and len(owner_row["deltas"]) == 1:
            owner_measured = True
        for s in sib:
            all_deltas.update(int(d, 16) if isinstance(d, str) else d for d in s.get("deltas", []))
        per_dump.append({"name": name, "size": len(data), "base": _hex(base), "end": _hex(base + len(data)),
                         "owner": {"mapping_status": owner_row["mapping_status"],
                                   "deltas": ["0x%04X" % d for d in owner_row.get("deltas", [])]},
                         "sibling_consensus": cons, "groups": sib})
    union = sorted(all_deltas)
    union_consensus = ("0x%04X" % union[0]) if len(union) == 1 else None
    # Candidate delta for resolution: the union consensus when it exists, else none (no resolution).
    cand = union[0] if union_consensus else None

    target_rows = []
    for raw, off in targets:
        t = {"raw": "%04X:%04X" % (raw, off), "sites": [s for s in site_rows
                                                        if s["raw_target"] == "%04X:%04X" % (raw, off)],
             "per_dump": []}
        for (name, dump), pdump in zip(dump_objs, per_dump):
            segs = mapped_segments(pdump["groups"], rows)
            entry = {"dump": name, "sibling_delta_candidate": _hex(cand)}
            if cand is not None:
                entry["resolution"] = classify_at(raw, off, cand, dump, files, segs, ovr, rows)
                if entry["resolution"]["status"] == "no-exact-match":
                    entry["masked"] = resolve_masked(raw, off, cand, dump, files)
            else:
                entry["resolution"] = {"status": "no-candidate-delta"}
            if run_sweep:
                entry["sweep"] = sweep(raw, off, dump, files, segs, rows, cand)
            t["per_dump"].append(entry)
        target_rows.append(t)

    closures = []
    for t in target_rows:
        for e in t["per_dump"]:
            res = e.get("resolution", {})
            status = res.get("status")
            file_off = None
            data = None
            if status == "jmp-stub-to-mapped-group" and res["group"]["prologue_ok"]:
                data, file_off = ovr, int(res["group"]["gameovr_offset"], 16)
            elif status == "unique-START.EXE":
                data, file_off = exe, int(res["exact"]["hits"][EXE_NAME][0], 16)
            elif status == "unique-GAME.OVR":
                data, file_off = ovr, int(res["exact"]["hits"][OVR_NAME][0], 16)
            elif e.get("masked", {}).get("status") == "masked-unique":
                h = e["masked"]["hits"][0]
                data, file_off = exe if h["file"] == EXE_NAME else ovr, int(h["offset"], 16)
            if data is not None:
                closures.append({"target": t["raw"], "dump": e["dump"], "file": (
                    OVR_NAME if data is ovr else EXE_NAME), "resolution": status,
                    "closure": closure_at(data, file_off)})
                break

    resolved_all = all(
        any(e.get("resolution", {}).get("status") in ("jmp-stub-to-mapped-group", "unique-START.EXE",
                                                      "unique-GAME.OVR")
            or e.get("masked", {}).get("status") == "masked-unique" for e in t["per_dump"])
        for t in target_rows)
    def _discriminated(e: dict) -> bool:
        sw = e.get("sweep", {})
        if sw.get("candidate_is_only_stub_run_delta"):
            return True                      # the stub-run slot singles out the candidate
        return sw.get("jmp_stub_to_mapped_group", 0) <= 1 and sw.get("exact_unique", 0) <= 1

    sweep_unique = bool(run_sweep) and all(_discriminated(e)
                                           for t in target_rows for e in t["per_dump"])
    if union_consensus is None:
        answer = "cannot-determine: sibling deltas disagree; no consensus candidate"
    elif owner_measured and resolved_all:
        answer = "resolved-under-measured-owner-delta"
    elif owner_measured:
        answer = "owner-delta-measured; some-target-unresolved"
    else:
        answer = "conditional-on-sibling-consensus-delta; owner-delta-unmeasured"
        answer += "; delta-unique-by-bytes" if sweep_unique else "; no-unique-delta-for-all-targets"
    if not run_sweep:
        answer += "; sweep-not-run"
    status = "ok" if (owner_measured and resolved_all and sweep_unique) else "diagnostic"

    wall_out = {k: v for k, v in wall.items() if k != "_raw"}
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL, "status_scope": STATUS,
        "playable": False, "status": status,
        "inputs": {OVR_NAME: {"size": len(ovr), "sha256": ogm.sha256(ovr), "pinned": True},
                   EXE_NAME: {"size": len(exe), "sha256": ogm.sha256(exe), "pinned": True},
                   "dumps": [{"name": name, "size": len(data), "sha256": ogm.sha256(data),
                              "base": _hex(base)} for name, data, base in dumps]},
        "owner": {"owner_offset": _hex(owner), "descriptor_offset": _hex(og["descriptor_offset"]),
                  "fileofs": _hex(og["fileofs"]), "codesz": _hex(og["codesz"]),
                  "fixupsz": _hex(og["fixupsz"]), "jmpcnt": og["jmpcnt"],
                  "fixup_count": len(og["fixups"])},
        "owner_closure": wall_out,
        "owner_far_sites": site_rows,
        "descriptor_refusals": [{"descriptor_offset": _hex(r["descriptor_offset"]),
                                 "reason": r["refused"]} for r in rows if "refused" in r],
        "delta_evidence": {"per_dump": per_dump,
                           "union_delta_values": ["0x%04X" % d for d in union],
                           "union_consensus_delta": union_consensus,
                           "owner_delta_measured": owner_measured},
        "targets": target_rows,
        "closures_conditional": closures,
        "verdict": {"answer": answer, "owner_delta_measured": owner_measured,
                    "every_target_resolved_under_candidate": resolved_all,
                    "sweep_unique_by_bytes": sweep_unique if run_sweep else None,
                    "playable": False},
        "claims": dict(CLAIMS),
        "not_established": list(NOT_ESTABLISHED),
    }


def _meta_dump(path: Path) -> tuple[str, bytes, int]:
    data = path.read_bytes()
    base = ogm.resolve_dump_base(path.name, len(data), None)
    return path.name, data, base


def probe(install: Optional[Path], dump_paths: list[Path], *, out: Path, owner: int,
          run_sweep: bool) -> tuple[dict, int]:
    folder = ogm.find_install(install)
    try:
        out_dir = validate_output_dir(folder, out)
    except PorSourceError as exc:
        raise ogm.Refusal(str(exc))
    if ogm.DATA_WORK.resolve() not in out_dir.parents:
        raise ogm.Refusal("output must be a folder under data/work; got %s" % out_dir)
    for p in dump_paths:
        if not p.is_file():
            raise ogm.Refusal("dump not found: %s" % p.name)
    ovr = (folder / OVR_NAME).read_bytes()
    exe = (folder / EXE_NAME).read_bytes()
    dumps = [_meta_dump(p) for p in dump_paths]
    doc = analyse(ovr, exe, dumps, owner, run_sweep=run_sweep)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "por_wall_far_target_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc, (0 if doc["status"] == "ok" else 1)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Resolve the owner closure's far targets (read-only).")
    ap.add_argument("--install", type=Path, default=None,
                    help="PoR install folder (or POOLRAD inside it); default $%s" % ogm.INSTALL_ENV)
    ap.add_argument("--dump", type=Path, action="append", default=[], required=True,
                    help="raw RAM dump named ram-LO-HI.bin (repeatable)")
    ap.add_argument("--owner", type=lambda s: int(s, 16), default=OWNER,
                    help="owner file offset (hex; default 0x2EEF4)")
    ap.add_argument("--no-sweep", action="store_true", help="skip the delta sweep")
    ap.add_argument("-o", "--out", type=Path, default=ogm.DEFAULT_OUT.parent / "por-wall-far-target-probe",
                    help="output folder under data/work")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.dump, out=args.out, owner=args.owner,
                          run_sweep=not args.no_sweep)
    except ogm.Refusal as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2
    print("status=%s answer=%s owner_measured=%s consensus=%s" % (
        doc["status"], doc["verdict"]["answer"], doc["delta_evidence"]["owner_delta_measured"],
        doc["delta_evidence"]["union_consensus_delta"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
