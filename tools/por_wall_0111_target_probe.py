#!/usr/bin/env python3
"""Pool of Radiance: identify the far target 0x0464:0x0111 called from GAME.OVR 0x32270, and bound its body.

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only, playable: false.

Question. The bounded census (docs/por-wall-32392-table-census.md, section 5) found that the procedure at
GAME.OVR 0x32270 passes a far pointer to an F-table element to the far callee 0x0464:0x0111, and that the
callee was not followed. This probe asks two things, each kept separate in the output:

  A. Identity. Can the pinned START.EXE / GAME.OVR bytes and the existing ignored RAM dumps locate the callee
     under an explicitly stated conditional mapping? The mapping used here is the CALLER'S OWN measured delta:
     the call's segment word lies in a fixup-listed word of the caller's VROOMM group, and if that group maps
     uniquely in a dump, the live word minus the raw word is the delta the loader applied to that segment.
     The probe records this per dump and refuses to resolve unless every dump measures the same delta, and
     the group's fixup words all share it. The sibling-consensus delta of por-wall-far-target-probe.md is not
     used here.
  B. Body. If the target is located uniquely, decode its body with a bounded walk (an explicit span; near calls
     followed only inside it) and report: writes and reads through the passed far pointer, tracked in straight-line
     order per procedure; INT 21h; WALLDEF / 8X8D / DAX literal tokens inside walked instruction bytes;
     DS-relative table region accesses (with the DS caveat); immediates equal to a region address; and
     pointer hand-off to callees.

What it does not establish, and does not claim: that the caller's delta is the callee segment's true delta
(only that it gives one unique window in each dump), that the callee runs, what the passed record is,
what the record fields mean, or how W/F/S/Q are initialised. The offset check against the already-resolved
0x0464 targets is arithmetic on offsets, not a segment model.

Usage
  python tools/por_wall_0111_target_probe.py --install "PATH/TO/POOLRAD" \
      --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
      --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
      -o data/work/por-wall-0111-target-probe/retail

Exit codes
  0  the callee is located uniquely in every dump under the caller's measured delta
  1  output written; not identified (diagnostic)
  2  named refusal: unpinned input, missing dump, caller not in exactly one group, or unsafe output folder
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_32392_table_census as cen  # noqa: E402
import por_wall_callee_probe as cp  # noqa: E402
import por_wall_far_target_probe as wft  # noqa: E402

SCHEMA = "openua.por-wall-0111-target-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_wall_0111_target_probe.py"
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"
TARGET_SEG = 0x0464
TARGET_OFF = 0x0111
CALL_BYTES = bytes([0x9A, 0x11, 0x01, 0x64, 0x04])     # call far 0464:0111
PROC_ENTRY = 0x32270                                    # caller procedure (census section 5)
PROC_SITE = 0x322F3                                     # its 9A site in group 0x42C2
WINDOW = 32
PARA = 16
# Explicit walk window for the callee body: a bound chosen for this probe, not evidence of the segment's
# extent. The resolved 0x0464 targets lie in 0x4778..0x6CAB. Near calls that leave the window are counted.
WALK_SPAN = (0x4000, 0x8000)
# Already-resolved 0x0464 targets (por-wall-far-target-probe.md), used only for an offset consistency check.
KNOWN_0464 = {0x00FF: 0x4778, 0x08D4: 0x4F4D, 0x1951: 0x5FCA, 0x1B52: 0x61CB, 0x2632: 0x6CAB}
DATA_WORK = Path(__file__).resolve().parents[1] / "data" / "work"
REGION_IMM = [(r["id"], r["lo"], r["hi"]) for r in cen.DS_REGIONS]
CALLER_TAIL = 8                                         # instructions shown before the focus site
SEG_PUSH_SAFE = (0x06, 0x0E, 0x16, 0x1E)
ALU_CMP = (0x38, 0x39, 0x3A, 0x3B)


class Refusal(Exception):
    """A named refusal; the CLI prints it and exits with 2."""


def u16(data: bytes, off: int) -> int:
    return data[off] | (data[off + 1] << 8)


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def check_pins(files: dict[str, bytes]) -> dict:
    out = {}
    for name, data in files.items():
        size, sha = fr.PINNED[name]
        ok = len(data) == size and fr._sha(data) == sha
        out[name] = {"size": len(data), "sha256": fr._sha(data), "pin_match": ok}
        if not ok:
            raise Refusal("%s does not match its pinned size and SHA-256" % name)
    return out


def find_call_sites(data: bytes, pattern: bytes = CALL_BYTES) -> list[int]:
    out, p = [], data.find(pattern)
    while p != -1:
        out.append(p)
        p = data.find(pattern, p + 1)
    return out


def group_containing(rows: list[dict], site: int) -> Optional[dict]:
    """The one well-formed group whose code span holds the file offset, or None (zero or several)."""
    hits = [r for r in rows if "refused" not in r and r["fileofs"] <= site < r["fileofs"] + r["codesz"]]
    return hits[0] if len(hits) == 1 else None


def group_deltas(g: dict, dump: ogm.Dump, base: int) -> list[int]:
    """Every fixup word's live-minus-raw delta in one mapped group (the wft.map_siblings rule)."""
    return sorted({(u16(dump.read(base + w, 2), 0) - u16(g["code"], w)) & 0xFFFF for w in g["fixups"]})


def site_record(site: int, ovr: bytes, rows: list[dict], dumps: list[tuple[str, ogm.Dump]]) -> dict:
    """One 0464:0111 call site in GAME.OVR, its containing group, and the caller's measured delta per dump."""
    rec = {"site": _hex(site), "bytes": ovr[site:site + 5].hex(" ")}
    g = group_containing(rows, site)
    if g is None:
        rec["group"] = "none-or-ambiguous"
        return rec
    seg_body = site + 3 - g["fileofs"]
    rec.update({"group": _hex(g["descriptor_offset"]), "group_fileofs": _hex(g["fileofs"]),
                "body_offset": _hex(site - g["fileofs"]), "seg_word_body_offset": _hex(seg_body),
                "seg_word_fixup_listed": seg_body in g["fixups"],
                "raw_seg_word": "%04X" % u16(g["code"], seg_body)})
    per = []
    for name, dump in dumps:
        m = ogm.map_group(g, g["code"], g["fixups"], dump)
        row = {"dump": name, "mapping_status": m["status"]}
        if m["status"] == "unique":
            base = m["base_linear"]
            live = u16(dump.read(base + seg_body, 2), 0)
            row.update({"base_linear": _hex(base), "live_seg_word": "%04X" % live,
                        "site_delta": "0x%04X" % ((live - TARGET_SEG) & 0xFFFF),
                        "group_fixup_deltas": ["0x%04X" % d for d in group_deltas(g, dump, base)]})
        per.append(row)
    rec["per_dump"] = per
    return rec


def caller_delta(focus: dict, n_dumps: int) -> Optional[int]:
    """The delta measured at the focus caller in every dump: one value, group-uniform, unique mapping."""
    per = focus.get("per_dump", [])
    if len(per) != n_dumps or any(p["mapping_status"] != "unique" for p in per):
        return None
    site_deltas = {p["site_delta"] for p in per}
    group_uniform = all(p["group_fixup_deltas"] == [p["site_delta"]] for p in per)
    if len(site_deltas) != 1 or not group_uniform or not focus.get("seg_word_fixup_listed"):
        return None
    if focus.get("raw_seg_word") != "%04X" % TARGET_SEG:
        return None
    return int(per[0]["site_delta"], 16)


def resolve_under(delta: int, dumps: list[tuple[str, ogm.Dump]], files: dict[str, bytes]) -> dict:
    """The callee's 32 live bytes under one delta: exact pinned-file hits plus one-far-word masked hits."""
    seg = (TARGET_SEG + delta) & 0xFFFF
    lin = seg * PARA + TARGET_OFF
    per, resolved = [], []
    for name, dump in dumps:
        row = {"dump": name, "live_seg": "%04X" % seg, "linear": _hex(lin)}
        if not dump.covers(lin, WINDOW):
            row["status"] = "out-of-dump"
            per.append(row)
            continue
        w = dump.read(lin, WINDOW)
        row["live_bytes"] = w[:8].hex(" ")
        exact = ogm.classify_target(w, files)
        masked = wft.masked_hits(w, files, delta)
        hits = [{"file": n, "offset": o, "mode": "exact-32-bytes"}
                for n, offs in exact["hits"].items() for o in offs]
        hits += [dict(h, mode="masked-one-far-word") for h in masked]
        row["hits"] = hits
        if len(hits) == 1:
            row["status"] = "unique"
            h = hits[0]
            resolved.append((h["file"], int(h["offset"], 16)))
            row["resolution"] = {"file": h["file"], "offset": h["offset"], "mode": h["mode"]}
        else:
            row["status"] = "absent" if not hits else "ambiguous"
        per.append(row)
    agree = len(per) == len(dumps) and all(p.get("status") == "unique" for p in per) and len(set(resolved)) == 1
    return {"delta": "0x%04X" % delta, "per_dump": per,
            "unique_and_agreeing_in_every_dump": agree,
            "resolution": ({"file": resolved[0][0], "offset": "0x%X" % resolved[0][1]} if agree else None)}


def _touches_di_or_es(i) -> bool:
    """Conservative: True when the instruction may change DI or ES (or is unknown). Used for the ES:DI origin."""
    op = i.op
    reg = i.modrm[1] if i.modrm else None
    mod = i.modrm[0] if i.modrm else None
    rm = i.modrm[2] if i.modrm else None
    if i.flow in ("call", "call_far", "indirect_call", "indirect_callf", "indirect_jmp", "indirect_jmpf",
                  "jmp_far", "ret", "retf", "int"):
        return True
    if 0x70 <= op <= 0x7F or op in (0xE0, 0xE1, 0xE2, 0xE3):       # conditional branches: fall-through keeps origin
        return False
    if op in range(0x50, 0x58) or op in range(0x58, 0x5F) or op in SEG_PUSH_SAFE:
        return False
    if op in (0x07, 0x5F, 0x8E, 0xC4, 0xC5, 0x8F, 0x97, 0x47, 0x4F, 0xBF, 0xE9, 0xEB, 0x9D):
        return op != 0x9D
    if op in (0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF):
        return True                                                  # string ops use and advance DI
    if op in (0x88, 0x8A, 0x8C, 0x84, 0x85, 0xA0, 0xA1, 0xA2, 0xA3, 0xA8, 0xA9, 0xC6, 0x9C, 0xF8, 0xF9):
        return False
    if op == 0x89:
        return mod == 3 and rm == 7
    if op == 0x8B:
        return reg == 7
    if op == 0x8D:
        return reg == 7
    if op == 0xC7:
        return mod == 3 and rm == 7
    if op == 0x87:
        return reg == 7 or (mod == 3 and rm == 7)
    if op in range(0x90, 0x97):
        return False
    if op in range(0x40, 0x50):
        return False
    if 0xB8 <= op <= 0xBF:
        return op == 0xBF                                            # mov reg,imm16: only BF names DI
    if op < 0x40 and (op & 7) < 6:
        if op in ALU_CMP:
            return False
        if (op & 7) in (0, 1):
            return mod == 3 and rm == 7
        if (op & 7) in (2, 3):
            return reg == 7
        return False                                                 # accumulator forms touch AX only
    if op in (0x80, 0x81, 0x82, 0x83):
        return mod == 3 and rm == 7 and reg != 7
    if op in (0xFE, 0xFF):
        if reg == 6:
            return False                                             # push r/m
        if reg in (0, 1):
            return mod == 3 and rm == 7
        return True
    if op in (0xF6, 0xF7):
        if reg == 0:
            return False                                             # test
        return mod == 3 and rm == 7 and reg in (2, 3)
    if op in (0xD0, 0xD1, 0xD2, 0xD3):
        return mod == 3 and rm == 7
    return True


def origin_tags(insns: list, branch_targets: set) -> dict:
    """Straight-line ES:DI origin per instruction, reset at proc entry, branch targets and clobbers.

    'passed-record' only after les di,[bp+6] (the callee's last stack argument, the far pointer the census
    reports) and before anything that may change DI or ES. Linear order, not a control-flow analysis.
    """
    tags, origin = {}, "unknown"
    for i in sorted(insns, key=lambda x: x.off):
        if i.off in branch_targets:
            origin = "unknown"
        tags[i.off] = origin
        o = cen.operand(i)
        if i.op == 0xC4 and i.modrm and i.modrm[1] == 7 and o and o["space"] == "stack" and o.get("disp") == 6:
            origin = "passed-record"
        elif _touches_di_or_es(i):
            origin = "unknown"
    return tags


def decode_body(exe: bytes, entry: int, span: tuple[int, int]) -> dict:
    """Bounded walk of the callee body with the census operand classifier and the ES:DI origin. Facts only."""
    trav = cen.walk_procs(exe, [entry], span[0], span[1])
    procs = trav["procs"]
    walk = {"span": [_hex(span[0]), _hex(span[1])], "entry": _hex(entry),
            "procedures": sorted(_hex(e) for e in procs),
            "instructions": sum(len(ex["_insns"]) for ex in procs.values()),
            "incomplete": [x for ex in procs.values() for x in ex.get("incomplete", [])],
            "outside_near_calls": [{"from": _hex(o["from"]), "at": _hex(o["at"]), "target": _hex(o["target"]),
                                    "text": o["text"]} for o in trav["outside_near_calls"]]}
    ops_out = {"passed_record_writes": [], "passed_record_reads": [], "other_origin_es_writes": [],
               "other_origin_es_reads": [], "other_origin_es_far_loads": [], "passed_record_string_stores": []}
    record_loads, region_hits, region_imms, ds_direct = [], [], [], []
    for e, ex in sorted(procs.items()):
        insns = ex["_insns"]
        branch = set(ex.get("branch_targets", set()))
        tags = origin_tags(insns, branch)
        for i in sorted(insns, key=lambda x: x.off):
            o = cen.operand(i)
            where = {"at": _hex(i.off), "proc": _hex(e), "text": i.text()}
            if o is not None:
                if o["space"] == "stack" and o["role"] == "far" and o.get("disp") == 6:
                    record_loads.append(where["at"])
                if o["segment"] == "es":
                    passed = tags.get(i.off) == "passed-record"
                    key = None
                    if o["role"] in cen.WRITE_ROLES:
                        key = "passed_record_writes" if passed else "other_origin_es_writes"
                    elif o["role"] == "far":
                        key = None if passed else "other_origin_es_far_loads"
                        if passed:
                            ops_out["passed_record_reads"].append(dict(where, role="far",
                                                                       disp=o.get("disp", o.get("address"))))
                    else:
                        key = "passed_record_reads" if passed else "other_origin_es_reads"
                    if key:
                        ops_out[key].append(dict(where, role=o["role"], disp=o.get("disp")))
                if o["space"] == "direct" and o["segment"] == "ds":
                    ds_direct.append(dict(where, address="0x%04X" % o["address"], role=o["role"]))
                for h in cen.region_matches(o):
                    region_hits.append(dict(where, **h, segment_caveat="DS not established to be the overlay DGROUP"))
            if i.op in cen.STRING_STORE_OPS:
                if tags.get(i.off) == "passed-record":
                    ops_out["passed_record_string_stores"].append(where)
                else:
                    ops_out["other_origin_es_writes"].append(dict(where, role="string-store"))
            if i.imm is not None:
                for rid, lo, hi in REGION_IMM:
                    if lo <= i.imm < hi:
                        region_imms.append(dict(where, region=rid, imm="0x%X" % i.imm))
    all_insns = [i for ex in procs.values() for i in ex["_insns"]]
    covered = set()
    for i in all_insns:
        covered.update(range(i.off, i.off + i.length))
    tokens = cp._string_tokens(exe)["file_offsets"]
    body_tokens = {}
    for k, v in tokens.items():
        a = int(k, 16)
        if any(b in covered for b in range(a, a + len(v))):
            body_tokens[k] = v
    calls = sorted((i for i in all_insns if i.flow in ("call", "call_far")), key=lambda x: x.off)
    handoff = []
    for c in calls:
        before = {i.op for i in all_insns if c.off - 6 <= i.off < c.off}
        if {0x06, 0x57} <= before:
            handoff.append({"at": _hex(c.off), "text": c.text(),
                            "basis": "push es and push di within the 6 bytes before the call"})
    ints = [{"at": _hex(x["at"]), "vector": x["vector"], "ah": x["ah"]} for ex in procs.values() for x in ex["ints"]]
    far = [{"at": _hex(f["at"]), "seg": "0x%04X" % f["seg"], "off": "0x%04X" % f["off"], "text": f["text"]}
           for ex in procs.values() for f in ex["far_calls"]]
    near = [{"at": _hex(n["at"]), "target": _hex(n["target"]), "text": n["text"]}
            for ex in procs.values() for n in ex["near_calls"]]
    indirect = [{"at": _hex(x["at"]), "kind": x["kind"], "text": x["text"]}
                for ex in procs.values() for x in ex["indirect"]]
    return {"walk": walk,
            "passed_record_access": ops_out,
            "passed_record_loads_bp6": record_loads,
            "int_calls": ints,
            "far_calls_not_followed": far,
            "near_calls": near,
            "indirect_calls": indirect,
            "ds_direct_operands": ds_direct,
            "ds_region_matches": region_hits,
            "region_address_immediates": region_imms,
            "pointer_handoff_candidates": handoff,
            "string_tokens_in_body_bytes": body_tokens,
            "string_tokens_in_start_file": len(tokens)}


def caller_tail(ovr: bytes) -> dict:
    """The caller procedure's instructions up to the focus site, as decoded (argument setup)."""
    proc = cp.explore(ovr, PROC_ENTRY, cp.DEFAULT_MAX_INSNS)
    insns = sorted(proc["_insns"], key=lambda x: x.off)
    before = [i for i in insns if i.off < PROC_SITE][-CALLER_TAIL:]
    site = [i for i in insns if i.off == PROC_SITE]
    return {"procedure": _hex(PROC_ENTRY), "site_in_procedure": bool(site),
            "instructions_before_site": [{"at": _hex(i.off), "text": i.text()} for i in before],
            "site_text": site[0].text() if site else None}


def verdict(identity: dict, body: Optional[dict]) -> dict:
    ident = identity["resolution"] is not None
    if body is None:
        return {"identified": ident, "answer": "not-identified", "reached_or_executed": "not-established"}
    acc = body["passed_record_access"]
    return {"identified": ident,
            "answer": ("unique-under-caller-measured-delta" if ident else "not-identified"),
            "passed_record_write_sites": len(acc["passed_record_writes"]) + len(acc["passed_record_string_stores"]),
            "passed_record_read_sites": len(acc["passed_record_reads"]),
            "other_origin_es_write_sites": len(acc["other_origin_es_writes"]),
            "other_origin_es_far_load_sites": len(acc["other_origin_es_far_loads"]),
            "int21_present": any(x["vector"] == 0x21 for x in body["int_calls"]),
            "dax_wall_8x8d_token_in_body_bytes": bool(body["string_tokens_in_body_bytes"]),
            "ds_region_access_in_walk": bool(body["ds_region_matches"]),
            "region_address_immediate_in_walk": bool(body["region_address_immediates"]),
            "walk_complete": not body["walk"]["incomplete"] and not body["walk"]["outside_near_calls"],
            "reached_or_executed": "not-established"}


def analyse(ovr: bytes, exe: bytes, dumps: list[tuple[str, ogm.Dump]], *, span: tuple[int, int] = WALK_SPAN,
            ) -> dict:
    files = {OVR_NAME: ovr, EXE_NAME: exe}
    pins = check_pins(files)
    rows = wft.descriptor_table(exe, ovr)
    recs = [site_record(s, ovr, rows, dumps) for s in find_call_sites(ovr)]
    focus = [r for r in recs if r["site"] == _hex(PROC_SITE)]
    if len(focus) != 1:
        raise Refusal("focus site %s not found in GAME.OVR" % _hex(PROC_SITE))
    caller = caller_tail(ovr)
    if not caller["site_in_procedure"]:
        raise Refusal("focus site %s is not decoded inside procedure %s" % (_hex(PROC_SITE), _hex(PROC_ENTRY)))
    delta = caller_delta(focus[0], len(dumps))
    identity = {"call_sites_gameovr": [r["site"] for r in recs],
                "call_sites_start": [_hex(s) for s in find_call_sites(exe)],
                "focus_site": focus[0],
                "caller_measured_delta": None if delta is None else "0x%04X" % delta,
                "resolution": None, "resolution_note": None}
    under = None
    body = None
    consistency = {}
    if delta is None:
        identity["resolution_note"] = "caller delta not measured uniformly in every dump; no resolution"
    else:
        under = resolve_under(delta, dumps, files)
        identity["resolution"] = under["resolution"]
    if identity["resolution"] is not None:
        if identity["resolution"]["file"] != EXE_NAME:
            raise Refusal("resolved file is %s; body walk expects START.EXE" % identity["resolution"]["file"])
        res_off = int(identity["resolution"]["offset"], 16)
        for k, v in sorted(KNOWN_0464.items()):
            consistency["0x%04X" % k] = {"start_file": "0x%X" % v, "start_minus_off": "0x%X" % (v - k)}
        consistency["callee_0111"] = {"start_file": "0x%X" % res_off,
                                      "start_minus_off": "0x%X" % (res_off - TARGET_OFF)}
        body = decode_body(exe, res_off, span)
    doc = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL, "status": STATUS,
           "playable": False, "target": "0x%04X:0x%04X" % (TARGET_SEG, TARGET_OFF),
           "inputs": {"pins": pins,
                      "dumps": [{"name": n, "base": "0x%X" % d.base, "size": len(d.data)} for n, d in dumps]},
           "caller": caller,
           "identity": identity,
           "identity_under_caller_delta": under,
           "consistency_with_resolved_0464_targets": consistency,
           "body": body,
           "claims": {"identity": "conditional on the caller group's measured delta applying to this segment word",
                      "reached_or_executed": "not-established",
                      "record_meaning": "not-established"},
           "not_established": [
               "that the caller's measured delta is the callee segment's true delta for every call of 0x0464",
               "that 0x0464:0x0111 runs, or with which arguments, at any real instant",
               "what the passed far pointer names at run time, or whether it is an F element",
               "the meaning of the record fields, and whether a write reaches W, F, S or Q",
               "W/F/S/Q initialisation, WALLDEF/8X8D/DAX binding, record selection"]}
    doc["verdict"] = verdict(identity, body)
    return doc


def probe(install: Optional[Path], dump_paths: list[Path], *, out: Path) -> tuple[dict, int]:
    folder = ogm.find_install(install)
    try:
        out_dir = validate_output_dir(folder, out)
    except PorSourceError as exc:
        raise Refusal(str(exc))
    if DATA_WORK.resolve() not in out_dir.parents:
        raise Refusal("output must be a folder under data/work; got %s" % out_dir)
    for p in dump_paths:
        if not p.is_file():
            raise Refusal("dump not found: %s" % p.name)
    ovr = (folder / OVR_NAME).read_bytes()
    exe = (folder / EXE_NAME).read_bytes()
    dumps = [(p.name, ogm.Dump(p.read_bytes(), ogm.resolve_dump_base(p.name, p.stat().st_size, None)))
             for p in dump_paths]
    doc = analyse(ovr, exe, dumps)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "por_wall_0111_target_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc, (0 if doc["verdict"]["identified"] else 1)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", type=Path, default=None)
    ap.add_argument("--dump", type=Path, action="append", default=[])
    ap.add_argument("-o", "--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.dump, out=args.out)
    except (Refusal, ogm.Refusal) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    print("answer=%s identified=%s" % (doc["verdict"]["answer"], doc["verdict"]["identified"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
