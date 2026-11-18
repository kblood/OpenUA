#!/usr/bin/env python3
"""Pool of Radiance: every decoded transfer into the plane-3 door routines or stub 1 (static, observe-only).

Status: STATIC-PROBE-ONLY. `playable: false`. Stdlib-only, read-only on the pinned install.

Question. The writer GAME.OVR:0x167D4, the clearer 0x166CB, and stub 1 (START file 0x0089C, proc 0x17438)
of group 0x166CB still have no established trigger. The caller probe counted near `E8` and literal `9A`;
the indirect probe counted `FF /2` and `FF /3`. This probe counts the remaining decoded transfer kinds:
near `E9` and `EB` jumps, far `EA` jumps, and a non-prologue entry (a decoded transfer that lands
inside a body but not on a Borland prologue or a named entry). It runs over every decoded instruction
start in every well-formed or partial group body and over the START.EXE image closure.

Address models. Far targets are reported under both models that earlier probes used, neither promoted:
  M0 file = hdr + seg*16 + off      (hdr = 0x200, the MZ header size)
  M1 file = seg*16 + off + 0x7E     (dump-anchored, docs/por-door-caller-probe.md)

Raw census. Undecoded `E8`/`E9`/`EB`/`9A`/`EA` byte patterns that land on a tagged target are reported in
`raw_hits`. They are never counted as routes: a byte pattern is not an instruction start.

Pins. GAME.OVR and START.EXE must match their pinned size and SHA-256 or the run is refused. Both are
re-hashed after the run. Output is written only under data/work, outside the install.

Usage
    python tools/por_door_entry_route_census.py --install PATH/TO/POOLRAD -o data/work/por-door-entry-route-census
Exit: 0 probe ran; 2 named refusal.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_door_caller_probe as dc  # noqa: E402
import por_door_indirect_probe as dip  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

SCHEMA = "openua.por-door-entry-route-census"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_door_entry_route_census.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-door-entry-route-census"

GROUP_FILE = 0x166CB           # group 0x166CB (codesz 0x10AC per the caller probe)
CLEARER = 0x166CB              # clearer routine (group-relative +0)
WRITER = 0x167D4               # plane-3 writer (group-relative +0x109)
READER = 0x2EC47               # plane-3 reader (group 0x2E8F7, not in this body)
PROC1 = 0x17438                # stub 1 proc (group-relative 0x0D6D)
STUB1 = 0x0089C                # START.EXE file offset of stub 1 (bytes cd 3f 6d 0d 00)
MZ_ENTRY = 0x0F932             # MZ CS:IP 0F72:0012 -> file 0x200 + 0x0F72*16 + 0x12
M1_DELTA = dc.M1_DELTA         # 0x7E

NAMED = {CLEARER: "clearer-0x166CB", WRITER: "writer-0x167D4", READER: "reader-0x2EC47",
         PROC1: "stub1-proc-0x17438", STUB1: "stub1-start-0x0089C"}

# Sites already reported as callers by the caller probe (near E8 into the writer or clearer). A tagged
# decoded transfer outside this set is a new route for this census.
PRIOR_SITES = {0x16B5C, 0x16B9A, 0x16C28, 0x16C66, 0x17558, 0x17697}

TRANSFER_FLOWS = ("call", "jmp")
FAR_FLOWS = ("call_far", "jmp_far")
RAW_NEAR_OPS = (0xE8, 0xE9)
RAW_FAR_OPS = (0x9A, 0xEA)


class Refusal(Exception):
    pass


def far_targets(seg: int, off: int, hdr: int) -> dict[str, int]:
    return {"M0": hdr + seg * 16 + off, "M1": seg * 16 + off + M1_DELTA}


def tags_for(target: int, body_lo: int, body_hi: int) -> list[str]:
    tags = []
    if target in NAMED:
        tags.append(NAMED[target])
    if body_lo <= target < body_hi:
        tags.append("group-0x166CB-body")
    return tags


def decoded_map(data: bytes, walks: list[dict]) -> dict[int, lh.Insn]:
    """Every decoded instruction start across these walks, decoded once."""
    out: dict[int, lh.Insn] = {}
    for w in walks:
        for row in w["listing"]:
            at = row["at"]
            if at not in out:
                out[at] = lh.decode(data, at)
    return out


def transfer_rows(data: bytes, insns: dict[int, lh.Insn], hdr: int, body_lo: int, body_hi: int,
                  image: str) -> list[dict]:
    rows = []
    for at in sorted(insns):
        ins = insns[at]
        if ins.flow in TRANSFER_FLOWS and ins.target is not None:
            t = ins.target
            tags = tags_for(t, body_lo, body_hi)
            if t not in insns and body_lo <= t < body_hi:
                tags.append("undecoded-body-target")
            if tags:
                rows.append({"image": image, "at": at, "flow": ins.flow, "kind": "near",
                             "target": t, "tags": tags,
                             "target_decoded": t in insns,
                             "target_prologue": data[t:t + 3] in dc.PROLOGUES})
        elif ins.flow in FAR_FLOWS and ins.far is not None:
            seg, off = ins.far
            for model, t in far_targets(seg, off, hdr).items():
                tags = tags_for(t, body_lo, body_hi)
                if tags:
                    rows.append({"image": image, "at": at, "flow": ins.flow, "kind": "far",
                                 "model": model, "seg": seg, "off": off, "target": t,
                                 "tags": tags, "target_decoded": t in insns})
    return rows


def raw_rows(data: bytes, decoded: set[int], hdr: int, body_lo: int, body_hi: int, image: str) -> list[dict]:
    """Undecoded byte patterns that would land on a tagged target. Reported, never counted."""
    out = []
    n = len(data)
    for p in range(n - 4):
        op = data[p]
        if p in decoded:
            continue
        if op in RAW_NEAR_OPS:
            rel = struct.unpack_from("<h", data, p + 1)[0]
            t = p + 3 + rel
            kind = "near"
        elif op == 0xEB:
            rel = struct.unpack_from("<b", data, p + 1)[0]
            t = p + 2 + rel
            kind = "near"
        elif op in RAW_FAR_OPS:
            off, seg = struct.unpack_from("<HH", data, p + 1)
            for model, tt in far_targets(seg, off, hdr).items():
                tags = tags_for(tt, body_lo, body_hi)
                if tags:
                    out.append({"image": image, "at": p, "op": "%02X" % op, "kind": "far", "model": model,
                                "seg": seg, "off": off, "target": tt, "tags": tags})
            continue
        else:
            continue
        if t < 0:
            continue
        tags = tags_for(t, body_lo, body_hi)
        if tags:
            out.append({"image": image, "at": p, "op": "%02X" % op, "kind": kind, "target": t, "tags": tags})
    return out


def analyse(ovr: bytes, start: bytes) -> dict:
    hdr = fr.mz_image_base(start)
    scan = fr.scan_all(start, ovr)
    allg = scan["groups"] + scan["partial_groups"]
    grp = fr.group_containing_code(allg, GROUP_FILE)
    if grp is None or grp["fileofs"] != GROUP_FILE:
        raise Refusal("group 0x166CB is not a stub-carrying group in this GAME.OVR")
    body_lo, body_hi = grp["fileofs"], grp["fileofs"] + grp["codesz"]

    cache = dc.GroupCache(ovr)
    ovr_walks: list[dict] = []
    for g in allg:
        gw = cache.get(g)
        ovr_walks.extend(list(gw.reached.values()) + list(gw.swept.values()))
    ovr_insns = decoded_map(ovr, ovr_walks)
    ovr_decoded = set(ovr_insns)

    # START.EXE: the indirect probe's own walk set (MZ-entry closure plus prologue sweep), reused read-only.
    sc = dip.start_census(start, hdr)
    if sc["entry_file"] != "0x%05X" % MZ_ENTRY:
        raise Refusal("START MZ entry is not at the expected file offset")
    start_walks = [w for _, _, w in sc["walks"]]
    start_insns = decoded_map(start, start_walks)
    start_decoded = set(start_insns)

    ovr_rows = transfer_rows(ovr, ovr_insns, hdr, body_lo, body_hi, "GAME.OVR")
    start_rows = transfer_rows(start, start_insns, hdr, body_lo, body_hi, "START.EXE")
    ovr_raw = raw_rows(ovr, ovr_decoded, hdr, body_lo, body_hi, "GAME.OVR")
    start_raw = raw_rows(start, start_decoded, hdr, body_lo, body_hi, "START.EXE")

    new_routes = [r for r in ovr_rows + start_rows
                  if r["kind"] == "near" and r["at"] not in PRIOR_SITES and
                  any(t in r["tags"] for t in ("clearer-0x166CB", "writer-0x167D4", "stub1-proc-0x17438"))]
    stub1_decoded = [r for r in ovr_rows + start_rows if "stub1-start-0x0089C" in r["tags"]]
    stub1_far_decoded = [r for r in ovr_rows + start_rows
                         if r["kind"] == "far" and "stub1-start-0x0089C" in r["tags"]]
    body_interior = [r for r in ovr_rows if "group-0x166CB-body" in r["tags"]
                     and "clearer-0x166CB" not in r["tags"] and "writer-0x167D4" not in r["tags"]]
    # A CALL into the body that does not begin on a Borland prologue is a non-prologue entry candidate.
    non_prologue_calls = [r for r in ovr_rows + start_rows
                          if r["kind"] == "near" and r["flow"] == "call"
                          and not r["target_prologue"] and "group-0x166CB-body" in r["tags"]]

    return {
        "groups_checked": len(allg),
        "group_0x166CB": {"fileofs": "0x%05X" % body_lo, "codesz": "0x%04X" % grp["codesz"]},
        "decoded_starts": {"GAME.OVR": len(ovr_decoded), "START.EXE": len(start_decoded)},
        "start_mz_entry": "0x%05X" % MZ_ENTRY,
        "address_models": {"M0": "file = hdr + seg*16 + off (hdr 0x200)", "M1": "file = seg*16 + off + 0x7E"},
        "decoded_transfers": ovr_rows + start_rows,
        "raw_hits": ovr_raw + start_raw,
        "verdicts": {
            "trigger_established": False,
            "stub1_decoded_near_transfers": sum(1 for r in stub1_decoded if r["kind"] == "near"),
            "stub1_decoded_far_transfers": len(stub1_far_decoded),
            "body_interior_decoded_transfers": len(body_interior),
            "non_prologue_decoded_calls": len(non_prologue_calls),
            "non_prologue_decoded_call_rows": non_prologue_calls,
            "new_decoded_near_routes_beyond_prior": new_routes,
        },
    }


def probe(install: Path) -> dict:
    ovr, start, pins = dc.load_pinned(install)
    doc = analyse(ovr, start)
    after = dip.recheck_pins(install, pins)
    if not all(v.get("pin_match") for v in after.values()):
        raise Refusal("a pinned file changed during the run")
    doc.update({
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS, "playable": False,
        "tool": TOOL, "pins": pins,
        "scope": "GAME.OVR group bodies and START.EXE closure; decoded starts only are counted.",
        "not_established": [
            "Runtime: nothing shows a transfer ran.",
            "The trigger for stub 1 (START 0x0089C) and for group 0x166CB.",
            "M0 and M1 are unproven; they are reported, not promoted.",
            "Raw byte hits are reported and never counted.",
            "Door semantics: the writer and clearer bodies are not read here.",
        ],
    })
    return doc


def render_report(doc: dict) -> str:
    v = doc["verdicts"]
    lines = [
        "# PoR door entry-route census (static, observe-only)", "",
        "status: %s, playable: false, trigger_established: %s" % (doc["status"], v["trigger_established"]), "",
        "groups checked: %d; group 0x166CB at %s (codesz %s)" % (
            doc["groups_checked"], doc["group_0x166CB"]["fileofs"], doc["group_0x166CB"]["codesz"]),
        "decoded starts: GAME.OVR %d, START.EXE %d" % (doc["decoded_starts"]["GAME.OVR"],
                                                       doc["decoded_starts"]["START.EXE"]),
        "stub1 decoded near transfers: %d; far transfers (M0 or M1): %d" % (
            v["stub1_decoded_near_transfers"], v["stub1_decoded_far_transfers"]),
        "decoded jumps/calls into group 0x166CB body, not a named entry: %d" % v["body_interior_decoded_transfers"],
        "decoded CALLs into the body that do not start on a Borland prologue: %d" % v["non_prologue_decoded_calls"],
        "new decoded near routes beyond the prior caller sites: %d" % len(v["new_decoded_near_routes_beyond_prior"]),
        "", "## Decoded transfers with a tag", "",
    ]
    for r in doc["decoded_transfers"]:
        if r["kind"] == "near":
            lines.append("- %s 0x%05X %s -> 0x%05X %s" % (r["image"], r["at"], r["flow"], r["target"],
                                                          ", ".join(r["tags"])))
        else:
            lines.append("- %s 0x%05X %s %s %04X:%04X -> 0x%05X %s" % (
                r["image"], r["at"], r["flow"], r["model"], r["seg"], r["off"], r["target"], ", ".join(r["tags"])))
    lines += ["", "## Raw hits (undecoded; never counted)", ""]
    for r in doc["raw_hits"]:
        lines.append("- %s 0x%05X %s %s -> 0x%05X %s" % (r["image"], r["at"], r["op"], r["kind"], r["target"],
                                                        ", ".join(r["tags"])))
    lines += ["", "## Not established", ""] + ["- " + s for s in doc["not_established"]] + [""]
    return "\n".join(lines)


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def write_outputs(doc: dict, out: Path, install: Path) -> None:
    if _inside(out, install):
        raise Refusal("output must not be inside the install folder")
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_door_entry_route_census.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_door_entry_route_census_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    try:
        doc = probe(args.install)
        write_outputs(doc, args.out, args.install)
    except (dc.Refusal, Refusal) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
