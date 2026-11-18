#!/usr/bin/env python3
"""Pool of Radiance: one-area pipeline plan from a candidate save-position / GEO join.

Status: HYPOTHESIS-ONLY ADAPTER. Read-only, playable: false, runtime_binding_claimed: false.

Takes ONE explicitly named pinned save and ONE explicitly named coordinate ordering, and
asks the existing compatibility check (tools/por_save_geo_candidate_check.py, called
read-only through its pinned loaders) where the save's full-cell GEO signature occurs.

A one-area plan is emitted only when that signature occurs in exactly one decoded block,
at exactly one cell, and that cell is the candidate position. If it is compatible with
more than one block (SAVGAMJ today), or with a block the caller did not request, or is
not evaluable, no plan is emitted: the report still lists every compatible block, and the
CLI exits 3. Nothing picks a block for the caller.

The facing name is never inferred from a raw code silently. Either the caller names it
(--facing) or asks for the GoldBox candidate mapping (--facing-candidate-mapping), which
is then recorded as candidate-mapping-unverified. The full-cell join does not use the
facing name at all; it only sets the plan row's orientation.

Every fact in the report is labelled observed, computed, candidate or hypothesis. The
join (block id 20 for ECL member 20), the coordinate ordering, and the caller-chosen area
number are hypotheses. The plan's provenance block forces playable false and
runtime_binding_claimed false. A plan that the pipeline's own loader refuses is never
written.

Usage
  python tools/por_save_geo_join_plan.py --install "PATH/TO/POOLRAD" --save SAVGAMA.DAT \\
      --ordering pose_xy --area 2 --facing-candidate-mapping \\
      [--block GEO2.DAX:2:20] -o data/work/por-save-geo-join-plan/retail

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths, no save bytes
beyond the six candidate fields):
  por_save_geo_join_plan.json          schema openua.por-save-geo-join-plan
  por_save_geo_join_plan_report.md     the readable summary
  pipeline_plan.json                   only when a plan is emitted; input to por_pipeline.py --plan

Exit codes
  0  plan emitted and validated by por_pipeline.load_plan; report written
  3  plan refused by a stated rule (ambiguity, no match, not evaluable, unmapped facing);
     report written, no pipeline_plan.json
  2  named refusal before any output: bad usage, pin mismatch, unsafe output location
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATA_DIR = REPO / "data"
sys.path.insert(0, str(HERE))

import por_save_geo_candidate_check as sg  # noqa: E402
import por_save_state_probe as sp  # noqa: E402
import por_map as pm  # noqa: E402
import por_pipeline as pp  # noqa: E402
from por_area_evidence import GEO_PINS  # noqa: E402

SCHEMA = "openua.por-save-geo-join-plan"
SCHEMA_VERSION = 0
STATUS = "hypothesis-only-adapter"
TOOL = "tools/por_save_geo_join_plan.py"
REPORT_JSON = "por_save_geo_join_plan.json"
REPORT_MD = "por_save_geo_join_plan_report.md"
PLAN_FILE = "pipeline_plan.json"
INSTALL_ENV = sp.INSTALL_ENV
DEFAULT_INSTALL = sp.DEFAULT_INSTALL
SIGNATURE = "full_cell"
ORDERINGS = ("pose_xy", "pose_yx")
JOIN_STATUS = "hypothesis"
JOIN_TEXT = ("same-suffix/same-id hypothesis: ECL member 20 is paired with GEO block id 20; "
             "compatibility of decoded cells is not a runtime binding")
FACING_STATUS_CALLER = "caller-supplied name; not verified against the game"
BLOCK_RE = re.compile(r"(GEO[1-8])\.DAX:(\d+):(\d+)")

PROVENANCE_FIXED = {
    "tool": TOOL,
    "status": JOIN_STATUS,
    "playable": False,
    "runtime_binding_claimed": False,
    "runtime_loaded": False,
    "engine_executed": False,
}

LIMITATIONS = (
    "Only the six candidate save bytes are used (pose x/y, facing raw, and the ECL/area "
    "fields for context). No other save byte is decoded and no save schema is claimed.",
    "The join to GEO block id 20 is a hypothesis. A single compatible block is a "
    "compatibility result, not evidence that the DOS game loaded that block for this save.",
    "The coordinate ordering is a hypothesis. Only the ordering the caller names is evaluated "
    "here; the other ordering is not judged by this adapter.",
    "The area number in the plan is the caller's choice. It is not derived from the save "
    "bytes and is not a verified game area.",
    "The facing name only sets the plan row's orientation. The full-cell join does not use it.",
    "The plan entry is a saved-state test position, not a new-game start.",
    "Compatibility is judged on the decoded cells of the eight pinned GEO archives only.",
    "Nothing was run: no emulator, DOSBox, GameLink, codewheel or input.",
    "No CoK or DoK rule is used.",
)
CLAIM_BOUNDARY = (
    "A one-area plan generated from a candidate save-position/GEO compatibility result. "
    "playable: false, runtime_binding_claimed: false. Not a runtime load, not a game-area "
    "mapping, not a save schema, not a start state."
)


class JoinRefusal(Exception):
    """A named refusal before any output is written (CLI exit 2)."""


def plan_name(save: str) -> str:
    """Design name for the plan row: 'P' + the save stem's last seven alphanumerics."""
    stem = re.sub(r"[^A-Z0-9]", "", Path(save).stem.upper())
    return ("P" + stem[-7:])[:8]


def parse_block(text: str) -> tuple[str, int, int]:
    m = BLOCK_RE.fullmatch(text)
    if not m:
        raise JoinRefusal("--block must be GEOn.DAX:TOC:ID, for example GEO2.DAX:2:20")
    return m.group(1) + ".DAX", int(m.group(2)), int(m.group(3))


def _save_row(doc: dict, save: str) -> dict:
    for s in doc["inputs"]["saves"]:
        if s["name"] == save:
            return s
    raise JoinRefusal("save %s is not one of the pinned saves" % save)


def _candidate(doc: dict, save: str, ordering: str) -> dict:
    for c in doc["candidates"]:
        if c["save"] == save and c["ordering"] == ordering:
            return c
    raise JoinRefusal("no candidate for %s / %s" % (save, ordering))


def _block_key(m: dict) -> tuple:
    return (m["archive"], m["toc_index"], m["block_id"])


def decide(doc: dict, *, save: str, ordering: str, area: int,
           facing_name: Optional[str], facing_from_mapping: bool,
           requested: Optional[tuple]) -> dict:
    """Pure: turn a sg.check() document into a report dict with a plan or a named refusal.

    Returns a dict with ``plan_emitted`` (bool), ``refusal`` (str or None), the observed and
    computed facts, the compatible-block list, and ``plan_row`` (None unless emitted).
    """
    srow = _save_row(doc, save)
    fields = srow["fields"]
    pose_x = fields["pose_x"]["value"]
    pose_y = fields["pose_y"]["value"]
    raw = fields["facing_raw"]["value"]
    cand = _candidate(doc, save, ordering)
    full = cand["signatures"][SIGNATURE]
    x, y = cand["x"], cand["y"]

    out = {
        "save": save,
        "ordering": ordering,
        "observed": {
            "pose_x": pose_x,
            "pose_y": pose_y,
            "facing_raw": raw,
            "wrapper_game_area": fields["wrapper_game_area"]["value"],
            "ecl_member": fields["ecl_member"]["value"],
            "area2_game_area": fields["area2_game_area"]["value"],
        },
        "candidate_position": {"x": x, "y": y, "in_bounds": cand["in_bounds"]},
        "signature": SIGNATURE,
        "evaluable": False,
        "compatible_blocks": [],
        "plan_emitted": False,
        "refusal": None,
        "plan_row": None,
        "facing": None,
        "area": area,
    }

    def refuse(reason: str) -> dict:
        out["refusal"] = reason
        return out

    if not full["evaluable"]:
        return refuse("signature not evaluable: %s" % full["reason"])
    if not full.get("matches_listed"):
        return refuse("full-cell matches were not listed; refusing to judge uniqueness")

    groups: dict[tuple, list] = {}
    for m in full["matches"]:
        groups.setdefault(_block_key(m), []).append(m)
    compatible = []
    for (archive, toc, bid), ms in sorted(groups.items()):
        compatible.append({
            "archive": archive,
            "toc_index": toc,
            "block_id": bid,
            "cell_matches": len(ms),
            "same_position_matches": sum(1 for m in ms if m["same_position"]),
            "cells": [[m["x"], m["y"]] for m in ms],
        })
    out["compatible_blocks"] = compatible
    out["evaluable"] = True

    if not compatible:
        return refuse("no decoded cell carries the candidate full-cell signature")
    if len(compatible) > 1:
        names = ", ".join("%s TOC %d (id %d)" % (b["archive"], b["toc_index"], b["block_id"])
                          for b in compatible)
        return refuse("signature is compatible with %d blocks (%s); a single-block plan is "
                      "refused and no block is chosen" % (len(compatible), names))
    blk = compatible[0]
    if requested is not None and requested != (blk["archive"], blk["toc_index"], blk["block_id"]):
        return refuse("requested block %s:%d:%d is not the compatible block %s:%d:%d"
                      % (requested + (blk["archive"], blk["toc_index"], blk["block_id"])))
    if blk["cell_matches"] != 1 or blk["same_position_matches"] != 1:
        return refuse("signature occurs %d time(s) in the block, %d at the candidate position; "
                      "a single cell at the candidate position is required"
                      % (blk["cell_matches"], blk["same_position_matches"]))

    if facing_from_mapping:
        fname = sp.FACING_CANDIDATE_NAMES.get(raw)
        if fname is None:
            return refuse("raw facing %d has no candidate name; no facing is inferred" % raw)
        fstatus = sp.FACING_NAME_STATUS
    else:
        fname = facing_name
        fstatus = FACING_STATUS_CALLER
    out["facing"] = {"name": fname, "status": fstatus, "raw": raw}

    out["plan_emitted"] = True
    out["plan_row"] = {
        "name": plan_name(save),
        "geo": int(blk["archive"][3]),
        "index": blk["toc_index"],
        "area": area,
        "entry": [x, y],
        "facing": fname,
        "title": ("candidate save %s position (%d,%d); full-cell join hypothesis, "
                  "playable false; facing %s" % (save, x, y, fstatus.split(" ")[0])),
    }
    return out


def build_plan(decision: dict, save: str, ordering: str) -> dict:
    return {
        "schema": pp.PLAN_SCHEMA,
        "version": pp.PLAN_VERSION,
        "designs": [decision["plan_row"]],
        "provenance": dict(PROVENANCE_FIXED, join=JOIN_TEXT, join_status=JOIN_STATUS,
                           save=save, ordering=ordering, signature=SIGNATURE,
                           facing_status=decision["facing"]["status"]),
    }


def _report_doc(decision: dict, doc: dict, save_pins_n: int) -> dict:
    sc = doc["search_scope"]
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "playable": False,
        "runtime_binding_claimed": False,
        "runtime_established": False,
        "join": {"archive": "GEO2.DAX", "toc_index": 2, "block_id": 20,
                 "status": JOIN_STATUS, "text": JOIN_TEXT},
        "selection": {"save": decision["save"], "ordering": decision["ordering"],
                      "signature": SIGNATURE, "area": decision["area"]},
        "observed": decision["observed"],
        "candidate_position": decision["candidate_position"],
        "facing": decision["facing"],
        "compatible_blocks": decision["compatible_blocks"],
        "plan_emitted": decision["plan_emitted"],
        "refusal": decision["refusal"],
        "plan_row": decision["plan_row"],
        "search_scope": {"archives": sc["archives"], "decoded_blocks": sc["decoded_blocks"],
                         "skipped_blocks": sc["skipped_blocks"],
                         "search_complete": sc["search_complete"]},
        "inputs": {"saves_pinned": save_pins_n,
                   "archives": [{"name": a["name"], "sha256": a["sha256"], "pin": a["pin"]}
                                for a in doc["inputs"]["archives"]]},
        "install_unchanged": doc["install_unchanged"],
        "facts": _facts(decision),
        "limitations": list(LIMITATIONS),
        "claim_boundary": CLAIM_BOUNDARY,
    }


def _facts(d: dict) -> list[dict]:
    o = d["observed"]
    f = [
        {"class": "observed", "fact": "pose_x byte %d, pose_y byte %d, facing_raw byte %d "
                                     "in %s (pinned, six-byte read)"
                                     % (o["pose_x"], o["pose_y"], o["facing_raw"], d["save"])},
        {"class": "candidate", "fact": "pose and ECL/area bytes are candidate fields from the "
                                       "GoldBox reference inspector"},
        {"class": "computed", "fact": "full-cell signature evaluable: %s"
                                      % ("yes" if d["evaluable"] else "no")},
        {"class": "computed", "fact": "compatible decoded blocks: %d" % len(d["compatible_blocks"])},
        {"class": "hypothesis", "fact": JOIN_TEXT},
        {"class": "hypothesis", "fact": "coordinate ordering %s" % d["ordering"]},
        {"class": "hypothesis", "fact": "plan area %d is caller-chosen" % d["area"]},
    ]
    if d["facing"] is not None:
        f.append({"class": "candidate" if d["facing"]["status"] == sp.FACING_NAME_STATUS
                  else "hypothesis",
                  "fact": "facing name %s: %s" % (d["facing"]["name"], d["facing"]["status"])})
    return f


def render_report(rep: dict) -> str:
    L = [
        "# Pool of Radiance: candidate save/GEO join as a one-area pipeline plan",
        "",
        "Status: `%s`. `playable: false`. `runtime_binding_claimed: false`. "
        "`runtime_established: false`." % rep["status"],
        "",
        "## 1. Selection",
        "",
        "- Save: `%s`; ordering `%s`; signature `%s`; plan area %d (caller-chosen)."
        % (rep["selection"]["save"], rep["selection"]["ordering"], SIGNATURE, rep["selection"]["area"]),
        "- Join: %s." % rep["join"]["text"],
        "",
        "## 2. Observed and candidate save fields",
        "",
        "| Field | Value | Role |",
        "| --- | ---: | --- |",
    ]
    o = rep["observed"]
    L += [
        "| pose_x | %d | candidate (observed byte) |" % o["pose_x"],
        "| pose_y | %d | candidate (observed byte) |" % o["pose_y"],
        "| facing_raw | %d | observed byte; name is a candidate |" % o["facing_raw"],
        "| ecl_member | %d | candidate, unproven |" % o["ecl_member"],
        "| area2_game_area | %d | candidate, unproven |" % o["area2_game_area"],
        "| wrapper_game_area | %d | candidate, unproven |" % o["wrapper_game_area"],
        "",
        "## 3. Compatible decoded blocks (full-cell signature)",
        "",
    ]
    if rep["compatible_blocks"]:
        L += ["| Archive | TOC | Block id | Cell matches | At candidate position |",
              "| --- | ---: | ---: | ---: | ---: |"]
        for b in rep["compatible_blocks"]:
            L.append("| %s | %d | %d | %d | %d |" % (b["archive"], b["toc_index"], b["block_id"],
                                                    b["cell_matches"], b["same_position_matches"]))
    else:
        L.append("None.")
    L += ["", "## 4. Decision", ""]
    if rep["plan_emitted"]:
        r = rep["plan_row"]
        L.append("Plan emitted: design `%s`, GEO%d TOC %d, area %d, entry (%d,%d), facing `%s`."
                 % (r["name"], r["geo"], r["index"], r["area"], r["entry"][0], r["entry"][1], r["facing"]))
    else:
        L.append("Plan refused: %s. No `pipeline_plan.json` is written." % rep["refusal"])
    if rep["facing"]:
        L += ["", "Facing: `%s`; %s." % (rep["facing"]["name"], rep["facing"]["status"]), ""]
    else:
        L += ["", "Facing: not resolved (no plan row).", ""]
    L += ["## 5. Facts by class", "", "| Class | Fact |", "| --- | --- |"]
    L += ["| %s | %s |" % (f["class"], f["fact"]) for f in rep["facts"]]
    sc = rep["search_scope"]
    L += ["", "Search scope: %d archives, %d decoded blocks, %d skipped, `search_complete: %s`. "
          "Install unchanged during run: `%s`." % (sc["archives"], sc["decoded_blocks"],
                                                   sc["skipped_blocks"], sc["search_complete"],
                                                   rep["install_unchanged"]), ""]
    L += ["## 6. Limitations", ""] + ["- %s" % item for item in rep["limitations"]]
    L += ["", "## Claim boundary", "", rep["claim_boundary"], ""]
    return "\n".join(L)


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def write_outputs(rep: dict, plan: Optional[dict], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    plan_path = out / PLAN_FILE
    if plan is None:
        if plan_path.exists() or plan_path.is_symlink():
            plan_path.unlink()
    else:
        _write_text(plan_path, json.dumps(plan, indent=2, sort_keys=True) + "\n")
        try:
            designs, _sha = pp.load_plan(plan_path)
            if len(designs) != 1 or designs[0]["name"] != plan["designs"][0]["name"]:
                raise JoinRefusal("pipeline loader returned an unexpected design list")
        except (pp.PorPipelineError, JoinRefusal) as exc:
            plan_path.unlink()
            raise JoinRefusal("generated plan refused by the pipeline loader: %s" % exc)
    _write_text(out / REPORT_JSON, json.dumps(rep, indent=2, sort_keys=True) + "\n")
    _write_text(out / REPORT_MD, render_report(rep))


def _check_usage(area: int, facing_name: Optional[str], facing_from_mapping: bool,
                 ordering: str, save: str, save_pins: dict) -> None:
    if ordering not in ORDERINGS:
        raise JoinRefusal("--ordering must be one of %s" % ", ".join(ORDERINGS))
    if save not in save_pins:
        raise JoinRefusal("--save must name a pinned save: %s" % ", ".join(sorted(save_pins)))
    if not (isinstance(area, int) and 1 <= area <= 999):
        raise JoinRefusal("--area must be 1..999 (the caller chooses it)")
    if (facing_name is None) == (not facing_from_mapping):
        raise JoinRefusal("give exactly one of --facing NAME or --facing-candidate-mapping")
    if facing_name is not None and facing_name not in pm.FACINGS:
        raise JoinRefusal("--facing must be one of %s" % ", ".join(sorted(pm.FACINGS)))


def build(install: Path, out: Path, *, save: str, ordering: str, area: int,
          facing_name: Optional[str] = None, facing_from_mapping: bool = False,
          requested_block: Optional[str] = None,
          save_pins: dict = sp.SAVE_PINS, geo_pins: dict = GEO_PINS,
          data_root: Path = DATA_DIR, recorded: Optional[dict] = sp.RECORDED_OBSERVATIONS,
          write: bool = True) -> tuple[dict, Optional[dict]]:
    """Run the adapter. Returns (report, plan-or-None). Raises JoinRefusal on input refusal.

    With write=False nothing is written, but the same checks run (used by tests)."""
    _check_usage(area, facing_name, facing_from_mapping, ordering, save, save_pins)
    requested = parse_block(requested_block) if requested_block else None
    try:
        doc = sg.check(install, out, save_pins=save_pins, geo_pins=geo_pins,
                       data_root=data_root, recorded=recorded)
    except sg.CheckRefusal as exc:
        raise JoinRefusal(str(exc)) from exc
    decision = decide(doc, save=save, ordering=ordering, area=area, facing_name=facing_name,
                      facing_from_mapping=facing_from_mapping, requested=requested)
    rep = _report_doc(decision, doc, len(save_pins))
    plan = build_plan(decision, save, ordering) if decision["plan_emitted"] else None
    if write:
        write_outputs(rep, plan, out)
    return rep, plan


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", help="PoR install folder (default: $%s or %s)"
                    % (INSTALL_ENV, DEFAULT_INSTALL))
    ap.add_argument("-o", "--output", required=True,
                    help="output folder, explicitly under data/ (relative paths are from the repo root)")
    ap.add_argument("--save", required=True, choices=sorted(sp.SAVE_PINS),
                    help="the one pinned save to join")
    ap.add_argument("--ordering", required=True, choices=ORDERINGS,
                    help="coordinate ordering (pose_xy is the primary hypothesis)")
    ap.add_argument("--area", required=True, type=int, help="plan area number, 1..999 (caller-chosen)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--facing", help="facing name for the plan row: north, east, south or west")
    g.add_argument("--facing-candidate-mapping", action="store_true",
                   help="use the GoldBox candidate facing mapping (recorded as unverified)")
    ap.add_argument("--block", help="requested block GEOn.DAX:TOC:ID; refused unless it is the one compatible block")
    args = ap.parse_args(argv)
    install = Path(args.install or os.environ.get(INSTALL_ENV) or DEFAULT_INSTALL)
    out = Path(args.output)
    if not out.is_absolute():
        out = (REPO / out).resolve()
    try:
        rep, plan = build(install, out, save=args.save, ordering=args.ordering, area=args.area,
                          facing_name=args.facing,
                          facing_from_mapping=args.facing_candidate_mapping,
                          requested_block=args.block)
    except JoinRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    if plan is None:
        print("plan refused: %s" % rep["refusal"], file=sys.stderr)
        print("wrote report %s (no pipeline plan)" % out)
        return 3
    print("plan emitted: design %s, GEO%d TOC %d, validated by por_pipeline.load_plan; playable false"
          % (plan["designs"][0]["name"], plan["designs"][0]["geo"], plan["designs"][0]["index"]))
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
