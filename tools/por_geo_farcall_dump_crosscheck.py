#!/usr/bin/env python3
"""Cross-check conditional PoR GEO-stub far-call candidates against RAM dumps.

Static candidates come from ``por_geo_farcall_census``. For each supplied dump,
this probe uniquely maps any resident owner group using stable code bytes, reads
the candidate's live far-call segment word, and compares the observed fixup
delta with the delta required to reach the GEO loader stub under the census's
paragraph-aligned MZ model. It also records whether the live target window
matches the GEO stub's START.EXE file offset.

The probe is read-only. A memory match establishes presence in a dump only; it
does not establish that the call executed or that the dump is atomic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"
sys.path.insert(0, str(TOOLS_DIR))

import por_geo_farcall_census as census  # noqa: E402
import por_overlay_group_map as group_map  # noqa: E402
import por_farcall_resolve as resolver  # noqa: E402

SCHEMA = "openua.por-geo-farcall-dump-crosscheck"
SCHEMA_VERSION = 1
STATUS = "capture-scoped-diagnostic"
TOOL = "tools/por_geo_farcall_dump_crosscheck.py"
RESULT_JSON = "por_geo_farcall_dump_crosscheck.json"
RESULT_MD = "por_geo_farcall_dump_crosscheck_report.md"


class CrosscheckRefusal(Exception):
    """A named refusal; no output is written."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_out(out: Path, install: Path) -> None:
    out_r = out.resolve()
    install_r = install.resolve()
    if out_r == install_r or install_r in out_r.parents:
        raise CrosscheckRefusal("output folder is inside the install folder")
    data_work = DATA_WORK.resolve()
    if out_r == data_work:
        raise CrosscheckRefusal("output folder must be a child of data/work")
    try:
        out_r.relative_to(data_work)
    except ValueError as exc:
        raise CrosscheckRefusal("output folder must be under data/work/") from exc


def _target_hits_geo_stub(row: dict) -> bool:
    hits = row.get("window", {}).get("hits", {}).get(census.EXE_NAME, [])
    return census._hex(census.GEO_STUB_F) in hits


def candidate_observation(candidate: dict, owner: dict, mapped_group: Optional[dict]) -> dict:
    """Join one candidate owner row to a mapped far-call site, if present."""
    site_file = int(candidate["at"], 16)
    owner_file = int(owner["owner_fileofs"], 16)
    base = {
        "site_file_offset": census._hex(site_file),
        "owner_fileofs": census._hex(owner_file),
        "static_candidate_status": owner["status"],
        "static_di_constraint_mod64k": owner.get("di_constraint_mod64k"),
        "strong_decode_path": bool(candidate["strong"]),
        "group_status": owner.get("group_status"),
    }
    if mapped_group is None:
        return {**base, "observation": "owner-group-absent-or-unmapped"}

    far_rows = [r for r in mapped_group.get("far_call_sites", [])
                if int(r["site_file_offset"], 16) == site_file]
    if len(far_rows) != 1:
        return {**base, "observation": "candidate-site-not-unique-in-mapped-fixups",
                "matching_fixup_rows": len(far_rows)}
    row = far_rows[0]
    raw_seg = int(row["seg_raw"], 16)
    live_seg = int(row["seg_live"], 16)
    delta = (live_seg - raw_seg) & 0xFFFF
    needed = owner.get("di_constraint_mod64k")
    return {
        **base,
        "observation": "mapped-live-callsite",
        "opcode_0x9a": row["opcode_0x9a"],
        "offset_matches_file": row["offset_matches_file"],
        "seg_raw": row["seg_raw"],
        "seg_live": row["seg_live"],
        "observed_delta_mod64k": delta,
        "delta_matches_candidate_constraint": needed is not None and delta == needed,
        "target_linear": row["target_linear"],
        "target_window_status": row["window"]["status"],
        "target_window_start_exe_offsets": row["window"].get("hits", {}).get(census.EXE_NAME, []),
        "target_window_matches_geo_stub": _target_hits_geo_stub(row),
    }


def analyze_dump(start: bytes, ovr: bytes, dump_data: bytes, dump_name: str,
                 candidates: list[dict]) -> dict:
    base = group_map.resolve_dump_base(dump_name, len(dump_data), None)
    groups = census.groups_of(start, ovr)
    mapped: dict[int, dict] = {}
    unmapped: dict[int, str] = {}
    for g in groups:
        try:
            row = group_map.analyze(ovr, start, dump_data, base, g["header_offset"],
                                    dump_name=dump_name)
        except group_map.Refusal as exc:
            unmapped[g["fileofs"]] = str(exc)
            continue
        mapped[g["fileofs"]] = row

    observations = []
    for candidate in candidates:
        for owner in candidate["owners"]:
            owner_file = int(owner["owner_fileofs"], 16)
            group_row = mapped.get(owner_file)
            observation = candidate_observation(candidate, owner, group_row)
            observation["dump_name"] = Path(dump_name).name
            observations.append(observation)

    covered = [r for r in observations if r["observation"] == "mapped-live-callsite"]
    totals = {
        "groups_parsed": len(groups),
        "groups_mapped_unique": len(mapped),
        "candidate_owner_rows": len(observations),
        "candidate_owner_rows_with_live_callsite": len(covered),
        "candidate_constraints_matching_observed_delta": sum(
            r["delta_matches_candidate_constraint"] for r in covered),
        "targets_matching_geo_stub_bytes": sum(r["target_window_matches_geo_stub"] for r in covered),
        "candidate_rows_unobserved": len(observations) - len(covered),
    }
    return {
        "name": Path(dump_name).name,
        "bytes": len(dump_data),
        "sha256": _sha(dump_data),
        "capture_id": _sha(dump_data)[:12],
        "base": "0x%X" % base,
        "end": "0x%X" % (base + len(dump_data)),
        "mapped_group_fileofs": [census._hex(v) for v in sorted(mapped)],
        "unmapped_groups": [{"fileofs": census._hex(k), "reason": v}
                            for k, v in sorted(unmapped.items())],
        "totals": totals,
        "candidate_observations": observations,
    }


def build_report(install: Path, dump_paths: list[Path]) -> dict:
    inputs = census.p.load_inputs(install)
    start, ovr = inputs[census.EXE_NAME], inputs[census.OVR_NAME]
    static = census.analyse(start, ovr)
    captures = []
    for path in dump_paths:
        if not path.is_file():
            raise CrosscheckRefusal("RAM dump not found: %s" % path.name)
        data = path.read_bytes()
        captures.append(analyze_dump(start, ovr, data, path.name, static["candidates"]))
    # Recheck pinned inputs after every dump has been analyzed.
    after = census.p.load_inputs(install)
    unchanged = {name: _sha(inputs[name]) == _sha(after[name]) for name in inputs}
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "geo_binding_established": False,
        "source_inputs": {name: {"bytes": len(data), "sha256": _sha(data)}
                          for name, data in sorted(inputs.items())},
        "source_inputs_unchanged": unchanged,
        "static_census": {
            "status": static["verdict"]["geo_status"],
            "candidate_count": static["verdict"]["candidate_count"],
            "near_calls_to_geo_body": static["totals"]["near_calls_to_geo_body"],
            "geo_stub_file": static["geo_stub_file"],
            "geo_body_file": census._hex(census.GEO_BODY),
        },
        "captures": captures,
        "runtime_claims": {"executed": "not_established", "called": "not_established",
                           "atomic_snapshot": "not_established"},
    }


def render_report(doc: dict) -> str:
    lines = [
        "# PoR GEO far-call candidate dump cross-check",
        "",
        "**Static/memory-presence diagnostic only. `playable: false`; no GEO",
        "binding is established.** A mapped callsite and target byte window show",
        "memory presence in a captured dump, not execution or control-flow reachability.",
        "",
        "## Static census",
        "",
        "- candidate far-call sites: %d" % doc["static_census"]["candidate_count"],
        "- direct near calls to GEO body: %d" % doc["static_census"]["near_calls_to_geo_body"],
        "- GEO stub: START.EXE %s; GEO body: GAME.OVR %s"
        % (doc["static_census"]["geo_stub_file"], doc["static_census"]["geo_body_file"]),
        "",
    ]
    for capture in doc["captures"]:
        t = capture["totals"]
        lines += [
            "## Capture `%s` (`%s`)" % (capture["name"], capture["capture_id"]), "",
            "- bytes: %d; SHA-256: `%s`; coverage: %s..%s"
            % (capture["bytes"], capture["sha256"], capture["base"], capture["end"]),
            "- uniquely mapped overlay groups: %d / %d"
            % (t["groups_mapped_unique"], t["groups_parsed"]),
            "- candidate owner rows with live callsite: %d / %d"
            % (t["candidate_owner_rows_with_live_callsite"], t["candidate_owner_rows"]),
            "- required-delta matches: %d; target windows matching the GEO stub: %d"
            % (t["candidate_constraints_matching_observed_delta"],
               t["targets_matching_geo_stub_bytes"]),
            "- candidate rows in absent or unmapped groups: %d" % t["candidate_rows_unobserved"],
            "",
            "| owner group | callsite | raw:live segment | observed delta | required delta | target window | GEO stub bytes |",
            "| --- | --- | --- | ---: | ---: | --- | --- |",
        ]
        for row in capture["candidate_observations"]:
            if row["observation"] != "mapped-live-callsite":
                continue
            lines.append("| %s | %s | %s:%s | 0x%04X | %s | %s | %s |" % (
                row["owner_fileofs"], row["site_file_offset"], row["seg_raw"], row["seg_live"],
                row["observed_delta_mod64k"],
                ("0x%04X" % row["static_di_constraint_mod64k"])
                if row["static_di_constraint_mod64k"] is not None else "unlisted/unknown",
                row["target_window_status"], str(row["target_window_matches_geo_stub"]).lower()))
        if not any(r["observation"] == "mapped-live-callsite"
                   for r in capture["candidate_observations"]):
            lines.append("| none mapped | | | | | | |")
        lines.append("")
    lines += [
        "## Limits",
        "",
        "- Each candidate site's observed delta applies only to the specific",
        "  mapped overlay group in that dump. Candidate sites in absent groups stay",
        "  unobserved; no group-wide delta is generalized to them here.",
        "- A target-window match is memory presence only. It does not show that the",
        "  far call executed or that the GEO loader ran.",
        "- The candidate arithmetic still assumes the paragraph-aligned MZ model",
        "  documented by the static census. No area or archive mapping is emitted.",
        "- Dump names are recorded without directory paths. Atomicity is not",
        "  established.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                    encoding="utf-8")
    (out / RESULT_MD).write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Cross-check PoR GEO-loader far-call candidates against RAM dumps.")
    ap.add_argument("--install", required=True, type=Path, help="folder holding pinned GAME.OVR and START.EXE")
    ap.add_argument("--dump", required=True, type=Path, action="append",
                    help="raw RAM dump named ram-LO-HI.bin; repeatable")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder under data/work/")
    args = ap.parse_args(argv)
    try:
        check_out(args.out, args.install)
        doc = build_report(args.install, args.dump)
    except (CrosscheckRefusal, census.p.ProbeRefusal, group_map.Refusal, OSError, ValueError) as exc:
        print("por_geo_farcall_dump_crosscheck: refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("captures=%d static_candidates=%d geo_binding_established=false" %
          (len(doc["captures"]), doc["static_census"]["candidate_count"]))
    return 0 if all(doc["source_inputs_unchanged"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
