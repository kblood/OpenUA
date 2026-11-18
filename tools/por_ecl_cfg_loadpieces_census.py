#!/usr/bin/env python3
"""Compare linear and candidate-CFG ECL LOAD_PIECES (0x37) locations.

This supplementary census is driven by the opt-in CFG diagnostic and conditional
PoR base. It never calls a candidate a runtime load and makes no art binding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import por_ecl as pe
import por_ecl_cfg_probe as cfg
from por_convert import PorSourceError, validate_output_dir
from por_walls import PorMapError, resolve_archive


SCHEMA = "openua.por-ecl-cfg-loadpieces-census"
TOOL = "tools/por_ecl_cfg_loadpieces_census.py"
ARCHIVES = tuple(range(1, 9))
OPCODE = 0x37


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compare_offsets(linear: list[int], candidate: list[int]) -> dict:
    linear_set = set(linear)
    candidate_set = set(candidate)
    return {
        "linear_offsets": sorted(linear_set),
        "candidate_offsets": sorted(candidate_set),
        "candidate_only_offsets": sorted(candidate_set - linear_set),
        "linear_only_offsets": sorted(linear_set - candidate_set),
        "same_offsets": linear_set == candidate_set,
    }


def analyze_block(block: bytes, framing: str = "spec-menus") -> dict:
    header = pe.parse_header(block)
    linear_instructions, _, linear_stop = pe.walk_block(block, framing)
    candidate = cfg.analyze_block(block, header, framing=framing)
    linear_rows = [i for i in linear_instructions if i.opcode == OPCODE]
    candidate_rows = [i for i in candidate["candidate_instructions"] if i["opcode"] == OPCODE]
    result = compare_offsets([i.offset for i in linear_rows], [i["offset"] for i in candidate_rows])
    result.update({
        "linear_operands": [{"offset": i.offset, "operands": i.operands,
                             "count_operands": i.count_operands} for i in linear_rows],
        "candidate_operands": [{"offset": i["offset"], "operands": i["operands"],
                                "count_operands": i["count_operands"]} for i in candidate_rows],
        "linear_instruction_count": len(linear_instructions),
        "linear_stop": {"kind": linear_stop.kind, "offset": linear_stop.offset,
                        "opcode": linear_stop.opcode},
        "candidate_instruction_count": candidate["candidate_instruction_count"],
        "candidate_edge_count": len(candidate["candidate_edges"]),
        "conditional_uncertainty_count": len(candidate["uncertainties"]),
        "candidate_parse_stops": candidate["stops"],
        "candidate_invalid_roots": candidate["invalid_roots"],
        "candidate_interior_targets": candidate["interior_targets"],
        "candidate_limit_hit": candidate["bounded_limit_hit"],
    })
    return result


def census_archive(path: Path, archive: str, framing: str) -> tuple[dict, list[dict]]:
    data = path.read_bytes()
    record = {"archive": archive, "file_bytes": len(data), "file_sha256": sha(data), "blocks": []}
    diagnostics = []
    try:
        entries, data_base = pe.parse_dax(data)
    except pe.EclError as exc:
        diags = [{"archive": archive, "code": "container-error", "message": str(exc)}]
        record.update({"container": "error", "error": str(exc)})
        record["source_unchanged"] = sha(path.read_bytes()) == record["file_sha256"]
        if not record["source_unchanged"]:
            diags.append({"archive": archive, "code": "source-changed-during-read",
                          "message": "archive hash changed during census"})
        return record, diags
    record["container"] = "ok"
    for entry in entries:
        brec = {"toc_index": entry.index, "block_id": entry.block_id,
                "raw_size": entry.raw_size, "comp_size": entry.comp_size}
        record["blocks"].append(brec)
        start = data_base + entry.data_offset
        try:
            block = pe.rle_decode(data[start:start + entry.comp_size], entry.raw_size)
            brec["decoded_sha256"] = sha(block)
            brec["analysis"] = analyze_block(block, framing)
            brec["status"] = "ok"
        except pe.EclError as exc:
            brec.update({"status": "decode-error", "error": str(exc)})
            diagnostics.append({"archive": archive, "toc_index": entry.index,
                                "code": "decode-error", "message": str(exc)})
    if sha(path.read_bytes()) != record["file_sha256"]:
        diagnostics.append({"archive": archive, "code": "source-changed-during-read",
                            "message": "archive hash changed during census"})
        record["source_unchanged"] = False
    else:
        record["source_unchanged"] = True
    return record, diagnostics


def summarize(archives: list[dict]) -> dict:
    blocks = [b for a in archives for b in a.get("blocks", []) if b.get("status") == "ok"]
    occurrences = [b["analysis"] for b in blocks]
    linear_n = sum(len(x["linear_offsets"]) for x in occurrences)
    candidate_n = sum(len(x["candidate_offsets"]) for x in occurrences)
    candidate_only = sum(len(x["candidate_only_offsets"]) for x in occurrences)
    linear_only = sum(len(x["linear_only_offsets"]) for x in occurrences)
    return {
        "archives_present": sum(1 for a in archives if a.get("present") is True),
        "blocks_total": sum(len(a.get("blocks", [])) for a in archives),
        "blocks_decoded": len(blocks),
        "linear_load_pieces_sites": linear_n,
        "candidate_load_pieces_sites": candidate_n,
        "candidate_only_sites": candidate_only,
        "linear_only_sites": linear_only,
        "blocks_with_candidate_only_sites": sum(bool(x["candidate_only_offsets"]) for x in occurrences),
        "blocks_with_linear_only_sites": sum(bool(x["linear_only_offsets"]) for x in occurrences),
        "candidate_flow_conditional_uncertainties": sum(x["conditional_uncertainty_count"] for x in occurrences),
        "candidate_flow_parse_stops": sum(len(x["candidate_parse_stops"]) for x in occurrences),
    }


def census(install: Path, out: Path, framing: str) -> tuple[dict, int]:
    if not install.is_dir():
        raise pe.EclError("install folder not found")
    out = validate_output_dir(install, out)
    archives = []
    diagnostics = []
    for number in ARCHIVES:
        name = "ECL%d.DAX" % number
        path = resolve_archive(install, "ECL", number)
        if path is None:
            archives.append({"archive": name, "present": False, "blocks": []})
            diagnostics.append({"archive": name, "code": "archive-absent"})
            continue
        record, found = census_archive(path, name, framing)
        record["present"] = True
        archives.append(record)
        diagnostics.extend(found)
    result = {
        "schema": SCHEMA, "version": 1, "tool": TOOL,
        "status": "conditional-candidate-census-only", "playable": False,
        "runtime_reachability_established": False,
        "scope": {"archives": ["ECL%d.DAX" % n for n in ARCHIVES],
                  "opcode": "0x37", "framing": framing,
                  "vbase": "0x98FE (conditional; not promoted)"},
        "summary": summarize(archives), "archives": archives,
        "diagnostics": diagnostics,
        "not_established": [
            "candidate control-flow edges execute at runtime",
            "the 0x98FE vbase or selected framing is correct for every block",
            "LOAD_PIECES operand semantics or archive/block identity",
            "any ECL block or WALLDEF record maps to a GEO area or wall slot",
            "any OpenUA art binding or playable conversion",
        ],
    }
    return result, 1 if diagnostics else 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Compare linear and candidate CFG ECL LOAD_PIECES sites")
    ap.add_argument("--install", required=True, help="PoR install folder")
    ap.add_argument("--framing", choices=pe.FRAMINGS, default="spec-menus")
    ap.add_argument("-o", "--out", required=True, help="new output folder outside the install")
    args = ap.parse_args(argv)
    try:
        result, status = census(Path(args.install), Path(args.out), args.framing)
        out = Path(args.out).resolve()
        out.mkdir(parents=True, exist_ok=True)
        (out / "por_ecl_cfg_loadpieces_census.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (pe.EclError, PorSourceError, PorMapError, OSError, ValueError) as exc:
        print("por_ecl_cfg_loadpieces_census: error: %s" % exc, file=sys.stderr)
        return 2
    s = result["summary"]
    print("status=%s blocks=%d linear=%d candidate=%d candidate-only=%d linear-only=%d diagnostics=%d playable=false" % (
        result["status"], s["blocks_decoded"], s["linear_load_pieces_sites"],
        s["candidate_load_pieces_sites"], s["candidate_only_sites"],
        s["linear_only_sites"], len(result["diagnostics"])))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
