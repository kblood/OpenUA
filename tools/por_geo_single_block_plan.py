#!/usr/bin/env python3
"""Pool of Radiance: one decoded GEO block from a test-only smoke plan -> one-design pipeline plan.

Status: TEST-ONLY. ``playable: false``. The area number and the entry point are
INVENTED for this fixture. Neither is recovered from the install, and neither
says anything about which game area a GEO block belongs to. GEO2 is not game
area 1, and nothing here implies it is.

What it is for
  ``tools/por_geo_smoke_plan.py`` plans one flat map-only design per decoded GEO
  block, all at one test position. This adapter narrows that to exactly one
  block, so a single ``NAME.DSN`` can be generated and checked on its own.

What one run does (reads two files, writes two files, touches nothing else)
  1. READ. Load the smoke plan (``openua.por-geo-smoke-plan`` v0) and the
     ``por_pipeline_plan.json`` it names. Both are read with the smoke tool's
     loader, which refuses duplicate object keys. Their SHA-256 values are
     recorded; no path is.
  2. VALIDATE. Refuse unless the smoke plan is ``playable: false``, ``test-only``,
     every key set is exactly the schema's (unknown fields are refused), the
     pipeline plan's SHA-256 equals ``plan.sha256`` in the smoke plan, the
     pipeline plan lists exactly the smoke plan's designs with the same fields,
     and the smoke plan's test entry equals ``--entry``.
  3. SELECT. Exactly one design whose (geo, index, block_id) match the request.
     A missing block, a block id that disagrees with the TOC index, or an
     ambiguous match is refused.
  4. WRITE. ``por_pipeline_plan.json`` (the pipeline's plan schema: one flat
     design) and ``por_geo_single_block_plan.json`` (this tool's manifest).
     Sorted keys, no timestamps, no absolute paths, so the same inputs give
     byte-identical output.

Usage
  python3 tools/por_geo_single_block_plan.py \
      --smoke-plan data/work/por-geo-smoke-plan/t/por_geo_smoke_plan.json \
      --pipeline-plan data/work/por-geo-smoke-plan/t/por_pipeline_plan.json \
      --geo 2 --index 2 --block-id 20 --entry 14,10,west \
      -o data/work/por-geo-single-block-plan/t

  The plan is then consumed by the pipeline, which this tool does NOT run:
  python3 tools/por_pipeline.py --install "G:/Games/Pool of Radiance" \
      -o data/work/por-pipeline/t --plan data/work/por-geo-single-block-plan/t/por_pipeline_plan.json

Output folder: must be outside both input folders and, under the repository,
under ``data/`` (git-ignored). Stdlib plus the repo's own tools only.

Exit codes
  0  plan and manifest written
  2  refusal: unreadable or malformed input, hash or provenance mismatch, unknown
     field, unresolved or non-test entry, no or ambiguous selection, bad output
     location (nothing written)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

import por_geo_smoke_plan as sp
import por_map as pm
from por_convert import PorSourceError, validate_output_dir

# The only folder that repository-relative output may use. Tests patch this.
DATA_ROOT = Path(__file__).resolve().parent.parent / "data"

SCHEMA = "openua.por-geo-single-block-plan"
SCHEMA_VERSION = 0
STATUS = "test-only-single-block-plan"
LABEL = "test-only"
PLAN_FILE = sp.PLAN_FILE
MANIFEST_FILE = "por_geo_single_block_plan.json"
AREA_STATUS = "invented-test-only"
ENTRY_STATUS = "test-only"

SMOKE_SCHEMA = sp.SCHEMA
SMOKE_VERSION = sp.SCHEMA_VERSION
SMOKE_STATUS = sp.STATUS
PIPELINE_SCHEMA = sp.PIPELINE_PLAN_SCHEMA
PIPELINE_VERSION = sp.PIPELINE_PLAN_VERSION
GEO_MAX = 8
MAX_INDEX = sp.MAX_TOC_INDEX
AREA_MAX = 999

SMOKE_TOP_KEYS = frozenset({"schema", "schema_version", "status", "label", "playable",
                            "scope", "scope_note", "archives", "archives_refused",
                            "source", "test_entry", "area", "plan", "designs",
                            "summary", "not_claimed"})
SMOKE_ROW_KEYS = frozenset({"name", "key", "geo", "index", "block_id", "decoded_sha256",
                            "title", "area", "entry", "label", "playable"})
SMOKE_ENTRY_KEYS = frozenset({"x", "y", "facing"})
SMOKE_TEST_ENTRY_KEYS = frozenset({"x", "y", "facing", "basis"})
SMOKE_PLAN_KEYS = frozenset({"file", "schema", "version", "sha256"})
SMOKE_SOURCE_KEYS = frozenset({"schema", "schema_version", "sha256"})
SMOKE_AREA_KEYS = frozenset({"value", "basis"})
PIPE_TOP_KEYS = frozenset({"schema", "version", "designs"})
PIPE_DESIGN_KEYS = frozenset({"name", "geo", "index", "area", "entry", "facing", "title"})

NOT_CLAIMED = [
    "Map serialization and reader compatibility only: the design round-trips through geo.Geo.parse.",
    "Not a claim that this GEO block is game area 1 or any authentic area: the area number is invented for this fixture.",
    "Not the authentic start location or facing: the entry is invented for this fixture.",
    "No transitions, wall art, events, text, monsters, items, shops or campaign logic.",
    "runtime_loaded and engine_executed are false: nothing here boots OpenUA or walks the design.",
]

SHA256_RE = re.compile(r"[0-9a-f]{64}")


class SingleBlockError(Exception):
    """A named refusal. The CLI prints it and exits with 2."""


# --------------------------------------------------------------------------
# Small checks
# --------------------------------------------------------------------------

def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_sha(v) -> bool:
    return isinstance(v, str) and SHA256_RE.fullmatch(v) is not None


def _exact_keys(where: str, obj, keys: frozenset) -> dict:
    """The object must be a dict with exactly ``keys``: unknown and missing are refused."""
    if not isinstance(obj, dict):
        raise SingleBlockError("%s must be an object" % where)
    extra = sorted(set(obj) - keys)
    if extra:
        raise SingleBlockError("%s has unknown field(s): %s" % (where, ", ".join(extra)))
    missing = sorted(keys - set(obj))
    if missing:
        raise SingleBlockError("%s is missing field(s): %s" % (where, ", ".join(missing)))
    return obj


def _load(path: Path, what: str) -> tuple[dict, str]:
    """Read one JSON file with the smoke tool's loader; return (data, sha256)."""
    try:
        return sp.load_manifest(Path(path))
    except sp.SmokePlanError as exc:
        raise SingleBlockError("%s: %s" % (what, exc))


def _entry_fields(where: str, x, y, facing) -> tuple[int, int, str]:
    try:
        return sp._check_entry_fields(where, x, y, facing)
    except sp.SmokePlanError as exc:
        raise SingleBlockError(str(exc))


def parse_entry(text: str) -> tuple[int, int, str]:
    """Parse ``X,Y,FACING`` for --entry. Range and facing are checked here."""
    parts = text.split(",")
    if len(parts) != 3:
        raise SingleBlockError("--entry expects X,Y,FACING, got %r" % text)
    try:
        x, y = int(parts[0]), int(parts[1])
    except ValueError:
        raise SingleBlockError("--entry X and Y must be integers")
    return _entry_fields("--entry", x, y, parts[2].strip())


# --------------------------------------------------------------------------
# Validation of the smoke plan and the pipeline plan it names
# --------------------------------------------------------------------------

def validate_smoke(m) -> dict:
    """Refuse anything but a complete, test-only, self-consistent smoke plan."""
    _exact_keys("smoke plan", m, SMOKE_TOP_KEYS)
    if m["schema"] != SMOKE_SCHEMA or not _is_int(m["schema_version"]) \
            or m["schema_version"] != SMOKE_VERSION:
        raise SingleBlockError("smoke plan schema must be %r version %d"
                               % (SMOKE_SCHEMA, SMOKE_VERSION))
    if m["status"] != SMOKE_STATUS or m["label"] != LABEL:
        raise SingleBlockError("smoke plan status must be %r and label %r"
                               % (SMOKE_STATUS, LABEL))
    if m["playable"] is not False:
        raise SingleBlockError("smoke plan must be playable: false (refusing a playable claim)")
    if m["scope"] not in (sp.SCOPE_FULL, sp.SCOPE_PARTIAL):
        raise SingleBlockError("smoke plan scope must be %r or %r"
                               % (sp.SCOPE_FULL, sp.SCOPE_PARTIAL))

    plan = _exact_keys("smoke plan.plan", m["plan"], SMOKE_PLAN_KEYS)
    if plan["file"] != PLAN_FILE or plan["schema"] != PIPELINE_SCHEMA \
            or not _is_int(plan["version"]) or plan["version"] != PIPELINE_VERSION:
        raise SingleBlockError("smoke plan.plan must name %r as a %r version %d"
                               % (PLAN_FILE, PIPELINE_SCHEMA, PIPELINE_VERSION))
    if not _is_sha(plan["sha256"]):
        raise SingleBlockError("smoke plan.plan.sha256 is not a SHA-256 value")

    source = _exact_keys("smoke plan.source", m["source"], SMOKE_SOURCE_KEYS)
    if source["schema"] != sp.MANIFEST_SCHEMA or not _is_int(source["schema_version"]) \
            or source["schema_version"] != sp.MANIFEST_SCHEMA_VERSION:
        raise SingleBlockError("smoke plan source must be a %r version %d manifest"
                               % (sp.MANIFEST_SCHEMA, sp.MANIFEST_SCHEMA_VERSION))
    if not _is_sha(source["sha256"]):
        raise SingleBlockError("smoke plan.source.sha256 is not a SHA-256 value")

    area = _exact_keys("smoke plan.area", m["area"], SMOKE_AREA_KEYS)
    if not _is_int(area["value"]) or not (1 <= area["value"] <= AREA_MAX):
        raise SingleBlockError("smoke plan.area.value must be 1..%d" % AREA_MAX)

    te = _exact_keys("smoke plan.test_entry", m["test_entry"], SMOKE_TEST_ENTRY_KEYS)
    test_entry = _entry_fields("smoke plan.test_entry", te["x"], te["y"], te["facing"])

    rows_in = m["designs"]
    if not isinstance(rows_in, list) or not rows_in:
        raise SingleBlockError("smoke plan.designs must be a non-empty list")
    if not isinstance(m["summary"], dict) or m["summary"].get("designs_planned") != len(rows_in):
        raise SingleBlockError("smoke plan summary.designs_planned disagrees with its designs")

    rows: list[dict] = []
    keys, names, positions = set(), set(), set()
    for i, r in enumerate(rows_in):
        where = "smoke plan designs[%d]" % i
        _exact_keys(where, r, SMOKE_ROW_KEYS)
        geo, index, block_id = r["geo"], r["index"], r["block_id"]
        if not all(_is_int(v) for v in (geo, index, block_id)):
            raise SingleBlockError("%s geo, index and block_id must be integers" % where)
        if not (1 <= geo <= GEO_MAX) or not (0 <= index <= MAX_INDEX) or block_id < 0:
            raise SingleBlockError("%s geo 1..%d, index 0..%d, block_id >= 0 required"
                                   % (where, GEO_MAX, MAX_INDEX))
        if r["key"] != sp.KEY_FMT % (geo, index, block_id):
            raise SingleBlockError("%s key %r does not match geo %d index %d block %d"
                                   % (where, r["key"], geo, index, block_id))
        try:
            expected_name = sp.design_name(geo, index)
        except sp.SmokePlanError as exc:
            raise SingleBlockError("%s: %s" % (where, exc))
        if r["name"] != expected_name:
            raise SingleBlockError("%s name %r is not %r" % (where, r["name"], expected_name))
        if r["key"] in keys or r["name"] in names or (geo, index) in positions:
            raise SingleBlockError("%s repeats a key, name or GEO%d TOC index %d"
                                   % (where, geo, index))
        keys.add(r["key"]); names.add(r["name"]); positions.add((geo, index))
        if not _is_sha(r["decoded_sha256"]):
            raise SingleBlockError("%s has no valid decoded_sha256" % where)
        if r["label"] != LABEL or r["playable"] is not False:
            raise SingleBlockError("%s must be test-only and playable: false" % where)
        if not _is_int(r["area"]) or r["area"] != area["value"]:
            raise SingleBlockError("%s area differs from the smoke plan area" % where)
        if r["title"] != "%s geo%d TOC %d" % (LABEL, geo, index):
            raise SingleBlockError("%s title is not the smoke plan's title" % where)
        entry = _exact_keys(where + ".entry", r["entry"], SMOKE_ENTRY_KEYS)
        if _entry_fields(where + ".entry", entry["x"], entry["y"], entry["facing"]) != test_entry:
            raise SingleBlockError("%s entry differs from the smoke plan test entry" % where)
        rows.append(r)

    return {"rows": rows, "test_entry": test_entry, "area": area["value"],
            "scope": m["scope"], "plan_sha256": plan["sha256"],
            "source_sha256": source["sha256"]}


def validate_pipeline(p, smoke: dict) -> None:
    """The pipeline plan must list exactly the smoke plan's designs, field for field."""
    _exact_keys("pipeline plan", p, PIPE_TOP_KEYS)
    if p["schema"] != PIPELINE_SCHEMA or not _is_int(p["version"]) \
            or p["version"] != PIPELINE_VERSION:
        raise SingleBlockError("pipeline plan schema must be %r version %d"
                               % (PIPELINE_SCHEMA, PIPELINE_VERSION))
    designs = p["designs"]
    if not isinstance(designs, list):
        raise SingleBlockError("pipeline plan.designs must be a list")
    table = {r["name"]: r for r in smoke["rows"]}
    if len(designs) != len(table):
        raise SingleBlockError("pipeline plan has %d designs; the smoke plan has %d"
                               % (len(designs), len(table)))
    seen = set()
    for i, d in enumerate(designs):
        where = "pipeline plan designs[%d]" % i
        _exact_keys(where, d, PIPE_DESIGN_KEYS)
        name = d["name"]
        if not isinstance(name, str) or not pm.DSN_NAME_RE.fullmatch(name):
            raise SingleBlockError("%s.name must be 1..8 of A-Z 0-9 _" % where)
        if name in seen:
            raise SingleBlockError("%s.name %r repeats" % (where, name))
        seen.add(name)
        if name not in table:
            raise SingleBlockError("%s names %r, which the smoke plan does not list"
                                   % (where, name))
        t = table[name]
        if not all(_is_int(d[k]) for k in ("geo", "index", "area")):
            raise SingleBlockError("%s geo, index and area must be integers" % where)
        entry = d["entry"]
        if not isinstance(entry, list) or len(entry) != 2:
            raise SingleBlockError("%s.entry must be [x, y]" % where)
        _entry_fields(where + ".entry", entry[0], entry[1], d["facing"])
        if not isinstance(d["title"], str):
            raise SingleBlockError("%s.title must be a string" % where)
        same = (d["geo"], d["index"], d["area"], d["title"], d["facing"],
                (entry[0], entry[1])) == (t["geo"], t["index"], t["area"], t["title"],
                                          t["entry"]["facing"],
                                          (t["entry"]["x"], t["entry"]["y"]))
        if not same:
            raise SingleBlockError("%s disagrees with the smoke plan design table for %r"
                                   % (where, name))


def select(rows: list[dict], geo: int, index: int, block_id: int) -> dict:
    """Exactly one decoded block with this (geo, index, block_id), or a named refusal."""
    at_position = [r for r in rows if r["geo"] == geo and r["index"] == index]
    if not at_position:
        raise SingleBlockError("no decoded block at GEO%d TOC index %d in the smoke plan"
                               % (geo, index))
    if at_position[0]["block_id"] != block_id:
        raise SingleBlockError("GEO%d TOC index %d is block %d in the smoke plan, not block %d"
                               % (geo, index, at_position[0]["block_id"], block_id))
    exact = [r for r in rows if (r["geo"], r["index"], r["block_id"]) == (geo, index, block_id)]
    if len(exact) != 1:
        raise SingleBlockError("GEO%d TOC index %d block %d matches %d designs; selection is "
                               "ambiguous" % (geo, index, block_id, len(exact)))
    return exact[0]


# --------------------------------------------------------------------------
# Plan and manifest
# --------------------------------------------------------------------------

def build_outputs(row: dict, smoke: dict, pipeline_sha256: str,
                  geo: int, index: int, block_id: int) -> tuple[bytes, bytes]:
    """Return (pipeline plan bytes, manifest bytes). Both sorted, no paths, no timestamps."""
    te = smoke["test_entry"]
    title = "%s geo%d TOC %d block %d (invented area and entry)" % (LABEL, geo, index, block_id)
    plan = {"schema": PIPELINE_SCHEMA, "version": PIPELINE_VERSION, "designs": [{
        "name": row["name"], "geo": geo, "index": index, "area": smoke["area"],
        "entry": [te[0], te[1]], "facing": te[2], "title": title}]}
    plan_bytes = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "label": LABEL,
        "playable": False,
        "selector": {"geo": geo, "index": index, "block_id": block_id, "key": row["key"]},
        "block": {"name": row["name"], "decoded_sha256": row["decoded_sha256"]},
        "area": {"value": smoke["area"], "status": AREA_STATUS,
                 "basis": "placeholder carried from the smoke plan; invented for this fixture; "
                          "not GEO%d area 1 and not recovered" % geo},
        "entry": {"x": te[0], "y": te[1], "facing": te[2], "status": ENTRY_STATUS,
                  "basis": "invented for this fixture; equals the smoke plan test entry; "
                           "not recovered from the install"},
        "source": {
            "smoke_plan": {"schema": SMOKE_SCHEMA, "schema_version": SMOKE_VERSION,
                           "scope": smoke["scope"], "sha256_recorded": True},
            "geo_manifest_sha256": smoke["source_sha256"],
            "pipeline_plan_sha256": pipeline_sha256,
        },
        "plan": {"file": PLAN_FILE, "schema": PIPELINE_SCHEMA, "version": PIPELINE_VERSION,
                 "designs": 1, "sha256": hashlib.sha256(plan_bytes).hexdigest()},
        "summary": {"designs_planned": 1, "designs_in_source": len(smoke["rows"]),
                    "designs_not_selected": len(smoke["rows"]) - 1,
                    "designs_all_test_only": True, "dsn_emitted": 0},
        "not_claimed": NOT_CLAIMED,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return plan_bytes, manifest_bytes


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

def _check_output(out: Path, inputs: list[Path]) -> None:
    """Outside both input folders (the shared rule), and strictly under DATA_ROOT."""
    for src in inputs:
        try:
            validate_output_dir(src.parent, out)
        except PorSourceError as exc:
            raise SingleBlockError(str(exc))
    root = DATA_ROOT.resolve()
    resolved = out.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise SingleBlockError("output folder must be a folder under data/ (git-ignored)")


def run(smoke_path: Path, pipeline_path: Path, geo: int, index: int, block_id: int,
        entry_text: str, out: Path) -> dict:
    smoke_path, pipeline_path, out = Path(smoke_path), Path(pipeline_path), Path(out)
    if not (1 <= geo <= GEO_MAX) or not (0 <= index <= MAX_INDEX) or block_id < 0:
        raise SingleBlockError("--geo 1..%d, --index 0..%d and --block-id >= 0 are required"
                               % (GEO_MAX, MAX_INDEX))
    x, y, facing = parse_entry(entry_text)
    for p, what in ((smoke_path, "smoke plan"), (pipeline_path, "pipeline plan")):
        if not p.is_file():
            raise SingleBlockError("%s file not found" % what)
    _check_output(out, [smoke_path, pipeline_path])
    if out.exists() and not out.is_dir():
        raise SingleBlockError("output path exists and is not a folder")

    smoke_data, _ = _load(smoke_path, "smoke plan")
    smoke = validate_smoke(smoke_data)
    pipe_data, pipeline_sha = _load(pipeline_path, "pipeline plan")
    if pipeline_sha != smoke["plan_sha256"]:
        raise SingleBlockError("pipeline plan SHA-256 does not match the smoke plan's plan.sha256")
    validate_pipeline(pipe_data, smoke)
    if smoke["test_entry"] != (x, y, facing):
        raise SingleBlockError("--entry %d,%d,%s differs from the smoke plan test entry %d,%d,%s"
                               % (x, y, facing, *smoke["test_entry"]))
    row = select(smoke["rows"], geo, index, block_id)

    plan_bytes, manifest_bytes = build_outputs(row, smoke, pipeline_sha, geo, index, block_id)
    out.mkdir(parents=True, exist_ok=True)
    (out / PLAN_FILE).write_bytes(plan_bytes)
    (out / MANIFEST_FILE).write_bytes(manifest_bytes)
    return json.loads(manifest_bytes.decode("utf-8"))


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Select one decoded GEO block from a test-only smoke plan and write a "
                    "one-design pipeline plan. Area and entry are invented (test-only).")
    ap.add_argument("--smoke-plan", type=Path, required=True,
                    help="por_geo_smoke_plan.json (openua.por-geo-smoke-plan v0)")
    ap.add_argument("--pipeline-plan", type=Path, required=True,
                    help="por_pipeline_plan.json that the smoke plan names (hash-checked)")
    ap.add_argument("--geo", type=int, required=True, help="GEO archive number, 1..8")
    ap.add_argument("--index", type=int, required=True, help="TOC index within that archive")
    ap.add_argument("--block-id", type=int, required=True, help="expected block id at that index")
    ap.add_argument("--entry", required=True, metavar="X,Y,FACING",
                    help="must equal the smoke plan test entry; invented, test-only")
    ap.add_argument("-o", "--out", type=Path, required=True,
                    help="output folder (outside both input folders; under data/ in-repo)")
    args = ap.parse_args(argv)
    try:
        manifest = run(args.smoke_plan, args.pipeline_plan, args.geo, args.index,
                       args.block_id, args.entry, args.out)
    except (SingleBlockError, sp.SmokePlanError) as exc:
        print("por_geo_single_block_plan: error: %s" % exc, file=sys.stderr)
        return 2
    sel = manifest["selector"]
    print("por_geo_single_block_plan: selected %s (GEO%d TOC %d block %d); 1 test-only design "
          "(playable: false, area and entry invented)"
          % (sel["key"], sel["geo"], sel["index"], sel["block_id"]))
    print("por_geo_single_block_plan: wrote %s and %s"
          % (args.out / PLAN_FILE, args.out / MANIFEST_FILE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
