# Pool of Radiance: all-map container plan (TEST-ONLY)

**Status: TEST-ONLY CONTAINER CHECK. `playable: false`. Nothing here is a conversion.**

Tool: `tools/por_geo_all_map_group.py`. Tests: `tests/test_por_geo_all_map_group.py`.
Input: the map-smoke plan folder made by `tools/por_geo_smoke_plan.py`
(see `docs/por-geo-smoke-plan.md`).

## What it is for

`por_geo_smoke_plan.py` writes one flat `por_pipeline.py` design per decoded GEO
TOC block (29 on retail). Each is its own `NAME.DSN` folder.

This tool takes that flat plan and writes ONE grouped `por_pipeline.py` design
that holds all 29 blocks as areas of one `TGALLMAP.DSN` folder. The existing
pipeline then emits a single all-map DSN folder from it. The point is to test
the container: can 29 GEO blocks share one folder and read back through
OpenUA's own reader.

## What is invented (labelled everywhere it appears)

- **Area numbers 1..29.** Sequential test-only ids, assigned in (GEO, TOC index)
  order. They are NOT recovered from the install or the game. No
  block-to-area mapping is claimed. Each row of the manifest's `areas` table
  carries `area_id_status: "invented-test-only"`.
- **Start area 1.** An invented placeholder (the first invented id). Not the
  authentic start location.
- **Design name `TGALLMAP`** and its title.
- **Per-area entry and facing.** Copied unchanged from the smoke plan's single
  test position (`0,0,north` in the retail run). Not authentic entries.

## What it checks, and what it does not

**It checks:** that a grouped design of 29 decoded blocks is accepted by
`por_pipeline.load_plan`, and that the pipeline can write and read back one
folder holding all of them.

**It does not establish:** a playable conversion of any area; that the game
loads or walks any block; any authentic area number, start location, facing,
transitions, art, events, text or monsters.

## Input validation (every refusal is named)

The input must be a smoke-plan manifest the producer wrote, and it is
cross-checked against the plan file it names:

- manifest schema `openua.por-geo-smoke-plan` v0, status
  `test-only-map-smoke-plan`, label `test-only`, `playable` exactly `false`,
  scope `all-geo`;
- summary: `designs_planned` = `retail_designs_expected` = 29,
  `blocks_refused_in_source` = 0, `dsn_emitted` = 0,
  `designs_all_test_only` = true;
- the design table has exactly 29 rows, each with the exact field set; key
  well formed and equal to its geo/index/block_id; no repeated key, name, or
  GEO+index; 64-hex `decoded_sha256`; `label` test-only, `playable` false;
- the plan file named by `plan.file` exists and its SHA-256 equals
  `plan.sha256`; no JSON object key is repeated in the plan;
- the plan is schema `openua.por-pipeline-plan` v0 with exactly the keys
  `schema`, `version`, `designs`, and holds exactly 29 designs;
- each design has exactly `name, geo, index, area, entry, facing, title`
  (nothing defaulted); name 1..8 of `A-Z 0-9 _`; no repeated name or GEO+index;
  geo 1..8; index 0..999; `entry` is a 2-element list of integers 0..15 (no
  booleans); `facing` is in the DSN facing set; `area` is an integer 1..999
  (only validated, then ignored);
- one-to-one with the table: every design has exactly one row by name, and the
  row's geo, index, title and entry agree with the design.

## Outputs

Both files are in `-o`, sorted keys, no timestamps, no absolute paths. The same
input bytes give byte-identical output.

- `por_pipeline_plan.json`: schema `openua.por-pipeline-plan` v0 and nothing
  else. One grouped design with keys `name, title, start_area, start_entry,
  areas`. `start_entry` is 1 (the pipeline's rule). Each area row is `geo,
  index, area, entry, facing`, with areas sorted by (GEO, TOC index).
- `por_all_map_group.json`: schema `openua.por-all-map-group` v0,
  `label: test-only`, `playable: false`. It records the source hashes (the
  smoke manifest and the plan, by SHA-256 only), the output plan hash, the group
  summary, the invented area table, the area numbering basis, and the
  not-claimed list. Summary: `groups_planned` 1, `areas_planned` 29,
  `dsn_emitted` 0, `playable_claims` 0.

## Usage

```sh
# 1. enumerate with one explicit test position (read-only on the install)
python tools/por_geo_manifest.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-all-map-group/src/manifest --test-entry 0,0,north
# 2. flat map-smoke plan (one design per decoded block)
python tools/por_geo_smoke_plan.py \
    --manifest data/work/por-all-map-group/src/manifest/por_geo_manifest.json \
    -o data/work/por-all-map-group/src/smoke
# 3. grouped all-map plan (this tool)
python tools/por_geo_all_map_group.py \
    --smoke data/work/por-all-map-group/src/smoke/por_geo_smoke_plan.json \
    -o data/work/por-all-map-group/bundle
# 4. the existing pipeline consumes the grouped plan
python tools/por_pipeline.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-all-map-group/pipeline \
    --plan data/work/por-all-map-group/bundle/por_pipeline_plan.json
```

| Exit | Meaning |
| --- | --- |
| 0 | plan and manifest written |
| 2 | refusal (nothing written): unreadable or malformed input, plan not matching the manifest hash, row count or one-to-one mismatch, invalid field, output inside the smoke folder, output inside the repository but not under `data/`, output path that is a file |

## Tests

```sh
python -m pytest tests/test_por_geo_all_map_group.py -q
```

40 tests, all on synthetic installs. The smoke folder is built by the real
`por_geo_manifest.py` and `por_geo_smoke_plan.py` code, once per module. Covered:

- one grouped design, 29 areas, area ids 1..29, start area 1, start entry 1;
- every source block appears exactly once (GEO+index sets equal);
- `por_pipeline.load_plan` accepts the output and gives the group kind;
- path-free outputs; a copied input gives identical bytes; repeat runs are identical;
- no `playable: true`, `runtime_loaded: true` or `engine_executed: true`;
  invented labels present; the not-claimed list says no block-to-area mapping;
- refused output paths (inside the smoke folder, equal to it, inside the
  repository outside `data/`, a file), a missing smoke file, CLI exit codes;
- smoke refusals: playable true, partial scope, wrong schema or label, a
  refused source block, plan hash mismatch, missing plan file, a repeated key
  in the plan;
- coverage: 28 or 30 plan rows, repeated name, repeated GEO+index, a plan
  design with no table row, a table row with no design, 28 table rows,
  repeated table key, key disagreeing with its fields;
- explicit entries: out-of-range coordinate, boolean coordinate, three-element
  entry, bad facing, missing facing or area, unknown field, entry disagreeing
  with the table, bad index, wrong pipeline schema.

## Retail run (2026-11-17)

Run read-only on the local GOG install. Test position `0,0,north`. Output is
under ignored `data/work/por-all-map-group/`. No DOSBox, GameLink or emulator.

- manifest: archives 8/8 ok, blocks decoded 29/29, DSN emitted 0, install
  `unchanged: true` (the manifest records a SHA-256 per GEO archive, and its
  `install.unchanged` flag is true);
- smoke plan: all-geo scope, 29 test-only designs;
- group plan: 1 grouped design `TGALLMAP`, 29 areas, start area 1, start entry 1;
- pipeline: blocks decoded 29/29; designs ok 1/1; loader-equivalent verdict
  `pass`. The folder `designs/TGALLMAP/TGALLMAP.DSN/` holds `GAME001.DAT` and
  29 `GEO0NN.DAT` files, each at the engine's 12962-byte size; each parses
  through `geo.Geo.parse`. `runtime_loaded: false`, `engine_executed: false`.

## Corrected-converter retail rerun (2026-11-18)

After correcting the converter's entry heading codes and wall-byte order, I
regenerated the test-only plan from the pinned GOG install with
`--test-entry 14,10,west` and ran the current pipeline. It decoded 29/29
blocks, emitted one grouped design with 29 `GEO*.DAT` files, and passed
loader-equivalent checks 1/1. Each file is 12,962 bytes; parsing every output
with `geo.Geo.parse` yields the same test entry `(row=10,col=14,facing=6)`.
The area ids 1..29 and start area 1 remain `invented-test-only`; the single
test position is not an authentic entry. The report says `playable: false`,
`runtime_loaded: false`, `engine_executed: false`, and `install_unchanged: true`.
Outputs are ignored under `data/work/por-pipeline-retail-20261118/`.

## Evidence limits

- A container check only. Nothing here boots OpenUA, runs the engine, or walks
  any area. The loader verdict is the pipeline's static checks, not a run.
- The area ids and the start area are invented. A later step that claims any
  block is a given area needs its own evidence and must not reuse this table.
- The test entry is not recovered from the install. Every area sits at that
  one position.
- Existing `data/work/por-all-map-bundle-*` files were not read, used, or
  changed. They are someone else's work product and not inputs here.
