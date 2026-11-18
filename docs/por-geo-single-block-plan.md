# Pool of Radiance: one GEO block from a test-only smoke plan

**Status: TEST-ONLY. `playable: false`. The area number and the entry point are
invented for this fixture. This is not a conversion of any area.**

Tool: `tools/por_geo_single_block_plan.py`. Tests: `tests/test_por_geo_single_block_plan.py`.
Inputs: the `por_geo_smoke_plan.json` and `por_pipeline_plan.json` written by
`tools/por_geo_smoke_plan.py` (see `docs/por-geo-smoke-plan.md`).

## What it is for

`por_geo_smoke_plan.py` plans one design per decoded GEO block, all at one test
position. This adapter selects exactly one block from that plan and writes a
single-design `por_pipeline_plan.json`, so one `NAME.DSN` can be generated and
host-checked on its own.

The fixture here is GEO2.DAX TOC index 2, block id 20, at test entry
`x=14, y=10, facing=west`, named `TG2I002`. The area is 5, the placeholder the
smoke plan carries. **GEO2 is not game area 1, and nothing here implies it is.**

## What the run checks

- Both files are read with the smoke tool's loader, which refuses duplicate
  object keys. The smoke plan must be `openua.por-geo-smoke-plan` v0,
  `label: test-only`, `playable: false`.
- Every key set is exact. An unknown or missing field is refused, in the smoke
  plan, its design rows and the pipeline plan.
- The pipeline plan's SHA-256 must equal `plan.sha256` in the smoke plan.
- The pipeline plan must list exactly the smoke plan's designs, with the same
  geo, index, area, entry, facing and title.
- `--entry` must equal the smoke plan's test entry, and must be in `0..15`.
- The request selects exactly one design by `(geo, index, block_id)`. A
  missing block, a block id that disagrees with its TOC index, or an ambiguous
  match is refused.
- Output must be outside both input folders and under `data/` (git-ignored).

Nothing is written on a refusal.

## What it does not establish

- That GEO2 block 20 is game area 1, or any authentic area.
- That `14,10,west` is the authentic start location or facing.
- Transitions, wall art, events, text, monsters, items or shops.
- That the game loads or walks the block. `runtime_loaded` and `engine_executed`
  are both `false`; nothing boots OpenUA, Hatari or DOSBox.

## Commands

Run from the repository root. Paths are relative; the install is read-only.

```sh
PY=/c/Python313/python    # any Python 3.10+ with the repo's stdlib tools

# 1. enumerate, with the test entry 14,10,west (read-only on the install)
$PY tools/por_geo_manifest.py --install "G:/Games/Pool of Radiance" \
    -o data/work/por-geo-manifest/geo2-b20-entry-14-10-west --test-entry 14,10,west

# 2. plan the map-smoke designs (all 29 blocks, test entry only)
$PY tools/por_geo_smoke_plan.py \
    --manifest data/work/por-geo-manifest/geo2-b20-entry-14-10-west/por_geo_manifest.json \
    -o data/work/por-geo-smoke-plan/geo2-b20-entry-14-10-west

# 3. select GEO2 TOC index 2 / block 20 at 14,10,west: one-design plan
$PY tools/por_geo_single_block_plan.py \
    --smoke-plan data/work/por-geo-smoke-plan/geo2-b20-entry-14-10-west/por_geo_smoke_plan.json \
    --pipeline-plan data/work/por-geo-smoke-plan/geo2-b20-entry-14-10-west/por_pipeline_plan.json \
    --geo 2 --index 2 --block-id 20 --entry 14,10,west \
    -o data/work/por-geo-single-block-plan/geo2-b20-entry-14-10-west

# 4. generate the fixture with the pipeline (decodes all blocks; emits one design)
$PY tools/por_pipeline.py --install "G:/Games/Pool of Radiance" \
    -o data/work/por-pipeline/geo2-b20-entry-14-10-west \
    --plan data/work/por-geo-single-block-plan/geo2-b20-entry-14-10-west/por_pipeline_plan.json

# 5. host load-smoke check on the emitted design (engine not run)
$PY tools/por_dsn_load_smoke.py \
    data/work/por-pipeline/geo2-b20-entry-14-10-west/designs/TG2I002/TG2I002.DSN \
    --report data/work/por-geo-single-block-plan/geo2-b20-entry-14-10-west/load_smoke.json
```

Tests (host-side, synthetic inputs, no install):

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_single_block_plan.py -q
```

## Outputs

`-o` receives two files, sorted keys, no timestamps, no absolute paths. The same
inputs give byte-identical output.

- `por_pipeline_plan.json`: schema `openua.por-pipeline-plan` v0, one flat design
  `TG2I002` with `area` 5, `entry` `[14, 10]`, `facing` `west`, and a title that
  says "invented area and entry".
- `por_geo_single_block_plan.json`: schema `openua.por-geo-single-block-plan` v0,
  `label: test-only`, `playable: false`. It records the selector and block key,
  the decoded SHA-256 of the block, the area and entry with their invented
  status, the SHA-256 of each input file (no paths) and of the output plan, and
  the claims the fixture does not make.

## Exit codes

| Exit | Meaning |
| --- | --- |
| 0 | plan and manifest written |
| 2 | refusal, nothing written: unreadable or malformed input, hash or provenance mismatch, unknown or missing field, entry out of range or not the smoke entry, no or ambiguous block, output inside an input folder, output outside `data/`, output path that is a file |
