# Pool of Radiance: candidate save/GEO join plan adapter

**Status: hypothesis-only adapter. `playable: false`. `runtime_binding_claimed: false`.**
This tool can turn one uniquely matching saved-position/GEO-cell signature into a
one-area pipeline plan for a bounded OpenUA test. It does not establish which block
the DOS game loaded, map a save to a game area, or create a playable campaign.

Tool: [`tools/por_save_geo_join_plan.py`](../tools/por_save_geo_join_plan.py).
Tests: [`tests/test_por_save_geo_join_plan.py`](../tests/test_por_save_geo_join_plan.py).
The adapter uses the pinned observations and full-cell search from
[`por-save-state-probe.md`](por-save-state-probe.md) and
[`por-save-geo-candidate-check.md`](por-save-geo-candidate-check.md).

## Use

For the unique SAVGAMA compatibility result:

```sh
python tools/por_save_geo_join_plan.py \
  --install "G:/Games/Pool of Radiance/POOLRAD" \
  --save SAVGAMA.DAT --ordering pose_xy --area 2 \
  --facing-candidate-mapping --block GEO2.DAX:2:20 \
  -o data/work/por-save-geo-join-plan/savgama

python tools/por_pipeline.py \
  --install "G:/Games/Pool of Radiance/POOLRAD" \
  -o data/work/por-save-geo-join-plan/pipeline-run \
  --plan data/work/por-save-geo-join-plan/savgama/pipeline_plan.json
```

The area number is caller-chosen. The facing option applies the reference inspector's
candidate facing table and records it as unverified; alternatively, supply a facing name
explicitly. Both choices affect orientation in the plan and are not needed for the
full-cell signature comparison. The selected coordinate ordering is also a hypothesis.

Output is required under `data/` and must not contain the install. The report is always
written for an evaluable or ambiguous result. `pipeline_plan.json` is written only when
there is exactly one compatible block and exactly one matching cell at the candidate
position. `--block` is an additional assertion: if it differs from that unique result,
the tool refuses to emit a plan. Output records contain no absolute paths or raw save
bytes.

Exit codes: `0` means a plan was emitted and accepted by `por_pipeline.load_plan`; `3`
means the report was written but a plan was refused (including ambiguity); `2` means a
named input or output-location refusal before reports are written.

## Evidence and result

The adapter reuses the existing pinned save/GEO probes and searches full-cell signatures
across all decoded cells in GEO1..8. It labels observed save bytes separately from
computed compatibility and from hypotheses. It requires the caller to choose the save,
coordinate ordering, area number and facing source.

Retail result (2026-11-18):

| Save | Candidate position (`pose_xy`) | Compatible blocks | Adapter result |
| --- | --- | --- | --- |
| SAVGAMA.DAT | (15,4) | GEO2.DAX TOC 2, id 20; one matching cell at that position | emits a plan when requested block is GEO2.DAX:2:20 |
| SAVGAMJ.DAT | (14,5) | GEO2.DAX TOC 2, id 20 and GEO8.DAX TOC 1, id 16 | refuses to choose |

The SAVGAMA plan uses area 2 because the caller supplied it, entry `[15,4]`, and
`GEO2.DAX` TOC index 2. The save contains candidate area value 2 and ECL member 20;
the shared id and matching cell are compatibility clues. They do **not** prove the
area/block join or runtime file selection. SAVGAMJ's ambiguity is reported rather than
resolved by this adapter.

The plan's `provenance` fields are reader-facing metadata. The pipeline validates the
plan's design schema and emitted GEO container, but does not promote or independently
verify that provenance. Its manifest still says `playable: false`, and the adapter also
sets `runtime_binding_claimed: false`, `runtime_loaded: false` and
`engine_executed: false`.

## Limits

- The pinned saves expose only a few candidate bytes; no full save schema or sidecar
  parsing is implemented here.
- The candidate same-id join (ECL member 20 to GEO block id 20) is unproven.
- A matching full-cell signature is a compatibility result, not runtime binding.
- The save coordinate ordering and facing-name mapping are unverified.
- The plan area is selected by the caller, not derived or verified by the adapter.
- The saved position is not a new-game start; party data, events, transitions, text,
  monsters and art are not reconstructed.
- No emulator or original DOS runtime was run by this tool. A passing host pipeline run
  checks conversion/container rules only.

## Verification

The implementation handoff reports 22 synthetic tests and 2 retail-gated tests passing.
The retail pipeline check accepted the SAVGAMA plan and emitted one loader-equivalent
design, with `playable: false`, `runtime_loaded: false` and `engine_executed: false`.
See the test and generated report for the exact checks; this document makes no claim of
runtime loading or gameplay validation.
