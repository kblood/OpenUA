# Pool of Radiance: save position vs GEO cell signature check

**Status: candidate-compatibility only. `playable: false`. `runtime_established: false`. `runtime_binding_claimed: false`.**

Tool: `tools/por_save_geo_candidate_check.py`. Tests: `tests/test_por_save_geo_candidate_check.py`.
Outputs: `data/work/por-save-geo-candidate-check/retail/` (JSON and report, git-ignored).

## Question

> For the two pinned retail saves, the candidate pose and facing select one decoded GEO cell of
> the hypothesised block `GEO2.DAX` TOC index 2 / block id 20. Does that cell's signature occur
> in any other decoded GEO block (`GEO1..8.DAX`), or is that block the only one that carries it?

This is a falsifiable compatibility question. It is not a question about which block the game
loads, and it does not map a save to a game area.

## 1. Directly observed saved bytes

Six candidate bytes per save. Each save is pinned by size (13,137 bytes) and SHA-256 in
`tools/por_save_state_probe.py`. The values match the 2026-11-17 readings recorded in
`docs/por-save-state-probe.md`.

| Save | pose_x (12801) | pose_y (12802) | facing_raw (12803) | Candidate facing name |
| --- | ---: | ---: | ---: | --- |
| `SAVGAMA.DAT` | 15 | 4 | 6 | `west` (candidate mapping) |
| `SAVGAMJ.DAT` | 14 | 5 | 4 | `south` (candidate mapping) |

The wrapper, ECL-member and Area2 bytes are read by the same probe and are not used here.
Nothing else in either save is examined.

## 2. Decoded GEO cell bytes

Cells come from `tools/por_map.py`'s Gen1 decoder: a 16 x 16 grid, row 0 north, four planes.
Each edge is `(slot, door)`. The descriptor is plane 2, raw. The candidate cell is read from
`GEO2.DAX` TOC index 2 / block id 20 at the candidate position. Under the primary ordering,
x = pose_x and y = pose_y.

| Save | Position (x,y) | N | E | S | W | Descriptor | Facing edge (candidate) |
| --- | --- | --- | --- | --- | --- | ---: | --- |
| `SAVGAMA.DAT` | (15,4) | (14,0) | (11,1) | (14,0) | (0,0) | `0x00` | W = (0,0) |
| `SAVGAMJ.DAT` | (14,5) | (10,1) | (0,0) | (0,0) | (9,0) | `0x00` | S = (0,0) |

The facing-edge column is a candidate reading. The decoded values agree with the earlier
note in `docs/por-save-state-probe.md`.

All eight archives are decoded: 29 TOC blocks, all decoded, none skipped. Search scope is
29 blocks x 256 cells = 7,424 cells.

## 3. Candidate join

Hypothesised block: `GEO2.DAX` TOC index 2, block id 20. The basis is the same-suffix/same-id
hypothesis: ECL member 20 is paired with GEO block 20. It is a hypothesis, not a binding.

Census fact: block id 20 occurs only at `GEO2.DAX` TOC index 2 across GEO1..8. The join is
therefore not contradicted by a duplicate id, but id uniqueness does not establish the join.

Two coordinate orderings are tested and both are reported:
- `pose_xy` (primary hypothesis): x = pose_x, y = pose_y.
- `pose_yx` (sensitivity only): x = pose_y, y = pose_x.

Neither is preferred. Both positions are in bounds here. If either coordinate were 16 or more,
both orderings would be not-evaluable, since each uses both values.

Two signatures are tested, strongest first:
- `full_cell`: the four edge `(slot, door)` pairs and the descriptor. It does not depend on the
  facing name.
- `facing_edge`: the one edge the candidate facing selects, and the descriptor. It depends on
  the unverified facing names.

## 4. Results

Retail run, 2026-11-17. Exit 0. `search_complete: true`.

| Save | Ordering | Signature | Matches | Same position | In hypothesised block | Distinct blocks | Verdict |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| SAVGAMA | pose_xy | full_cell | 1 | 1 | 1 | 1 | unique-to-hypothesised-block |
| SAVGAMA | pose_xy | facing_edge | 1940 | 13 | 58 | 24 | non-unique-across-blocks |
| SAVGAMA | pose_yx | full_cell | 3 | 1 | 3 | 1 | repeats-only-within-hypothesised-block |
| SAVGAMA | pose_yx | facing_edge | 42 | 1 | 37 | 5 | non-unique-across-blocks |
| SAVGAMJ | pose_xy | full_cell | 2 | 1 | 1 | 2 | non-unique-across-blocks |
| SAVGAMJ | pose_xy | facing_edge | 1869 | 6 | 53 | 24 | non-unique-across-blocks |
| SAVGAMJ | pose_yx | full_cell | 3 | 1 | 3 | 1 | repeats-only-within-hypothesised-block |
| SAVGAMJ | pose_yx | facing_edge | 36 | 1 | 36 | 1 | repeats-only-within-hypothesised-block |

What this shows, reading only the primary ordering:
- **SAVGAMA (15,4):** the full-cell signature occurs once among 7,424 decoded cells, in
  `GEO2.DAX` TOC 2. Under this signature it is unique to the hypothesised block.
- **SAVGAMJ (14,5):** the full-cell signature occurs twice. The second occurrence is
  `GEO8.DAX` TOC 1 (block id 16) at cell (4,8), which is outside the hypothesised block. The
  signature is therefore not unique for this save.
- **Facing-edge signatures** are weak. The candidate edge plus descriptor 0 occurs in 5 to 24
  distinct blocks, with 36 to 1,940 matching cells. They give no discrimination and are not
  evidence for the join.
- **Swapped ordering:** the full-cell signature repeats only inside the hypothesised block.
  It is not unique there, but it does not spread to other blocks either.

## 5. Hypothesis and claim limits

Compatibility, not a runtime binding. A matched signature shows that a decoded cell has the
same bytes. It does not show that the DOS game read that block for either save. The tool
writes `runtime_binding_claimed: false`.

Claims this check does **not** make:
- No game-area mapping. Area 2 / ECL member 20 is not tied to GEO2 block 20 by this check.
- No runtime load. Nothing was run, no DOSBox, GameLink, emulator or codewheel was started,
  and no input was sent.
- No save schema. Six bytes are read per save. Other bytes are unexamined.
- No start state. These saves are not a new-game start.
- No CoK or DoK rule is used.
- Facing names (0 north, 2 east, 4 south, 6 west) are an unverified candidate mapping. The
  raw facing byte is the observation.
- The coordinate ordering is a hypothesis. Other conventions (flipped rows, 1-based indexing,
  other block-to-cell layouts) are not tested.
- The Gen1 cell layout is applied as decoded by `tools/por_map.py`. Two cell values are
  PoR-checked in this repo (`docs/por-converter.md`). Other semantics are assumed, not verified.
- Uniqueness covers decoded blocks only. `search_complete` is true because all 29 blocks decoded
  on this run.
- The sidecars named by the saves are not examined. Nothing in this check reads them.

## Inputs and pins

- Saves: `SAVGAMA.DAT` and `SAVGAMJ.DAT`, pinned in `tools/por_save_state_probe.py`
  (13,137 bytes each, with SHA-256).
- Archives: `GEO1.DAX` to `GEO8.DAX`, pinned in `tools/por_area_evidence.py` as `GEO_PINS`.
  The hashes match the values in `docs/por-converter.md` for GEO2 and GEO8.
- A size, hash, symlink or missing-file mismatch is refused with a named reason. Nothing is
  written. A malformed DAX container is refused. A block that does not decode as Gen1 GEO is
  skipped and listed.
- All ten inputs are re-hashed after the reads. A change during the run is refused.
- Output must resolve under `data/` and must not be inside or contain the install.
- Outputs contain no absolute paths, no install-folder string, and no raw save bytes.

## Commands and results

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_save_geo_candidate_check.py -q
#  23 passed, 7 skipped   (no OPENUA_POR_INSTALL: 6 retail tests and the symlink test skipped)

OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" \
  tools/.venv/Scripts/python.exe -m pytest tests/test_por_save_geo_candidate_check.py -q -rs
#  29 passed, 1 skipped   (symlink test skipped: this host does not permit symlink creation)

tools/.venv/Scripts/python.exe tools/por_save_geo_candidate_check.py \
  --install "G:/Games/Pool of Radiance/POOLRAD" -o data/work/por-save-geo-candidate-check/retail
#  saves: 2; archives: 8; decoded blocks: 29; skipped: 0; search_complete True   (exit 0)

tools/.venv/Scripts/python.exe -m pytest tests/test_por_save_state_probe.py tests/test_por_area_evidence.py -q
#  50 passed   (neighbouring probes, unchanged)
```

Synthetic tests build fixture DAX archives and stand-in saves in a temp directory. They cover:
unique, cross-block non-unique, repeat-within-block, ordering swap, out-of-grid positions,
unmapped facing, absent hypothesised block, the block-id 20 census, a skipped undecodable block,
the scope count, malformed DAX, missing archive, archive and save hash and size mismatches,
input changed during the run, output-location refusals, the CLI refusal exit, deterministic
output with no path or sentinel leakage, and the recorded comparison.

The retail class runs only when `OPENUA_POR_INSTALL` is set. It checks the pins, the search
scope, the block-id census, the candidate cells, and the two full-cell verdicts recorded above,
plus path hygiene on the outputs.

## Open questions

- Which GEO block, if any, the DOS loader reads for either save. That needs runtime evidence
  (a trace or an instrumented run), which this check does not provide.
- Whether `pose_xy` or `pose_yx` is the right coordinate convention, or neither.
- Whether the facing names are right.

Until those are settled, the full-cell result is a compatibility observation: for SAVGAMA,
the signature matches only the hypothesised block; for SAVGAMJ, it also matches a block in
GEO8.
