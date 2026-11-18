# Pool of Radiance: read-only saved-state byte probe

**Status: save-byte observation only. `playable: false`. `runtime_established: false`.**

Tool: `tools/por_save_state_probe.py`. Tests: `tests/test_por_save_state_probe.py`.
Outputs: `data/work/por-save-state-probe/retail/` (JSON and report, git-ignored).

## Question

> What do the candidate save fields that the GoldBox reference inspector reads hold in the two
> pinned retail saves, `SAVGAMA.DAT` and `SAVGAMJ.DAT`, and which sidecars do the saves name?

The probe answers only the byte question. It emits the bytes at the candidate offsets and
the sidecar filenames the save names. It does not say what those bytes mean in the game.

## Candidate fields (byte observations)

Offsets are the GoldBox reference inspector's candidate offsets (`tools/inspect_pool_save.py`
in the reference repo). Values are read from the pinned files, and each one matches the
recorded read-only GoldBox inspection.

| Field | Offset | SAVGAMA.DAT | SAVGAMJ.DAT | Status |
| --- | ---: | ---: | ---: | --- |
| `wrapper_game_area` | 0 | 2 | 2 | candidate, unproven |
| `ecl_member` | 485 (0x1E5) | 20 | 20 | candidate, unproven |
| `area2_game_area` | 3621 (0xE25) | 2 | 2 | candidate, unproven |
| `pose_x` | 12801 (0x3201) | 15 | 14 | candidate, unproven |
| `pose_y` | 12802 (0x3202) | 4 | 5 | candidate, unproven |
| `facing_raw` | 12803 (0x3203) | 6 | 4 | observed byte; name is a candidate |

- Facing names `0 north / 2 east / 4 south / 6 west` are the reference inspector's candidate
  mapping. SAVGAMA reads as `west` and SAVGAMJ as `south` under that mapping. The raw byte is
  the observation.
- Offsets are derived as `AREA1_FILE_OFFSET = 1` and `AREA2_FILE_OFFSET = 1 + 0x800`, so
  `ecl_member = 1 + 0x1E4` and `area2_game_area = 1 + 0x800 + 0x624`. This matches the reference
  values exactly.
- Nothing here is checked against PoR code in this repo, against a live run, or against a
  GEO TOC block.

## Sidecars (names only)

The probe scans each save's bytes for `CHRDAT[A-J][1-6]` and lists the names. It then lists
the install's files that match those names with a `.SAV`, `.ITM` or `.SPC` suffix. Nothing
is opened, parsed or copied, and each report says `content_examined: false`.

- `SAVGAMA.DAT` names `CHRDATA1` to `CHRDATA6`. All 16 matching files are present.
  `CHRDATA4` and `CHRDATA5` have no `.SPC` file.
- `SAVGAMJ.DAT` names `CHRDATJ1` to `CHRDATJ6`. All 18 matching files are present.

Presence says nothing about a sidecar's content.

## Outputs

- `por_save_state_probe.json`: schema `openua.por-save-state-probe`, `schema_version` 0,
  deterministic (sorted keys, no timestamps, no absolute paths, no save contents).
- `por_save_state_probe_report.md`: the readable table, sidecar names and limitations.

Only the field values listed above are written. Raw save bytes are not written. The report
contains no absolute path and no install-folder string.

## Safety rules (enforced in code)

- Both saves must match their pinned size (13,137 bytes) and SHA-256. Otherwise the probe
  refuses with a named reason and writes nothing (exit 2). There is no unpinned mode.
- `-o` is required and must resolve under the repo's `data/` folder. It may not be inside or
  contain the install. Any other location is refused.
- The install is hashed before and after the run. `install_unchanged` records whether it
  changed.
- Stdlib only. No write to the install, the repo's tracked files, or any emulator state.

## Commands and results

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_save_state_probe.py -q
#  24 passed (includes the retail-gated class, which ran against the local install)

tools/.venv/Scripts/python.exe tools/por_save_state_probe.py -o data/work/por-save-state-probe/retail
#  saves inspected: 2; sidecars listed by name only; install unchanged True   (exit 0)

tools/.venv/Scripts/python.exe tools/por_save_state_probe.py -o docs/por-save-state-probe-out
#  refused: output must be under data/ (git-ignored)                          (exit 2, nothing written)
```

Synthetic tests use a temp install, stand-in saves with their own pinned hashes, and
sentinel sidecars. They cover offset extraction, facing names including unmapped bytes, the
recorded comparison, the sidecar name rules and the no-open check, deterministic output with
no path or sentinel leakage, the limitations text, size and hash refusals, missing-file
refusals, and output-location refusals. Retail-gated tests check both pins, the six field
values per save against the recorded values, the sidecar names-only rule, and the CLI output
against path leakage.

## What this does not claim

- **No full save schema.** Six candidate bytes are read. Every other byte is unexamined.
- **No new-game start.** These bytes are not a start state.
- **No live DOS state.** Nothing was run. No DOSBox, emulator, codewheel or input was used.
- **No GEO TOC mapping.** The game-area and member values are not tied to any `GEO*.DAX`
  block or to an ECL archive member.
- **No CoK or DoK rules.** The reference inspector is read for its offsets and sidecar
  approach only. Its CoK/DoK-specific pose check and its ECL2 descriptor-3 candidate rule are
  not carried over.
- **No runtime claim.** `runtime_established: false` in the output.

## Candidate map consistency check (2026-11-17)

The two observed poses were compared with `GEO2.DAX` block id 20 (TOC index 2) using
`tools/por_map.py`'s PoR DAX/GEO decoder:

| Save | Candidate pose | GEO2#20 cell | Descriptor | Facing edge |
|---|---|---|---:|---|
| `SAVGAMA.DAT` | `(15,4)`, facing candidate west | present | `0x00` | west slot 0, door 0 |
| `SAVGAMJ.DAT` | `(14,5)`, facing candidate south | present | `0x00` | south slot 0, door 0 |

This is a geometry consistency check only. The join `game area 2 / ECL member 20 ->
GEO2.DAX block 20` is a same-suffix/same-id hypothesis; neither the save probe nor
the map decoder proves that the DOS runtime used it for these saves. Facing names also
remain a candidate mapping. Both candidate facing edges are slot 0 in the decoded GEO,
but no DOS movement was performed at either pose.

For a future runtime comparison, the existing pipeline generated a separate candidate
map-only design from the `SAVGAMJ` pose using this plan:
`data/work/por-save-candidate-plan-20261117.json`. Output is under
`data/work/por-pipeline/retail-save-candidate-review-20261117/`. Its manifest records
GEO parse/round-trip and loader-equivalent host checks passing, while keeping
`playable: false`, `runtime_loaded: false` and `engine_executed: false`. It is a
saved-state test position, not the campaign's new-game start or a full-game module.

## Relation to other notes (context only, not evidence here)

- `docs/por-save-loader-trace.md` pins the same two hashes. That static trace found no
  save-file read at `GAME.OVR:0x1F42C`, so no save offset or length is proven there.
- The GoldBox runtime ECL host-selector note records a different save hash (not one of these
  two files). It reports that a staged save requests ECL2 member 18, and that ECL2 has no
  member 18. These results do not bear on the two pinned saves, and this probe does not
  compare them.

## Limits (exact)

- Pins cover only `SAVGAMA.DAT` and `SAVGAMJ.DAT` from the retail install. Any other save is
  refused, not inspected.
- `matches recorded` compares today's bytes with the 2026-11-17 GoldBox readings. It is a
  regression check, not an oracle for the save format.
- `playable: false`, `runtime_established: false`, and no mapping is emitted.
