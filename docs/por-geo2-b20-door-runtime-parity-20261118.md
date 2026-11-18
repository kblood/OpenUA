# Pool of Radiance GEO2 block 20 flag-2 door: runtime parity attempt (2026-11-18)

**Status: TEST-ONLY DSN GENERATED; NOT RUN IN ANY EMULATOR.**
`playable: false`. The area and entry are invented; runtime and parity remain
unverified.

This note records how far one bounded parity experiment could go on this host,
and the exact boundary where it stopped. It does not claim that OpenUA
reproduces the PoR door behaviour.

## Question

The PoR DOS runtime trace (cited from the read-only GoldBox note, see
[por-geo-door-semantics.md](por-geo-door-semantics.md#por-original-game-runtime-observation-flag-2))
records a party facing west at `(14,10)` in `GEO2.DAX` block 20. The edge is
wall slot 10 with flag 2. The native game shows `LOCKED. BASH PICK EXIT`. A
successful Bash moves the party to `(13,10)` and persists the opened edge.

Question for OpenUA: does the generated GEO edge reach the engine's
passability-15 "Blocked:" menu, and, if input is possible, does Bash move the
party to `(13,10)` and leave the edge open?

## Stage results

| Stage | Result | Evidence |
| --- | --- | --- |
| 0. Generated edge (host, static) | **Observed** | `data/work/por-geo2-b20-door-parity-20261118/static-check.txt` |
| 0b. One-area DSN fixture (host) | **Generated and checked** | `data/work/por-pipeline/geo2-b20-entry-14-10-west/designs/TG2I002/TG2I002.DSN` |
| 0c. Host loader-equivalent smoke check | **Pass** | `data/work/por-geo-single-block-plan/geo2-b20-entry-14-10-west/load_smoke_review.json` |
| 1. Engine source path to the menu | **Read, not executed** | `src/engine/boot.c` (see below) |
| 2. Current build with a resource fork | **Blocked** | see "Build blockers" |
| 3. Emulator with key input | **Blocked** | see "Emulator blockers" |
| 4. Menu shown / Bash moves party | **Not reached** | depends on 2 and 3 |

### Stage 0: the generated edge (observed)

The initial map-only pipeline output is
`data/work/por-pipeline/retail/maps/geo2-i02-b020/por_map.json`; it says
`openua.emitted: false`. The later single-block test plan produced the DSN
fixture listed in stage 0b.

- Cell `(14,10)` planes `[0x00, 0x7A, 0x00, 0x80]`. West edge: slot 10,
  door 2. This matches the GoldBox note's raw bytes.
- `tools/por_map.py` `map_edge(10, 2)` returns `(0xFA, "locked")`, that is
  passability 15 with slot 10. The pipeline report counts this as
  "blocked edge (15)".
- The test-only plan adapter emits one module folder for this block and
  position. The placeholder area number is 5, copied from the smoke-plan
  convention; it is not an authentic PoR area. Its output passes the pipeline's
  round-trip and loader-equivalent checks, and the standalone host smoke validator
  reports `pass`. Neither check runs the engine.
- Cell `(13,10)`: descriptor `0x83` (plane 2 = 131), matching the trace.

**Shared-edge disagreement.** The east edge of `(13,10)` is slot 5, door 1,
which `map_edge` maps to `0x15` ("auto-door", passable). The west edge of
`(14,10)` is `0xFA`. So the one physical wall has two different OpenUA bytes,
one on each side. The report's shared-edge stats show 74 disagreements in this
block. This is a converter property, not something the runtime was seen to do.
If the engine checks only the edge of the cell being left, then walking east
from `(13,10)` is not blocked by this door. Not verified at runtime.

### Stage 1: source path to the Blocked menu (read only)

- `play_can_pass` (`src/engine/boot.c:18075`) returns 0 for nibble 15 with no
  menu. Its comment says it is the menu-less rule used for overland moves and
  strafe/backstep.
- The forward step uses `play_forward_allowed` (`boot.c:53028`). That calls
  `jt955_dungeon_decide()`, and sets `g_event_modal_shown` for `t == 15`
  ("a Blocked: menu ran"). So the forward path does reach a menu for nibble 15.
- The menu, `l45f0_menu` (`boot.c:~52924`), builds its option list from state:
  FORCE only if `-22726` is armed; PICK only if `-22725` is armed and a thief
  (class 6) is aboard; USE-KEY only if a type-31 key is carried; LEAVE always.
  The prompt is the string at `0x6cfc` ("Blocked:") for wall arts 2/3/15.
- The engine source contains no "Bash" verb. The PoR prompt `BASH PICK EXIT`
  has no counterpart in the menu as coded. Which options appear by default
  depends on flag values that were not read at runtime. So the menu contents
  are **not** shown to match PoR.
- After a menu action, the result lands in `-22308` (`play_forward_allowed`
  reads it back as the move decision). Not verified at runtime.

**Persistence.** `docs/por-geo-door-semantics.md` records that OpenUA has no
door state: flags 2 and 3 both become a bash/knock blocked edge. Nothing in the
map or the converter opens `(14,10)` west after a successful interaction. So
even a working menu would not reproduce the persisted opening. This is a
known design gap, not a new finding.

### Stage 2: build blockers (observed)

- `build/` does not exist. `frua.prg` is at the repo root, last written
  2026-11-17 19:49. `src/engine/boot.c` was modified at 2026-11-17 20:40 and
  has uncommitted changes. **The binary is older than the source and cannot
  stand for the current tree.**
- `data/work/UnlimitedAdventures.rfork` does not exist. The Makefile needs it
  (`Makefile:297`, `RFORK ?= data/work/UnlimitedAdventures.rfork`). Producing it
  requires unpacking the Mac release (see `docs/mac-release.md`), which was not
  done.
- Neither Windows nor WSL Ubuntu has `m68k-atari-mint-gcc` or
  `m68k-atari-mint-objdump` on PATH, so a fresh `make` cannot run here.

### Stage 3: emulator blockers (observed)

- Hatari is not installed on this Windows host. `where hatari`, PATH, and
  `C:\Program Files\Hatari` were all empty.
- WSL Ubuntu also has no `hatari` command. The extracted Linux `.deb` binary
  under `data/work/por-hatari-input-probe-deb/` was not run.
- The key-input route in `docs/por-hatari-input-probe.md` (`--cmd-fifo`) has
  never been run. It needs a Linux host with a FIFO, and the doc says "not
  verified at runtime".
- The generated fixture is a map-only host artifact. It has not been loaded by
  OpenUA in an emulator.

## Test-only area and entry

The fixture assigns placeholder area 5 (`dsn.demo_design` convention), not a
PoR area number, and labels it `invented-test-only`. The start point `(14,10)`
facing west (direction 6) is taken from the cited trace and labelled test-only;
the plan cannot prove that it is the game's authentic start. Reproduction steps
are in [por-geo-single-block-plan.md](por-geo-single-block-plan.md).

## Verification run

```sh
# static edge check: reads por_map.json and calls por_map.map_edge; output was
# written to data/work/por-geo2-b20-door-parity-20261118/static-check.txt
# (inline `python -I` script, not kept as a tool; see the file for its output)
# existing tests that exercise map_edge
python -m pytest tests/test_por_geo_door_census.py tests/test_por_map.py -q
#  -> 58 passed

# test-only one-block fixture plan + pipeline run: see por-geo-single-block-plan.md
# focused test suites: tests/test_por_geo_single_block_plan.py, por_geo_smoke_plan.py,
# and por_pipeline.py -> 176 passed

# host load smoke (not an engine run):
tools/.venv/Scripts/python.exe tools/por_dsn_load_smoke.py \
    data/work/por-pipeline/geo2-b20-entry-14-10-west/designs/TG2I002/TG2I002.DSN \
    --report data/work/por-geo-single-block-plan/geo2-b20-entry-14-10-west/load_smoke_review.json
#  -> verdict pass; engine_executed=false; runtime_loaded=false
```

Running `pytest -k` over all of `tests/` failed at collection on three test
files with a `charmap` UnicodeDecodeError (`tests/test_walk_key_gate.py` among
them). That is unrelated to this note and was not fixed here.

## What would settle it

1. Build the current tree with the rfork present and check `frua.prg` is newer
   than `src/engine/boot.c`.
2. On a Linux host with Hatari 2.x and the 68k toolchain, run `frua.prg` with `--cmd-fifo`. Generate
   the key lines with `tools/por_hatari_input_probe.py generate` and write them
   with a bounded writer.
3. Put the party at `(14,10)` facing west in a test fixture. Then record the
   menu text and option list (screenshot or `dbg.log` marker), and whether Bash
   moves the party to `(13,10)`.

Until steps 1-3 are done, the honest finding is: **the generated fixture passes
host-side container checks; source routes passability 15 to OpenUA's Blocked
menu, but OpenUA has no PoR Bash verb or persisted opening in this path, and
there is no runtime observation.**

## Not claimed

- That OpenUA shows `LOCKED. BASH PICK EXIT` or any PoR menu wording.
- That Bash moves the party, or that the edge stays open afterwards.
- That the shared-edge disagreement changes play. It is a static observation.
- Anything about flag 3 or any other GEO block.
- That the PoR trace was re-run. It is cited from the GoldBox note and was not
  reproduced here.
