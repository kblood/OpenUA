# Pool of Radiance GEO2 block 20 flag-2 door: runtime parity attempt (2026-11-18)

**Status: PARTIAL RUNTIME CHECK. Two different harnesses; keep them apart.**

- **Stage 0b one-block fixture** (placeholder area 5, `TG2I002.DSN`): host
  container checks only. This fixture was **not** loaded in any emulator.
- **Area-20 all-map harness** (`POR2NEW.DSN`, area 20, `data/work/por-flag2-openua-runtime-20261118-o/`):
  run in Hatari 2.3.1. It loaded GEO020 and read the converted west edge as
  passability 15 at `(14,10)` facing west. Up/Return selected menu item 0, but
  the item was not allowed, and no successful Bash crossing or persistent
  opening was demonstrated.

Both are test-only. `playable: false`. The areas and entries are invented
test fixtures. Runtime parity with the PoR DOS door behaviour is **not**
established.

This note records how far one bounded parity experiment could go on this host,
and where it stopped. It does not claim that OpenUA reproduces the PoR door
behaviour.

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
| 0b. One-area DSN fixture (host, area 5) | **Generated and checked; not run in an emulator** | `data/work/por-pipeline/geo2-b20-entry-14-10-west/designs/TG2I002/TG2I002.DSN` |
| 0c. Host loader-equivalent smoke check (area 5 fixture) | **Pass** | `data/work/por-geo-single-block-plan/geo2-b20-entry-14-10-west/load_smoke_review.json` |
| 1. Engine source path to the menu | **Read; partly exercised by the area-20 harness** | `src/engine/boot.c` (see below) |
| 2. Build for the runtime check | **Clone build ran; repo build still blocked** | see "Build status" |
| 3. Emulator with key input | **Ran for the area-20 harness** | Hatari 2.3.1, `--cmd-fifo`; see "Area-20 all-map runtime harness" |
| 4. Menu shown / Bash moves party | **Partly reached.** Item 0 selected, not allowed; no Bash success, no visible `Blocked:` text read, no persistence | `DBG.LOG` lines 86-107 |

### Stage 0: the generated edge (observed)

The initial map-only pipeline output is
`data/work/por-pipeline/retail/maps/geo2-i02-b020/por_map.json`; it says
`openua.emitted: false`. The later single-block test plan produced the DSN
fixture listed in stage 0b.

- Cell `(14,10)` planes `[0x00, 0x7A, 0x00, 0x80]`. West edge: slot 10,
  door 2. This matches the GoldBox note's raw bytes.
- `tools/por_map.py` `map_edge(10, 2)` returns `(0xFA, "locked")`, that is
  passability 15 with slot 10. The pipeline report counts this as
  "blocked edge (15)". The current static check output agrees
  (`map_edge(10,2) = (250, 'locked')`).
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
The area-20 harness read the west byte of `(14,10)` when moving forward, but it
did not test the east side of `(13,10)`. Whether walking east from `(13,10)` is
blocked by this door is not verified at runtime.

### Stage 1: source path to the Blocked menu (read only)

- `play_can_pass` (`src/engine/boot.c:18075`) returns 0 for nibble 15 with no
  menu. Its comment says it is the menu-less rule used for overland moves and
  strafe/backstep.
- The forward step uses `play_forward_allowed` (`boot.c:53028`). That calls
  `jt955_dungeon_decide()`, and sets `g_event_modal_shown` for `t == 15`
  ("a Blocked: menu ran"). So the forward path does reach a menu for nibble 15.
  The area-20 harness logged this path (`DOOR forward edge=15`).
- The menu, `l45f0_menu` (`boot.c:~52924`), builds its option list from state:
  FORCE only if `-22726` is armed; PICK only if `-22725` is armed and a thief
  (class 6) is aboard; USE-KEY only if a type-31 key is carried; LEAVE always.
  The prompt is the string at `0x6cfc` ("Blocked:") for wall arts 2/3/15.
  These line numbers come from the earlier read and were not re-checked in this
  edit.
- The word "bash" does not appear as a literal in `src/engine/boot.c`
  (checked by search in this edit). Menu wording is therefore carried by
  resource strings, which were not read here. The semantics note reads item 0
  as the force/Bash check. The runtime harness confirms that item 0 is what
  Return selected; it does not show the item's label.
- The PoR prompt `BASH PICK EXIT` is not shown to match OpenUA's menu. Which
  options appear by default depends on flag values not read at runtime.
- After a menu action, the result lands in `-22308` (`play_forward_allowed`
  reads it back as the move decision). In the harness the result was 0
  (`DOOR forward allowed=0`).

**Persistence.** `docs/por-geo-door-semantics.md` records that OpenUA does not
yet persist a successfully opened edge: the current Bash path only reports
success to the movement gate. Nothing in the map or the converter opens
`(14,10)` west after a successful interaction. So even a working menu would
not reproduce the persisted opening. This is a known design gap, not a new
finding.

## Area-20 all-map runtime harness (2026-11-18)

This is the later runtime check. It is **separate from** the stage 0b one-block
fixture above.

- Fixture: `POR2NEW.DSN`, area 20, the converted `GEO020` for block 20. The
  design starts at `(col=14,row=10)` facing west (code 6). The target cell
  stores N/E/S/W bytes `00 00 E7 FA`; the west byte is `0xFA`. No campaign
  content.
- Build: a clone of `frua.prg` with `FRUA_AREATEST`, `FRUA_SKIP_ENTRY_EVENTS`,
  `FRUA_GEO_SWEEPTEST`, and `FRUA_DOOR_DIAG`. The binary is
  `data/work/por-flag2-openua-runtime-20261118-o/frua.prg`. The sweep is
  test-only and invents area ids 1..29.
- Emulator: Hatari 2.3.1, STE, 14 MB, EmuTOS 512k, input from `--cmd-fifo`
  (`run-door-test-o.sh`). The Hatari binary is the WSL copy under
  `data/work/atari-runtime-bootstrap/hatari-root/`.
- Sweep result (`DBG.LOG` lines 14-77): GEO020 loaded (`width 16 height 16
  cells 256 specials 0`). The loop reported **loaded 1, skipped 28, failed 0**.
  The run then continued into `jt948`.
- Up event (`DBG.LOG` lines 86-96): `DOOR forward row=10`, `col=14`,
  `facing=6`, `edge=15`. The engine read the converted west edge as
  passability 15. This is the corrected facing and edge ordering (N/E/S/W),
  not the earlier fixture that encoded `west` as facing 3.
- Return event (`DOOR menu pick=0`, `DOOR menu edge=15`, `DOOR menu
  allowed=0`, `DOOR forward allowed=0`). A second Up/Return pass (lines
  97-107) repeated the same four lines. Item 0 was selected both times and was
  not allowed.
- Not shown: the screen capture (`shots-q/`) shows the first-person view but no
  readable `Blocked:` menu text. Whether Pick is selectable in this harness was
  not established.
- Not shown: a successful Bash crossing, the party moving to `(13,10)`, or a
  persisted opening. The bounded test party did not succeed.

The PoR DOS run still provides the separate observation of a failed Pick
followed by a successful Bash ([por-geo-door-semantics.md](por-geo-door-semantics.md#por-original-game-runtime-observation-flag-2)).
The area-20 harness does not reproduce that sequence.

## Static door-entry census (negative bounded result)

[`por-door-entry-route-census.md`](por-door-entry-route-census.md) decoded
transfers into the door writer `GAME.OVR:0x167D4`, clearer `0x166CB`, and stub
1 (START `0x0089C`, proc `0x17438`). In the walked bytes it found **no decoded
`E9`/`EB` jump, `EA` far jump, or `9A` far call** into the writer, clearer, or
stub 1. The six `E8` callers are the ones the earlier caller probe already
reported. Its own status is `trigger_established: false`.

This is a negative, bounded static result. It does not identify the event that
sets or clears the door field, and it does not resolve the event semantics of
flag 2 or flag 3. The census also reports no decoded `E8` call to stub 1's proc;
the six `E8` calls are to the writer and clearer only. It is not runtime
evidence.

## Test-only area and entry (one-block fixture, stage 0b)

The fixture assigns placeholder area 5 (`dsn.demo_design` convention), not a
PoR area number, and labels it `invented-test-only`. The start point `(14,10)`
facing west (direction 6) is taken from the cited trace and labelled test-only;
the plan cannot prove that it is the game's authentic start. Reproduction steps
are in [por-geo-single-block-plan.md](por-geo-single-block-plan.md).

The area-20 harness above uses a different area and design (`POR2NEW.DSN`).

## Build status

- The repo build is still not reproducible here. `build/` does not exist, and
  `data/work/UnlimitedAdventures.rfork` does not exist. The Makefile needs it
  (`Makefile:297`, `RFORK ?= data/work/UnlimitedAdventures.rfork`). Producing it
  requires unpacking the Mac release (see `docs/mac-release.md`), which was not
  done. A fresh `make` therefore still cannot run from the Makefile.
- The root `frua.prg` was last written 2026-11-18 05:38, which is **newer** than
  `src/engine/boot.c` (2026-11-17 20:40). The older blocker "the binary is older
  than the source" no longer holds on mtimes. Whether that root binary was built
  from the current tree was not verified.
- The area-20 runtime used the clone binary in its run directory (stage 2
  above), not the repo root binary.
- The `m68k-atari-mint` toolchain availability was not re-checked in this edit.
  The earlier note reported it absent on PATH; treat that as unverified now.

## Emulator status

- The earlier note said Hatari was absent. That was true for the Windows host
  PATH (`where hatari` finds nothing in this edit). It does not hold for the
  2026-11-18 run, which used the Hatari 2.3.1 binary under
  `data/work/atari-runtime-bootstrap/hatari-root/` through WSL.
- The `--cmd-fifo` key-input route in
  [`por-hatari-input-probe.md`](por-hatari-input-probe.md) was used by the
  area-20 harness. The probe doc itself still says "Hatari was not launched" for
  its own validator. Its generator and validator remain separate from this run.

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

# area-20 all-map Hatari run (runtime, test-only clone build):
#   data/work/por-flag2-openua-runtime-20261118-o/run-door-test-o.sh
#   evidence: data/work/por-flag2-openua-runtime-20261118-o/DBG.LOG lines 14-107
```

Running `pytest -k` over all of `tests/` failed at collection on three test
files with a `charmap` UnicodeDecodeError (`tests/test_walk_key_gate.py` among
them). That is unrelated to this note and was not fixed here.

## What would settle it

1. Build the current tree with the rfork present and check `frua.prg` is newer
   than `src/engine/boot.c`. The root binary is already newer on mtime; a
   rebuild from the Makefile is still needed to tie it to the source.
2. Read the menu wording and option list for item 0 (the `0x6cfc` resource
   strings). Capture the first-person view with the Blocked prompt visible,
   since `shots-q/` shows no readable text.
3. Show a successful Bash in the area-20 harness: the party moves to `(13,10)`,
   and the `(14,10)` west edge is open afterwards. Today OpenUA does not
   persist that edge, so this step also needs a persistence change, which is
   outside this note.
4. Separately, the event that sets or clears the door field is still open. The
   static census above does not settle it.

Until those are done, the honest finding is: **the generated edge reaches
OpenUA's passability-15 forward gate in the area-20 all-map harness, and the
Blocked menu's item 0 is selected and refused. No successful Bash, visible menu
text, or persisted opening is demonstrated, and no PoR parity is claimed.**

## Not claimed

- That OpenUA shows `LOCKED. BASH PICK EXIT` or any PoR menu wording.
- That Bash moves the party, that Pick succeeds, or that the edge stays open
  afterwards.
- That the shared-edge disagreement changes play. It is a static observation.
- That the static door-entry census identifies the trigger for the door
  field, or the event semantics of flag 2 or flag 3.
- Anything about flag 3 or any other GEO block.
- That the PoR trace was re-run. It is cited from the GoldBox note and was not
  reproduced here.
