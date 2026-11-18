# PoR flag-2 door candidate: bounded OpenUA runtime comparison

**Status: candidate behavior observed; PoR parity not established.** The
default converter remains unchanged. An explicit diagnostic option can encode
flag 2 as OpenUA passability 2 for experiments. This is not promoted to the
conversion rule.

## Question and evidence

The PoR-specific DOS observation recorded in
[`por-geo-door-semantics.md`](por-geo-door-semantics.md) is one GEO2 block 20
edge at `(14,10)`, west, slot 10, flag 2. The original route offered a locked
door interaction and a successful Bash crossed to `(13,10)`. OpenUA's existing
converter emitted `0xFA` (passability 15, wall slot 10). OpenUA source refuses
Force success whenever the selected passability is 15, even if a party member
would otherwise pass the Strength check.

The experiment compared the default edge `0xFA` with an opt-in candidate
`0x2A` (passability 2, same slot) in an isolated area-20 test design. The
default and first candidate runs used a disposable build with `FRUA_DOOR_DIAG`
and `FRUA_DOOR_STR25`; the second macro sets the first active party member's
Strength to 25 in that test build. A later candidate follow-up used the same
fixture without `FRUA_DOOR_STR25`. Its six existing `.CCH` files were retained
from the fixture and their character stats were not decoded, so this is not a
claim about an ordinary or native party. The design files were compared before
and after each run.

| Run | Selected edge | Menu pick | Action allowed | Forward allowed | Stored edge at next decision |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default | 15 (`0xFA`) | 0 | 0 | 0 | 15 |
| Candidate | 2 (`0x2A`) | 0 | 1 | 1 | 2 |

Both passability-2 runs logged `menu pick=0`, `menu allowed=1`, and
`forward allowed=1`; the passability-15 control logged `menu pick=0` and
`allowed=0`. OpenUA source maps menu case 0 to the FORCE handler (`l45f0_menu`
case 0 calls `l326e`), and `jt954` rearms that option before the blocked-menu
decision. The visible label was not read from a screenshot. One candidate run
used the Strength-25 override; the follow-up did not, but used fixture
characters whose stats remain unparsed. This shows the test result is not
dependent on the compile-time Strength override. It does not establish
ordinary-party success odds or PoR action equivalence.

## Follow-up: source-to-OpenUA coordinate transform

The first candidate run exposed an axis mismatch. I repeated the same key
sequence and used the same test binary, but transposed the 16x16 GEO cell grid
and entry coordinates in a fresh copy. The wall bytes, including the tested
`0x2A`, were unchanged. The two candidate runs report:

| Fixture | Initial OpenUA cell | Facing | Selected edge | Cell at next forward decision |
| --- | --- | ---: | ---: | --- |
| Direct x/y placement | row 10, column 14 | 6 | 2 | row 9, column 14 |
| Transposed cell grid and entry | row 14, column 10 | 6 | 2 | row 13, column 10 |

The second destination matches the recorded PoR route `(13,10)`. The selected
edge remains passability 2 in the direct-placement run. The transposed run's
post-menu readback is not a read of the selected edge: its diagnostic is
hard-coded to `jt210(10,14,6)`, while the transposed party stands at
`row=14,column=10`. That cell was already open (`0x00`) in the transposed
fixture. The transposed run therefore verifies the allowed move and destination,
but does not measure whether the selected edge changed. The test-only logger
has since been corrected to read `jt210(14,10,6)`, the tested source edge (the
readback is exercised in the corrected run described below). The converter now
places source `(x,y)` at OpenUA `cell(col=y,row=x)` and writes the entry as
`row=x, col=y`. This is evidence for one route; it does not validate all areas,
events, transitions, or direction labels.

The diagnostic also logs `DOOR forward edge=0` at the destination `(row=13,
column=10)`, matching that cell's pristine fixture byte. The corrected logger
samples `(row=14,column=10,west)` on each subsequent forward decision. Until
that sample is observed in a fresh run, persistence remains unverified. In the
direct-placement run, the diagnostic re-read its decision cell and reported
passability 2 after the successful force action and move.

The final comparison is in ignored folders
`data/work/por-flag2-candidate-20261118/run-cand-direct-final/` and
`run-cand-transpose/`. The second folder was made by transposing every
six-byte cell record in `GEO020.DAT` and swapping the header entry row/column;
the original run folders were left intact. The run script used the rebuilt
68000 test binary in both cases; SHA-256 was
`1b1a8fcddd0dbfc0d57c27a6087d728e77c0799bb27e358ccce7e4303d66d705`. A final
direct-placement rerun in `run-cand-direct-final/` produced that first result
with the same binary. Its GEO hash is `42696ab54d0cf32bb749ab87207311a78f9ac132085fd68cd8088f743c2964f4`; the transposed
GEO hash is `b8c35f0f5f524ce077b78e517d0ab65809a966c2bc009444d68069e1de191644`.
The updated converter emitted a byte-identical GEO to the transposed runtime
fixture. `por_dsn_load_smoke.py` passes its host checks on that emitted design;
it does not execute the engine.

## Limits

- The coordinate result is a single-route runtime check. Other coordinate
  joins and the full map have not been checked.
- In the direct-placement run, the in-memory decision edge remained 2 after
  the successful force action and move. The transposed run did not read back
  its decision edge, because its diagnostic samples the untransposed cell.
  All 16 files in each design folder had identical hashes before and after the
  runs. These results do not establish whether the transposed edge changes in
  memory; the direct run shows no persistence for its measured cell.
- This is one controlled test route: one passability-15 control and two
  passability-2 runs. It does not bind stored GEO flag-2 bytes generally to the
  OpenUA runtime field or prove all flag-2 semantics.
- The candidate changes all flag-2 edges in the selected GEO block, not only
  `(14,10)` west. Its CLI setting is intended for bounded experiments.
- Door state persistence, wall art, visible menu text, and full-game behavior
  remain unverified. No persistence implementation is included.

## Reproduction

The fixture, build copy, inputs, logs, and before/after hashes are under
`data/work/por-flag2-candidate-20261118/` (ignored). The run used Hatari 2.3.1,
the local EmuTOS 1.4 image, and the control-channel key script in that folder.
Build command in the disposable copy:

```text
make CPU68K=68000 NOEMBED=1 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_GEO_SWEEPTEST -DFRUA_DOOR_DIAG -DFRUA_DOOR_STR25"
```

To generate an opt-in candidate from the converter, pass
`--candidate-flag2-passable 2`. Omitting it preserves pre-option output bytes
exactly. See `tests/test_por_map_flag2_candidate.py` and
`tests/test_por_flag2_diag_guard.py` for the byte and guard checks.

### Standard pipeline reproduction

The tested candidate GEO was also reproduced through `por_pipeline.py` using a
one-area plan for GEO2.DAX TOC 2 / block id 20, entry `(14,10)`, facing west,
and `--candidate-flag2-passable 2`. The pipeline decoded 29/29 source blocks,
emitted 1/1 designs, and reported loader-equivalent `pass`. Its
`GEO020.DAT` SHA-256 is
`B8C35F0F5F524CE077B78E517D0AB65809A966C2BC009444D68069E1DE191644`, exactly
matching the transposed candidate fixture used by the successful Hatari run.
This establishes repeatable production of the tested GEO bytes. The current
manifest records that one OpenUA test run logged `allowed=1` for passability 2,
marks the input action label and PoR parity unverified, links this evidence
document, and still says `runtime_loaded: false` and `engine_executed: false`;
the runtime result below comes from a separate Hatari run.

Reproduction command (from the repository root):

```text
tools/.venv/Scripts/python.exe tools/por_pipeline.py --install "G:\\Games\\Pool of Radiance\\POOLRAD" -o data/work/por-flag2-pipeline-check-20261118/final --plan data/work/por-flag2-pipeline-check-20261118/route-plan.json --candidate-flag2-passable 2
```

The generated report and design are under the ignored `data/work/por-flag2-pipeline-check-20261118/` folder. Its plan is a bounded test plan and retains `playable: false` and the unproven block-to-area join. The pipeline's `GAME001.DAT` and `GEO020.DAT` hashes both match those in the Hatari runtime folder below.

### Hatari run of the pipeline output

I copied the disposable runtime assets from `run-cand-transpose/`, then replaced
its `POR2NEW.DSN` contents with the exact pipeline-emitted design. Hatari 2.3.1
ran the same binary (`frua.prg` SHA-256
`1B1A8FCDDD0DBFC0D57C27A6087D728E77C0799BB27E358CCCE7E4303D66D705`). The
pipeline's `GAME001.DAT` and `GEO020.DAT` hashes were `360B5F14…E31717` and
`B8C35F0F…E191644`; both remained unchanged after exit. The source install was
not used as a runtime directory.

The bounded script reached the ready marker and logged the following route:

| Observation | Runtime log |
| --- | --- |
| Sweep | entry level 020; loaded area 020, skipped 28 absent test areas, failed 0 |
| Tested edge | row 14, column 10, facing 6 (west), passability 2 |
| Menu/action | pick index 0; action allowed 1; forward allowed 1 |
| Next forward decision | row 13, column 10; passability 0; forward allowed 1 |

The runtime therefore executes the exact pipeline-produced GEO and crosses the
tested edge to the expected neighboring OpenUA cell. The visible menu label was
not inspected, so “pick index 0” is not a screen-verified Bash label. The
diagnostic used during this run sampled `(row=10,column=14,west)`, not the
tested `(14,10,west)` edge; this run gives no post-action state for the tested
edge. The run is in the ignored
`data/work/por-flag2-candidate-20261118/run-pipeline-transpose/` folder.

### Corrected source-edge readback

I corrected the compile-time `FRUA_DOOR_DIAG` logger to read
`jt210(14,10,6)`, matching the tested source edge. A fresh bounded Hatari run
used that binary in
`data/work/por-flag2-candidate-20261118/run-pipeline-transpose-corrected/`.
The binary SHA-256 was
`2EF83CE48781C9BE9ACBC570465F086397933F6383D7029151A1F5B8D24518EF`. The
pipeline-produced design inputs remained the same: GAME001.DAT
`360B5F148B94E1BDCF2FD9C3F4ABBEBDE3E67296C3B737D45337AEC962E31717` and
GEO020.DAT
`B8C35F0F5F524CE077B78E517D0AB65809A966C2BC009444D68069E1DE191644`.

The fresh log records edge 2 before the menu, action allowed 1, movement
allowed 1, then a readback of the same `(14,10,west)` edge as 2 at the next
forward decision from `(13,10)`. Thus this route crossed without changing the
tested edge's in-memory passability; it did not open the edge. That is one
bounded observation, not a general door-state rule or PoR parity result. The
corrected readback also does not identify the visible menu label. The run
compared the two design files before and after and found no changes; no Hatari
process remained after exit.

### Sample-location status

The readback at `jt210(14,10,6)` is already in `src/engine/boot.c` at the
committed `FRUA_DOOR_DIAG` site (`6a21e650`); the earlier `jt210(10,14,6)`
sample is no longer in the source. This fixes the sample location only. It
does not establish persistence: the single corrected run above is one bounded
observation of one route, and a new runtime observation is needed before the
stored-edge result can be stated as a repeatable fact. The guard
`tests/test_por_flag2_diag_guard.py` now also rejects a `(10,14)` sample.

### No-STR25 follow-up

A second candidate run used the same `POR2NEW.DSN` fixture and key sequence,
but a separately built binary without `FRUA_DOOR_STR25`. The build command was:

```text
make CPU68K=68000 NOEMBED=1 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_GEO_SWEEPTEST -DFRUA_DOOR_DIAG"
```

The run binary SHA-256 is
`3DE4EAC7A68D4A05BD10D36B4620F2653A349CB78FF3F15F428924F3CB1217B9`.
The `GAME001.DAT`, `GEO020.DAT`, and `start.dat` hashes matched the corrected
run fixture; all six `.CCH` hashes also matched before and after this run.
`DBG.LOG` recorded:

```text
DOOR forward row=14
DOOR forward col=10
DOOR forward facing=6
DOOR forward edge=2
DOOR menu pick=0
DOOR menu allowed=1
DOOR forward allowed=1
DOOR stored edge 14,10 W=2
DOOR forward row=13
DOOR forward col=10
DOOR forward facing=6
DOOR forward edge=0
```

This is a second OpenUA observation that the test fixture crosses passability 2
without the compile-time Strength override. It does not show the characters'
Strength or establish success odds for a normally prepared party. The selected
menu index maps to FORCE in source; visible text was not captured. The edge
still reads 2 after crossing, and the DOS design files are unchanged.
