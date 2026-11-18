# FRUA_GEO_SWEEPTEST — all-GEO load sweep (TEST-ONLY)

**Status: opt-in test harness. Nothing here is a conversion, and nothing here
shows gameplay.** It is compiled only with `-DFRUA_GEO_SWEEPTEST` and needs
`-DFRUA_AREATEST`. Without the macro the source compiles to the original
`frua_areatest_entry` (verified by `tests/test_geo_sweeptest_guard.py`).

Code: `src/engine/boot.c`, the `frua_areatest_entry` section only
(`frua_geo_sweep_present`, `frua_geo_sweep_check`, and the
`#ifdef FRUA_GEO_SWEEPTEST` block just before `jt948()`).

## What it does

One bounded run, inside the AREATEST entry, after the normal entry setup and
before the walk:

1. Captures the configured entry level (`g_a5_18878`, from GAME001.DAT byte 48)
   and the party cell (`g_a5_12288/12287/12286`).
2. If the configured level's `GEO<n>.DAT` is absent, logs an abort and returns
   **without** entering `jt948` and without touching the live map.
3. For each area 1..29 in order:
   - logs `begin`;
   - if `GEO<nnn>.DAT` is absent, logs `skip` and continues;
   - otherwise calls the real `jt198(n)`, then re-reads the parsed header
     (`width` = ds[2], `height` = ds[3]) and counts non-zero cell specials;
   - logs `end`.
4. Calls `jt198(configured)` again (the same load a normal fresh entry makes),
   restores the saved party cell, and logs `restore`.
5. Falls through to the unchanged `jt948()` call.

Nothing in the sweep renders, places the party, or fires an event.

## Area ids are invented

Areas 1..29 are **test-only ids** for the TGALLMAP fixture
(`docs/por-geo-all-map-group.md`). They are the GEO file numbers the fixture
was written with, not an authentic PoR area mapping, start, or transition.
The log says so on its first line.

## Loader behaviour the harness depends on

- **`jt198` never returns on a bad byte count or a parse reject.** It logs
  `jt198: GEO bytes = <n>` or `jt198: l720a reject`, then calls `jt69`
  (which logs `jt69: FATAL content-load error`, then `ExitToShell`). The sweep cannot
  recover from that. The evidence is the last `begin` marker plus jt198's own
  line. A wrong-size GEO in the fixture ends the run there.
- **An absent file must not reach `jt198`.** `jt127` tries the direct
  `<design>:GEO<nnn>.dat` open, then a `.glb` lookup, then a cold disk load
  (`jt987`) that retries rather than failing. The sweep's probe opens the same
  direct path (same `jt431` concatenation, `jt398` with flags 0) and closes it.
  It only reads the directory entry; `jt398` has side effects only for
  `.tlb`/`.ctl`.
- **Reloads do not stack.** `l7226` zero-fills the existing map buffer
  (`jt399`, 3746 bytes) and parses into it. No allocation per load.
- **jt198 also resets** `g_a5_-12296` (to -1) and, when the zone flag is clear,
  `g_a5_-12290`. The restore's `jt198` gives the same state a fresh entry has.

## Build recipe

Probe-free build (the `ENGINE_PROBE` block is not wanted in the boot path; see
`docs/por-areatest-group19-modal.md`):

```sh
make CPU68K=68000 NOEMBED=1 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_GEO_SWEEPTEST"
```

This is the group-19 run-e build (`docs/por-areatest-group19-modal.md`) with
`-DFRUA_CELLSCAN` dropped and `-DFRUA_GEO_SWEEPTEST` added. Leave CELLSCAN out:
its per-cell trace is large, and the sweep's own markers are enough for this.

Stage the fixture the same way as run-b in `docs/por-areatest-group19-modal.md`:
the design folder is `TGALLMAP.DSN/` containing `GAME001.DAT` and
`GEO001.DAT`..`GEO029.DAT` (12,962 bytes each), and `start.dat` names
`TGALLMAP.DSN` with flag `01`. The fixture is produced by the pipeline in
`docs/por-geo-all-map-group.md` (ignored `data/work/`).

## Run and read

Bound the run to **45 s** (the proven bound in the group-19 runs; the shorter
900-VBL run ended before the harness). Then read `DBG.LOG`:

```
GEO-SWEEP begin: test-only, invented area ids 1..29
GEO-SWEEP configured entry level 001
GEO-SWEEP area 001 begin
GEO-SWEEP area 001: width W height H cells C specials S
GEO-SWEEP area 001 end
... 002..029 ...
GEO-SWEEP loop done: loaded L skipped K failed F
GEO-SWEEP restore: entry level 001 reloaded, party cell X,Y facing D
GEO-SWEEP end: continuing into jt948
```

- A complete `end: continuing into jt948` line means the sweep finished inside
  the bound.
- If the log stops at an `area NNN begin` line with no `end`, the run died
  inside `jt198(NNN)`; look for `jt198: GEO bytes` / `jt198: l720a reject` /
  `jt69: FATAL` above it.
- `failed > 0` means a map header failed the dimension check
  (`FAIL: bad dims`). `skipped > 0` means that GEO file was absent from the
  staged folder.

## Runtime result (Hatari, 2026-11-17)

The test-only build ran in the isolated stage
`data/work/por-openua-areatest-geosweep-run/` with Hatari 2.3.1, EmuTOS 1.4,
STE, 14 MB, and dummy SDL video/audio. The run was bounded at 45 seconds.
Build flags were:

```sh
make CPU68K=68000 NOEMBED=1 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_GEO_SWEEPTEST"
```

The executed `frua.prg` SHA-256 was
`367717BEED5E9AEE562EFAFD62221E9F7A99E5BA524F0E268BB6038CB92D4AE9`.
`DBG-geosweep.LOG` records every `GEO001.DAT` through `GEO029.DAT` load,
each reporting 16×16 dimensions and 256 cells, followed by:

```text
GEO-SWEEP loop done: loaded 29 skipped 0 failed 0
GEO-SWEEP restore: entry level 001 reloaded, party cell 0,0 facing 4
GEO-SWEEP end: continuing into jt948
```

The staged `GAME001.DAT` remained at start area 1, entry 1; its SHA-256 was
`BBD3E236FF9A3DA3497167D48A56D265A781ED6EFD7959B91C1641B7C350C01C` before
and after the run. Hatari was stopped by the 45-second bound after the sweep
and the handoff to the walk. The evidence proves that the 29 generated test
GEO files were read and accepted by OpenUA's `jt198`/`l720a` path. It does not
prove their authored semantics or that any map is playable.

## Corrected-converter rerun (Hatari, 2026-11-18)

I repeated the sweep against the current corrected converter output in an
isolated source/build tree at
`data/work/por-geosweep-isolated-20261118/`. The 29 test areas use the current
`(14,10,west)` placeholder position; their sequential area ids and start area
remain invented. The staged DSN had 29 GEO files and `GAME001.DAT`. All 30
files were SHA-256 identical before and after Hatari.

The isolated build used m68k-atari-mint-gcc 15.2.0 and the recipe above. Its
`frua.prg` SHA-256 is
`C951F10C4AB6136EC338456C448FB011F369436305ED8E61EA7312BAB3C22794`.
The build reported that `UnlimitedAdventures.rfork` was absent, so it did not
produce a new `frua.rsc`; the run reused the staged test resource file
(`471176A5B28F66BBB530CFBD78D830F7ECBDCBB5FA092C5CC914BEC595110A36`).

Hatari 2.3.1 logged 29 `begin`, 29 dimension and 29 `end` records, for ids
001..029. Every map reported 16×16 dimensions, 256 cells and zero specials.
The final records were:

```text
GEO-SWEEP loop done: loaded 29 skipped 0 failed 0
GEO-SWEEP restore: entry level 001 reloaded, party cell 0,0 facing 4
GEO-SWEEP end: continuing into jt948
```

Hatari exited with status 1 after these records and before the 45-second bound.
The sweep and entry reload completed; the exit status leaves the engine state
after the handoff to `jt948` unverified. The full log is
`data/work/por-geosweep-isolated-20261118/run/DBG.LOG` (SHA-256
`4AD92ADF2455E2D4B62E70B738781978F0CF5ACE36322C4D55C998527DBBF5DD`).
This establishes parser/load acceptance for all 29 generated GEO files in
this run. It does not establish gameplay or playability.

## Limits

- Test harness only. It does not run the walk, check any area's content,
  events, text, art, or monsters, and it does not establish playability.
- Area ids are invented (see above). A `width/height/specials` line describes
  the parsed file, not a verified PoR area.
- The `.glb` fallback and the cold disk-load path are never exercised. Absent
  files are skipped, not loaded.
- The isolated 68000 build compiles the test harness; the regular build is
  unchanged when `FRUA_GEO_SWEEPTEST` is absent. The source guards cover that
  macro boundary and ordering.
- This sweep does not render, place the party on, walk, or execute events from
  these areas. Area ids are test ids; it is not a full-game validation.

## Tests

```sh
python -m pytest tests/test_geo_sweeptest_guard.py -q
```

Source-level only: macro gating of every sweep identifier, the compiled-out
entry tail, the begin / probe / jt198 / check order, skip-before-load, the
restore before `jt948`, and the probe's jt127-equivalent open.
