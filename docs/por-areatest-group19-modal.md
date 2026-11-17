# AREATEST run: `ERRMODAL: Group 19 in use for ''` before the GEO load

Status: the premature probe-only modal is diagnosed, and the no-probe AREATEST
build has reached a verified GEO parse in Hatari. No production source file was
changed. The census tool and its tests are new, uniquely named files.

## Verdict

Two different runs, same symptom. Both stop in the same place, and that place
is a `jt127` design-file read that misses and falls back to a shared `.GLB`
library bound to **group 19**, while the group table is still all zero:

| run | `start.dat` name | first failing read | where it is in the source | ERRMODAL line |
|---|---|---|---|---|
| `…20261117a` | `TGALLMAP` (no `.DSN`) | `GAME001.DAT` under `TGALLMAP:` | `port_test_seed_design` (before the probe block) | 43 |
| `…20261117b` | `TGALLMAP.DSN` (corrected) | `GEO040.DAT` (self-test) | `boot_a5_seed_defaults`, `FRUA_ENGINE_PROBE` block | 412 |

Run-b is the case you asked about. Its start.dat is already corrected, so the
remaining blocker is the GEO040 self-test, not the name.

## Source-level path (run-b)

1. `main.c:545` `boot_a5_seed_defaults()` (`boot.c:11822`) — the A5 world is
   zero-filled by `data_pool_replay()`. `data_pool.c` is a zero-length stub and
   `frua.rsc` has **only `STRS`** (census below), so no `DATA`/`ZERO`/`DREL`
   replay happens (`data_pool_replay.c:163`, "no compiled pool and no runtime
   DATA/DREL"). Nothing seeds the group freemap `g_a5_10074` to `0xFF`.
2. `boot.c:12005` `port_test_seed_design()` — reads `start.dat` (`l0444`,
   `boot.c:23135`), `jt127("GAME",1)` reads `GAME001.DAT` (**succeeds**), then
   the GEO start-level probe (`jt398` on `GEO<hlv>.dat`, no GLB fallback).
3. `boot.c:12008` `#ifdef FRUA_ENGINE_PROBE` — the probe-only self-tests.
   `L2856 self-test` is logged at entry (run-b log line 381).
4. `boot.c:12060` `jt127("GEO", (short)40, &out, geobuf)`. The design folder
   `TGALLMAP.DSN/` has `GEO001..GEO029.DAT` but **no `GEO040.DAT`**
   (`jt398: open refnum = -1`, run-b line 397).
5. `jt127` (`boot.c:41440`) takes its `.GLB` fallback: `GEO.glb` →
   truncated to `GEO.g` → key `GEO.g40`, then `jt464(path, 19)`
   (`boot.c:41472`).
6. `jt464` (`boot.c:85682`): `if (!(g_a5_10074[19] & 0x80))` → `l036a("Group %d
   in use for '%s'", …)`. The byte is `0`, not `0xFF`, so the check fails. The
   name printed is `g_a5_10026[0]`, the zeroed record table, which is why it
   says `''`.
7. `l036a` (`boot.c:86311`) logs `ERRMODAL:` (line 412) and then waits in
   `while (!l0088())`. The harness never returns, so the 120 s bound ends the run.

The freemap is set to `0xFF` only by `jt463` (pool open) and `jt465(NULL)`.
`jt463` runs from `glib_pool_open` ← `master_init` (`boot.c:2570`), which runs
**after** `boot_a5_seed_defaults` (`ua_main` phase 3). So the probe's GEO040
read happens before the pool that would have marked group 19 free exists.

Other probe-only callers of the same jt463/jt464 path, all also skipped in a
non-probe build: `glib_pool_selftest` (`boot.c:82394`, body in `#ifdef`),
`fc_cache_audit` (`boot.c:85751`, no-op stub when off).

### Why run-a is a different (earlier) failure

`…20261117a/start.dat` contains `TGALLMAP` with no suffix. `TGALLMAP.DSN/` is
the folder, so `jt127` looks for `TGALLMAP:GAME001.DAT`, gets `-1`, and falls
back to the same group-19 `.GLB` path before the probe block is reached (it
has no `L2856` line). `tools/dsn.py` writes the same name to the folder and to
`start.dat`, so run-a's `start.dat` was not produced by it; it was hand-written.

## Evidence

- Build stamp `.machine` in `data/work/por-openua-areatest-build-20261117`:
  `falcon-68000-nofpu-1-planar1-probe0-x1935877434`. The checksum equals
  POSIX `cksum` of **`-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_ENGINE_PROBE`**
  (checked with the tool's `posix_cksum` and with coreutils `cksum`). `probe0`
  means `ENGINE_PROBE` was unset; the probe came in through `EXTRA_CFLAGS`.
- `frua.prg` (identical in run-b and the build dir) contains the strings
  `L2856 self-test` and `jt127 self-test`, so the probe-only blocks are compiled in.
- Run-b `DBG.LOG`: 34,045 `stub:` lines with 68 unique names, so this is the
  flood form (`FRUA_ENGINE_PROBE`); the once-per-name mode cannot repeat names.
- Run-b `DBG.LOG` has no `jt127 self-test:` line. It is only logged after the
  GEO040 read returns, and that never happens.
- `frua.rsc` census (`data/work/por-areatest-diag/frsc_census.py`): one resource
  type, `STRS` (1 entry, 29148 bytes). No `DATA`, `ZERO`, or `DREL`.
- `GEO*.DAT` in `TGALLMAP.DSN`: `GEO001`–`GEO029`, no `GEO040`.
- No `FRUA_AREATEST` / `jt361` / `jt198` / `evtsnd:` / `SPILL:` marker appears
  before line 412 in run-b (census: 0 markers before the modal).

## Smallest way to reach the GEO load

**Recipe change only (no source edit), verified below:**

1. Keep `start.dat` = `TGALLMAP.DSN` + flag `01` (run-b is already correct).
2. Build **without** `-DFRUA_ENGINE_PROBE`. That removes the probe block
   (GEO040 self-test, `L2856` self-test, `glib_pool_selftest`, `fc_cache_audit`)
   from the boot path:
   `make CPU68K=68000 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS"`
   If DBG.LOG coverage is still wanted, use `ENGINE_PROBE=1` (once-per-name). It
   defines only `FRUA_ENGINE_PROBE_ONCE` (`Makefile:250`), so the GEO040 block
   stays out. Note `ENGINE_PROBE=flood` *does* define `FRUA_ENGINE_PROBE`.
3. Expected: `master_init` → `jt463` seeds the freemap, `jt361(1)` loads the
   design, then the `FRUA_AREATEST` entry (`boot.c:2758`) runs. Confirm with
   `python tools/areatest_modal_census.py <run-dir>`: no `PROBE_GEO040_SELFTEST`
   or `DESIGN_NAME_MISSING` verdict, and markers before any ERRMODAL.

### Runtime confirmation (run-e, 2026-11-17)

The recipe was built in the ignored snapshot
`data/work/por-openua-areatest-build-20261117/` with
`CPU68K=68000 NOEMBED=1 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_CELLSCAN"`.
The binary SHA-256 is `B4B5620B0E29403AC01396595E4F2224F5460A8DC19A8318411415E9509B4F16`.
It contains neither probe-only self-test string. The 45-second Hatari run in
`data/work/por-openua-areatest-20261117e/` ended at its bound and logged no
`ERRMODAL`. Its `DBG.LOG` reports `== GEO level1` twice, each followed by
`width(ds2)16` and `height(ds3)16` (lines 14–27). In `jt198`, the `FRUA_CELLSCAN`
block that emits those lines runs after the 12,962-byte check and `l720a` parse;
this is runtime evidence that the generated level 1 file was read and parsed
twice. The source maps level 1 to `jt127("GEO", 1, ...)`, which constructs
`GEO001.DAT` under the design name in `start.dat`; the staged design contains
that file at exactly 12,962 bytes.

The once-per-function trace in run-d showed `jt361`, `jt198`, `L720a`, `L7226`,
`jt948`, and `L0bbc` in order, with no modal. Run-e supplies the explicit
post-parse confirmation. This proves the OpenUA engine can load and parse one
generated GEO block in the test harness. It does not prove all 29 blocks,
authentic area mappings, campaign transitions, or full-game playability.

**Source-level alternative (NOT applied; `boot.c` is a protected file for this
task).** Guard the GEO040 self-test so it only reads a file that exists, which
keeps the self-test's intent without the GLB fallback. Location:
`src/engine/boot.c:12059-12060`. Replace

```c
		geobuf[0] = geobuf[1] = geobuf[2] = geobuf[3] = 0;
		jt127("GEO", (short)40, &out, geobuf);
```

with

```c
		geobuf[0] = geobuf[1] = geobuf[2] = geobuf[3] = 0;
		/* Only when GEO040.DAT is in the design: a missing file falls back to
		 * GEO.GLB group 19, which is unbound until jt463 opens the FAR pool
		 * (master_init runs after this) and raises ERRMODAL. */
		if (self_test_design_has("GEO", 40))
			jt127("GEO", (short)40, &out, geobuf);
```

and add above `boot_a5_seed_defaults` (same probe-existence check the GEO
start-level probe already uses at `boot.c:23176-23190`):

```c
static int self_test_design_has(const char *prefix, int num)
{
	char  path[402], dpath[202];
	short refnum;

	jt394(path, "%s%03d.dat", prefix, num);
	dpath[0] = 0;
	jt431(dpath, &g_a5_31336);
	jt431(dpath, path);
	refnum = jt398(dpath, 0);
	if (refnum < 0)
		return 0;
	(void)jt411(refnum);
	return 1;
}
```

This is a **probe-only** change (`#ifdef FRUA_ENGINE_PROBE` at `boot.c:12008`),
so production builds are unaffected. It has not been compiled or run here.
Compile it first, check `jt394`/`jt431`/`jt398`/`jt411` are declared above line
12008, and confirm the `FRUA_ENGINE_PROBE` build still logs `L2856`.

The deeper issue (the freemap is zero until `master_init`, and `boot_a5_seed_defaults`
does design I/O before that) is not fixed by either option. A real fix would seed
`g_a5_10074` to `0xFF` early (as `jt463` does) or move the design-I/O
self-tests after `master_init`. Both change boot order, so they are out of scope
for a harness fix. Not recommended without a run.

## Tools, tests, outputs

- `tools/areatest_modal_census.py` — read-only census; verdicts `PROBE_GEO040_SELFTEST`,
  `DESIGN_NAME_MISSING`, `MODAL_BEFORE_MARKERS`, `MODAL_AFTER_MARKERS`,
  `GEO_PARSE_REACHED`, `NO_MODAL`, `NO_DBG_LOG`. Also implements POSIX `cksum`
  for the build-stamp check.
  Usage: `python tools/areatest_modal_census.py <run-dir> [--build-dir DIR] [--extra-cflags STR] [--out PATH]`.
- `tests/test_areatest_modal_census.py` — 15 tests: synthetic run dirs, the cksum
  vector, flood detection, verdict classification, successful GEO parse markers,
  the build-stamp match, and two skipped-if-absent checks on the real `data/work`
  runs (a and b).
- `data/work/por-areatest-diag/frsc_census.py` — the FRSC type census used above.
- Outputs: `data/work/por-areatest-diag/census-run-a.md`, `census-run-b.md`,
  and `census-run-e.md`.

## Limits

- Runtime used the locally extracted Hatari 2.3.1 and EmuTOS 1.4 under WSL,
  with an STE, 14 MB, dummy SDL video/audio, and a 45-second timeout. This was
  one test-only design and a bounded boot/map run, not a campaign session.
- The DATA/ZERO/DREL question: this worktree has no `data/work/UnlimitedAdventures.rfork`,
  so a full-fork build's `frua.rsc` could not be produced here. Whether the
  replayed A5 image would set the freemap to `0xFF` is **unknown**. If it did,
  a full build would not hit this path even with the probe on. The census
  reports whether the replay resources are present.
- The census's verdict is a reading of DBG.LOG plus the directory, not proof.
  `PROBE_GEO040_SELFTEST` is "consistent with", as the tool's text says.
- Source line numbers are from the working tree at the time of writing, which is
  being edited (`boot.c` has uncommitted changes that do not touch this path).
- `ENGINE_PROBE=1` coverage mode was not run, so its DBG.LOG shape is inferred from
  `probe_once` (`boot.c:420-435`).

## Side effects

- No tracked file was modified. No `git` write. No commit, no push.
- New untracked files: `tools/areatest_modal_census.py`, `tests/test_areatest_modal_census.py`,
  `docs/por-areatest-group19-modal.md`.
- `data/work/por-areatest-diag/` (ignored) holds the census script and outputs.
- Did not touch the retail install, DOSBox/GameLink/codewheel, or emulator processes.
