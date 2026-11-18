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
`0x2A` (passability 2, same slot) in an isolated area-20 test design. Both runs
used one disposable build with `FRUA_DOOR_DIAG` and `FRUA_DOOR_STR25`; the
second macro sets the first active party member's Strength to 25 in that test
build. The design files were compared before and after each run.

| Run | Selected edge | Menu pick | Action allowed | Forward allowed | Stored edge at next decision |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default | 15 (`0xFA`) | 0 | 0 | 0 | 15 |
| Candidate | 2 (`0x2A`) | 0 | 1 | 1 | 2 |

This establishes that, in this OpenUA test path, passability 2 reaches the
same blocked-action decision and lets its item-0 Force branch allow movement;
passability 15 does not. It does not verify the visible label on item 0.

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
edge remains passability 2 in both runs, so the transform preserves the tested
door interaction while aligning this route's coordinates. The converter now
places source `(x,y)` at OpenUA `cell(col=y,row=x)` and writes the entry as
`row=x, col=y`. This is evidence for one route; it does not validate all areas,
events, transitions, or direction labels.

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
- The in-memory edge remained 2, and all 16 files in the design folder had
  identical hashes before and after both runs. OpenUA did not persist an
  opened edge in this experiment.
- This is one controlled test route and one run per encoding. It does not bind
  stored GEO flag-2 bytes generally to the OpenUA runtime field or prove all
  flag-2 semantics.
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
