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

## Limits

- The candidate did **not** reproduce the original destination: the next
  forward-decision log was row 9, column 14, facing 6. The cause is unresolved;
  no destination parity is claimed.
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
