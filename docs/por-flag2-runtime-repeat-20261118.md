# PoR flag-2 door runtime: recorded-observation repeat check

**Status: the recorded observations re-parse exactly from the captured logs.**
This is a parser and comparison over the two existing runs. It is not a new
engine run, and it does not establish PoR parity.

The experiment is described in
[`por-door-flag2-candidate-runtime-20261118.md`](por-door-flag2-candidate-runtime-20261118.md).
This note only records that its `run-ctl` and `run-cand` DBG.LOG captures
say what the doc says they say.

## What is checked

`tools/por_flag2_runtime_repeat.py` (stdlib only) reads
`run-ctl/DBG.LOG` and `run-cand/DBG.LOG` under the ignored capture folder
`data/work/por-flag2-candidate-20261118/` and checks:

- selected edge: 15 in `run-ctl`, 2 in `run-cand`;
- menu pick: 0 in both;
- action allowed (the `DOOR menu allowed` line): 0 in `run-ctl`, 1 in `run-cand`;
- forward allowed (the `DOOR forward allowed` line): 0 in `run-ctl`, 1 in
  `run-cand`, for the selected decision;
- stored edge at `14,10` stays equal to the selected edge at every later
  `DOOR stored edge` line in the same run.

The `run-cand` log also has a second forward decision at row 9, column 14. The
tool checks its recorded edge (14), its absent menu lines, and its forward
allowed value (0), and it checks that the stored edge still reads 2. It does
not interpret that second decision beyond those values.

The `14,10` literal is the one `boot.c` prints; its comment ties it to row 10,
column 14. The tool compares the literal as recorded.

## Refusals

The tool refuses rather than guesses (exit 2, nothing written) when a log is
missing, not ASCII, holds more than one boot session (`main: display up`
must occur exactly once), has no `DOOR` lines, has a `DOOR` line it does not
recognise, has a decision block that does not match one of the two known key
sequences (missing, duplicated or reordered keys), or has a value outside its
range. Output never includes filesystem paths.

A clean parse whose values differ from the recorded ones is a FAIL (exit 1),
not a refusal.

## Run

```text
python tools/por_flag2_runtime_repeat.py
python tools/por_flag2_runtime_repeat.py --report data/work/por-flag2-candidate-20261118/runtime-repeat-check.json
```

`--report` must resolve under `data/work/`. The focused tests are
`tests/test_por_flag2_runtime_repeat.py`; the real-log test skips when the
capture is absent.

## Result on the captured logs

Both logs parsed as two decision blocks each. All 33 checks passed,
including the four cross-run comparisons:

| Value | run-ctl | run-cand |
| --- | ---: | ---: |
| Selected edge | 15 | 2 |
| Menu pick | 0 | 0 |
| Action allowed | 0 | 1 |
| Forward allowed | 0 | 1 |

The stored edge read 15 in `run-ctl` and 2 in `run-cand` at every decision,
so it was unchanged within each run.

## Limits

- This checks the two captured runs only. It is not a repeat of the engine
  run, and it does not re-run Hatari.
- The menu pick and action-allowed labels are the code's `DOOR menu ...`
  lines. The visible menu label on item 0 is not verified.
- Destination parity with PoR `(13,10)` is not checked here; the second
  decision's cell is recorded, not compared with PoR.
- "Stored edge unchanged" covers only the captured runtime nibble within one
  run. It says nothing about persistence across sessions.
- No general flag-2 semantics are implied.
