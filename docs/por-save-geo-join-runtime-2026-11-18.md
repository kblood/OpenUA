# PoR SAVGAMA one-area design: bounded runtime check (2026-11-18)

**Status: partial. Area-2 load, OpenUA entry coordinates and one blocked overland step observed; DOS parity NOT established.**
`playable: false`. `runtime_binding_claimed: false`. The DOS save-to-area and block-to-area join,
the original game's start area and facing remain hypotheses.

Plan: [`por-save-geo-join-plan.md`](por-save-geo-join-plan.md). Candidate check:
[`por-save-geo-candidate-check.md`](por-save-geo-candidate-check.md). Prior door run:
[`por-door-flag2-candidate-runtime-20261118.md`](por-door-flag2-candidate-runtime-20261118.md).

## Question

Does the committed adapter's one-area SAVGAMA design (`PSAVGAMA.DSN`, area 2, entry
`[15,4]`, facing west, from `GEO2.DAX` TOC 2 / block 20) load in the OpenUA runtime, put the
party at row 15, column 4, and let a first forward key produce an observable edge and move?

## Verdict

| Check | Result |
| --- | --- |
| Design from the default converter (no candidate flag) | Yes. One area-2 design; GEO002 emitted; flag 2 encoded as passability 15 (the default). |
| Runtime loader reaches area 2 | **Yes.** `GEO-SWEEP area 002: width 16 height 16 cells 256` and the configured level is 002 from GAME001 byte 48. |
| OpenUA overland entry coordinates | **Observed in attempt 8:** row 15, column 4 (`y*100+x = 1504`), facing byte 6 before the first logged command-dispatch return. This matches the candidate coordinates; it does not establish the DOS save-to-area or GEO block join. |
| First candidate forward step | **Observed in attempt 9:** candidate `(15,3)`, in bounds, `jt210` returned wall-art code 14, and the party stayed at `(15,4)`. The OpenUA source classifies 14 as solid. This tests the emitted design in OpenUA only. |

The OpenUA coordinate observation does not confirm that the original game used this area/block join or that a forward command moves correctly.

## Run identity

| Item | Value |
| --- | --- |
| Hatari | 2.3.1 under WSL2 (`6.6.87.2-microsoft-standard-WSL2`), `--machine ste --memsize 14`, `--sound off` |
| TOS | EmuTOS 1.4, `emutos/emutos-512k-1.4/etos512us.img` |
| Test binary | `frua.prg`, SHA-256 `1B1A8FCDDD0DBFC0D57C27A6087D728E77C0799BB27E358CCCE7E4303D66D705`; the same file as the flag-2 door run |
| Binary build flags | From `build/build-str25.log`: `CPU68K=68000 NOEMBED=1 EXTRA_CFLAGS="-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_GEO_SWEEPTEST -DFRUA_DOOR_DIAG -DFRUA_DOOR_STR25"`. Strings present: `GEO-SWEEP begin`, `GEO-SWEEP restore`, `DOOR forward edge=`, `DOOR stored edge`, `dbg_dump_view: wrote`. |
| Test fixture | `DOOR_STR25` sets the first party member's Strength to 25 on each forward decision. It does not change position. It was not exercised in this run. |
| Design | `PSAVGAMA.DSN`: `GAME001.DAT` 388 B, SHA-256 `5CBF1C30D2721CD36E4A59EC0823A2E0861FDAE0AD4CEF51838433F8AAFE085F`; `GEO002.DAT` 12,962 B, SHA-256 `C863D2A8D6452C42BC96A542CE43F35595D2722DED70AA4802DF4F438FB7DA40` |
| `start.dat` | 35 B: `PSAVGAMA.DSN` padded to 34 B, then resume byte `0x01`; SHA-256 `8B3C441B5662386CEDF4F75E36D06716AEE49C8826B333D9614668D8B33E7652` |
| Runtime folder | `data/work/por-save-geo-join-runtime-20261118/runtime-savgama/` (87 root assets copied from the flag-2 `run-cand-direct-final` folder, minus its logs, its `POR2NEW.DSN` and its `start.dat`). No user save, no `SAVE/` folder. |
| Final run | Hatari PID `1308`, script PID `1302`, watchdog PID `1310`, wrapper `wsl.exe` Windows PID `43020`. Started 09:59:29, exited 10:00:57, rc 0. |
| Screenshot | `evidence/grab0001.png`, SHA-256 `AFECCFEE9ABA4A450974A4B488073B370DA22E163CA53D5A8D10EDADAD08C814` |

No Hatari process was active before any run (checked in WSL with `pgrep`). The GOG Galaxy
process and the Pool of Radiance install were not touched. DOSBox was not run.

## Commands

```sh
# 1. Plan (committed adapter; read-only on the install; writes under data/)
tools/.venv/Scripts/python.exe tools/por_save_geo_join_plan.py \
  --install "G:/Games/Pool of Radiance/POOLRAD" --save SAVGAMA.DAT --ordering pose_xy --area 2 \
  --facing-candidate-mapping --block GEO2.DAX:2:20 -o data/work/por-save-geo-join-runtime-20261118/plan
#  plan emitted: design PSAVGAMA, GEO2 TOC 2, validated by por_pipeline.load_plan; playable false

# 2. Default converter (no --candidate-flag2-passable)
tools/.venv/Scripts/python.exe tools/por_pipeline.py \
  --install "G:/Games/Pool of Radiance/POOLRAD" \
  -o data/work/por-save-geo-join-runtime-20261118/pipeline-default \
  --plan data/work/por-save-geo-join-runtime-20261118/plan/pipeline_plan.json
#  blocks decoded 29/29; designs ok 1/1; loader-equivalent pass 1/1 (MAP-ONLY, engine not run)

# 3. Runtime: wsl.exe -e bash .../scripts/<script>.sh, started from PowerShell with
#    Start-Process -PassThru and WaitForExit(420000). Attempt 1 used an earlier revision of
#    run_savgama.sh (it pre-created the FIFO); attempt 2 used run_savgama_attempt2.sh; attempt 3
#    used run_savgama.sh; attempt 4 used run_savgama_shot.sh. See the attempt table.
```

Scripts live in `data/work/por-save-geo-join-runtime-20261118/scripts/`. Each run used
`--harddrive . --gemdos-drive C --auto 'C:\FRUA.PRG' --cmd-fifo <fifo>`, a 240 s watchdog
that sends SIGINT only to the Hatari PID it started, and a 60 s wait after the ready marker
`GEO-SWEEP end: continuing into jt948`.

## Attempts

Attempts 1–5 used the runtime described above; attempts 6–8 used fresh disposable copies.
A new `evidence*` folder was kept for each.

| Attempt | Folder | Keys sent after the marker | Result |
| --- | --- | --- | --- |
| 1 | `evidence-attempt1-fifo-precreate-error/` | none | Script pre-created the FIFO; Hatari refused with `FIFO creation error: File exists`. Fixed by removing the `mkfifo` line. No keys reached Hatari. |
| 2 | `evidence-attempt2-forward-only-no-walk/` | **one** Up (72) at +60 s | No walk render, no `DOOR` line. Quit at +30 s. |
| 3 | `evidence-attempt3-return-no-walk/` | one Return (28) at +60 s, no forward key | No walk render (`dbg_dump_view` not written within 40 s). No forward key was sent. |
| 4 | `evidence/` (final) | none (diagnostic) | Screenshot of the pre-walk screen (first try: `Screen dump failed!` because `runtime-savgama/shots/` did not exist). |
| 5 | `evidence-attempt5-updoor-sequence/` | **Up (72), Return (28), Up (72)**, after the ready marker; see [Attempt 5](#attempt-5-up-return-up-2026-11-18) | No walk render (`dbg_dump_view` not written within 40 s after the last key), no `DOOR` line. Quit at +66 s after the marker. |
| 6 | `evidence-attempt6-overland-cells/` | **Up (72), Return (28), Up (72)** | Overland image appeared; no `OVSTEP`. This run had no live coordinate instrumentation. |
| 7 | `evidence-attempt7-overland-extra-up/` | Same sequence, then one extra Up (72) | Overland image remained; no `OVSTEP`. No live coordinate instrumentation. |
| 8 | `evidence-attempt8-overland-extra-up/` | Same sequence and extra Up, with `FRUA_CELLSCAN` position markers | Entry position/facing and later snapshots recorded below. No `OVSTEP`; no successful movement observed. |
| 9 | `evidence-attempt9-overland-extra-up/` | Same sequence and extra Up, with `FRUA_CELLSCAN` and `FRUA_OVDIAG` | `jt955` candidate `(15,3)`, in bounds, blocked result 14; no landing. |

The earlier flag-2 door run sent Up, Return and Up, and it reached the dungeon walk. In attempts
2–5 here, the first Up produced no walk render, and neither did Return on its own. That walk
marker is dungeon-specific, so its absence did not assess the level-2 overland loop. Hatari's screenshot shows the
pre-walk screen: a scene picture above an empty text panel (what the game is waiting for is not identified). Which key advances that screen was
not determined within the key budget. Up is the same scan code as the forward key, so it could
not be used for that purpose here. A mouse event (Hatari exposes `hatari-event` clicks) was not
tried.

### Attempt 5: Up, Return, Up (2026-11-18)

The same design and binary as attempts 2 to 4, run in a disposable copy so the source runtime
was not touched. The input sequence was the area-20 door-harness sequence (Up, Return, Up), sent
only after the `GEO-SWEEP end: continuing into jt948` marker.

| Item | Value |
| --- | --- |
| Runtime copy | `runtime-savgama-updoor-attempt5/` (copied from `runtime-savgama/` with `cp -a`; `DBG.LOG` and `shots/` cleared before the run). Its `PSAVGAMA.DSN/SAVE/` (six `*.CCH` files, 398 B each) came with the copy, unchanged; they are not user saves. The "no SAVE folder" note above is wrong for this design. |
| Script | `scripts/run_updoor_attempt5.sh` (not in the runtime folder). Refuses if any Hatari process exists. Signals only its own PID. Watchdog 240 s. |
| Hatari | PID `1096`, script PID `1091`, watchdog PID `1098`. Started 10:05:21. Exited 10:06:47, rc 0. |
| Input | Ready marker at 10:05:41. Screenshot (`hatari-shortcut`, not a game key) at +5 s. Up 72: keydown 0.2 s, keyup, 3 s wait. Return 28: same. Up 72: same. Walk-marker wait up to 40 s. Screenshot at +5 s. `hatari-shortcut quit`. |
| Walk marker | Not seen: `walk marker seen=0`. |
| Screenshots | `grab0001.png` (before keys, SHA-256 `dd8c1c2a296b8f1c271a85781821dc952f9117e9eaf33a12fc66add757081ed9`); `grab0002.png` (after keys, SHA-256 `96f2f3ad4a34ac81fbf5cb26409963c6f0945f31d44027f5927f9ab7c40bc1d8`). Both show the same overhead lake-and-town scene above an empty lower panel. The screen did not change after the keys. |

**Result: the sequence does not enter the walk in OpenUA's PSAVGAMA one-area design.** No
`dbg_dump_view`, no `DOOR forward`, and no position or edge was observed. This does not
reproduce the earlier flag-2 door run, whose walk was reached with the same keys. The
binary is the same `frua.prg`, but the design is not: the flag-2 run used its own candidate design
and this run uses the default `PSAVGAMA.DSN`. The cause is unexplained. The key sequence alone
did not enter the walk for this design, and the flag-2 result is not a reproduction of it.

The Hatari log has a `Bus Error reading at address $ffffa200, PC=$e00d98` warning. It appears in
every run of this design, including attempts 2 to 5, so it is not new here. It was not
classified, and the earlier "only benign warnings" statement above is revised: this warning is
recurring and unclassified.

### Attempts 6–8: overland path and live coordinate trace (2026-11-18)

Source inspection showed that level 2 dispatches through the overland path in `jt948`; the
earlier `dbg_dump_view`/dungeon `DOOR` markers were therefore not a valid movement test for this
design. Attempts 6 and 7 repeated the known key sequence against fresh copies and reached the
overland scene, but produced no `OVSTEP`. Attempt 8 used a disposable build with extra
`FRUA_CELLSCAN` logs around the overland dispatcher. The instrumentation was added only to the
ignored build copy under `data/work`; tracked source was not changed for this run.

Attempt 8 emitted these values in order:

| Snapshot | Level | Mode | Position (`y*100+x`) | Facing byte | `jt953` result |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before first logged dispatch | 2 | 3 | 1504 (row 15, column 4) | 6 | — |
| After first dispatch | 2 | 3 | 1504 | 0 | -120 |
| After second dispatch | 2 | 3 | 1504 | 0 | -120 |
| After third dispatch | 2 | 3 | 1504 | 0 | -120 |
| Fourth dispatch entry before quit | 2 | 3 | 1504 | 0 | no return logged |

The scheduled input during these snapshots was Up (scan 72), Return (28), Up (72), followed
by one extra Up. The first observed facing change is temporally consistent with the first Up;
the log does not tag a particular input at the state write, so this remains a correlation.
Coordinates remained 1504 in every recorded snapshot. `OVSTEP` did not appear. The fourth
dispatch had a pre-state record but no post-state record before the process was quit, so the
extra Up has no completed post-input measurement. These observations establish the OpenUA
entry coordinates for this fixture and that the tested sequence did not produce a logged
landing; they do not establish DOS behavior or the original game's facing convention.

Attempt 8 run identity: Hatari PID 1200, script exited rc 0; the attempt script's 240 s watchdog
was armed and did not fire. The instrumented `frua.prg` SHA-256 was
`667C0FB0BF25FA6B9626B3B0591B12DA04E3DF457E428C47EEA1E5359FCD333D`. The initial screenshot
(`grab0001.png`) is SHA-256 `AFECCFEE9ABA4A450974A4B488073B370DA22E163CA53D5A8D10EDADAD08C814`;
the screenshot after the initial sequence (`grab0003.png`) and the final screenshot
(`grab0004.png`) are both `96F2F3AD4A34AC81FBF5CB26409963C6F0945F31D44027F5927F9AB7C40BC1D8`.
The Hatari log again reports the unclassified bus error at `$ffffa200`.

The attempt-8 copy's `GAME001.DAT`, `GEO002.DAT` and `start.dat` hashes were identical to the
source runtime both before launch and after exit: `5CBF1C30…FE085F`, `C863D2A8…B7DA40` and
`8B3C441B…3E7652`, respectively. The copied `frua.prg` hash was `667C0FB0…CD333D`.

### Attempt 9: identify the blocked overland candidate (2026-11-18)

This run used a second disposable diagnostic build with the existing `FRUA_OVDIAG` logs enabled,
and a fresh screenshot folder. It repeated Up (72), Return (28), Up (72), then one extra Up. The
first three dispatch/step cycles logged the same state:

```text
OV pre level2 / mode3 / y*100+x1504 / facing6
OV jt953 res-120; post position1504, facing0
OVCAND cur-row 15; cand-row 15; cand-col 3; oob 0
has_str(-5213 set) 0; blocked t 14; msg[0] 0
OV post jt955 y*100+x1504 facing0
```

The next two cycles began at `(15,4)`, facing 0, and again reported candidate `(15,3)`,
`oob=0`, `blocked t=14`; no `OVSTEP` was emitted. In `jt210`, the returned value is the
high nibble (wall-art code) of the selected edge. The `jt955` switch treats code 14 as solid
(`docs/play-vs-edit-audit.md`). Thus this run shows that OpenUA's converted map blocks the
tested step at that edge. It does not show whether the original PoR game blocks the corresponding
edge, and the save-to-GEO edge binding remains a hypothesis.

The instrumented binary SHA-256 was
`A53E39D7326BB08642B3C9BF775FBBC30A9A88D14C214953D02249F75CA60E3C`; the build exited 0 with
a Make clock-skew warning. Hatari PID 1220 exited rc 0, with its 240 s watchdog not firing. The
run copy's `GAME001.DAT`, `GEO002.DAT` and `start.dat` hashes match attempt 8's values above.
The recurring `$ffffa200` Bus Error warning remained unclassified.

## Relevant log lines (final run, `evidence/DBG.LOG`)

```text
GEO-SWEEP begin: test-only, invented area ids 1..29
GEO-SWEEP configured entry level 002
GEO-SWEEP area 002: width 16 height 16 cells 256 specials 0
GEO-SWEEP area 002 end
GEO-SWEEP loop done: loaded 1 skipped 28 failed 0
GEO-SWEEP restore: entry level 002 reloaded, party cell 0,0 facing 4
GEO-SWEEP end: continuing into jt948
```

Absent from every attempt's log: `dbg_dump_view: wrote VIEWDIAG.TXT`, `rm_audit`,
`j200_dump`, every `DOOR forward ...` and `DOOR menu ...` line. The `DBG.LOG` is 77 lines in
each of attempts 2 to 4.

The Hatari log contains: no GEMDOS dir for `AUTO` and for `PSAVGAMA.DSN/SAVE`, font clip
warnings, and a `Bus Error reading at address $ffffa200` warning (see Attempt 5; it is
unclassified). The earlier statement that the design has no SAVE folder is wrong: attempt 5's
copy has `PSAVGAMA.DSN/SAVE/*.CCH`, and the source `runtime-savgama/` has the same six files.

## Input immutability and hashes

- Install: `SAVGAMA.DAT` SHA-256 `ABCA248371287C43C99E1B34E03394819FCA3CF406BED184E7E4FBFE4F0C08F1`,
  13,137 B. This matches the pin in `tools/por_save_state_probe.py`. The install is read-only for every step.
- Design and binary before and after the final run: `evidence/design-hashes-before.txt` and
  `design-hashes-after.txt` are identical for `GAME001.DAT`, `GEO002.DAT`, `start.dat` and
  `frua.prg`.
- Pipeline default outputs: `por_pipeline.json` `C0562381C14182C30FC8B37C0166959C909E67354A957E162B1801AAE4C3EC2A`;
  `por_pipeline_report.md` `AE8CFD85CBC965BC7F3455DA131259D751E2858A0585974530D20B14443C4792`;
  `plan/pipeline_plan.json` `73EC97629C253A2A4679135E7048583F4334C189D616E1176FAA7F9E882832C7`.

## Process cleanup

After the final run, WSL shows no Hatari process, no `sleep` from the watchdog, and no `frua`.
The wrapper `wsl.exe` PIDs (28808, 45100, 39424, 35420, 43020) have all exited. Three other
`wsl.exe` entries were visible during one check; they had exited by the next query and none
belonged to this session.

## Limits

- No walk render was reached, so the party position, the first forward edge and the first move
  are all unmeasured. The candidate `(15,4)` transform is untested in the runtime.
- The `restore` line's `0,0 facing 4` is the cell captured before the sweep. It is not evidence
  about the entry position.
- The binary includes the `DOOR_STR25` fixture. It was not exercised here, but the fixture
  stays in the binary for any later door run.
- The area-2 result is loader-reach only: the sweep loads whichever `GEO*.DAT` is present in the
  design and reports its dimensions. It does not show the DOS block binding or the area join.
- The original game's facing (west, from the unverified candidate mapping) and start area are
  hypotheses.
- Attempts 8–9 observed OpenUA's entry coordinates `(15,4)` and facing byte `6`. Attempt 9's
  tested edge resolves to wall code 14 in OpenUA; neither run compared the original game's live
  state or proved that the candidate join is authentic.
- Flag 2 is encoded as passability 15 (the default). The flag-2 candidate option was not used.
- One design, one binary, one screen. No second route was checked.

## Next step (needs a decision)

The overland trace confirms the candidate coordinates as the live OpenUA entry coordinates and
shows the tested edge is blocked by wall code 14. Next, compare the original PoR cell/edge and
movement outcome against this exact candidate, including a live DOS observation if the codewheel
gate can be passed. Until then, the saved-position join and the block-to-area binding remain
hypotheses, and no parity claim is supported.
