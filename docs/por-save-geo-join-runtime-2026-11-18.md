# PoR SAVGAMA one-area design: bounded runtime check (2026-11-18)

**Status: partial. Area-2 load reached; runtime position, first forward edge and move NOT established.**
`playable: false`. `runtime_binding_claimed: false`. The save-to-area and block-to-area join,
the start area and the facing remain hypotheses.

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
| Party at row 15, column 4 (candidate transform) | **Not observed.** The walk never rendered in any run. The logged `restore ... party cell 0,0 facing 4` is the value captured before the sweep, not the entry cell. |
| First forward edge / move | **Not measured.** No `DOOR forward` line was logged in any run; no forward decision was reached. |

Nothing in this run confirms the candidate join, the facing, or the start position.

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

Every attempt started from the same runtime folder. A new `evidence*` folder was kept for each.

| Attempt | Folder | Keys sent after the marker | Result |
| --- | --- | --- | --- |
| 1 | `evidence-attempt1-fifo-precreate-error/` | none | Script pre-created the FIFO; Hatari refused with `FIFO creation error: File exists`. Fixed by removing the `mkfifo` line. No keys reached Hatari. |
| 2 | `evidence-attempt2-forward-only-no-walk/` | **one** Up (72) at +60 s | No walk render, no `DOOR` line. Quit at +30 s. |
| 3 | `evidence-attempt3-return-no-walk/` | one Return (28) at +60 s, no forward key | No walk render (`dbg_dump_view` not written within 40 s). No forward key was sent. |
| 4 | `evidence/` (final) | none (diagnostic) | Screenshot of the pre-walk screen (first try: `Screen dump failed!` because `runtime-savgama/shots/` did not exist). |

The earlier flag-2 door run sent Up, Return and Up, and it reached the walk. Here the first
Up produced no walk render, and so did Return on its own. Hatari's screenshot shows the
pre-walk screen: a scene picture above an empty text panel (what the game is waiting for is not identified). Which key advances that screen was
not determined within the key budget. Up is the same scan code as the forward key, so it could
not be used for that purpose here. A mouse event (Hatari exposes `hatari-event` clicks) was not
tried.

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

The Hatari log contains only benign warnings: no GEMDOS dir for `AUTO` and for
`PSAVGAMA.DSN/SAVE` (the design has no SAVE folder), and font clip warnings.

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
- Facing (west, from the unverified candidate mapping) and the start area are hypotheses.
- Flag 2 is encoded as passability 15 (the default). The flag-2 candidate option was not used.
- One design, one binary, one screen. No second route was checked.

## Next step (needs a decision)

The walk is not entered by Return alone, and Up is the forward scan code. A follow-up needs one
of: (a) an approved non-forward input that advances the title panel (e.g. a Hatari mouse click),
or (b) permission to send Up as a menu key before the one forward key. Until then this check
stops at area-2 load.
