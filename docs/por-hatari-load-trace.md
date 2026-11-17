# PoR Hatari GEMDOS load-trace checker

`tools/por_hatari_load_trace.py` checks a Hatari verbose GEMDOS log against a DSN
folder and reports, for each `GEO###.DAT` the trace opens from that folder,
whether the open was **open-only** (no `Fread` before `Fclose`) or
**open+read** (at least one `Fread`). It is a read-only evidence checker. It
starts no emulator, rebuilds no source, and writes nothing except the optional
`--out` JSON, which must resolve under `data/`.

Tests: `tests/test_por_hatari_load_trace.py`. They use literal excerpts of both
logs and synthetic design folders. They need no retail data and no ignored data.

## Results (2026-11-17)

Reports are in `data/work/por-hatari-load-trace-20261117/` (ignored data; no
absolute or host paths inside).

| Trace | `source_status` | Verdict | GEO file observed | Status |
|---|---|---|---|---|
| `por-openua-runtime-allmap-smoke-20261117/hatari-gemdos.log` | `fresh-bounded-run` | evidence | `GEO001.DAT`, 1 lifecycle (lines 196–199) | **open-only** |
| `por-openua-party-runtime-diag2-20261117/hatari-gemdos.log` | `historical-runtime-log` | evidence | `GEO005.DAT`, 2 lifecycles (lines 196–199, 24052–24055) | **open-only** |

Both reports: `playable: false`, no refusals. The GEO001.DAT sha256 in the smoke
report is `c96dfdfb…1624`, the pipeline output, and the GEO005.DAT sha256 in the
diag2 report is the design file's own hash.

## What the fresh smoke excerpt shows

Source: `data/work/por-openua-runtime-allmap-smoke-20261117/hatari-gemdos.log`,
lines 191–199 (literal in the test as `SMOKE_191_199`):

| Log lines | Event | Result |
|---|---|---|
| 191–195 | `Fopen PORALL29.DSN\GAME001.dat` → FD 64, `Fread(64, 32766)`, `Fclose(64)` | A GAME001 read. Not a GEO file. |
| 196–199 | `Fopen PORALL29.DSN\GEO001.dat` → FD 64, then `Fclose(64)` | **GEO001.DAT open-only.** No `Fread` between open and close. |

The run opens GEO001.DAT and closes it. No GEO Fread appears in the trace. The
whole log has only these two GEO lines (196 and 197); the other GEO-looking text
is not a GEO open.

## What the historical diag2 excerpt shows

Source: `data/work/por-openua-party-runtime-diag2-20261117/hatari-gemdos.log`
(ignored data; the test copies the lines as literals).

| Log lines | Event | Result |
|---|---|---|
| 24047–24051 | `Fopen PORALL29.DSN\GAME001.dat` → FD 64, `Fread(64, 32766)`, `Fclose(64)` | A GAME001 read. Not a GEO file. |
| 24052–24055 | `Fopen PORALL29.DSN\GEO005.dat` → FD 64, then `Fclose(64)` | **GEO005.DAT open-only.** No `Fread`. |
| 196–199 | `Fopen PORALL29.DSN\GEO005.dat` → FD 64, then `Fclose(64)` | A second GEO005.DAT open, also open-only. |

The `Fread(64, 32766, …)` at line 24050 belongs to the GAME001.DAT lifecycle. It
comes before the GEO005 open and is not attributed to GEO005.

## Claims this tool supports

Only when the checker returns `verdict: evidence` (exit 0):

- The Hatari GEMDOS trace shows OpenUA opening a `GEO###.DAT` from the supplied
  design folder. The open is file-level evidence, with its FD and line numbers.
- Per lifecycle and per file, it separates **open-only** from **open+read**. For
  the fresh smoke run, GEO001.DAT is **open-only**. For the historical diag2
  log, GEO005.DAT is **open-only** on both occurrences (lines 196–199 and
  24052–24055). **No GEO read is observed in either trace.**
- Claim `open-only` unless the same FD lifecycle contains a `Fread`. Nothing in
  these traces supports `open+read`.
- The design file's size and sha256 are recorded, as identity of the design
  file only.

## What it does NOT claim

- `playable` is always `false`.
- The tool does not claim the campaign or any map is playable, that any map was
  displayed or rendered, or that original Pool of Radiance was matched.
- The tool does not claim the emulator consumed every byte of a design file.
  Hatari logs the requested `Fread` count but not the returned count. The
  report marks each file `byte_consumption: not-asserted`.
- The tool does not claim which executable produced the trace. See the next
  section.

## Provenance and binary identity

- `--source-status` records what kind of run the trace is. It is recorded as
  given and is not verified. Use `historical-runtime-log` for the diag2 log and
  `fresh-bounded-run` for the allmap smoke run. The default is `unspecified`.
- The diag2 log is **historical runtime evidence**. It came from a prior diag2
  runtime build. It is not a rerun of current source. The tool does not verify
  that, so the caller records it with `--note`.
- `diag2\frua.prg` is a **symlink to the repo-root `frua.prg`**. The bytes that
  the historical run executed are therefore **unpinned**. The current
  `frua.prg` is a newer file, and nothing here shows which bytes the old run
  executed. Do not describe the diag2 log as produced by a pinned binary.
- The smoke trace carries no binary identity either, and this tool does not
  hash an executable. The report says so in `provenance.binary_identity`. Do
  not describe the smoke run as produced by a pinned binary.

## Refusals

The checker refuses (exit 2; `verdict: refused`; the report names each
refusal, with its line, and makes no claims) when the trace is ambiguous:

| Code | Meaning |
|---|---|
| `fd-reuse-while-live` | An FD is opened again while still open. |
| `event-on-non-live-fd` | `Fread`, `Fwrite`, `Fseek`, or `Fclose` on an FD with no open lifecycle. Handles 0–5 (devices) are exempt. |
| `incomplete-lifecycle` | A GEO file is opened and never closed before the trace ends. |
| `path-outside-design` | A GEO name is not exactly `<design folder>\<file>`. Rejects traversal (`..`), absolute or drive names, nested folders, bare names, and other folders. |
| `host-mismatch` | The `-> host:` path does not end in `<design folder>/<file>`. |
| `geo-not-in-design` | A GEO file is opened that the design folder does not contain. |
| `duplicate-open-of-live-geo` | A GEO file is opened while another handle to it is still open. |
| `geo-create` / `geo-write` | A GEO file is created or written. |
| `fd-line-unbound` / `reserved-handle` | Log-structure anomalies around an open. |

A failed open (`Fopen` with no `-> FD` line before the next call) is counted in
`counters.failed_opens` and is **not** evidence. It is not a refusal.

Exit codes: 0 = evidence observed; 1 = no GEO open observed; 2 = refusal.

## Usage

```sh
python tools/por_hatari_load_trace.py \
    --trace data/work/por-openua-party-runtime-diag2-20261117/hatari-gemdos.log \
    --design data/work/por-openua-party-runtime-diag2-20261117/PORALL29.DSN \
    --out data/work/por-hatari-load-trace-20261117/diag2-20261117.json \
    --source-status historical-runtime-log \
    --note "historical diag2 runtime; frua.prg is an unpinned symlink; not a rerun of current source"

python tools/por_hatari_load_trace.py \
    --trace data/work/por-openua-runtime-allmap-smoke-20261117/hatari-gemdos.log \
    --design data/work/por-openua-runtime-allmap-smoke-20261117/PORALL29.DSN \
    --out data/work/por-hatari-load-trace-20261117/allmap-smoke-20261117.json \
    --source-status fresh-bounded-run \
    --note "fresh bounded Hatari run against current TGALLMAP output; binary identity not recorded in the trace"
```

The report carries no absolute paths and no host paths. It records the trace
basename and sha256, the design folder basename, and the line numbers.

## Limits

- It reads one log and one design folder. It does not resolve whether the
  design folder is the one the game used at runtime.
- It treats any `Fread` on a file FD as a read, whatever the caller intended.
- It reads the log as latin-1 text, one physical line per record. A multi-line
  record would be misparsed.
- Passing the checker is not proof of correct game behaviour. It only shows
  what the trace records about file opens and reads.
