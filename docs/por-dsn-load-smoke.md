# PoR `.DSN` load smoke: loader-equivalent host checks

Tool: `tools/por_dsn_load_smoke.py`. Tests: `tests/test_por_dsn_load_smoke.py`.

## What it is

A read-only check of one generated design folder (`NAME.DSN/`). It runs the
byte-level tests that the engine's loader applies before it accepts a GEO or
GAME record, and reports each one with the engine routine it mirrors.

A `verdict: pass` means the bytes pass these host-side checks. It does **not**
mean the engine loaded the design, and it makes no gameplay or playability claim.

## Why it is not the engine

The loader is 68k code in the Atari build (`src/engine/boot.c`: `jt198` →
`L720a` → `L7226`, plus `jt127` and `jt361`). It runs only inside an emulator or
on hardware. This tool does not run it, does not launch an emulator or DOSBox,
and claims no runtime load. The report always records `runtime_loaded: false`
and `engine_executed: false`.

## Checks

| id | rule | engine source |
|---|---|---|
| `design-folder-name` | folder is `*.DSN` | design picker enumerates `*.DSN` folders |
| `game001-present` | `GAME001.DAT` exists | `jt361` |
| `game001-start-bytes` | bytes 48 and 49 exist | `jt361`, Play reads `gh[48]`, `gh[49]` |
| `start-area-nonzero` | start area ≥ 1 | writer convention (`tools/dsn.py`, areas 1..999) |
| `geo-files-present` | at least one `GEO<NNN>.DAT` | `jt198` |
| `start-geo-present` | `GEO<start>.DAT` exists | `jt198`: missing → read count 0 → `jt69` |
| `geo-addressable:F` | area number ≤ 255 | `jt127`: `(unsigned char) num` |
| `geo-size:F` | exactly 12962 bytes | `jt198`: read count must equal 12962 |
| `geo-parse:F` | `geo.Geo.parse` accepts it | `L7226` structure, `tools/geo.py` |

The container parse is `geo.Geo.parse` and the size is `geo.GEO_SIZE`; nothing
is copied from the engine. The tool adds the exact-size rule, the presence rules
and the reporting.

## Where it differs from the engine

- **Size (looser in `geo.py`):** `geo.Geo.parse` accepts 12963 bytes (odd-size
  padding). `jt198` requires exactly 12962. This tool refuses the 12963-byte
  file. Test: `test_padded_geo_parses_in_geo_py_but_is_refused_by_size`.
- **Raw data (stricter here):** `L7226` accepts a GEO whose first long is not
  `FORM`/`CAT `/`LIST` as raw legacy data. `geo.Geo.parse` refuses it, and so
  does this tool.
- **Area numbers:** `tools/dsn.py` allows areas up to 999, but `jt127` addresses
  only 0..255. A `GEO256+` file is reported as not addressable.

## Not checked

- `start.dat` (the design name the engine resolves).
- GEO event, string and monster contents; art resolution.
- The start entry (`GAME001.DAT` byte 49) against the area's entry-point table.
- The `GAME001.DAT` length beyond bytes 48–49 (`jt361` reads whatever length the file has).

## Usage

```
python3 tools/por_dsn_load_smoke.py <path>\NAME.DSN [--report out.json]
```

- Exit `0`: every loader-equivalent check passed.
- Exit `1`: at least one check failed; the output and report say which.
- Exit `2`: refusal. The path is not a directory, or `--report` would land
  inside the design folder.

The folder is read only. The report has sorted keys, no timestamps and no
absolute paths, so the same folder gives byte-identical output.

## Tests

`tests/test_por_dsn_load_smoke.py` builds every fixture from synthetic
`geo.Geo.blank` areas written by the real `tools/dsn.py` writer, into `tmp_path`.
No retail data is used. Run with:

```
python -m pytest tests/test_por_dsn_load_smoke.py -q
```
