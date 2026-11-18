# PoR WALLDEF loader-to-table link probe

**Status: static byte link only.** This probe connects the partial group-29
WALLDEF-name path to a shared far-pointer slot and a 156-byte consumer. It does
not establish execution, a selected DAX archive or block, or an art mapping.

## What the bytes establish

- START descriptor `0x3DD7` identifies a partial VROOMM group at
  `GAME.OVR:0x2E8F7`. Stub 6 is structurally valid and places its candidate
  entry at `GAME.OVR:0x2F6FF`; the descriptor as a whole remains partial.
- The entry references the Pascal pieces `WALLDEF` at file `0x2F6AB` and
  `.dax` at `0x2F6B3`. At `0x2F735` and `0x2F74F`, it passes their group-relative
  offsets to the string-copy helper `0AF8:0B0B`.
- At `0x2F715`, the code reads `DS:0x5376`. At `0x2F767`, it calls
  `0802:0716`. The body divides a returned size by `0x030C` (780) and checks
  the quotient against 4.
- The loader body uses `LES DI,[0x6A58]` at `0x2F7EE`, `0x2F8B6`, and
  `0x2F8EE`. The neighboring consumer at `0x2EB08` uses the same far-pointer
  slot, scales an index by `0x009C` (156), and reads through it at `0x2EBAB`
  and `0x2EBDC`.
- The static owner at `0x2EEF4` has 18 decoded near calls to that consumer.
  This records an edge in the bytes; it does not show the owner or consumer
  running.
- `780 = 5 × 156`, so the sizes are structurally consistent with five
  consumer slices per loader-sized record. The copy direction remains
  conditional on the separately decoded helper ABI.

## What remains open

- No established caller or runtime observation shows stub 6, the loader body,
  owner `0x2EEF4`, or the consumer executing.
- The live selector value, archive filename, requested block id, and runtime
  contents of `DS:0x6A58` are unknown.
- The evidence does not bind any WALLDEF record or 156-byte slice to an 8X8D
  block, tile, OpenUA texture group, or screen.
- The partial-group classification and the runtime placement model remain
  hypotheses. No mappings or events are emitted.

## Reproduce

```powershell
tools/.venv/Scripts/python.exe -I tools/por_walldef_table_link_probe.py `
  --install "G:/Games/Pool of Radiance/POOLRAD" `
  -o data/work/por-walldef-table-link-probe/retail
tools/.venv/Scripts/python.exe -I -m pytest `
  tests/test_por_walldef_table_link_probe.py -q -p no:cacheprovider
```

The retail run checked pinned `GAME.OVR` and `START.EXE`, re-read both inputs
after analysis, and reported 22/22 checks. The focused suite reported 12
passed and one retail-gated skip when `OPENUA_POR_INSTALL` was unset. The JSON
and Markdown output are written under `data/work/`.

The probe is diagnostic evidence only. It does not load the game, access
GoldBox data, or claim that the shared table is a WALLDEF table at runtime.
