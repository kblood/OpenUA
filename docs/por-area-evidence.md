# Pool of Radiance: GEO map-load evidence probe

**Status: static evidence only. `playable: false`. `mappings: []`.**

Tool: `tools/por_area_evidence.py`. Tests: `tests/test_por_area_evidence.py` (26 tests;
the retail anchor runs only when `OPENUA_POR_INSTALL` names the install, or the default
`G:/Games/Pool of Radiance/POOLRAD` is present).

## Question and answer

> Can a GEO archive TOC block be tied to an in-game area, and can the authentic start
> area or start entry be recovered statically or from existing run artifacts?

**Not established.** No mapping meets the proof bar. The probe does narrow the search:
it locates the routine that loads a GEO archive, shows that no recognised overlay stub
exports or calls it, and lists the unknown fields with reasons. Both open questions
(block to area, start entry) need evidence the install and the existing run logs do
not contain (see "What would settle it").

## What the probe measures (retail, 2026-11-17)

Run:

```sh
python tools/por_area_evidence.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-area-evidence/retail --run-artifacts data/work
```

Exit 0. Pins match for `GAME.OVR` and `START.EXE`, and for all eight GEO archives. The
install is unchanged across the run (hashed before and after).

| Item | Value (retail) |
| --- | --- |
| `GAME.OVR` | 206,105 bytes, `872964a3…7928614` (pinned) |
| `START.EXE` | 65,231 bytes, `d825df2b…60b6a07bd` (pinned) |
| GEO TOC blocks | 29 across GEO1..8; ids 0..32 with **8, 11, 12, 19 absent**; no id repeats in the install |
| `SAVGAMA.DAT` / `SAVGAMJ.DAT` | 13,137 bytes each; SHA-256 recorded, **not parsed** (no PoR save-format evidence in the repo) |

### Layout candidate for the GEO literal's owner (not a GEO load routine)

The name literal for the GEO archive sits in `GAME.OVR` at file offset `0x2F994`, a
Turbo Pascal length-prefixed piece `\x03GEO` followed by `\x04.dax`. The same run of
bytes carries the error text "Unable to load geo in Load3DMap". Its layout owner, found
by the probe, is the procedure whose final `retf` ends exactly at `0x2F994`. That procedure is the WALLDEF wrapper (stub 6's entry), not the GEO routine. The literal is read by `mov di,0x109D` at `0x2F9E5`, inside the GEO fill at `0x2F9BE`. A layout candidate is not a use, and this probe does not check use sites:

| Fact | Value |
| --- | --- |
| Owner entry | `GAME.OVR:0x2F6FF` (`push bp; mov bp,sp`; the WALLDEF wrapper), unique among prologues in a 0x2000-byte window |
| Return | `retf 4` at `0x2F991` (four argument bytes) |
| Decoded length | 258 instructions, linear, no decode error |
| Argument compares | `cmp [bp+6],1` at `0x2F706`, `cmp [bp+6],3` at `0x2F70C`, `cmp [bp+8],0` at `0x2F911`, `cmp [bp+8],0xA` at `0x2F958` |
| Locals compared | `[bp-2]`, `[bp-11]`, `[bp-15]`, `[bp-16]` (not arguments) |
| CS-relative operand candidates | `mov r16,imm` then `push cs` at four sites: imm `0xDB4`, `0xDBC`, `0xDC1`, `0xDE8` |
| Single overlay base making all four Pascal strings | **0 of 206,105** tested |
| Near-call byte candidates to the owner (`E8`) | **0** |
| Recognised VROOMM stub groups exporting the owner | **0** |
| Overlay group containing the literal | **uncovered** (no group from the START.EXE stub scan spans `0x2F994`) |

The `[bp+6]` pair reads as a range test on the first argument: `cmp [bp+6],1` at
`0x2F706` with `jb 0x2F712` (to the exit at `0x2F98E`), then `cmp [bp+6],3` at `0x2F70C`
with `jbe 0x2F715` (to continue). That is a decoded reading of the branches, not a proven
meaning: nothing here shows that `[bp+6]` is a GEO number.

The other name literals in `GAME.OVR` (`ECL` x2, `ITEM`, `CHA`, `savgam` x2, `FINAL`,
`WALLDEF`) are listed in the report with their owner status. Four of them have a layout owner, as
does the GEO literal above: `ECL` at `0x190E` (owner `0x1898`), `ITEM` at `0x26D3`
(`0x263E`), one `savgam` at `0x1F565` (`0x1F42C`), and `WALLDEF` at `0x2F6AB` (`0x2EEF4`,
see the next section). The other literals do not: `ECL` at `0x780B`, `CHA` at `0x1EE82`,
the second `savgam` at `0x1FCF1`, and `FINAL` at `0x2E165`. `START.EXE` has the literal
`8X8d1` at `0x723A` with a layout owner (`0x7180`). Its piece-less literal at `0x4785` has
no block start, so no owner is searched for.

Follow-up: the routine ending at `0x1F562` is only a layout neighbour of the `savgam` literal
at `0x1F565`. A pinned PoR trace found no reference to that literal and no save-file reads in
the routine; it registers an in-memory record and calls unresolved far targets. See
[`por-save-loader-trace.md`](por-save-loader-trace.md). The layout-owner label does not identify
the save-file reader.

Correction: an earlier version of this section said that only `ECL`, `ITEM` and one
`savgam` literal have a layout owner among the non-GEO `GAME.OVR` literals, and that the
rest do not. That was true only at the old walk bound of 800 instructions, which hid the
`WALLDEF` owner. The `WALLDEF` result is the only change from raising the bound.

### What this does and does not show

- **Shows:** the layout of the owner procedure (the WALLDEF wrapper: owner, return width, two argument range
  compares), the pins, the 29-block TOC, and that no recognised overlay stub or decoded
  near call reaches it.
- **Does not show:** how the arguments select a TOC block, which block or file is which
  area, or who calls the routine. The four CS-relative operands do not resolve as one
  string set under any single overlay base, so the GEO literal's reference is **not**
  established. The probe does not claim it.
- **Owner link is by layout.** The literal block sits directly after the owner's `retf`.
  No instruction in the owner was matched to the literal's offset. Treat the owner as a
  candidate.

### The WALLDEF layout candidate (not a reference)

`GAME.OVR` 0x2F6AB holds the Pascal piece `\x07WALLDEF` followed by `\x04.dax`. Its layout
owner is the procedure at `GAME.OVR:0x2EEF4`, whose `retf 6` at `0x2F6A8` ends exactly at
the literal's block start. The owner is 827 instructions long, decodes linearly with no
error, and is the only prologue in the 0x2000-byte window whose walk ends there. It is a
layout candidate, labelled as one. Nothing in the probe shows that this procedure reads the
`WALLDEF` literal, calls the GEO fill, or binds any wall art, and the probe does not
decode what a WALLDEF file holds. Its argument compares and outgoing calls are not
recorded here.

The probe missed this owner at the old bound. The walk stopped at 800 instructions before
the `retf`, so the literal reported `no-layout-match`, and the JSON field
`truncated_walks` counted the cut walk. The walk bound is now `MAX_WALK = PROLOGUE_WINDOW`
(0x2000). A walk that ends at a block start from a prologue within the window spans at most
0x2000 bytes, and each instruction is at least one byte, so such a walk never needs more
than 0x2000 instructions. The bound therefore cannot hide a layout owner. On the retail
install, no candidate walk in any literal's window reaches the bound: `truncated_walks` is
0 for every literal. The owner at `0x2F6FF` (the WALLDEF wrapper, 258 instructions) is unchanged.

## External leads (not retail evidence)

`docs/fan-module-hacks.md` (2026-07-14 section) records, from a runtime session with a
Mac-release module, that the start area is `GEO016` (civilized Phlan) and that the slums
are `GEO015`, reached through a transfer cell. This is a runtime observation of a
different release, in its own area numbering. The probe records it and reports only a
presence check: DOS TOC block 15 is in GEO2 (index 1) and block 16 is in GEO8 (index 1).
A shared number between two releases is not a mapping, and no start area is taken from
it here.

## Run artifacts

`--run-artifacts DIR` scans `*.log` files for `GEO<n>.DAX` lines. The only `*.log` under
`data/work` is `por-farcall-probe/run.log`, a tool-output log (it records where the
handler report was written, not DOS file operations). It has no `GEO` line. The DOSBox-X
smoke run recorded in `docs/por-runtime-capture-assessment.md` logged file operations for
`START.EXE` and `GAME.OVR` only, with no `GEO` line, but that log was not kept under
`data/work`, so the probe does not scan it. Other `txt` and `md` artifacts mention `GEO`
file names in hash listings and reports, so they are excluded on purpose. The scan is a
check of the logs that exist, not a census of all runs.

## Unknown fields

| Field | Status | Reason |
| --- | --- | --- |
| `block_to_area` | unknown | The loader is located by layout only; how its arguments select a TOC block is not decoded. |
| `geo_file_to_area_group` | unknown | The file name is assembled from pieces at run time, and the argument that selects the GEO number is not traced to a caller. |
| `start_area` | unknown | No retail start-area value is recorded in the binaries read here. `GAME001.DAT` byte 48 is an OpenUA design field. |
| `start_entry` | unknown | The GoldBox CoK entry-pointer invariant does not hold for PoR (`docs/por-ecl-decoder.md` section 1). |
| `start_facing` | unknown | Not recovered. |

## What would settle it

1. **Callers of the owner.** A capture or decode of the code that calls the procedure at
   `0x2F6FF`, with the argument values at each call. The probe found no `E8` near call
   and no stub export. A far call from another overlay needs its segment word resolved
   at load time, so a capture is the practical route.
2. **Which TOC block is loaded for which area.** A DOSBox-X run that opens `GEO<n>.DAX`
   and records the seek to a TOC block, paired with the area number in use. The
   `data/work` logs contain no such run.
3. **The start entry.** A new-game run that records the party's first map and cell. An
   ECL header pointer is not evidence for PoR (see section 1 of `por-ecl-decoder.md`).
4. **A save-format reading of `SAVGAMA.DAT`.** Parsing it needs PoR evidence for which
   bytes hold the area. Until then it is hashed and not read.

Only a runtime observation or a decoded call with its argument values can turn an
unknown field into a mapping. The probe is built to show such a result when one arrives,
with its offsets and hashes.

## Method (reused)

All decoding uses existing tools, read-only: `por_map.parse_dax` (TOC, the strict
container check), `por_loadpieces_handler` (`decode`, `linear`, flow classes),
`por_farcall_resolve` (`PINNED`, `scan_groups`, `group_containing_code`), and
`por_convert.validate_output_dir` (output refusal). No file in the install is written.

## Not touched

- `tools/por_geo_manifest.py`, its docs and tests, and `tools/por_game001.py`, unchanged.
- `tools/README.md` and the other existing uncommitted `por_*` files, left as found.
- No commit, no push. GoldBox was used as a read-only reference (its `AGENTS.md`,
  `CLAUDE.md` and `docs/engine/ORCHESTRATION.md` were read for the working rules); no PoR
  fact here is inferred from CoK or DoK.

## Tests

```sh
python -m pytest tests/test_por_area_evidence.py -q
```

26 tests, 25 synthetic and 1 retail anchor. The synthetic cases cover the Pascal piece
chain, the layout owner and its refusal of a misplaced block, the argument compares and
return width, near-call decoding, the base test (positive and negative), the no-mapping
output, pin and output refusals, a corrupt archive (exit 1), determinism, install
immutability, no absolute path in outputs, run-artifact scanning, the walk bound equal to
the prologue window, an 827-instruction owner detected under that bound, and the same
owner hidden at a bound of 800 with `truncated_walks` at least 1. The retail anchor
checks the pins, the 29-block TOC, the literal at `0x2F994`, the owner at `0x2F6FF`,
the zero-base result, the empty `mappings` list, the two `external_leads` presence
values, and the `WALLDEF` literal at `0x2F6AB` with owner `0x2EEF4` (827 instructions,
`retf 6` at `0x2F6A8`).

Neighbouring suites still pass: `test_por_geo_manifest.py`, `test_por_map.py`,
`test_por_game001.py`, `test_por_mapping_gate.py` (100 tests).
