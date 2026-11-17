# PoR GEO selector-global reference census

**Status: bounded static census only. `playable: false`; archive and area mappings remain unresolved.**

Tool: [`tools/por_geo_selector_reference_probe.py`](../tools/por_geo_selector_reference_probe.py). Tests:
[`tests/test_por_geo_selector_reference_probe.py`](../tests/test_por_geo_selector_reference_probe.py). Retail output is under ignored `data/work/por-geo-selector-reference-probe-final/`.

This follow-up checks the context around the selector feed reported by
[`por-geo-loader-open-probe.md`](por-geo-loader-open-probe.md). That probe established a byte chain at
GAME.OVR `0x1FBA7` which reads through `DS:[0x49D6]`, loads `ES:[DI+0x624]`, and stores AL at
`DS:[0x5376]`. The current probe asks how broadly these globals are referenced in decoded code and
whether the one dynamic assignment is exclusive.

## Retail result

Both executables matched their pinned size and SHA-256. The probe scanned candidate VROOMM
descriptors in START.EXE, then walked every `55 89 E5` prologue candidate inside those code ranges
with the repository 16-bit decoder. It found 35 candidate descriptors and 675 roots; all 675 bounded
walks completed. Near/far calls are recorded by the decoder but their targets are not entered.

| DGROUP address | Decoded direct sites | Pointer reads | Writes | Other reads/compares |
|---|---:|---:|---:|---:|
| `0x49D6` | 144 | 143 | 1 | 0 |
| `0x49D8` | 1 | 0 | 1 | 0 |
| `0x5376` | 20 | 0 | 3 | 17 |

The decoded `0x49D6` write is at `0x0E620`; the paired segment-word write to `0x49D8` is at
`0x0E623`. In the same decoded routine, GAME.OVR `0x0E617` loads the allocator argument `0x0400`
and calls `0x0AF8:0x023F`, then stores the returned words in `0x49D6/0x49D8`. This establishes the
instruction sequence, not the allocation unit, the allocated object's schema, or the meaning of
its field at `+0x624`.

The three decoded direct writes to `0x5376` are:

| Site | Bytes | Instruction effect |
|---|---|---|
| `0x0E9A3` | `C6 06 76 53 01` | write constant `1` |
| `0x19AE7` | `C6 06 76 53 03` | write constant `3` |
| `0x1FBB0` | `A2 76 53` | write AL, loaded by the instruction at `0x1FBAB` from the structure at `DS:[0x49D6]` plus `0x624` |

There are also two decoded `mov DI,0x5376` address immediates at `0x1F7C1` and `0x1FF09`. They do
not themselves read or write the global. Each is followed by code passing `DS:DI` to another
routine, so indirect writes through those calls remain possible and are outside this census.

## Evidence boundary

The byte census shows that `0x1FBA7` is not the only direct assignment to `0x5376`. It does not say
which assignments run before `START:0x8624`, what those values select, or whether they identify
`GEO1.DAX` through `GEO8.DAX`. `0x49D6` is a widely read far-pointer slot; its one decoded initializer
does not identify the pointee. The field at `+0x624` remains unnamed.

Coverage is bounded to candidate prologue roots inside candidate group bodies. A signature may
occur in data, calls are not followed, indirect references are not resolved, and unwalked bytes may
contain more references. Therefore the counts are not a whole-image proof of exclusivity or
absence. No runtime value, execution, archive, requested block, or area mapping is established.

No converter behavior changes. GoldBox and retail files were read-only; before/after input pins
matched. No emulator or copy-protection input was used.
