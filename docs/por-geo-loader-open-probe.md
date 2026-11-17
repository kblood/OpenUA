# Pool of Radiance GEO loader open path (static, observe-only)

**Status: `playable: false`. Archive, requested id, and GEO block identity remain unresolved.**

Tool: [`tools/por_geo_loader_open_probe.py`](../tools/por_geo_loader_open_probe.py). Tests:
[`tests/test_por_geo_loader_open_probe.py`](../tests/test_por_geo_loader_open_probe.py) (11 tests; 10 synthetic and 1 retail-gated). Retail output is written under ignored `data/work/por-geo-loader-open-probe-final/`.

This trace follows the body at START.EXE file `0x8624`, which the existing output-pointer probe labels `open_or_gate_8624`. It asks whether its bytes identify the GEO archive path or the requested block. The answer remains **no**, but the downstream DOS open ABI is now explicit.

## What the pinned bytes establish

The bounded decoder walk made during this analysis reports these five routines as complete. The repeatable probe pins the relevant entry, return, and call-site spans, then recalculates the direct call targets:

| Start file offset | Decoded instructions | Direct edges observed |
|---|---:|---|
| `0x8624` | 118 | near call `0x82B4`; far helper calls including `0AF8:13E2`, `0AF8:1410`, `0AF8:14FB`, `0AF8:1563` |
| `0x82B4` | 63 | near calls `0x8342`, `0x81EA`; far calls `0AF8:13E2`, `0AF8:1410` |
| `0x8342` | 43 | far calls `0AF8:13E2`, `0AF8:1410`, `0AF8:1491`, `0AF8:04A2` |
| `0x81EA` | 48 | near calls `0x81CC`, `0x815C`; far call `0899:0059` |
| `0x0AF8:1410` | 40 | module placement at START file `0xC086` is conditional on the existing module-base evidence |

The path builder at file `0x8624` selects a Pascal string using these instructions at `0x8671..0x8687`:

```text
A0 76 53       mov al,[0x5376]
30 E4          xor ah,ah
BA 1E 00       mov dx,0x1E
F7 E2          mul dx
8B F8          mov di,ax
81 C7 14 26    add di,0x2614
1E 57          push ds; push di
9A 0B 0B F8 0A call 0AF8:0x0B0B
```

So the selected string source is `DS:[0x2614 + low_byte(DS:[0x5376])*0x1E]`. The loader caller at `0x876D` supplies five far-pointer arguments to `0x8624`: record 1 at `[bp+6]`, record 2 at `[bp+0xA]`, the two-byte W word at `[bp+0xE]`, a `.dax` suffix piece at `[bp+0x12]`, and a prefix-plus-`GEO` piece at `[bp+0x16]`. This call-site mapping is a static stack reconstruction; the routine's execution is not shown.

The routine constructs two different strings. The open path combines the prefix-plus-`GEO` piece with `.dax`. A second string combines the selected DS table row, the first character at `DS:0x547D`, and the bytes at `CS:0x05CB`; the `0x82B4` path-check routine uses this as its missing-file display text. That second string is not a suffix selecting the archive. The actual path still cannot be named because the caller's prefix, runtime DS table contents, and selected row index are unknown. The helper identities remain conditional on the module placement.

The byte chain at GAME.OVR `0x1FBA7` reads a far pointer from `DS:[0x49D6]`, loads `ES:[DI+0x624]`, and stores AL to `DS:[0x5376]`, which feeds the filename selector above. This is one verified static writer chain, not proof that it is the only writer, what record field `+0x624` means, or what value reaches the loader.

The open routine probes the composed path through `0AF8:0x1410` with a record-size argument of `0x80`, closes the probe handle, then initializes and opens its two records with record size 1. The wrapper's sibling entry at conditional START offset `0xC08F` selects DOS create (`AH=3Ch`); the traced START call sites do not call that entry. Each file record has a handle at `+0`, state at `+2`, record size at `+4`, and a NUL-terminated path at `+0x30`. The routine reads two bytes into W, adds two, and seeks the second record from that offset. The module helper `0AF8:0x1491` is the close path. These helper interpretations depend on the `0x0AF8` module-to-START placement; no live handle, seek, or read was captured. DOS errors can branch to the error handler rather than return normally.

The downstream wrapper is conditional on the established `0AF8` module base `0xAC76`, which places `0AF8:0x1410` at START file `0xC086`. Its bytes establish:

- `mov al,[DS:0x442C]`, then `mov ah,0x3D`;
- a check that the FCB path at `[ES:DI+0x30]` is nonempty;
- `push ds; lea dx,[di+0x30]; push es; pop ds; xor cx,cx; int 21h; pop ds`.

This is DOS `INT 21h/AH=3Dh` open, with the path at `ES:DI+0x30` and the access mode supplied in AL from `DS:0x442C`. DOS expects a NUL-terminated path. This establishes the interface, not the bytes of the name passed at runtime.

## What remains open

- The DS table entry selected at `DS:0x2614 + index*0x1E`, its runtime index, and the runtime DS value in the `0x8624` context.
- The caller's concrete prefix-plus-`GEO` and `.dax` values, and the runtime contents of the display-message source at `CS:0x05CB`.
- Whether the `DS:[0x49D6]` structure field at `+0x624` is an archive selector, and whether other code also writes `DS:[0x5376]`.
- Whether the path passed to the wrapper is `GEO1.DAX` through `GEO8.DAX`.
- The requested id byte, TOC record, seek base, archive handle, returned bytes, and decoded GEO block.
- Whether this routine is entered from the gameplay map loader.

The runtime pointer capture for START's INT 3Fh handler does not settle these items: that startup call reaches a `retf` no-op and does not show a GEO archive open. See [por-int3f-live-dispatch.md](por-int3f-live-dispatch.md).

## Verification and limits

- START.EXE is pinned to 65,231 bytes and SHA-256 `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd`.
- Synthetic falsifiers change the DOS function, path displacement, INT vector, relative and far call target encodings, and DS table-selector chain. The probe reports selected byte-span checks, not a whole-image decode.
- The retail-gated suite passed with the local POOLRAD install. The tool wrote only under `data/work/` and did not launch an emulator or access GoldBox.
- `0x0AF8` helper placement is conditional on the separate copy-helper evidence; no new runtime placement is claimed here.
- `playable: false`; no conversion rule or GEO-to-area mapping is emitted.

The next evidence that would settle the path is a bounded runtime stop at the DOS `AH=3Dh` call while the GEO loader runs, recording `DS:DX`, `AL`, and the file handle, plus the caller's id and seek base. The existing codewheel gate still prevents the available startup-only DOSBox route from reaching gameplay.
