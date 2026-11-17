# PoR GEO archive selector: bounded static trace (observe-only)

**Status: `playable: false`. The archive, the requested block, the digit mapping and the origin of the selector are not established. The trace found several writers, not one.**

Tool: [`tools/por_geo_archive_selector_probe.py`](../tools/por_geo_archive_selector_probe.py). Tests:
[`tests/test_por_geo_archive_selector_probe.py`](../tests/test_por_geo_archive_selector_probe.py) (18 tests: 17 synthetic falsifiers and verdict/refusal checks, 1 retail-gated anchor; with `OPENUA_POR_INSTALL` set all 18 ran, none skipped). Output is written under ignored `data/work/por-geo-archive-selector-probe/`.

## What was checked, and against what

Inputs are the pinned retail `GAME.OVR` (206,105 bytes, SHA-256 `872964a3…7928614`) and `START.EXE` (65,231 bytes, SHA-256 `d825df2b…60b6a07bd`), read from the install and confirmed unchanged after the run. The pins are the ones in `tools/por_overlay_group_map.py`. Nothing was executed.

Instruction boundaries come from the repository's 16-bit decoder (`tools/por_loadpieces_handler.py`), walked from each `55 89 E5` prologue. GAME.OVR roots are the 675 prologue candidates inside the 35 VROOMM group bodies; START roots are all 132 prologue candidates in the file. Each walk follows branches and fallthroughs and records calls without entering them. Only sites from complete walks are used (131 of 132 START walks are complete; the incomplete one begins at file `0x2F6`, is a false prologue match in the header area, and contributes no sites).

This probe starts from the committed chain in [`por-geo-loader-open-chain-probe.md`](por-geo-loader-open-chain-probe.md) and [`por-geo-selector-reference-probe.md`](por-geo-selector-reference-probe.md). It re-derives the sites it uses from the bytes. It does not depend on their outputs.

## Result in one paragraph

`DS:[0x49D6]` has one decoded store, at GAME.OVR `0x0E620`, immediately after a call to the far allocator `0x0AF8:0x023F` with argument `0x800`. The field at displacement `0x624` has exactly one decoded store and one decoded load, both through `ES:[DI]` with `DI` loaded from `DS:[0x49D6]` immediately before. The store (`0x1FEFE`, in the routine rooted at `0x1FD3E`) writes the zero-extended selector `DS:[0x5376]` into the field. The load (`0x1FBAB`, in the routine rooted at `0x1F5E8`) writes the field's low byte back into `DS:[0x5376]` at `0x1FBB0`. So the field is a save/restore cell for the selector, not an independent source. The selector itself has five direct writers in the two images (two constants in GAME.OVR, the restore from the field, a parameter store and a copy from the one-byte save slot in START), plus two address-immediate passes whose callees are not entered. **No unique origin of the selector exists in the decoded bytes, and no value-to-archive mapping is in them.**

## The far-pointer slot `DS:[0x49D6]`

| Site | Bytes | Instruction | Owning root | Producer (contiguous) |
|---|---|---|---|---|
| GAME.OVR `0x0E620` | `a3 d6 49` | `mov [0x49d6], ax` | `0x0E600` | `call 0x0AF8:0x023F` at `0x0E61B`; `push ax` at `0x0E61A`; `mov ax,0x800` at `0x0E617` |
| GAME.OVR `0x0E623` | `89 16 d8 49` | `mov [0x49d8], dx` | `0x0E600` | segment word, directly after the offset store |

The initializer `0x0E600` allocates four far blocks in one routine: `0x800` into `0x49D2` (at `0x0E607`), `0x800` into `0x49D6` (at `0x0E617`), `0x400` into `0x49DA` (at `0x0E627`) and `0x1E00` into `0x49DE` (at `0x0E637`), and further blocks at `0x5E20` and `0x6A58`. The store pattern (`AX` to the offset word, `DX` to the segment word) is structural. The allocator's unit (bytes or paragraphs), its return convention and whether it zeroes memory are **not established**. If the unit is bytes, a `0x800` block covers the field (`0x624` and `0x625`); this is consistent with the decoded layout, not a proof of it.

The slot is read through `les` 143 times in GAME.OVR; those reads are the consumers of the pointer. Only two of them reach displacement `0x624`, listed below.

## The field at displacement `0x624`

| Site | Bytes | Instruction | Root | Value chain (contiguous) |
|---|---|---|---|---|
| GAME.OVR `0x1FEFE` | `26 89 85 24 06` | `es: mov [di+0x624], ax` | `0x1FD3E` | `mov al,[0x5376]` (`0x1FEF5`), `xor ah,ah` (`0x1FEF8`), `les di,[0x49D6]` (`0x1FEFA`) |
| GAME.OVR `0x1FBAB` | `26 8a 85 24 06` | `es: mov al,[di+0x624]` | `0x1F5E8` | `les di,[0x49D6]` at `0x1FBA7`; sink `mov [0x5376],al` at `0x1FBB0` |

The save is a word store, so the high byte of the field (`0x625`) is written as zero. The restore reads only the low byte. Each run is straight-line code: the save's three instructions (`mov al,[0x5376]`, `xor ah,ah`, `les`) and the restore's `les` followed directly by its load and store are contiguous, with no branch between them.

No other decoded instruction in either image uses displacement `0x624` on any base register (the decoder renders these as `[di+1572]`). No decoded immediate operand of `0x624` appears in the opcode forms the probe checks (ALU, `mov reg,imm`, `add`).

## Writers of `DS:[0x5376]`

| Site | Image / root | Instruction | Source class | Source detail |
|---|---|---|---|---|
| GAME.OVR `0x0E9A3` | GAME.OVR `0x0E600` | `mov [0x5376], 1` | constant | value 1 (with `mov [0x5377], 1` at `0x0E9A8`) |
| GAME.OVR `0x19AE7` | GAME.OVR `0x19AE0` | `mov [0x5376], 3` | constant | value 3 |
| GAME.OVR `0x1FBB0` | GAME.OVR `0x1F5E8` | `mov [0x5376], al` | field low byte | `mov al,es:[di+0x624]` at `0x1FBAB` |
| START `0x089AD` | START `0x089A1` | `mov [0x5376], al` | parameter | `mov al,[bp+6]` at `0x089AA` |
| START `0x089BA` | START `0x089B4` | `mov [0x5376], al` | save-slot copy | `mov al,[0x5377]` at `0x089B7` |

Two further sites pass the address of `DS:[0x5376]` to a callee, so a callee could write it through the pointer. The callee is not entered:

- GAME.OVR `0x1F7C1` (`mov di,0x5376`, in `0x1F5E8`) followed by `call 0x0AF8:0x14FB`.
- GAME.OVR `0x1FF09` (`mov di,0x5376`, in `0x1FD3E`) followed by `call 0x0AF8:0x1502`.

The START procedures at `0x089A1` and `0x089B4` form a save/restore pair for the selector through the one-byte slot `DS:[0x5377]`:

- `0x089A1` (`retf 2`): `mov al,[0x5376]; mov [0x5377],al; mov al,[bp+6]; mov [0x5376],al`. It saves the old selector and sets the selector from its byte parameter.
- `0x089B4` (`retf`): `mov al,[0x5377]; mov [0x5376],al`. It restores the saved selector.

`DS:[0x5377]` has two decoded writers: GAME.OVR `0x0E9A8` (constant 1, in the same routine as the constant-1 selector store at `0x0E9A3`), and START `0x089A7` (`mov [0x5377],al`, directly after `mov al,[0x5376]` at `0x089A4`, which is the save inside the set procedure).

**Neither START procedure has a direct call site.** A byte scan of both images finds no `E8` near call and no `9A` far call whose offset word equals `0x89A1` or `0x89B4`, and no decoded call edge targets them. So their callers, if any, are indirect (a function-pointer or table dispatch) and are **not established**.

## Readers of `DS:[0x5376]`

The reads are classified by the next instructions in straight-line order, so the classes are window associations, not proofs of data flow:

| Class | Count | Examples |
|---|---:|---|
| `row_select_stride_0x1E` (`mov dx,0x1E; mul`) | 3 | START `0x08671` (in the open routine at `0x8624`), GAME.OVR `0x0EB37` (in `0xE600`), `0x1EB6D` (in `0x1EAD2`) |
| `formatter_call_within_16_insns` (a `call 0x0AF8:0x1366` within 16 instructions) | 12 | `0x2F9C5` (root `0x2F9BE`, which the open-chain probe calls the GEO fill procedure), `0x2F715` (root `0x2F6FF`), `0x202E6` (root `0x202BB`), `0x1EEB1`, `0x01945`, and seven more |
| `copied_to_field_0x624` | 1 | GAME.OVR `0x1FEF5` (the save) |
| `compare_immediate` | 1 | `cmp [0x5376],3` at `0x21537` |
| `other` | 2 | GAME.OVR `0x07F1A`; START `0x089A4` (the set procedure's save) |

The `0x0AF8:0x1366` call is the one all twelve formatter-window reads lead into. The probe does not enter it, so whether it turns the selector into a decimal digit is **not established**. Its arguments are decoded only as shape: the selector is zero-extended and pushed as the low word of a 32-bit value, between two other pushes.

## Callers of the routines on this path

| Routine | Decoded near calls | Raw `E8` matches | Raw far offset-word matches |
|---|---:|---:|---:|
| START `0x089A1` (set) | 0 | 0 | 0 |
| START `0x089B4` (restore) | 0 | 0 | 0 |
| GAME.OVR `0x1FD3E` (save) | 1 (from `0x202BB` at `0x203B8`) | 1 | not applicable (above `0xFFFF`) |
| GAME.OVR `0x1F5E8` (restore) | 0 | 0 | not applicable |
| GAME.OVR `0xE600` (allocation and constant 1) | 0 | 0 | 0 |

Callee edges from these routines are recorded: `0x1F5E8` calls `0x1EAD2` at `0x1F9BD` (which reads the selector at `0x1EB6D`), and `0x202BB` calls the save routine at `0x203B8`. The order of these calls relative to the restore is not established. Far-call offset words are segment-relative, so a file offset equal to a far offset word is only a candidate match, and the probe labels it so.

## Claims and status

| ID | Claim | Status |
|---|---|---|
| A1 | `DS:[0x49D6]` has one decoded store, after an allocator call with argument `0x800` (GAME.OVR `0x0E620`) | `bytes_established_decoded` (allocator unit and return convention not established) |
| A2 | The only decoded accesses to displacement `0x624` are one ES store (`0x1FEFE`) and one ES load (`0x1FBAB`), both based on `DS:[0x49D6]` | `bytes_established_decoded` (complete walks only) |
| A3 | The field's store is the zero-extended `DS:[0x5376]`, and its load is written back into `DS:[0x5376]` | `bytes_established_decoded` (a copy cycle; the field's only writer is the selector) |
| A4 | `DS:[0x5376]` has a unique decoded origin | `not_established_not_unique` (constant, parameter, save-slot copy, field low byte) |
| A5 | The START set and restore procedures have no direct call site in either image | `bytes_established_no_direct_sites` (indirect calls not excluded) |
| A6 | The archive digit or area id equals the selector value | `not_established` |
| A7 | The field's content before its first save is zero or known | `not_established` (allocator zeroing not established) |
| A8 | The `0x0AF8:0x1366` formatter turns the selector into a decimal digit | `not_established` (callee not entered) |

## Corrections to the earlier probes

- [`por-geo-loader-open-chain-probe.md`](por-geo-loader-open-chain-probe.md), claim C5 ("`DS:[0x5376]` is fed from `ES:[DI+0x624]` through `DS:[0x49D6]`, one static chain") is refined here. The field is fed from the selector as well as feeding it: the field's only decoded writer is a copy of `DS:[0x5376]`. So the GAME.OVR restore is a copy from a save cell, not an origin. The chain is circular in the decoded code.
- [`por-geo-selector-reference-probe.md`](por-geo-selector-reference-probe.md) reported one dynamic write to `0x5376` among several direct assignments. That remains true. This probe adds that START also writes the selector (`0x089AD` and `0x089BA`), and that the START save and restore pair runs through `DS:[0x5377]`.

## Not established

- The origin of the selector at any GEO load. The candidates are the constants 1 and 3, the caller-supplied parameter to the START set procedure, the save-slot copy, the field's last saved value, and any callee that writes through the passed pointers.
- Which of these runs before a GEO load, or whether the field is zero before its first save.
- Any value-to-archive mapping: no digit literal beside the GEO stem (per the open-chain probe), and no decoded map from selector to `GEO<n>.DAX`.
- The formatter's behaviour at `0x0AF8:0x1366`, the callee of the row routine, the allocator's unit and zeroing, and the DS value.
- The table at `DS:0x2614` (stride `0x1E`) that the row-select readers index.
- Any runtime value or execution.

## Limits

- Decoded prologue roots only. Code reached only from non-prologue entries is not counted, and a computed displacement is not recognized as `0x624`.
- Call edges are recorded and not entered. Writes through a passed pointer (`0x1F7C1`, `0x1FF09`) are unresolved.
- The window classes for reads (`formatter_call_within_16_insns` and the others) are association windows, not argument proofs.
- Raw `E8` and `9A` byte scans are not instruction-aligned. They show the absence of a direct operand, not a call graph.
- Indirect calls through a function pointer or table are not excluded for either START procedure.
- The one START walk that is incomplete (file `0x2F6`) contributes no sites.

## Next discriminating observation

A single live run that stops at `0x1FBB0` (the restore's store to `DS:[0x5376]`, GAME.OVR) and at `0x1FEFE` (the save), recording the value of `DS:[0x5376]`, the word at `ES:[DI+0x624]`, and which of the `0x089A1` or `0x089B4` procedures ran last, would show whether the field carries a value from an earlier constant or a parameter. A dump of the field's bytes before the first save would settle the zeroing question. This probe does not run one.

## Verification

```sh
python -I tools/por_geo_archive_selector_probe.py --install "G:/Games/Pool of Radiance/POOLRAD"   # writes data/work/por-geo-archive-selector-probe/
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_geo_archive_selector_probe.py -q   # 18 passed
python -m pytest tests/test_por_geo_archive_selector_probe.py -q                                                          # 17 passed, 1 skipped
python -m pytest tests/test_por_geo_selector_reference_probe.py tests/test_por_geo_loader_open_chain_probe.py -q          # 37 passed, 1 skipped (their own gate)
```

The tool refuses unpinned binaries, a missing install, and any output outside `data/work`. It re-reads both pinned inputs after the analysis and refuses if either changed.
