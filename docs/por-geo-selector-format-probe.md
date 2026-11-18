# PoR GEO selector: formatter, fill arguments and filename dataflow (static)

**Status: `playable: false`. The formatter's behaviour is established from bytes. The formatted digit reaches the composed open path by static dataflow, conditional on the module, loader and wrapper identities. The prefix piece `DS:[0x547C]`, the runtime selector values and any block/area mapping are not established.**

Tool: [`tools/por_geo_selector_format_probe.py`](../tools/por_geo_selector_format_probe.py). Tests:
[`tests/test_por_geo_selector_format_probe.py`](../tests/test_por_geo_selector_format_probe.py) (19 tests: 17 synthetic falsifiers and refusal checks, 2 retail anchors). With `OPENUA_POR_INSTALL` set all 19 pass; without it 17 pass and 2 skip. Output is written under ignored `data/work/por-geo-selector-format-probe/` (`.json` and `_report.md`), deterministic (the retail test compares two runs byte for byte).

Inputs are the pinned `GAME.OVR` (206,105 bytes, SHA-256 `872964a3…7928614`) and `START.EXE` (65,231 bytes, SHA-256 `d825df2b…60b6a07bd`), re-read after the run and unchanged. Nothing is executed. The "model" below is a hand reading of the decoded instructions, tied to byte checks that pin each routine by SHA-256 of its decoded span. It is not a CPU emulator.

## Answers

1. **Formatter behaviour (bytes): decimal, not hex.** The routine at `0x0AF8:0x1366` (START file `0xBFDC`, retf 0x0C) takes a signed 32-bit value (bp+14 low, bp+16 high), a minimum count (bp+12), a maximum width (bp+6), and a far destination (bp+8/bp+10). Its near helper at file `0xBECA` writes `-` for negatives and the decimal digits, from the powers-of-ten table at `CS:0x12A6` (file `0xBF1C`: ten u32 values, 10^9 down to 10^0). The formatter writes a Pascal length byte, then `width − copied` spaces, then the first `min(len, width)` characters. **With width 1 the field is two bytes: `01` and the leading character of the decimal text.**
2. **Incorporated into the open path: yes, by static dataflow.** The fill passes the one-character field to `0x0AF8:0x0B98`, which appends it to `GEO` (the literal `\x03GEO`). The result, `GEO<d>`, is the loader's P20. The loader and the open routine carry it to the path field of a file record, and the DOS open wrapper reads that field. The chain is verified at the byte level. It depends on the module base `0xAC76`, the loader identity `0x876D` and the wrapper at file `0xC086`, all conditional (the literals also rely on the group base `0x2E8F7`). The digit is therefore in the composed path bytes handed to the open. **The full filename is not established**, because the first piece, `DS:[0x547C]` (copied before `GEO<d>`), is DS data that the bytes do not give.
3. **Selector values and guards.** The decoded writers of `DS:[0x5376]` are two constants, a field restore and two START routes (table below). The literal values are **1** (GAME.OVR `0x0E9A3`, in the initializer `0x0E600`) and **3** (GAME.OVR `0x19AE7`, in `0x19AE0`). Both sit on every path from their routine's entry to a return. The field restore (`0x1FBB0`) is conditional: it sits behind `jz 0x1F643` (taken to `0x1F684`), `jz 0x1F689` (taken to `0x1F68E`) and `jnz 0x1F693`. The START set routine (`0x089A1`) stores its byte parameter, and the callers of that routine are not decoded. **No decoded direct caller exists** for any writer root or for the fill (`0x2F9BE`). Callers through function pointers, and the callees of the two address passes (`0x14FB`, `0x1502`), are not established.
4. **Mappings.** A **selector → stem-digit formula** is established from the bytes: the stem is `GEO<d>.DAX` where `d` is the leading decimal digit of the selector (`0`–`255`). This is a formula, not a table, and it is many-to-one (selectors 1 and 10–19 all name `GEO1`). The formula gives `GEO0` and `GEO9` for some values, and the pinned install has neither (it has `GEO1.DAX`–`GEO8.DAX`). **No selector → block or area mapping is established.** The table at `DS:[0x2614 + 30·selector]` is read into a prompt string only (see the path-check section), not into the name.

## Correction to the brief

The brief placed the helper's near target at `0x0ECA`, mapped to file `0xBECA`. Under the `0x0AF8` base `0xAC76` used everywhere in the PoR probes, file `0xBECA` is in-module offset `0x1254`, not `0x0ECA` (`0xAC76 + 0x0ECA = 0xBB40`). The file address itself is right: the `rel16` call at file `0xBFED` (`E8 DA FE`) lands on `0xBECA` regardless of base. The `0x0ECA` label does not fit the `0xAC76` model and is not used here.

The earlier [`por-geo-archive-selector-probe.md`](por-geo-archive-selector-probe.md) left the formatter's behaviour as "not established" (claim A8). The bytes now establish it (answer 1). That file is not edited.

## The fill: arguments (GAME.OVR `0x2F9BE`, group base `0x2E8F7`)

| Argument | Value | Bytes |
|---|---|---|
| value low word (bp+14) | selector, zero-extended (`mov al,[0x5376]; xor ah,ah`) | `0x2F9C5`–`0x2F9CD` |
| value high word (bp+16) | `0` | `0x2F9CA`–`0x2F9CC` |
| min count (bp+12) | `0` | `0x2F9CE`–`0x2F9D0` |
| destination (bp+8/10) | `SS:[bp-10]` | `0x2F9D1`–`0x2F9D4` |
| max width (bp+6) | `1` | `0x2F9D6`–`0x2F9D9` |

The fill reads the selector before any branch. Its pieces for the loader are then built in the frame: `SS:[bp-267]` = `GEO` + formatter output (`0x2F9DF`–`0x2F9F4`), and `SS:[bp-272]` = `.dax` (`0x2F9F9`–`0x2FA04`). Both are left on the stack by the copy helpers, and the loader call `0x0802:0x0716` (`0x2FA17`) consumes them as P20 and P16.

The literals are at file `0x2F994` (`\x03GEO`) and `0x2F998` (`\x04.dax`). This is group base `0x2E8F7` plus CS-relative `0x109D` and `0x10A1`. The group base comes from the overlay group map (group-relative addressing). That mapping is conditional, but the literal bytes match at both places.

## Copy, append and clamp helpers (module `0x0AF8`, base `0xAC76`)

| Helper | File | Semantics (decoded) | Stack effect |
|---|---|---|---|
| `0x0B0B` | `0xB781` | Pascal copy: length byte and characters, no clamp | pops source (retf 4), leaves destination |
| `0x0B98` | `0xB80E` | Pascal append: destination length += source length; source chars after old content | pops source (retf 4), leaves destination |
| `0x0B25` | `0xB79B` | Pascal copy clamped to `min(length, CL)`, `CL` the low byte of the count word | pops all (retf 10) |
| `0x13E2` | `0xC058` | file record: `+0` 0, `+2` 0xD7B0, `+4..+0x2F` 0, path at `+0x30` (≤79), NUL | pops both (retf 8) |

The "leaves destination" behaviour is why the fill's two pieces survive to the loader. It is the caller-frame probe's model, now confirmed by the helpers' bytes (`retf 4` pops only the source).

## Loader and open path (conditional identities)

| Step | Site (START file) | Effect |
|---|---|---|
| Loader body | `0x876D` (identity of `0x0802:0x0716`, conditional) | copies P20 (`GEO<d>`) and P16 (`.dax`), clamp 20, into local copies; `0x0B0B` copies `DS:[0x547C]` (prefix) and `0x0B98` appends the P20 copy (`0x87A5`–`0x87AF`) |
| Call to open | `0x87CC` | near call `0x8624` with five far pointers: prefix+`GEO<d>` (P_a), `.dax` (P_b) and three others |
| Open routine | `0x8624` | copies P_a and P_b (clamp 40), builds `bp-341` = P_a + P_b = prefix + `GEO<d>` + `.dax`. Builds row text from `DS:[0x2614 + 30·selector]`, `DS:[0x547D]` and `CS:0x05CB` into `bp-853`. Calls `0x82B4` with `bp-341`, `bp-853` and `DS:[0x557C]` |
| Path check | `0x82B4` | copies name (clamp 40) to `bp-42`; calls the name probe `0x8342`; on the prompt branch only, uses the row text (`lea [bp-83]` at `0x82FB` → `0x81EA`) |
| Name probe | `0x8342` | copies name (clamp 40); `0x13E2` writes it to a record at `bp-170`; `0x1410` with record size `0x80` (probe); `0x1491` (close) |
| Open | `0x82B4` (second use) | `0x13E2` writes the name to the caller's record `bp+6`; `0x1410` with size 1 |
| Wrapper | `0x0AF8:0x1410` = START file `0xC086` (conditional) | checks record state `[di+2] == 0xD7B0`; path at `[di+0x30]` non-empty; `mov ah,0x3D`; `lea dx,[di+0x30]`; `int 21h` at `0xC0CC` |

The wrapper's state check matches the record writer's `0xD7B0`, which ties the record path to the wrapper. The wrapper's `INT 21h` is at file `0xC0CC`, as the open-chain probe says.

**The row text is not in the path.** It reaches only the prompt. In `0x82B4`, the only `lea di,[bp-83]` sites are the copy at `0x82D2` and the prompt argument at `0x82FB`, which the probe pins. The name at `0x82B4`/`0x8342` comes from `bp+16` (`bp-341`), not from the row.

## Claims

| ID | Claim | Evidence |
|---|---|---|
| F1 | The formatter writes decimal text (signed 32-bit, `-` first) in a Pascal field; spaces are written before digits | `bytes_established` (span digests of formatter and helper; table values) and `model_from_decoded_bytes` |
| F2 | With width 1 the field is `01` + the leading character of the decimal text | `model_from_decoded_bytes` from F1; the fill's `[bp+6]=1` is `bytes_established` |
| F3 | The fill passes the selector zero-extended, min 0, width 1 | `bytes_established` (sites `0x2F9C5`–`0x2F9DA`) |
| F4 | The digit is in the composed path: `GEO<d>` is the P20 piece; the loader and open routine carry it to `bp-341` and the record path | `bytes_established` (copy/append sites) with `bytes_established_conditional` (module base `0xAC76`, loader `0x876D`, wrapper `0xC086`, group base `0x2E8F7`) |
| F5 | The wrapper opens the record path with DOS `AH=3Dh` | `bytes_established_conditional` (wrapper bytes at `0xC086`–`0xC0CC`) |
| F6 | The full filename is `<DS:[0x547C] piece>GEO<d>.dax` (clamp 40) | `not_established` (DS value); the form is conditional on F4 |
| F7 | Literal selector values assigned: 1 (`0xE600`) and 3 (`0x19AE0`); both on every path from their routine's entry | `bytes_established` (sites, must-pass check), `not_established` for callers |
| F8 | The field restore (`0x1FBB0`) is conditional | `bytes_established` (avoid-path decisions) |
| F9 | The START set routine stores its byte parameter; the restore routine copies `DS:[0x5377]` | `bytes_established`; callers `not_established` |
| F10 | No decoded direct caller of any writer root or of the fill | `bytes_established` (decoded and raw `E8` scans, within prologue roots) |
| F11 | The selector → stem digit is the leading decimal digit (formula) | `model_from_decoded_bytes` from F2, conditional on F4 |
| F12 | The stem set is `GEO0`–`GEO9`; the install has `GEO1`–`GEO8` | `bytes_established` (install listing, presence only) |
| F13 | No selector → block or area mapping; the row table feeds only the prompt | `bytes_established` (path check sites), `not_established` for the table's contents |

## Writers of `DS:[0x5376]` and `DS:[0x5377]`

| Site | Slot | Source | Root | Must pass entry | Decoded direct callers |
|---|---|---|---|---|---|
| GAME.OVR `0x0E9A3` | `0x5376` | constant 1 | `0x0E600` | True | none |
| GAME.OVR `0x19AE7` | `0x5376` | constant 3 | `0x19AE0` | True | none |
| GAME.OVR `0x1FBB0` | `0x5376` | field low byte | `0x1F5E8` | False (avoid path: `jz 0x1F643`→`0x1F684`, `jz 0x1F689`→`0x1F68E`, `jnz 0x1F693` fall-through) | none |
| GAME.OVR `0x0E9A8` | `0x5377` | constant 1 | `0x0E600` | True | none |
| START `0x089AD` | `0x5376` | parameter `[bp+6]` | `0x089A1` | True | none |
| START `0x089BA` | `0x5376` | copy of `DS:[0x5377]` | `0x089B4` | True | none |
| START `0x089A7` | `0x5377` | copy of selector | `0x089A1` | True | none |

Address passes (`mov di,0x5376`, not entered): GAME.OVR `0x1F7C1` → `0x0AF8:0x14FB`; GAME.OVR `0x1FF09` → `0x0AF8:0x1502`. Writes through those pointers are not established.

Scope: direct-addressed writes (`A2`, `88`/`89` with a direct operand, `C6`/`C7`) in complete prologue-rooted walks of both images (675 GAME.OVR roots and 132 START roots, all complete for GAME.OVR). Indirect writes through pointers are outside that scope.

## Digit mapping

Digit counts over selector values 0–255: `0`:1 (value 0), `1`:111 (1, 10–19, 100–199), `2`:67 (2, 20–29, 200–255), and 11 each for `3`–`9`. Files named by some value and absent from the install: `GEO0.DAX`, `GEO9.DAX`. Selector values 1 and 3, the two literal writes, name `GEO1.DAX` and `GEO3.DAX`, both present.

## Not established

- The runtime value of `DS:[0x5376]` at any fill, and which values the parameter route and the field restore can carry at runtime.
- The DS value, the prefix piece `DS:[0x547C]` and its length, `DS:[0x547D]`, `DS:[0x557C]`, and the contents of the table `DS:[0x2614]`.
- Which callers run the fill, the initializer `0x0E600`, `0x19AE0`, `0x1F5E8`, or the START set and restore routines, including indirect callers and the overlay dispatch to the fill.
- The callees `0x0AF8:0x14FB` and `0x0AF8:0x1502`, and any write they make through the passed pointers.
- The semantics of `0x81EA`, `0x1491`, `0x04A2` and the DOS result, and the retry and prompt control flow in `0x82B4`.
- Whether the module base `0xAC76` and the loader identity `0x876D` hold at runtime. The chain is conditional on them.
- Anything about the archive contents or the block and area meanings of the GEO files.

## Next discriminating observations

1. Live stop at the formatter's `retf` (START file `0xC024`) on the fill's call: expect `[bp+6]=1`, `[bp+12]=0`, `[bp+14]=selector`, `[bp+16]=0`, and `SS:[bp-10]` = `01 d`.
2. Live stop at the wrapper's `int 21h` (file `0xC0CC`), reading `DS:DX` as the path: expect `prefix + GEO<d>.DAX`. This settles F4 and F6 together.
3. Read `DS:[0x547C]` and `DS:[0x5376]` at the fill's entry (`0x2F9BE`): settles the prefix and the selector value of that load.
4. Stop at `0x0E9A3`, `0x19AE7` and `0x089AD` recording the return address and the stack's near or far frame, to identify the callers of the writer roots.

## Verification

```sh
python -I tools/por_geo_selector_format_probe.py --install "G:/Games/Pool of Radiance/POOLRAD"   # wrote ... (checks=94 failed=0), exit 0
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_geo_selector_format_probe.py -q   # 19 passed
python -m pytest tests/test_por_geo_selector_format_probe.py -q                                                          # 17 passed, 2 skipped
```

Probe result: 94 byte checks, 0 failed. Coverage: 675 of 675 GAME.OVR prologue walks complete, 132 START roots, the fill's walk complete, fill group base `0x2E8F7`. The probe refuses unpinned or missing inputs (exit 2, with no output written) and any output outside `data/work` or inside the install.

## Files and side effects

- New, untracked (parent to commit): `tools/por_geo_selector_format_probe.py`, `tests/test_por_geo_selector_format_probe.py`, `docs/por-geo-selector-format-probe.md`.
- New, ignored output: `data/work/por-geo-selector-format-probe/por_geo_selector_format_probe.json` and `por_geo_selector_format_probe_report.md`.
- Reused read-only: `por_loadpieces_handler` (decoder), `por_overlay_group_map` (pins, descriptors, install lookup), `por_geo_archive_selector_probe` (`Image`, selector writes, callers, address passes, prologue roots).
- No edits to existing source, tests or docs. No emulator, DOSBox, GameLink, retail-file write, GoldBox access, or CoK/other-title rule. No copy-protection bypass.
