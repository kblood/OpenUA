# Pool of Radiance DAX open chain: byte census and memory presence (static, observe-only)

**Status: `playable: false`. The archive, the requested block and the GEO archive digit are not established.** The open ABI and the DS-table selector chain are byte-consistent. The filename that reaches DOS is not resolved.

Tool: [`tools/por_geo_loader_open_chain_probe.py`](../tools/por_geo_loader_open_chain_probe.py). Tests:
[`tests/test_por_geo_loader_open_chain_probe.py`](../tests/test_por_geo_loader_open_chain_probe.py) (26 tests: 24 synthetic with falsifiers, 2 retail-gated; all 26 ran, none skipped). Output is written under ignored `data/work/por-geo-loader-open-chain-probe/`.

## What was checked, and against what

The brief named a handoff. No handoff document exists in the repo: a search of `docs/`, `tools/` and `tests/` for "handoff" and "filename assembly" finds only unrelated notes. The claims tested here are therefore the DAX open and filename chain as the earlier probes record it, mainly [`por-geo-loader-open-probe.md`](por-geo-loader-open-probe.md) under "What the pinned bytes establish". The name-piece and copy-helper facts come from [`por-geo-loader-caller-frame-probe.md`](por-geo-loader-caller-frame-probe.md) and [`por-geo-loader-output-probe.md`](por-geo-loader-output-probe.md), which this probe does not re-derive.

Inputs are the pinned retail START.EXE (65,231 bytes, SHA-256 `d825df2b…60b6a07bd`) and GAME.OVR (206,105 bytes, SHA-256 `872964a3…7928614`), read from the install and unchanged after the run. The two RAM dumps are `data/work/por-live-memory-pid34644/ram-000000-100000.bin` and `data/work/por-wheel-live-capture/ram-000000-100000.bin`, each 1,048,576 bytes at base 0. Neither dump was modified.

## Result in one paragraph

The `.dax` suffix is always a separate length-prefixed Pascal piece (`\x04.dax`). The GEO name is a stem piece `\x03GEO` at GAME.OVR `0x2F994`, followed by the suffix at `0x2F998`. No archive-digit literal sits beside that stem, so the digit in `GEO<n>.DAX` is not in the bytes as a literal. The open wrapper and the selector chain are byte-consistent. In memory, the open routine and its caller body are present at one consistent displacement, while the GAME.OVR bytes that build the GEO name are absent from both dumps. The probe therefore cannot show what name reaches DOS.

## Byte census (file bytes)

A **piece** is `[len][len text bytes]`. A **suffix** is the `\x04.dax` piece. A **stem chain** is the run of DOS-name-like pieces (1 to 8 alphanumerics) that ends just before the suffix length byte. Non-name text in front of a name is rejected and counted, not used as a stem.

| Image | Suffix at | Stem chain | Stem at | Notes |
| --- | --- | --- | --- | --- |
| GAME.OVR | `0x01912` | `ECL` | `0x0190E` | install `ECL1..8.DAX` |
| GAME.OVR | `0x026D8` | `ITEM` | `0x026D3` | install `ITEM1..8.DAX` |
| GAME.OVR | `0x0780F` | `ECL` | `0x0780B` | one rejected non-name chain before it |
| GAME.OVR | `0x1EE86` | `MON+CHA` | `0x1EE7E` | ambiguous: `CHA` alone also parses; install `MON1CHA..MON8CHA.DAX` |
| GAME.OVR | `0x2E16B` | `PIC+FINAL` | `0x2E161` | ambiguous; no install name matches the joined pattern |
| GAME.OVR | `0x2F6B3` | `WALLDEF` | `0x2F6AB` | install `WALLDEF1..8.DAX` |
| GAME.OVR | `0x2F998` | **`GEO`** | **`0x2F994`** | unique; no digit piece in the window; install `GEO1..8.DAX` |
| START.EXE | `0x04785` | (none) | - | bare suffix after `retf`; no stem chain ends before it |
| START.EXE | `0x07240` | `8X8d1` | `0x0723A` | the digit sits inside a literal stem; install `8X8D1.DAX` |

Two points follow from the table. First, the census shows that a digit *can* be a literal (`8X8d1`), so the absence of one beside `GEO` is a specific finding, not a general rule. Second, the two ambiguous rows are flagged rather than decided. The longer reading (`MON+CHA`) is the one the install supports, and the bytes alone do not choose it.

### Install slot check (file names; consistency, not mechanism)

| Stem chain | Names with one digit between pieces | Names with one digit after | Exact `stem.DAX` |
| --- | --- | --- | --- |
| ECL | n/a | 8 | 0 |
| ITEM | n/a | 8 | 0 |
| MON+CHA | 8 | 0 | 0 |
| PIC+FINAL | 0 | 0 | 0 |
| WALLDEF | n/a | 8 | 0 |
| GEO | n/a | 8 | 0 |
| 8X8d1 | n/a | 0 | 1 |

These counts show the stem-plus-one-digit pattern fits the install for GEO, ECL, ITEM, WALLDEF and MON. They do not show that the digit comes from the same place in code. `PIC+FINAL` fits neither pattern, so those two pieces are not one name with one digit slot.

## Chain checks (file bytes)

All of these are byte matches at the stated file offsets in the pinned binaries.

- Open routine `START 0x8624` prologue `55 89 e5 81 ec 56 04 c4 7e 16`.
- Caller body `START 0x876D` prologue `55 89 e5 81 ec 3e 02 c4 7e 14`.
- Selector chain `START 0x8671`: `mov al,[0x5376]; xor ah,ah; mov dx,0x1E; mul dx; mov di,ax; add di,0x2614; push ds; push di; call 0AF8:0B0B`. This gives the DS-table row `DS:[0x2614 + low(DS:[0x5376])*0x1E]`. The far-call segment word is part of the match.
- Open wrapper `0xC086` (module base `0xAC76`, conditional): `mov al,[0x442C]; mov ah,0x3D; ...`, with the path guard at `0xC0BD` and the open sequence at `0xC0C4` (`push ds; lea dx,[di+0x30]; push es; pop ds; xor cx,cx; int 21h; pop ds`, so `INT 21h` is at `0xC0CC`). This is DOS `AH=3Dh` open on the path at `ES:DI+0x30`.
- Selector writer `GAME.OVR 0x1FBA7`: `les di,[0x49D6]; mov al,es:[di+0x624]; mov [0x5376],al`. This is one static writer chain, not proof that it is the only writer.
- Byte scan of START for `E8` near-call and `9A` far-call patterns to `0x8624`: exactly one raw near-call-pattern candidate, at `0x87CC`, and no far-call-pattern candidate. This scan is not instruction-aligned or a decode, so it does not prove a call edge. The caller-frame probe places a body span from `0x876D` to its `retf 0x12` at `0x899E`; the candidate lies inside that span.

## Memory presence (RAM dumps, unknown instant; not execution)

A window is searched in each dump with far-call segment words wildcarded, since the loader relocates them. A window is **unique**, **ambiguous** (more than one hit) or **absent**.

| Window | File offset | Dump 1 | Dump 2 | Displacement (dump minus file) |
| --- | --- | --- | --- | --- |
| START open routine | `0x08624` | unique `0x20C4D` | unique `0x20C4D` | `0x18629` |
| START caller body | `0x0876D` | unique `0x20D96` | unique `0x20D96` | `0x18629` |
| START selector chain | `0x08671` | ambiguous `0x20C9A`, `0x3C0B4` | same | `0x18629` at `0x20C9A`; the other hit is not on it |
| START open wrapper (conditional) | `0x0C086` | unique `0x249F0` | unique `0x249F0` | `0x1896A` |
| START open sequence with `INT 21h` (conditional) | `0x0C0C4` | unique `0x24A2E` | unique `0x24A2E` | `0x1896A` |
| START piece `8X8d1` | `0x0723A` | unique `0x1F861` | unique `0x1F861` | `0x18627` |
| GAME.OVR GEO literal | `0x2F994` | absent | absent | - |
| GAME.OVR GEO fill procedure | `0x2F9BE` | absent | absent | - |
| GAME.OVR GEO loader body | `0x2F6FF` | absent | absent | - |
| GAME.OVR ECL literal | `0x0190E` | ambiguous `0x40FF8`, `0x46808` | same | - |
| GAME.OVR selector writer | `0x1FBA7` | absent | absent | - |

Readings, with their limits:

- The START code windows (open routine, body, and the selector chain's near hit) sit at one displacement, `0x18629`. That displacement comes from the two unique anchors only.
- The module wrapper at `0xC086` sits at a different displacement, `0x1896A`. That fits a separate module placement, but this probe does not prove it.
- The `8X8d1` literal sits two bytes off the anchor displacement. The probe reports the difference and does not interpret it.
- None of the GAME.OVR windows is present in either dump. The overlay bytes that build the GEO name were not resident at either instant. Absence means these dumps do not show them, not that the code never runs.
- The ECL literal has two hits, so it is not used for any claim.

## Claims and status

| ID | Claim | Status |
| --- | --- | --- |
| C1 | The open is DOS `AH=3Dh` on the path at `ES:DI+0x30` | `bytes_established_conditional` (wrapper `0xC086`, module base conditional) |
| C2 | The path row is `DS:[0x2614 + low(DS:[0x5376])*0x1E]` | `bytes_established_runtime_unproven` (DS and the table contents are not read) |
| C3 | The GEO stem and `.dax` suffix exist as Pascal pieces in GAME.OVR | `established_file_bytes` (`0x2F994`, `0x2F998`) |
| C4 | The archive number is a literal digit piece beside GEO | `not_established_no_digit_literal` |
| C5 | `DS:[0x5376]` is fed from `ES:[DI+0x624]` through `DS:[0x49D6]` | `bytes_established_single_chain_runtime_unproven` |
| C6 | A raw E8 byte pattern to `0x8624` occurs at `0x87CC` inside the `0x876D` body span | `byte_pattern_candidate` (not an instruction-decoded call edge) |
| C7 | The GEO fill procedure (`GAME.OVR 0x2F9BE`) runs and pushes the pieces | `not_established_overlay_not_resident` |
| C8 | The file opened is `GEO<n>.DAX` for `n` in 1..8 | `not_established` |

The probe's `handoff_status` is `bytes_consistent_runtime_open_unresolved`. It means the byte checks for C1, C2, C3 and C5 match, while C6 is only a raw byte-pattern candidate; runtime claims C4, C7 and C8 are unresolved. It does not mean the GEO filename was observed.

## Not established

- The DS value at the open routine. The `mov ax,imm; mov ds,ax` immediates in the file (for example `0x8AE` at `0x9B5B`) do not match the dump bytes at those offsets, so DS cannot be read from these dumps. This was checked, not decoded.
- The DS table at `DS:0x2614` and the prefix at `DS:0x547C`, so the selected row and prefix are unknown.
- Whether the digit comes from a runtime value (the id, a word the caller passes, or table data). No literal supplies it.
- The bytes DOS receives in a running open, and the handle, seek and read that follow.
- Whether the GEO fill or loader runs at any instant.
- Any archive, block, area or playability.

## Limits

- Static and byte-level. Nothing was executed, no emulator or DOSBox run was made, and the codewheel and GoldBox were not used.
- "Present in a dump" means memory-present at an unknown instant. The dumps carry no SS, SP or instant label.
- Code offsets use the same file-offset convention as [`por-geo-loader-open-probe.md`](por-geo-loader-open-probe.md). The module base `0xAC76` and the body identity at `0x876D` are that probe's conditional mappings.
- The `E8` and `9A` scan finds direct calls only. An indirect call to `0x8624` would not appear.
- The name-like filter is a heuristic. Its effect is reported (rejected count, ambiguity flag), not hidden.
- Install-name matches show consistency with a digit slot, not the mechanism that chooses the digit.

## Next discriminating observation

One live stop at the open wrapper's `INT 21h` (START.EXE file `0xC0CC`, the wrapper entry `0x0AF8:0x1410` at file `0xC086`) during a GEO load. Read `DS:DX` as the NUL-terminated path, `AL` as the access mode, and the returned handle. A dump taken while the GAME.OVR fill is resident would also show the pieces in place. Until a run supplies that, `GEO<n>.DAX` remains unestablished. This probe does not run one.

## Verification

```sh
python -I tools/por_geo_loader_open_chain_probe.py     # exit 0; writes data/work/por-geo-loader-open-chain-probe/
python -m pytest tests/test_por_geo_loader_open_chain_probe.py -q   # 26 passed
python -m pytest tests/test_por_geo_loader_open_probe.py -q         # 11 passed (neighbour regression)
```

The tool refuses unpinned binaries, a dump whose name does not match its length, an explicit dump that is missing, and any output outside `data/work` or inside the install. It re-reads both pinned inputs after the run and refuses if either changed.
