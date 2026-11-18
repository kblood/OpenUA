# Pool of Radiance: the far module targets 0x0AF8:0x023F and 0x0AF8:0x0254 (static, conditional)

**Status: STATIC-PROBE-ONLY. `playable: false`. `executed: not_established`.** Answer: **the two targets are identified by bytes, conditional on the module base and the live module segment, and their wrappers and the wall-helper call shapes are consistent with an allocate/release pair.** Nothing here shows that either target runs, what DS holds, or that the F table is initialised at run time.

Follows [por-wall-0111-target-probe.md](por-wall-0111-target-probe.md), which left `0x0AF8:0x023F` and `0x0AF8:0x0254` unidentified and asked for their return and size conventions (its "Next discriminator", item 1). The companion [fill/callers probe](por-wall-0111-fill-callers-probe.md) now resolves the `0x16A8` fill body and classifies two additional START call frames; it does not establish runtime use or pointer identity. This probe uses the module base and live segment already measured in [por-geo-copy-helper-probe.md](por-geo-copy-helper-probe.md), which identified the same module for the copy helper `0x0AF8:0x1685`.

`tools/por_wall_0111_module_target_probe.py` is read-only and stdlib-only; it reuses `por_geo_copy_helper_probe` (pins, handler base, dump anchor), `por_overlay_group_map` (`Dump`) and `por_loadpieces_handler` (16-bit decoder). `tests/test_por_wall_0111_module_target_probe.py` has 22 synthetic tests (each with a mutated-byte falsifier) and one retail test gated on `OPENUA_POR_INSTALL`.

## Usage

```sh
python tools/por_wall_0111_module_target_probe.py --install data/work/por-geo-run/POOLRAD \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-wall-0111-module-target-probe
OPENUA_POR_INSTALL="data/work/por-geo-run/POOLRAD" python -m pytest tests/test_por_wall_0111_module_target_probe.py -q
```

Output: `data/work/por-wall-0111-module-target-probe/por_wall_0111_module_target_probe.json` (schema `openua.por-wall-0111-module-target-probe` v1, sorted keys, no timestamps, no absolute paths). Two runs are byte-identical. Exit `0` = every self-check matched; exit `1` = the report was written but one or more self-checks failed; exit `2` = named refusal (unpinned input, module anchor not unique at load `0x1866`, output outside `data/work`, output inside the install). The JSON records `self_checks_passed`. The tool writes nothing to the install.

## Pinned inputs and the module mapping

| Input | Bytes | Note |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | SHA-256 `872964a3…7928614`, pin matched |
| `START.EXE` | 65,231 | SHA-256 `d825df2b…60b6a07bd`, pin matched |
| RAM dumps | 1,048,576 each | the two existing captures (`por-live-memory-pid34644`, `por-wheel-live-capture`), base 0 |

- **Module file base `0xAC76`**: the routine-B handler pattern `b8 d0 00 83 c4 06 eb 03` occurs once in START (file `0xAD4D`), at module offset `0xD7`. Unique.
- **Live module segment `0x235E`** = `0x0AF8 + 0x1866`. The load `0x1866` is measured from the module's 16-byte anchor at module `0xD0`, which is unique at linear `0x235E0` in **both** dumps.
- Target file offsets: `0x023F` → file `0xAEB5`; `0x0254` → file `0xAECA`. Live linear: `0x2381F` and `0x23834`.

The mapping `file = 0xAC76 + module offset` is the one the copy-helper probe verified for module offset `0x1685` (file `0xC2FB`). This probe checks it again at the two new offsets, with its own 32-byte windows.

## Identity: both targets, by bytes, in both dumps

| Target | File placement | Dump 1 (`pid34644`) | Dump 2 (`wheel-live`) |
| --- | --- | --- | --- |
| `0x0AF8:0x023F` | `0xAEB5`, unique | memory equals file, 32 bytes, unique placement | same |
| `0x0AF8:0x0254` | `0xAECA`, unique | memory equals file, 32 bytes, unique placement | same |

Both dumps agree on every byte of both windows. Each window's file placement is unique. The result is **conditional** on (a) the routine-B base `0xAC76` holding for this module and (b) the anchor load `0x1866` applying to the module segment. Neither is proved independently of the dumps.

## The two wrappers (exact template, derived targets)

Both wrappers are small and share one error join. Each is a byte-exact template (21 and 26 bytes), checked by the tool.

| | `0x0AF8:0x023F` (file `0xAEB5`) | `0x0AF8:0x0254` (file `0xAECA`) |
| --- | --- | --- |
| Arguments read | word `[bp+6]` (size) | word `[bp+6]` (size); far pointer `[bp+8]` (offset) and `[bp+10]` (segment), loaded to ES:CX, with BX = ES |
| Near helper called | module `0x308` (file `0xAF7E`) | module `0x3D3` (file `0xB049`) |
| Carry set on return | `mov ax,0x00CB` and jump to module `0xE2` | `mov ax,0x00CC` and jump to module `0xE2` |
| Carry clear on return | `retf 2`, AX/DX pass through from the helper | `retf 6`, no value |

So the wrapper's return value, when there is one, is the helper's `DX:AX`. The carry branch skips the `retf` (`jc +3`), and the error code is set only on the carry path. Module `0xE2` is the shared join; its body (`pop cx; pop bx; jmp`) is not decoded here.

## What the near helpers do (bytes, not run)

**Helper `0x308` (called by `0x023F`), 53 instructions to `ret`.** Reads as a first-fit search over a DS-resident list.

- `or ax,ax; jz` — a zero size is refused.
- `mov [DS:0x8754],ax` — the size is stored in a DS word.
- `call 0x491` — a helper that returns `DX:AX` from the size (add 7, shifts, `and 8`); not interpreted.
- `mov di,0x440C` — a DS list head at `0x440C`; ES:DI is loaded from it with `es les`.
- `cmp [DS:0x4406]`, and per-node compares of 32-bit words at node `+4` and `+6` against the request.
- On success, writes node `+0..+3` and `+4..+7`, then `pop ax; pop dx; clc; ret`. The `pop`s return the ES:DI saved at module `0x336` (the chosen node), so `DX:AX` = the node's far pointer.

**Helper `0x3D3` (called by `0x0254`), 40 instructions to `ret`.** Reads as a validate-and-release.

- `or ax,ax; jz` — a zero size is refused.
- `test cx,0xFFF7; jnz` — the block offset must be `0` or `8`.
- Range compares of the far pointer: `BX` against `DS:0x4402` and `DS:0x4406`, `CX` against `DS:0x4400` and `DS:0x4404` (a low pointer `DS:0x4402:0x4400` and a high pointer `DS:0x4406:0x4404`).
- `call 0x491`, then `es mov [di+4],ax; es mov [di+6],dx` — the block's `+4..+7` dword is written with the `DX:AX` that `0x491` returned (not the raw size).
- Relinks through `mov di,0x440C` and calls module `0x432` twice. Module `0x432` stores `DS:0x4404` and `DS:0x4406` (module `0x45F`, `0x463`), i.e. it rewrites the high pointer. Its role is read from those stores only.
- `clc; ret`.

No string move (`rep movs`/`stos`) and no interrupt appear in helpers `0x308`, `0x3D3`, `0x491` or `0x432`. **The bytes give no support for a copy reading of either target.**

## The callers: two helpers in the wall path (START)

Byte occurrences of `9A 3F 02 F8 0A` (call `0x023F`) and `9A 54 02 F8 0A` (call `0x0254`): START has 6 and 7, GAME.OVR has 64 and 27. These are byte matches; only the sites inside the two wall helpers below are decoded.

**`0x6B07` (near-called from the wall body; `retf 0xC`; 95 instructions).** Entry `[bp+6]` is a far pointer (the element, `les [bp+6]`). The bytes give:

| Step | Bytes (file) | Reading |
| --- | --- | --- |
| base size | `0x6B0D`: `[bp-2] = ([bp+16] * [bp+14]) << 1`; `0x6B18`: shifted again when `DS:0x4A1E != 0` | `DS:0x4A1E` selects a size scale (meaning not established) |
| header | `0x6B27`: `[bp-4] = byte[bp+12] * [bp-2]`; `0x6B81`: block `+17` ← `[bp-2]`; `0x6B8E`: block `+8` ← byte `[bp+12]` | the block records its own size fields |
| main allocate | `0x6B32`: `023F([bp-4] + 0x17)` | size = payload + 23 bytes |
| element store | `0x6B3E`: element `[0..3]` ← `DX:AX` | the element holds the returned far pointer |
| main fill | `0x6B50`: `16A8(block, [bp-4]+0x17, 0)` | a 3-argument fill (ptr, count, value); the companion [fill/callers probe](por-wall-0111-fill-callers-probe.md) decodes `16A8` as `rep stosb` |
| sub-block (only when `[bp+10]` bit 0 is set) | `0x6B9B` flag test; `0x6BA2`: `023F([bp-4] >> 2)` when flag `== 1`, else `0x6BDB`: `023F([bp-4])`; `0x6BAF`: block `+19..+22` ← `DX:AX` | a second pointer in the block |
| sub fill | `0x6BD4`, `0x6C03`: `16A8` | same helper; both call sites pass value 0, and their count expressions match the allocation sizes (see companion probe) |

**`0x6C0E` (near-called from the wall body; `retf 4`; 52 instructions).** The release.

| Step | Bytes (file) | Reading |
| --- | --- | --- |
| guard | `0x6C14`: element dword `== 0` → exit | release only a non-null element |
| block | `0x6C32`: `[bp-2] = byte(block+8) * word(block+17)` | the same size product the allocation wrote |
| sub release | `0x6C4F` flag test; `0x6C61`: `0254([bp-2] >> 2)` when flag `== 1`, else `0x6C7B`: `0254([bp-2])`; pointer = block `+21 : +19` | releases the sub-block (only when `+19`/`+21` non-zero) |
| main release | `0x6C8D`: `0254(element, [bp-2] + 0x17)` | releases the block at the element's pointer |
| clear | `0x6C99`: element dword `← 0` | the slot is emptied after release |

Both helpers are entered with the element as `[bp+6]`. The caller at START `0x47B4`–`0x47B7` pushes `ES`, `DI`, then `CS` and near-calls `0x6C0E`; the caller at START `0x4892`–`0x4898` does the same for `0x6B07`. With `push bp` the callee's `[bp+6]` is `DI` and `[bp+8]` is `ES`, so `les [bp+6]` reads the element pointer, and `retf 4` (or `retf 0xC`) pops the pushed CS, IP and the argument words. This is the caller link the wall-0111 note relied on, checked here by bytes.

## Allocate/release symmetry (static reading of the matched bytes)

| Quantity | Allocation (`0x6B07`) | Release (`0x6C0E`) | Equal when the header is intact? |
| --- | --- | --- | --- |
| main size | `[bp-4] + 0x17` with `[bp-4] = byte[bp+12] * [bp-2]` | `[bp-2] + 0x17` with `[bp-2] = byte(+8) * word(+17)` | yes: `+8` and `+17` are the values the allocation stored |
| sub size | `[bp-4] >> 2` if flag `== 1`, else `[bp-4]` | `[bp-2] >> 2` if flag `== 1`, else `[bp-2]` | yes, given the same flag and the same header |
| sub pointer | `DX:AX` stored at block `+19`/`+21` | pushed from `+21` then `+19` | yes (same offsets) |

So the bytes **establish a size-symmetric allocate/release pair**: the size released is the size allocated, provided the block header and `DS:0x4A1E` are unchanged between the two calls. They also show the sub-block and the main block using the same flag test on the same word. This is the shape of an allocate/free pair. It is **not** a proof that the calls run as a pair.

## What the bytes establish, and what they do not

| Question | Established by bytes | Not established |
| --- | --- | --- |
| Are `0x0AF8:0x023F` and `0x0AF8:0x0254` the module code at the file placements? | yes, under the module base `0xAC76` and load `0x1866`, in both dumps | that the module base holds for every offset in the module |
| What is the caller ABI? | `023F`: one word (size); return `DX:AX` passed through. `0254`: word (size), far pointer (`ES:CX`, `BX`=seg); no return value | that every caller of `023F`/`0254` passes the same kinds of argument |
| Allocation? | `023F` is a size-driven search of a DS-resident list at `0x440C`, returning the chosen node's far pointer; the wall helper stores that pointer in the element and calls `16A8` with a matching-size zero fill | that the list is initialised; the meaning of the node fields; runtime allocation |
| Release? | `0254` range-checks the far pointer against the DS words `0x4400..0x4406`, writes the `0x491` result into the block and relinks it at `0x440C`; the wall helper releases the element's pointer and clears it | that the release runs on any real path (the walk ignores branch conditions) |
| Copy? | no string or block move in either helper | nothing (no copy reading is supported) |
| DS values (`0x440C`, `0x4400..0x4406`, `0x4A1E`, `0x8754`) | the bytes read and write them | their values at any instant; the overlay's DGROUP base is not measured |

## Not established

- That either target runs at any real instant, or with which arguments. The caller's DS, table index and size are not measured in either dump.
- That `DS:0x440C` and the bounds `DS:0x4400..0x4406` hold the values the helpers assume. The F table is **not** shown to be initialised at run time, and the F element address (`0x5E3A + 4·index`, from the wall-0111 note) is a conditional link, not measured here.
- That `DX:AX` returned by `0x023F` is the block the caller keeps, rather than a free-list node that is later reused.
- That `0x0254` frees the block it is handed. The helper writes words into the block and relinks it; that fits release but is not proved.
- That `DS:0x4A1E` is a bit-depth or mode switch. It selects the shifted and unshifted size paths; its meaning is not established.
- The meaning of block offsets `+8`, `+17`, `+19` and `+21` beyond the size and pointer roles the bytes show.
- That the wall helpers are called with a null element. `0x6B07` stores the new pointer without testing the old one; whether the caller always releases first is not established.

## Other callers

`0x0AF8:0x023F` is also called at START `0x227D`, and `0x0AF8:0x0254` at START `0x2268`. Their immediate caller frames are decoded in [por-wall-0111-fill-callers-probe.md](por-wall-0111-fill-callers-probe.md): both use size `0x3F`, and their pointer roles match as a static shape. Whether they operate on the same block at runtime remains unestablished.

## Limits

| Edge | Status |
| --- | --- |
| Module base `0xAC76` | from the unique routine-B handler pattern; the copy-helper probe agrees at offset `0x1685` |
| Load `0x1866` | from the module's own anchor, unique in both dumps; the same value as the wall-0111 caller's delta, not used for identity |
| Helper decode | the repo's 16-bit decoder; 53 and 40 instructions; `ret` reached; operand summary from `Insn.direct` and immediates |
| Wall-helper patterns | byte patterns at fixed START offsets (19 of them), all matched; a fixed set, not a general matcher |
| `DS:0x4A1E`, `DS:0x440C`, bounds | read and written by the bytes; values not measured |

## Next discriminator

1. **Measure the overlay's DGROUP base in a dump** (a DS-relative constant the body reads, for example `DS:0x4A1E` or `DS:0x440C`). Without it, the list head, the bounds and the flag cannot be read from memory, and nothing here about DS can be checked.
2. **A RAM capture taken inside the wall path** (after the `023F` call at `0x6B39` returns, and before the `0254` call at `0x6C69`): the element's dword, block `+8`, `+17`, `+19`/`+21`, and the list head `DS:0x440C`. Equal sizes at alloc and release, with the element's pointer matching, would promote the pair from "shape" to "observed"; it needs new capture.
3. **Decode module `0x432`** (the bound update). The fill helper and the two additional caller frames are now covered by the companion probe; module `0x432` remains open.

## Commands and results (2026-11-18)

```sh
python tools/por_wall_0111_module_target_probe.py --install data/work/por-geo-run/POOLRAD \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-wall-0111-module-target-probe
python -m pytest tests/test_por_wall_0111_module_target_probe.py -q
OPENUA_POR_INSTALL="data/work/por-geo-run/POOLRAD" python -m pytest tests/test_por_wall_0111_module_target_probe.py -q
```

- CLI: `wrote data\work\por-wall-0111-module-target-probe (identity=…identified-by-bytes-in-pinned-dumps (both), wrappers matched=True, wall patterns matched=True)`, exit `0`. A second run is byte-identical (`cmp`). The CLI exit status now follows the self-check result.
- Tests with the pin: **24 passed**. Without the pin: **23 passed, 1 skipped** (the retail test). The synthetic tests cover: call bytes; wrapper template and its derived targets (four one-byte falsifiers: retf immediate, carry offset, error code); window identity (agree, one-byte disagreement, repeated placement, degenerate window, uncovered live window); the helper exit tail (with a falsifier); direct DS operands and immediates; the 19 wall-helper patterns (all matched; falsified by a callee change, a size-expression change and a removed flag guard); the CLI refusals; and exit 1 when a self-check fails.

Pins (checked before and after; matched): `GAME.OVR` `872964a3…7928614`, `START.EXE` `d825df2b…60b6a07bd`.

## Files and side effects

- New, tracked: `tools/por_wall_0111_module_target_probe.py`, `tests/test_por_wall_0111_module_target_probe.py`, `docs/por-wall-0111-module-target-probe.md`.
- New, git-ignored output: `data/work/por-wall-0111-module-target-probe/por_wall_0111_module_target_probe.json`.
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, and the existing probes it imports.
- No existing source, doc, tool or test was modified. No commit, no push, no emulator run, no GoldBox or other-title rule is used.
