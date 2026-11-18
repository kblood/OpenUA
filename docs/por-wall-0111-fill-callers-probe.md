# Pool of Radiance: the fill 0x0AF8:0x16A8 and the two START callers of 0x023F / 0x0254 (static)

**Status: STATIC-PROBE-ONLY. `playable: false`. `executed: not_established`.** Answer, by bytes under the module mapping of [por-wall-0111-module-target-probe.md](por-wall-0111-module-target-probe.md):

- **`0x0AF8:0x16A8` is a memset-like fill.** `rep stosb` of CX bytes of AL at ES:DI, with ES:DI = the far pointer at callee sp+8/+10, CX = the word at sp+6, AL = the low byte of the word at sp+4; `cld`; `retf 8`. Byte-exact, and identified in both pinned dumps.
- **The three wall-helper fills (call sites START `0x6B5A`, `0x6BD4`, `0x6C03`) pass the value 0 and a count expression byte-identical to the size expression of the allocation they follow** (`[bp-4]+0x17`, `[bp-4]>>2`, `[bp-4]`). The fill destination is loaded from the stored result pointer; this is a static caller shape, not a heap-state observation.
- **START `0x227D` (frame entry `0x2273`) is an allocate-and-copy:** it passes size `0x3F` to `0x023F`, keeps DX:AX at `[bp-8]`, copies `0x3F` bytes from its first far-pointer argument into that block through `0x1685`, clears the block's link words at `+42`/`+44`, and appends the block to the list at its second far-pointer argument.
- **START `0x2268` (frame entry `0x2185`) is a find-unlink-release:** it clears the link words of its first far-pointer argument, unlinks that argument from the list at its second far-pointer argument, and releases it with size `0x3F` through `0x0254`.
- **The two frames pair on size (`0x3F` in both) and on pointer role** (allocated far pointer out; far pointer in, from an argument). **Whether the block one frame allocates is the block the other releases is not established:** no near call to either entry exists in START, and no far call with either offset was found; their callers were not traced.

`tools/por_wall_0111_fill_callers_probe.py` is read-only and stdlib-only. It reuses `por_wall_0111_module_target_probe` (module file base `0xAC76`, live segment `0x235E`, the anchor load `0x1866`), `por_geo_copy_helper_probe` (pins, handler base, dump anchor), and `por_loadpieces_handler` (the 16-bit decoder). `tests/test_por_wall_0111_fill_callers_probe.py` has 32 synthetic tests (each claim has a mutated-byte falsifier) and one retail test gated on `OPENUA_POR_INSTALL`.

## Usage

```sh
python tools/por_wall_0111_fill_callers_probe.py --install data/work/por-geo-run/POOLRAD \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-wall-0111-fill-callers-probe
OPENUA_POR_INSTALL="data/work/por-geo-run/POOLRAD" python -m pytest tests/test_por_wall_0111_fill_callers_probe.py -q
```

Output: `data/work/por-wall-0111-fill-callers-probe/por_wall_0111_fill_callers_probe.json` (schema `openua.por-wall-0111-fill-callers-probe` v1, sorted keys, no timestamps, no absolute paths). Exit `0` = every check matched; `1` = a check did not match (the JSON is still written); `2` = named refusal (unpinned input, module anchor not unique at load `0x1866`, output outside `data/work`, output inside the install). Nothing is written to the install.

## Pinned inputs

| Input | Bytes | SHA-256 (prefix) | Note |
| --- | ---: | --- | --- |
| `GAME.OVR` | 206,105 | `872964a3…7928614` | pin matched |
| `START.EXE` | 65,231 | `d825df2b…60b6a07bd` | pin matched |
| dump 1 `por-live-memory-pid34644` | 1,048,576 | `f8191750ea6c672e` | base 0, anchor `0x235E0` unique |
| dump 2 `por-wheel-live-capture` | 1,048,576 | `3788787cd795f1f5` | base 0, anchor `0x235E0` unique |

The mapping is the module-target note's: file `= 0xAC76 + module offset`, live linear `= (0x235E << 4) + offset`. Every claim below is conditional on it.

## `0x0AF8:0x16A8`: the fill body (file `0xC31E`)

| Offset | Bytes | Text | Reading |
| --- | --- | --- | --- |
| `0xC31E` | `8b dc` | `mov bx,sp` | frame base for SS-relative reads |
| `0xC320` | `36 c4 7f 08` | `les di,[ss:bx+8]` | ES:DI ← dst (offset at sp+8, segment at sp+10) |
| `0xC324` | `36 8b 4f 06` | `mov cx,[ss:bx+6]` | CX ← count (sp+6) |
| `0xC328` | `36 8a 47 04` | `mov al,[ss:bx+4]` | AL ← **low byte** of the value word (sp+4) |
| `0xC32C` | `fc` | `cld` | forward fill (DF left clear) |
| `0xC32D` | `f3 aa` | `rep stosb` | fill CX bytes of AL at ES:DI |
| `0xC32F` | `ca 08 00` | `retf 8` | callee pops four words: value, count, dst offset, dst segment |

The caller pushes, in order: dst segment, dst offset, count, value word. The decoder's linear walk from `0xC31E` stops at the `retf` on a boundary at each template step. The template is hand-decoded and checked byte-exact (fail closed).

**Identity (both dumps):** file window `0xC31E`, 32 bytes; live linear `0x24C88`. Memory equals file in both dumps, placement unique, verdict `identified-by-bytes-in-pinned-dumps`.

## The wall-helper fill sites (START, the `0x6B07` and `0x6C0E` helpers)

| Pair | Allocation (`0x023F`) | Count expression (alloc = fill) | Fill (`0x16A8`) | Dst pushed | Value |
| --- | --- | --- | --- | --- | --- |
| main | `0x6B32` → call `0x6B39` | `8b 46 fc 05 17 00 50` | `0x6B50` → call `0x6B5A` | `push es; push di` | `mov al,0; push ax` |
| sub-shr2 | `0x6BA2` → call `0x6BAA` | `8b 46 fc d1 e8 d1 e8 50` | `0x6BC9` → call `0x6BD4` | yes | zero |
| sub-raw | `0x6BDB` → call `0x6BDE` | `ff 76 fc` | `0x6BFD` → call `0x6C03` | yes | zero |

All three rows match. Each fill follows its allocation in the same straight-line run; each fill's count equals the size the allocation was given. The main fill runs before the header stores (`+0`/`+2` from `[bp+16]`/`[bp+14]`, `+8` from byte `[bp+12]`, `+17` from `[bp-2]`, at `0x6B5F`–`0x6B92`), so the header is written into a zeroed block.

## The two START callers (file offsets of the 9A far-call opcode)

| | `0x227D` → `0x023F` | `0x2268` → `0x0254` |
| --- | --- | --- |
| Enclosing entry (nearest prologue that reaches the site on a boundary) | `0x2273` (`55 89 e5 83 ec 08`) | `0x2185` (`55 89 e5 83 ec 2c`) |
| Frame return | `retf 8` at `0x230C` | `retf 8` at `0x2270` |
| Frame arguments read | `[bp+6]` (first far pointer), `[bp+10]` (second far pointer) | `[bp+6]`/`[bp+8]` (first far pointer), `[bp+10]` (second) |
| Size pushed | `mov ax,0x3F; push ax` (`0x2279`) → **0x3F** | `mov ax,0x3F; push ax` (`0x2264`) → **0x3F** |
| Pointer pushed | none (`023F` takes one word) | `push [bp+8]` (segment), `push [bp+6]` (offset): the **first argument** of the frame |
| Result | DX:AX → `[bp-8]`/`[bp-6]` (`0x2282`–`0x2287`) | none |
| Copy | `les di,[bp+6]`; `push es; push di`; `les di,[bp-8]`; `push es; push di`; `mov ax,0x3F; push ax`; `call 0x1685` (`0x2288`–`0x2296`): `0x3F` bytes **from the first argument into the new block** | none |
| Link words | `+42`/`+44` of the new block ← 0 (`0x229B`–`0x22A8`) | `+42`/`+44` of the first argument ← 0 (`0x2251`–`0x225D`), straight-line into the release call |
| Entry guard | none | `mov ax,[bp+6]; or ax,[bp+8]; jnz` (`0x218B`): a null first pointer takes an error path (code `0x0E`), not a release |

Both straight-line runs are checked: no branch target lies inside `(start, end]`. The list words are the same in both frames: the second argument's `+200`/`+202` is the head, and the `+42`/`+44` words of blocks link them. The alloc frame walks to the tail and stores the new block there (or in the head when empty); the release frame finds the first argument in that chain, stores its successor into the predecessor (or head), and releases it. **That this is a singly linked list is a reading of the word accesses, not established.**

## Pair verdict

| Quantity | `0x227D` frame | `0x2268` frame | Paired? |
| --- | --- | --- | --- |
| Size | `0x3F` (023F and copy) | `0x3F` (0254) | yes |
| Pointer role | allocated far pointer, stored at `[bp-8]` | far pointer from the first argument | yes (form) |
| Same block? | the block the copy writes into | the block that is unlinked and released | **not established** |

The result is `shapes_pair_on_size_and_pointer_role: true`, `pointer_identity_between_frames: not-established`.

## Not established

- That any of these runs at any instant, or with which arguments. The caller's DS, the list contents and the sizes are not measured.
- That the block `0x227D` allocates (and copies into) is the block `0x2268` releases. Callers of both frames were not traced; no near call to `0x2185` or `0x2273` exists in START, and no far call with either offset was found in START or GAME.OVR (indirect and cross-segment callers were not searched).
- That the list words form a list, or that the head is `+200`/`+202`: the bytes read and write them; the meaning is not shown.
- That the zero-fill can see a count larger than its block, or zero: only the count expression is compared with the allocation's.
- That DF is clear across the fill call: the callee executes `cld` and does not restore the flag; the caller's assumption is not checked.
- The runtime segment of START's code: the two frames are identified by file bytes only, with no dump-level identity claimed.

## Limits

| Edge | Status |
| --- | --- |
| Module base `0xAC76`, load `0x1866` | inherited from the module-target note (unique routine-B pattern and anchor in both dumps) |
| Fill body | hand-decoded, byte-exact template, boundaries checked |
| Frame classification | nearest prologue that reaches the site on a boundary; `bp` operands read from the decoder, with retf 8 as the argument-size evidence |
| Static callers | a same-segment near-call search and a far-call offset count; no argument tracing |

## Discovered issues (not edited; existing files untouched)

1. **The module-target probe's exit code does not match its note.** `tools/por_wall_0111_module_target_probe.py` `main()` writes the JSON and returns `0` whatever the verdict; the note says `exit 0 = every check matched`. Its verdict is in the JSON only.
2. **The module-target note leaves two items open that this probe now answers:** "decode `0x0AF8:0x16A8`" (item 3 of its *Next discriminator*) and "its body is not decoded here" (*Not established*). The "Other callers" paragraph is also superseded.
3. **The decoder's `bp_disp` reports one displacement per operand.** `les [bp+10]` reports `10`, not the segment word at `12`. My first version counted arguments as `[6,8,10,12]` and failed; the probe now uses `retf 8` plus the operands. Any future probe that counts far-pointer arguments with `bp_disp` must do the same.
4. **`Insn.text()` drops the register for memory-form loads and stores** (it prints `mov [bp+6]` for `8b 46 06`). The probe reads the raw bytes for direction and register; the printed text alone is not enough.
5. **The `frua-reference` MCP server did not connect this session.** It was not needed here (the task used the pinned bytes), but the Mac-side Toolbox corpus was not consulted.

## Commands and results (2026-11-18)

```sh
python tools/por_wall_0111_fill_callers_probe.py --install data/work/por-geo-run/POOLRAD \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-wall-0111-fill-callers-probe
python -m pytest tests/test_por_wall_0111_fill_callers_probe.py -q
OPENUA_POR_INSTALL="data/work/por-geo-run/POOLRAD" python -m pytest tests/test_por_wall_0111_fill_callers_probe.py -q
python -m pytest tests/test_por_wall_0111_module_target_probe.py -q
```

- CLI: `wrote data\work\por-wall-0111-fill-callers-probe (checks={fill_body: True, fill_identity: True, size_pairs: True, frames: True, pair: True})`, exit `0`. A second run is byte-identical (`cmp`).
- Tests without the pin: **32 passed, 1 skipped** (the retail test). With the pin: **33 passed**.
- The existing module-target tests (not modified): **22 passed, 1 skipped** without the pin.

Files:
- New, tracked: `tools/por_wall_0111_fill_callers_probe.py`, `tests/test_por_wall_0111_fill_callers_probe.py`, `docs/por-wall-0111-fill-callers-probe.md`.
- New, git-ignored output: `data/work/por-wall-0111-fill-callers-probe/por_wall_0111_fill_callers_probe.json`.
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, and the existing probes it imports.
- No existing source, doc, tool or test was modified. No commit, no push, no emulator run. No GoldBox or other-title rule is used.
