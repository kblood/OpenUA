# Pool of Radiance: 8X8D archive read path, bounded static trace (observe-only)

**Status: `static-probe-only`. `playable: false`. `mappings: []`. `binding_established: false`.**
**Verdict: bounded-negative. No end-to-end DAX read path is established.** Two candidate routines
are located. Neither is bound to a DAX open, a file handle, or a block read, and neither has an
established caller.

Tool: [`tools/por_8x8d_archive_chain_probe.py`](../tools/por_8x8d_archive_chain_probe.py). Tests:
[`tests/test_por_8x8d_archive_chain_probe.py`](../tests/test_por_8x8d_archive_chain_probe.py) (24 tests: 18
synthetic falsifiers and CLI checks, 6 retail-gated anchors and determinism; without `OPENUA_POR_INSTALL` the 6
anchors skip). Output is under ignored `data/work/por-8x8d-archive-chain-probe/`.

Related: [por-8x8d-loader-probe](por-8x8d-loader-probe.md) (the 0x7180 chain, already negative for 8X8D),
[por-wall-render-probe](por-wall-render-probe.md) (the name-literal scan this trace builds on),
[por-geo-archive-selector-probe](por-geo-archive-selector-probe.md) (the same selector read at
GAME.OVR `0x3228A`, rooted at `0x32270`, recorded there as a formatter reader),
[por-8x8d-blocks](por-8x8d-blocks.md) (the 8X8D block rule and the unsupported block 201).

---

## Question

Does any decoded routine in the pinned retail `START.EXE` or `GAME.OVR` open or read an 8X8D DAX
archive, select a block or tile id, and reach that read by a call path the bytes establish? The
answer is no for the end-to-end path. The pieces of the path are listed below with their labels.

Evidence labels: **decoded** (the instruction decodes and lies on a ret-stopped walk), **consistency**
(a pointer or byte relation that holds, not proven), **model** (depends on the image-relative far-call
model `file = 0x200 + seg*16 + off`, which is not validated), **not-established**.

---

## Pinned inputs

| File | Bytes | SHA-256 | Pin |
| --- | ---: | --- | --- |
| `START.EXE` | 65,231 | `d825df2b…60b6a07bd` | match, unchanged after run |
| `GAME.OVR` | 206,105 | `872964a3…7928614` | match, unchanged after run |
| `8X8D1.DAX` … `8X8D8.DAX` | (see tool `X8D_PINS`) | per-file | match |

`START.EXE` has no MZ relocation entries (`e_crlc = 0`) and an image base of `0x200`.
`8X8D1.DAX` TOC (shared `tools/por_map.parse_dax`): block ids `[1, 3, 5, 201, 202, 203]`; index 3 is block
201, raw size 1416. The eight archives' TOCs are in the JSON.

---

## Candidate A: `START.EXE 0x7245` (block 201, named "8X8d1")

**decoded.** A ret-stopped routine of 44 instructions (`retf` at `0x72A7`, end `0x72A8`).

- It takes the Turbo Pascal pieces `05 "8X8d1"` at `0x723A` and `04 ".dax"` at `0x7240` through two CS
  pointers: `mov di,0x171; push cs; push di` at `0x7250` and `mov di,0x177; push cs; push di` at `0x725F`.
  **consistency:** under CS base `0x070C9`, both pointers land on the length bytes of those pieces
  (`0x171 + 0x70C9 = 0x723A`, `0x177 + 0x70C9 = 0x7240`). Two of two; not proof.
- It copies each piece into a local (`lea [bp-12]` and `lea [bp-17]`, via `0x0AF8:0x0B0B`). Those locals
  are referenced once each in the routine (BP-displacement counts `-12: 1`, `-17: 1`), so the copied names have
  **no decoded consumer here**.
- It requests block `0xC9` (201) with `mov al,0xc9` at `0x7269`, then calls `0x0802:0x0716` (50 instructions,
  `retf`, **model**) with that byte and two result slots `[bp-2]` and `[bp-6]`. Then it
  tests `[bp-2]` and calls `0x0AF8:0x1685` and `0x0AF8:0x0254` (**model**).
- Block 201 exists in `8X8D1.DAX` (TOC index 3, raw 1416), and `docs/por-8x8d-blocks.md` records it as the
  one unsupported block (its dimension words are garbage). This matches the request id; it does not show
  that the request reads from `8X8D1.DAX`.
- The high byte of the pushed word is not established (`mov al` leaves AH).

**Callers: none.** No decode-verified `E8` targets `0x7245`, and no `9A` in either image has a linear
address equal to it.

---

## Candidate B: `GAME.OVR 0x32270` (the "8x8d" loader shape)

**decoded.** A ret-stopped routine of 106 instructions (`retf 4` at `0x3236C`, end `0x3236F`). Its
frame has two byte parameters: `[bp+6]` (read 3 times, used as a slot index) and `[bp+8]` (read twice).

- **Group.** It is the VROOMM group body at `0x32235` (code size `0x2B2`), relative entry `0x3B`, which is
  one of the three well-formed procedures. Its VROOMM stub is START `0x42DE` (`cd 3f 3b 00 00`; word = the
  relative entry). Stub index 1 is the only match.
- **Pointers.** Four CS pointers (`0x3227B` imm `0x00`, `0x322C4` imm `0x20`, `0x3231D` imm `0x25`,
  `0x32331` imm `0x39`). Under the group body base, **consistency**: `CS:0x20` is the Pascal
  `8x8d` (length byte at `0x32255`) and `CS:0x25` is the Pascal `Unable to load 8x8D` (length byte at `0x3225A`).
  `CS:0x39` is the Pascal `-` (length 1, at `0x3226E`). `CS:0x00` is body start, not a printable string.
  An earlier hand reading that R did not reference these pieces was wrong; the tool's check corrects it.
- **Selector.** `mov al,[0x5376]` at `0x3228A`, zero-extended, formatted by `0x0AF8:0x1366` (twice:
  the selector into `[bp-2]`, `[bp+8]` into `[bp-6]`). The GEO selector probe records the same read,
  rooted at `0x32270`.
- **Sequence (decoded order).** `0x0AF8:0x0DC0` (its result gates the rest: `jnz 0x3228A`, else
  exit at `0x32369`); the formatter calls (arguments as decoded; destinations `[bp-2]` and `[bp-6]`); a copy of CS:0x20 into the local at `[bp-264]`; two `0x0AF8:0x0B98`
  calls; then **unconditionally** `0x0464:0x0111` with the arguments `[bp+8]`, `1`, `13`, and the far
  pointer `DS:[0x5E3A + 4*[bp+6]]` (`0x322F3`); then the slot test `[slot] | [slot+2]`; `jnz 0x32364`
  (to `0x0899:0x0104`, the epilogue) at `0x3230B`; otherwise `0x0464:0x00FF`, a copy of CS:0x25 (the
  message), and a display-shaped call sequence (`0x0899:0x0059`, `0x0899:0x0000`).
- **Reading (hypothesis, not established).** The name is `"8x8d"` plus a selector digit (and a second
  digit from `[bp+8]`); the slot words are a post-load success check, and the error message is shown when
  both are zero. The `-` and the extension are not accounted for. The `0x0464` and `0x0AF8` callees are not
  entered, so none of this is confirmed.

**Callers: none found.** No `E8` targets `0x32270` or the stub in either image; no `9A` in either image has a
linear address equal to the stub (`0x42DE - 0x200`).

---

## INT 21h inventory (decode-verified)

| Image | Sites | By AH | Notes |
| --- | ---: | --- | --- |
| `START.EXE` | 58 | `3D`×1 (`0x0A8B6`), `3E`×3, `3F`×5, `42`×9, unknown×8 | AH taken from the immediate predecessor only; see the follow-up entry walk |
| `GAME.OVR` | 0 | none | all DOS I/O is in START |

- `0x0A8B6` (open, AH=3Dh): the original prologue-only scan did not contain it. A follow-up non-prologue
  entry walk identifies helper `0x0A89E`, copies the Pascal name from `[bp+6]`, and reaches this open through
  three decoded near-call sites. This establishes an open helper, not an 8X8D archive open; its caller chain
  does not identify the archive name. See [`por-8x8d-dos-sites-probe.md`](por-8x8d-dos-sites-probe.md).
- `0x0A77A` (read, AH=3Fh): contained by the routine at `0xA728` (85 instructions, ret-complete). That routine
  reads the first 8 bytes of a file and compares them with `MZ` (`0x5A4D`), `FB` (`0x4246`) and `OV` (`0x564F`),
  then sets vector 3Fh with `mov ax,0x253f; int 21h`. GAME.OVR begins with `46 42 4F 56` (`FBOV`). **So this
  read is the overlay manager's header probe, not a DAX read.**
- `0x0A9B5`, `0x0A9D6`, `0x0B333`, `0x0B374` (reads): follow-up entry walks contain these in four routines,
  but their connection to a DAX archive remains unresolved. Five INT 21h sites also have unresolved AH.

---

## Far-call model (model-conditional)

The image model is not validated. `START.EXE` has no relocation entries, and at delta 0 no far target begins
a prologue. Counts for the `0x0AF8` targets (42 distinct): ret-complete at delta 0 = 30, decode error = 12,
prologue = 0. For `0x0802` (3 targets) and `0x0464` (8 targets) the delta-0 ret-complete counts are 3 and 8.

Under the model, Candidate A's far callee `0x0AF8:0x0254` (file `0xB3D4`) has a model entry whose first
byte is `00`; the routine `mov bx,sp; les di,[bx+4]; mov bx,es:[di]; cmp bx,4; jbe; mov ah,3Eh; int 21h; retf 4`
begins at `0xB3D5`. It closes a handle only above 4 (a TP-style file close with INT 21h AH=3Eh), one byte after the model address. So the model is
off by one at this target, or the call goes to a different entry. Either way the link is **not established**.

Bounded closure under the model (depth 3 from `0x0802:0x0716`) reaches the close at `0xB3E5` and no open
or read. Depth 2 from R's callees reaches no INT 21h.

---

## Unresolved edges (from the JSON `unresolved_edges`)

- **U1** callers of `START 0x7245`: not-established (no E8 and no linear 9A).
- **U2** callers of `GAME.OVR 0x32270` and its stub: not-established.
- **U3** far calls `0x0802:0x0716`, `0x0AF8:0x0254` and R's far callees: model-conditional.
- **U4** the relationship of the open helper and four read sites to an 8X8D/DAX request: not-established.
  The open helper at `0x0A89E` and its three E8 callers are decoded; the routine supplying its Pascal filename
  and the read handles' purpose are still unresolved. See [`por-8x8d-dos-sites-probe.md`](por-8x8d-dos-sites-probe.md).
- **U5** which archive the block-201 request reads from: not-established (the name copies have no consumer).
- **U6** meaning of `[bp+6]`, `[bp+8]` and the slot words: not-established (`0x0464:0x0111` not entered).
- **U7** use of `CS:0x39` (the `-` string) and how the name is assembled: not-established.
- **U8** the high byte of the block-201 request word: not-established.

---

## GoldBox reference (read-only)

`C:\Modding\GoldBox\docs\engine\research\8x8d-tile-encoding-cok.md` (Champions of Krynn, DOS) states the 17-byte
8X8D block header and that block 201 is not a tile block. Both agree with PoR bytes already recorded in
`por-8x8d-blocks.md`. **Nothing in this probe depends on GoldBox.** The length-prefixed Pascal pieces, the
CS-pointer consistency, and the block-201 TOC entry were all checked against the PoR bytes here. No
GoldBox code or rule was carried over as a binding.

---

## Commands and results

```sh
python tools/por_8x8d_archive_chain_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-8x8d-archive-chain-probe/retail          # exit 0; JSON + report written
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_8x8d_archive_chain_probe.py -q
#   24 passed
python -m pytest tests/test_por_8x8d_archive_chain_probe.py -q
#   18 passed, 6 skipped (retail anchors skip without OPENUA_POR_INSTALL)
```

---

## Side effects

- New files only: `tools/por_8x8d_archive_chain_probe.py`, `tests/test_por_8x8d_archive_chain_probe.py`,
  `docs/por-8x8d-archive-chain-probe.md`, and `data/work/por-8x8d-archive-chain-probe/retail/` (ignored).
- No existing file was modified. Shared modules were imported read-only (`por_loadpieces_handler`,
  `por_farcall_resolve`, `por_map`, `por_convert`).
- No emulator was run, no codewheel was touched, nothing was committed or pushed, and nothing in GoldBox or the
  retail install was written.
- Python test runs created `__pycache__` folders (ignored).

---

## Limits

- Decoded prologue roots and linear walks only. A routine with no prologue, or a walk that hits an unsupported
  opcode (`0x0F`, `0x65`, `0xFF /7` appear in callees), is counted as incomplete, not as absent.
- The AH rule takes only the immediate predecessor (`mov ah,imm8` or `mov ax,imm16`). Eight INT 21h sites
  are reported as unknown rather than guessed.
- CS base and pointer checks are consistency tests on two or more pointers. The R base is the VROOMM body
  start from the group descriptor, which fits the proc offsets but was not separately verified.
- The far-call model is labelled model-conditional throughout; nothing above is a binding.

---

## Next discriminating observation

Static, bounded: find indirect and jump-based callers of `0x0A728`, `0x0A97E` and `0x0B360`, then resolve
the caller's filename and the read handles. Trace what `0x0464:0x0111` and `0x0AF8:0x0DC0` do if their
targets can be fixed by a stub or an MZ-consistent base. A live run that stops at the start of `0x32270` and
at `0x3230B` and dumps the selector `DS:[0x5376]`, the words at `DS:[0x5E3A + 4n]`, and the first archive name
would settle U5, U6 and U7. That observation is not run here.
