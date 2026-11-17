# Pool of Radiance: ECL operand framing from the retail bytes (static probe)

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`.**

Tool: `tools/por_ecl_native_framing_probe.py`. Tests: `tests/test_por_ecl_native_framing_probe.py` (19 tests:
18 synthetic, 1 retail-gated on `OPENUA_POR_INSTALL`).

Companions (read, not changed): [por-ecl-decoder.md](por-ecl-decoder.md) (the `spec-menus` vs `conservative` framing
conflict, and the unexplained stops above `0x40`), [por-ecl-menu-framing-probe.md](por-ecl-menu-framing-probe.md)
(the `0x15`/`0x2B` default arm and the zero-skew model), [por-ecl-opcode2d-probe.md](por-ecl-opcode2d-probe.md)
(the `0x2D` handler reads `[0x7086]`/`[0x7046]`), [por-ecl-length-xref.md](por-ecl-length-xref.md) (the `0x80`
count byte). This probe takes its facts from `GAME.OVR` and `START.EXE` bytes only. The GoldBox Pool dispatch map was
read as a clue: its operand-parser address `0x74d3` is the same address the PoR bytes give here, but nothing here
depends on that agreement and no CoAB opcode semantics are used.

---

## Question and answer

> From PoR's own bytes, what operand framing does the ECL classifier and parser impose on each opcode, and where does
> that framing stop being established?

**Partly.** The classifier's per-opcode class (the operand count for 213 of 256 opcode values is "none", and 43 values
have a class) and the parser's per-operand byte rules are established by the bytes. What is not established: the
byte effect of the two string/post-step helpers the parser calls for some tags, the handler-level reads of the menu
opcodes, and whether the classifier path runs at all for a given opcode in play. The probe does not force a complete
table; the open terms are written into each row.

| Question | Answer | Basis |
| --- | --- | --- |
| Where does the per-opcode operand count come from? | The **classifier** compare chain at `0x9390` (entry `0x9379`). Each class arm pushes a class byte and calls the parser `0x74D3`. The class **is** the operand count: the parser's loop runs `i = 1..c` | Concrete chain walk for all 256 values; loop anchors `0x74E3`–`0x74EA`, `0x75F4`–`0x75FC` |
| Which opcodes have a class? | 43 values: class 1 (15 values, incl. `0x2D`), 2 (8), 3 (13, incl. `0x37`), 4 (2), 5 (1), 6 (2), 8 (1, `0x27`), 14 (1, `0x29`). Full list in the JSON `classifier.class_sets` | Chain walk |
| What does the default arm do? | `inc [0x49ED]`: one byte, zero parser operands. It covers **213** values, including all of `0x40`–`0xFF` and the menu opcodes `0x15`, `0x2B` | Chain walk |
| How is one operand framed? | Tag at `cursor+1`, value at `cursor+2`, cursor `+= 2`. Tag `1`, `2`, `3` or `0x81` adds a third byte at `cursor+3`. Tag `0x80` with value `> 0` calls the unpacker `0x8626` (open). Other tags: two bytes | Decoder-walked path enumeration over `0x74F5..0x75F4` |
| What is the per-opcode framing? | `1 + Σ d_i` over the `c` operands, with `d_i` = 2, or 3 for tags `{1,2,3,0x81}`, or `2 + X` for `0x80` with count `> 0`. Lower bound `1 + 2c`; the exact-closed upper bound `1 + 3c` holds only when no operand takes an open term | Operand-kind table below |
| Is the operand framing closed for every tag? | **No.** Two kinds are open: `0x80` count `> 0` (unpacker `0x8626`: far calls, cursor refs) and `0x81` (post-step `0x87CE`: far calls). `X` and the `0x87CE` cursor effect are not established | Helper census; far calls are literal `0x0AF8:xxxx`, fixup-listed in the existing docs |
| What are the menu opcodes' operands? | **Not established by the classifier**: both are default-arm (one byte). Their handlers call `2B:2A`/`2B:25`, whose zero-skew targets `0x92C3`/`0x9196` do **not** call the parser or the classifier and do not touch the cursor cell directly. `0x9196` has 21 far call sites | Callers census; menu helper census |
| Are there other parser callers? | Yes, **13** near call sites: the 8 classifier arms, and five class-1 calls in the routine at `0x7689`. The earlier docs describe the parser's caller as far-only; this refines that. Near callers of `0x7689` itself: none. Whether `0x7689` runs is not established | Walk of `0x7689`; `near_call_candidates` returns no caller |

---

## Pinned inputs (read-only; hashes checked by the probe, before and after)

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched on the retail run (`G:\Games\Pool of Radiance\POOLRAD`). The probe opens them read-only and refuses
unpinned files and an output folder inside the install. Nothing else was read: no DAX, no ECL block, no DOSBox,
GameLink or codewheel data.

## Reproduce

```sh
python tools/por_ecl_native_framing_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-ecl-native-framing/retail
```

Exit `0`: all 25 checks pass. Output: `data/work/por-ecl-native-framing/retail/por_ecl_native_framing_probe.json`
(schema `openua.por-ecl-native-framing-probe` v1, git-ignored). Exit `1`: a structural check failed. Exit `2`: a named
refusal.

---

## 1. The classifier at `GAME.OVR:0x9379` (bytes)

- **Key load** (`0x9379`–`0x938D`): `mov ax,[0x49ED]; les di,[0x49DE]; add di,ax; es mov al,[di+0x6700]; mov [0x6F7F],al`.
  So the opcode is the byte at the stream cursor `[0x49ED]`, read through the far pointer `[0x49DE]` at offset
  `0x6700`. The parser's operands therefore start at `cursor+1`.
- **Chain** (`0x9390`–`0x947E`): a `cmp al,imm8` / `jcc` tree. Each parser arm is `mov al,class; push ax; push cs;
  call 0x74D3; jmp 0x9482`. The default arm (`0x947E`) is `inc [0x49ED]`. `0x9482`: `pop bp`; `0x9483`: `retf`.
- **Call sites of the parser**: the eight arms, near calls at `0x93D0`, `0x93FA`, `0x9430`, `0x9441`, `0x944E`,
  `0x945F`, `0x946C`, `0x9479`.
- **Entry**: the classifier is reached by the far stub at START.EXE index 22 (zero-skew model, from the menu probe).
  Its prologue `55 89 E5` at `0x9379` is consistent with that model, but the model is not proved here.

### Opcodes with a class

| Class (= operand count `c`) | Opcode values |
| ---: | --- |
| 1 | `01 02 0A 0E 11 12 1D 20 2D 32 34 36 38 39 3C` |
| 2 | `03 08 09 0C 0F 10 1F 22` |
| 3 | `04 05 06 07 0B 21 28 2A 2F 30 35 37 3B` |
| 4 | `14 23` |
| 5 | `2E` |
| 6 | `1E 2C` |
| 8 | `27` |
| 14 | `29` |

### Default arm (one byte, zero parser operands): 213 values

Every value `0x40`–`0xFF`, and these below `0x40`: `00 0D 13 15 16 17 18 19 1A 1B 1C 24 25 26 2B 31 33 3A 3D 3E 3F`.
Eighteen of them also have a structured case in PoR's own dispatcher `0x3C73` (the decoder's `dispatch_cases` reader):
`00 0D 13 15 16 17 18 19 1A 1B 1C 24 25 26 2B 31 33 3A`. For those, the classifier frames **one byte** and the
handler does the rest, if anything. This is the first byte fact that bears on the decoder doc's "unknown stops above
`0x40`": the classifier itself gives every value above `0x40` a one-byte advance, so the stops there are at least
consistent with the default arm and are not operand evidence.

---

## 2. The operand body (`GAME.OVR:0x74F5..0x75F4`), decoder-walked

The parser `0x74D3` (`push bp; mov bp,sp; ...; retf 2`) reads its class from `[bp+6]` into `[bp-7]`, then runs the
loop `i = 1..c` (`0x74E3`–`0x74EA`, `0x75F4`–`0x75FC`: `mov al,[bp-1]; cmp al,[bp-7]; jz 0x75FF; jmp 0x74F2`).
Its per-operand buffers are `DS:[0x7005+i]` (tag), `DS:[0x7045+i]` (extra), `DS:[0x7085+i]` (value). Exit (`0x75FF`):
`inc [0x49ED]` (one byte), `retf 2`.

The walk (`body_paths`) follows the decoder's instruction starts and tracks, per path, which cursor-relative byte each
read takes, which buffer it lands in, every cursor write, every call, and the tag and value domains that the compare
chain partitions. It found seven tail paths and no refusal; the tag-value rectangles tile the 256 x 256 space exactly
once (`tiling_complete`, `tiling_disjoint`).

| Operand kind (tag) | Stream reads (cursor-relative) | Buffers written | Cursor delta | Open? |
| --- | --- | --- | ---: | --- |
| `1`, `2`, `3` (`0x753D`–`0x7547`, then `0x7549`) | `+1`, `+2`, `+3` | `0x7005`, `0x7085`, `0x7045` | **3** | no |
| `0x81` (`0x75A6`, then `0x75AD`) | `+1`, `+2`, `+3` | same three, then `0x7B82` then `0x87CE` | **3** | **yes**: `0x87CE` far calls |
| `0x80`, value `0` (`0x7584` `jbe` taken) | `+1`, `+2` | `0x7005`, `0x7085` | **2** | no |
| `0x80`, value `> 0` (`call 0x8626` at `0x758F`) | `+1`, `+2` | `0x7005`, `0x7085` | **2 + X** | **yes**: `0x8626` cursor refs, far calls |
| every other tag (`0x00`, `0x04`–`0x7F` except as above, `0x82`–`0xFF`) | `+1`, `+2` | `0x7005`, `0x7085` | **2** | no |

Reading of the three-byte form: the value of a `0x81` operand is `0x7B82`'s result, `((byte at +3) << 8) | (byte at +2)`,
a little-endian 16-bit word (the `0x7B82` arithmetic is checked as a byte sequence). `0x7B82` has no far call, no near
call and no DS reference, so it is pure by byte census.

**Per-opcode framing.** For an opcode with class `c`: framing `= 1 + Σ d_i`, the `1` being the opcode byte the
classifier points at. Lower bound `1 + 2c`. The exact-closed upper bound `1 + 3c` holds only for operands that are not
`0x80` with count `> 0` and not `0x81` (those add open terms). Examples:

| Opcode | Class | Framing: lower bound | Closed upper bound | Open terms |
| --- | ---: | ---: | ---: | --- |
| `0x2D` | 1 | 3 | 4 | one `0x80`/`0x81` operand adds `X` or `0x87CE` effect |
| `0x37` | 3 | 7 | 10 | same, per operand |
| `0x27` | 8 | 17 | 25 | same, per operand |
| `0x29` | 14 | 29 | 43 | same, per operand |
| `0x15`, `0x2B`, default | — | 1 | 1 | handler-level reads not established |

---

## 3. Helpers (byte census, `por_loadpieces_handler.walk`)

| Helper | Role (from the bytes) | Far call sites | Direct DS refs | Cursor cell `0x49ED` | Status |
| --- | --- | ---: | --- | --- | --- |
| `0x7B82` | value decode `((bp+6)<<8) \| (bp+8)`, `retf 4` | 0 | none | no | **pure** |
| `0x8626` | string unpacker for the `0x80` arm (`inc [0x49ED]` at `0x8656`; loop with a far call) | 8, literal `0x0AF8:xxxx` | `0x49DE`, `0x49ED` | **yes** | open |
| `0x87CE` | post-step of the `0x81` arm. Its only near callee is `0x7BCE` (row below) | 17, literal `0x0AF8:xxxx` | `0x49D2`, `0x49D6`, `0x49DA`, `0x49DE`, `0x5D92` | no (direct) | open: far callees not resolved |
| `0x7BCE` | near callee of `0x87CE`: a range test on its argument, `retf 2` | 0 | none | no | **pure** |

The `0x0AF8` segment word is the one the existing docs (opcode2d probe) show is fixup-listed, and its delta is not
established, so none of these far callees is mapped. The cursor effect of `0x87CE`'s far calls is therefore open even
though it has no direct cursor reference.

---

## 4. Callers and the caller routine `0x7689`

- **The classifier** (eight arms, above) is the only caller the probe found for the chain.
- **The routine at `0x7689`** (START.EXE stub index 3, zero-skew) makes five class-1 parser calls at `0x7724`, `0x773A`,
  `0x7750`, `0x7766`, `0x777C`. Each is followed by `0x7B82` on `[0x7086]`/`[0x7046]` (operand 1's value and extra
  buffers), and the result is stored to `[0x49E3]`, `[0x49E5]`, `[0x49E7]`, `[0x49E9]`, `[0x49EB]`. The routine has
  no near caller in GAME.OVR (`near_call_candidates` is empty), and index 3 has no literal far candidate in any
  segment. Whether it runs is **not established**.
- **Menu helpers** `0x9196` (zero-skew target of `2B:25`) and `0x92C3` (of `2B:2A`) make no near call to the parser or
  the classifier and do not reference the cursor cell directly. They make 21 and 2 far calls. What they read from the
  stream is **not established**.

The `0x2D` handler reads `[0x7086]`/`[0x7046]` (operand 1's buffers). `0x2D` is class 1, so if the classifier runs
before dispatch (the call-site lead at `0x40A3` in the menu doc), those cells are filled for `0x2D`. The `0x15` and
`0x2B` handlers read the same cells, but their opcodes take the default arm, so the classifier fills nothing for them. Either something else fills the cells before those reads, or the reads are of stale values. The bytes here do
not decide which.

---

## 5. Stub model (START.EXE, zero-skew, a model)

The group header at `START.EXE:0x45B` has `fileofs 0x74D3`; its stub run starts at `0x471`, 25 entries.

| Index | Stub `proc_off` | Zero-skew target | Prologue | Literal `9A` candidates |
| ---: | ---: | --- | --- | ---: |
| 2 | `0x0000` | `0x74D3` (the parser) | `55 89 E5` | **0** |
| 3 | `0x01B6` | `0x7689` (the five-call routine) | `55 89 E5` | 0 |
| 20 | `0x1CC3` | `0x9196` (`2B:25`) | `55 89 E5` | 52 |
| 21 | `0x1DF0` | `0x92C3` (`2B:2A`) | `55 89 E5` | 42 |
| 22 | `0x1EA6` | `0x9379` (classifier) | `55 89 E5` | 2 |

The prologues are consistent with the model, not proof of it. The literal-candidate counts are byte matches
`0x200 + seg*16 + off` that land on an aligned stub, with no caller check.

---

## Checks (retail run, 25 of 25 pass)

Pins; classifier key-load bytes; every value reaches an arm; class arms call `0x74D3`; `0x27`→8, `0x29`→14, `0x2D`→1,
`0x37`→3; `0x15`/`0x2B` default; parser anchors; body without refusal; tag-value tiling complete and disjoint; the exit
path is one byte; the `0x7B82` formula anchored; `0x7B82` pure; `0x8626` open with a cursor ref; `0x87CE` with far calls
and its only near callee `0x7BCE` pure; the caller routine's five class-1 calls; eight classifier arms; the stub header;
the stub prologues; menu helpers not calling the parser or the classifier.

---

## Tests

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_native_framing_probe.py            # Windows
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_native_framing_probe.py
```

Local result: `19 passed` with the variable set; `18 passed, 1 skipped` without it.

- **Synthetic classifier** (hand-assembled chains): matched and unmatched values; mutation of the compare immediate
  flips the arm; a call to another target is `other-call`; an unmodelled byte and a `jcc` without a compare are
  refusals; unsigned predicates.
- **Synthetic operand body** (sequentially assembled in the same forms): tag tiling and per-tag cursor deltas; mutation
  of the tag compare moves the tag set; mutation of `jnz` to `jz` flips which tag pays the increment; reads are
  cursor-relative and land in the named buffers; an unknown AX at a cursor write is refused; a `jcc` after an unmodelled
  compare is refused (not read stale); an unknown near callee is refused; the two helpers are classed open or pure.
- **Refusals**: an unpinned install and an output folder inside the install.
- **Retail-gated**: pins unchanged before and after; class sets; default arm and dispatcher cross-check; seven operand
  kinds with the expected deltas and open flags; five stored decodes; stub index 2 unreferenced; menu helpers clean.

---

## Not claimed

- No runtime claim. Reachability of the classifier path, of the `0x7689` routine, and of any opcode is not established.
- No operand or opcode meaning. No FRUA event mapping, no module, no campaign or route claim.
- No opcode semantics from any other game. The GoldBox dispatch map was read as a clue and is not used for any number here.
- The `0x80` unpacker's advance (`X`) and the `0x87CE` far callees' cursor effect are open.
- The zero-skew stub mapping is a model.
- The handler-level reads of `0x15`, `0x2B` (and of every other default-arm opcode with a dispatcher case) are not established.

---

## Refinements to earlier notes

- The codec and length notes say the parser's caller is a far call that has not been located. The bytes now show 13
  near call sites: the eight classifier arms and the five class-1 calls in `0x7689`. The far path is still the only one
  the menu probe reaches from `2B:`. The `0x7689` routine's own caller is still unlocated.
- The `0x80` count byte is the byte at cursor `+2` (the value buffer `DS:[0x7085+i]`), consistent with the length-xref
  note's `0x07526` / `0x07577`.

## Next evidence that would settle it

1. **Run-time capture** of the parser entry `0x74D3` and of the stub index 2 (`0x47B`) during an ECL walk: the class byte
   pushed and the cursor before and after. That tests the classifier-to-parser path and the operand framing together.
2. **The far callees** of `0x8626` and `0x87CE` (literal `0x0AF8:xxxx`): their resolved bodies decide `X` and the cursor
   effect of the `0x81` post-step. Needs the fixup delta, which is still open.
3. **The menu helpers** `0x9196` and `0x92C3`: a walk of their own stream reads (their 21 and 2 far calls) would show
   whether they parse the operands the `0x15`/`0x2B` handlers then read.
4. **Who runs `0x7689`**: its five class-1 parses would store decoded words at `0x49E3`–`0x49EB`. A byte census of
   `[0x49E3]`–`[0x49EB]` readers (the `0x49EB` cell is also pushed at `0x40AD` in the dispatch driver, per the menu doc)
   would connect it to a caller.
