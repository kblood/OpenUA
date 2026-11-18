# Pool of Radiance ECL entry origin: what the pinned bytes establish

**Status: static probe. `playable: false`. No base or origin promoted.** The decoder
has a separate opt-in `--por-vbase` mode for `0x98FE`, labelled CONDITIONAL and
`promoted: false`; this probe's conclusion remains unchanged. Tool:
`tools/por_ecl_entry_origin_probe.py`. Tests: `tests/test_por_ecl_entry_origin_probe.py`. Source: the pinned
retail `GAME.OVR` (206,105 bytes, SHA-256 `872964a3...28614`), `START.EXE` (65,231 bytes, `d825df2b...6b07bd`) and
`ECL1..8.DAX`, read-only. Output under `data/work/por-ecl-entry-origin-probe/retail/` (not committed).

Question: the native stream diagnostic (`tools/por_ecl_native_stream_probe.py`) walks from block offset 22 and
labels that origin as inherited from `tools/por_ecl.py`. Does PoR's own loader and header code establish a starting
stream offset, and is the 22-byte header end the instruction origin? No GoldBox framing rules are used: the DAX
container (TOC and signed-byte RLE) is read through `por_ecl.parse_dax` and `rle_decode` only. The header layout and
`ECL_HEADER_LEN` are not read.

---

## Verdict

| Quantity | Status | Basis |
| --- | --- | --- |
| Far pointer `[0x49DE]:[0x49E0]` is the block buffer | **Established by bytes** (one store, from an allocation of `0x1E00` bytes) | Sites `0x0E640`, `0x0E643`; allocator call `0x0E63B` |
| Initial cursor is the literal `0x9900` | **Established by bytes** (two literal stores) | `0x076C8` (routine `0x7689`), `0x0E993` (init routine) |
| The five-record header table is parsed from `0x9900` and ends at vaddr `0x9914` | **Established by bytes** (arithmetic over the parser's cursor steps) | Parser `0x74D3`, tag-1 path, exit `0x75FF` |
| Buffer index of vaddr `0x9914` is `20` | **Established by bytes** | Fetch displacement `0x6700` (parser and key-load bytes) |
| Block byte `22` is the stream origin | **Conditional.** The 2-byte loader skip is in the bytes and the retail parse pins the total offset; two links are unresolved (below) | Loader copy `0x78B1..0x78C6`, skip `2`, retail check 29/29 |
| Origin 22 is "the instruction stream start" | **Not established.** PoR's code never reads the cursor after the table parse; the VM step takes its own vaddr from the entry slots | Routine `0x7689` has zero cursor loads; callers of `0x3EB7` push `[0x49E3..0x49EB]` |

So the answer to the question "is origin 22 PoR-established?" is: **no, not as an instruction start. The table
boundary (vaddr `0x9914`, block byte 22) is PoR-derived and consistent, with every retail entry slot at or after it,
but two loader links are not resolved statically.** The `por_ecl.py` value 22 agrees with PoR's own structure,
2 bytes (the magic, skipped by the loader) plus five 4-byte records. The inherited label can be upgraded to
"PoR-derived, conditional on the loader source", which is a change for the parent to make (no existing tool or doc
was edited here).

---

## Instructions, byte candidates and models (kept apart)

- **Decoded instructions** (exact offsets, decoded with `tools/por_loadpieces_handler.decode`; byte sequences
  checked with `seq_at`): everything in the tables below.
- **Byte candidates**: every `disp16 == 0x49DE/0x49E0/0x49ED/0x49E3..0x49EB` occurrence was found by a byte scan and kept
  only when a decode from a nearby start reproduces the same DS-direct operand. Candidates that fail the decode are
  dropped, not counted.
- **Models** (not bytes): (a) the record model `c_k = 0x9900 + 4k` (k = 0..4); (b) the loader model: buffer index `k` holds
  block byte `k + 2`; (c) the copy is a byte copy, not a transform; (d) the record `R` the loader reads is the block from
  byte 0. (b) is supported by the retail grid below; (c) and (d) are not resolved.

---

## The byte chain

### 1. Far pointer slot `[0x49DE]:[0x49E0]`

- Direct stores, exactly one each (byte scan plus decode): `0x0E640  a3 de 49  mov [0x49de], ax` and
  `0x0E643  89 16 e0 49  mov [0x49e0], dx`.
- The value comes from `0x0E637..0x0E63B`: `mov ax,0x1e00 ; push ax ; call 0x0af8:0x023f` (`b8 00 1e 50 9a 3f 02 f8 0a`).
  So the pointer is the allocator's return, for a `0x1E00` (7680-byte) buffer. The return in `AX:DX` is an assumption
  (the caller stores `AX` and `DX`); the allocator body is not located.
- Reads: 18 `les di,[0x49de]` sites (listed in the JSON, `checks.pointer_slot.sites`), including the fetch in the VM
  step at `0x3EDC`, the parser body (`0x74F9`, `0x7514`, `0x7550`, `0x75B4`), the key-load path, and the loader
  (`0x781B`, `0x78BA`). No direct `push` of the cell, and no store through another cell.
- Not searched: stores through a register that holds `0x49DE` (a `di`-based `stosw` is not found by a direct scan).

### 2. Initial stream cursor `[0x49ED]`

- Literal `mov word [0x49ed], 0x9900` (`c7 06 ed 49 00 99`) at exactly two sites:
  - `0x076C8`: inside routine `0x7689`, straight-line to the first parser call at `0x07724`. The window
    `0x076C8..0x07724` has no branch; one far call (`0x076EF`, `0x0AF8:0x16A8`, pushes `ds:0x6F78`, 6, 0) sits
    between, and its effect on `DS:[0x49ED]` is assumed nil.
  - `0x0E993`: inside the init routine that starts at `0x0E600` (the allocation). Its consumer is not located: no
    near call from the next 60 instructions reaches the parser or the VM step.
- `0x7689` has zero cursor loads in `[0x7689, 0x7814)`: the cursor is never read after the five parses.

### 3. Loader `0x7814` (fills the buffer)

- `0x781B`: `les di,[0x49de] ; push es ; push di ; mov ax,0x1e00 ; push ax ; mov al,0 ; push ax ; call 0x0af8:0x16a8`:
  a zero fill of `0x1E00` bytes (the callee's body is not located; its arguments are the buffer, the count and the value).
- `0x78A6`: `call 0x0802:0x0716` (the record source `R`, returns `[bp-12]:[bp-10]` pointer and `[bp-8]` length; not resolved).
- `0x78AB`: `cmp [bp-8],2 ; jb` (guard: at least two bytes).
- `0x78B1`: `les di,[bp-12] ; add di,0x0002 ; push es ; push di ; les di,[0x49de] ; push es ; push di ; mov ax,[bp-8] ;
  dec ax ; dec ax ; push ax ; call 0x0af8:0x1685`: copies `len - 2` bytes from `R + 2` to `[0x49DE]`.
- `0x78CB..0x78D4`: `push [bp-10] ; push [bp-12] ; push [bp-8] ; call 0x0af8:0x0254` (not resolved).
- Source of the call sites: none is near-called from GAME.OVR (`0x7814`, `0x7689`, `0x0E600` have no `E8` callers); the
  entry into these routines is a far or INT 3Fh path that this probe does not trace.

### 4. Operand parser `0x74D3` (one class-1 operand per call)

- Class argument `mov al,[bp+6]` (`0x74DD`) with the loop bound `cmp al,[bp-7]`; the loop tail `mov al,[bp-1] ; cmp al,[bp-7]`
  (`0x75F4`) ends after one operand for class 1.
- Operand reads: tag at `cursor+1` (`0x74F5..0x74FF`), value at `cursor+2` (`0x750F..0x751A`), extra at `cursor+3`
  (`0x754D..0x7556`), each a `les di,[0x49de]; add di,ax; es mov dl,[di+0x6700]` (displacement `0x6700`, read from the bytes).
- Tag `1/2/3` path, from the bytes: `0x752A  a1 ed 49 40 40 a3 ed 49` stores `cursor := cursor + 2`; `0x7549  ff 06 ed 49`
  increments to `cursor + 3`; the exit `0x75FF  ff 06 ed 49 89 ec 5d ca 02 00` increments once more. A tag-1 record
  therefore advances the cursor by **4** bytes (leader, tag, value, extra).

### 5. Header table: five records from `0x9900`

- Routine `0x7689` calls the parser five times (`0x07724`, `0x0773A`, `0x07750`, `0x07766`, `0x0777C`), each preceded by
  `mov al,1 ; push ax ; push cs` (class 1).
- Each result is decoded by `0x7B82` as `((byte [bp+6]) << 8) | (byte [bp+8])` (`mov al,[bp+8] ; ... mov al,[bp+6] ;
  mov cl,8 ; shl ax,cl ; add ax,dx`): the value word of the record (extra high, value low).
- The five words are stored to `0x49E3, 0x49E5, 0x49E7, 0x49E9, 0x49EB` in that order (`0x07733`, `0x07749`, `0x0775F`,
  `0x07775`, `0x0778B`).
- Those five cells are the entry slots the VM step is called with: `push [0x49E3]` at `0x03FFF` and `0x04199`,
  `push [0x49E5]` at `0x0400E`, `0x04151`, `0x04228`, `push [0x49E7]` at `0x03B23`, `push [0x49E9]` at `0x03B40`,
  `push [0x49EB]` at `0x03F33` and `0x040A8` (each followed by `push cs ; call 0x3EB7`).

### 6. Fetch arithmetic (the stream address)

- The key load (classifier entry `0x9379` is `push bp ; mov bp,sp`; the key load itself is at `0x937C`), and the same
  fetch in the VM step at `0x3ED9`: `mov ax,[0x49ed] ; les di,[0x49de] ; add di,ax ; es mov al,[di+0x6700] ; mov [0x6f7f],al`.
- So the buffer index of vaddr `v` is `(v + 0x6700) & 0xFFFF` from the base of `[0x49DE]`. Vaddr `0x9900` is index `0`,
  vaddr `0x9914` is index `0x14` (`20`).

---

## The retail check (29 blocks, read-only container)

All seven byte checks pass on the pinned `GAME.OVR` (`checks.*.ok`). The block table is then tested against the
model:

- Each block's bytes `0..1` are the magic `0x1388` in all 29 blocks.
- Each block's five records at block bytes `2 + 4k` are `(seg 0x0101, vaddr)`: the segment word is the leader and
  tag `01 01` of a tag-1 record, and the vaddr is the value and extra. All five parse to the header's vaddrs in
  all 29 blocks, and the parse ends at `0x9914`.
- Skip grid (displacement fixed at `0x6700`, copy skip varied from `-4` to `+4`): only skip **`+2`** passes all 29
  blocks; every other skip passes 0. The grid pins the *sum* `displacement + skip = 0x6702`. Because the
  displacement is a fetch byte and the skip is the loader's `add di,2`, both are PoR bytes and agree.
- Every entry slot of every block is at or after `0x9914` (29 of 29). Slot 0 equals `0x9914` in 15 of 29 blocks.

What this shows: the origin 22 is the *only* skip that makes PoR's five-record parse read every retail table. It does
not show that the loader's source `R` begins at the block's byte 0 (that would make the copy a byte copy of the block),
and it does not show that the entries start at 22 (PoR does not read the post-table cursor).

---

## Falsifiers (`tests/test_por_ecl_entry_origin_probe.py`)

Each mutation changes one byte run of an in-memory copy of `GAME.OVR`; the named check must fail. The test file
asserts the old bytes first, so each mutation is applied to the instruction it names.

| Falsifier | Mutation | Expected failure |
| --- | --- | --- |
| Wrong pointer slot, parser | `les di,[0x49de]` at `0x74F9` becomes `[0x49d2]` | parser: `0x074F9` leaves the far-pointer loads |
| Wrong pointer slot, loader | `les` at `0x78BA` becomes `[0x49d2]` | loader copy bytes |
| Pointer store moved | `mov [0x49de],ax` at `0x0E640` becomes `[0x49d2]` | pointer-slot store list |
| Allocation size changed | `0x1E00` at `0x0E638` becomes `0x1D00` | pointer-slot alloc sequence |
| Cursor write removed | `mov [0x49ed],0x9900` at `0x076C8` becomes NOPs | header routine, cursor literals; no model |
| Cursor literal shifted | `0x9900` becomes `0x9902` | cursor literals; no model |
| Displacement changed (parser) | fetch `[di+0x6700]` at `0x74FF` becomes `0x6702` | parser (displacement set) |
| Displacement changed (key load) | key-load displacement at `0x9388` becomes `0x6702` | key-load check |
| Copy skip changed (bytes) | `add di,2` at `0x78B6` becomes `0` | loader copy bytes |
| Copy skip changed (data) | skip `0` or `+1`, `+3`, `+4` on the retail blocks | grid: 0 of 29 (synthetic and retail) |
| Branch between store and parse | `xor ax,ax` at `0x76D3` becomes `jmp short +0` | header routine: branch list |
| Class argument not one | `mov al,1` before the first parse at `0x7720` becomes `2` | header routine: class pushed |
| Value formula changed | `add ax,dx` at `0x7B98` becomes `sub` | value decode body |
| Entry slot order swapped | store at `0x7749` goes to `0x49E7` | value decode stored-into list |
| Cursor literal, wrong origin on data | parse from `0x9902` on the retail blocks | 0 of 29 blocks |

Synthetic tests (run everywhere): the access classifier on decoded opcodes; the cell scan on a hand-built buffer; the
buffer-index wrap (`0x9914` is index `0x14`); the five-record model and its closed-tag refusal; the copy-skip falsifier
on a synthetic block (skips `0, 1, 3, 4` each fail); zero bytes fail every check; refusals for an unpinned or missing
install file, output inside the install, and CLI output outside `data/work/`.

---

## Not established

1. The record source `R` returned by `0x0802:0x0716` (its body is not located). This is the link that would make
   the copy a byte copy of the block from byte 0.
2. Whether `0x0AF8:0x1685` is a byte copy of `R + 2` or a transform (its body is not located; the arguments are
   `(R + 2, [0x49DE], len - 2)`). The retail grid is consistent with a copy, not proof of one.
3. The zero fill `0x0AF8:0x16A8`, the allocator `0x0AF8:0x023F` and its `AX:DX` return convention, and the
   follow-on call `0x0AF8:0x0254`: inferred from their pushes, not from their bodies.
4. Reachability: no GAME.OVR near call reaches `0x0E600`, `0x7689` or `0x7814`. The far or INT 3Fh path that does
   reach them is not traced here.
5. The consumer of the second cursor literal at `0x0E993`.
6. The cursor effect of the far callee `0x0AF8:0x16A8` at `0x076EF` on `DS:[0x49ED]` (assumed nil).
7. Whether the five entry slots are the only entries the event loop uses.
8. Any meaning of an operand value. The parser carries raw bytes; the probe gives no opcode or header meaning.

---

## Correction to the brief

The brief named the key load at `GAME.OVR:0x9379`. That offset is the classifier's `push bp ; mov bp,sp`
prologue. The key load (`mov ax,[0x49ed] ; les di,[0x49de] ; ...`) starts at `0x937C`, and the same fetch
appears inside the VM step at `0x3ED9`. The probe checks both.

---

## Reproduce

```sh
python tools/por_ecl_entry_origin_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-ecl-entry-origin-probe/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_ecl_entry_origin_probe.py -q
python -m pytest tests/test_por_ecl_entry_origin_probe.py -q        # synthetic tests only, no install
```

Exit codes: 0 every byte check and the retail consistency check pass, and the report is written; 1 a check
failed; 2 a named refusal (missing or unpinned file, output inside the install, output outside `data/work/`).
Inputs are re-hashed after the run (`self_checks.inputs_unchanged`).
