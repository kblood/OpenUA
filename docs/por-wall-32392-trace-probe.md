# Pool of Radiance: static trace of GAME.OVR 0x32392 (conditional placement)

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`.**

**Conditional.** [por-wall-far-target-probe.md](por-wall-far-target-probe.md) maps the owner's far call
`0428:002A` to GAME.OVR `0x32392` only under the sibling consensus delta `0x1866` and the stub-run model
(START stub `0x42E3`). The owner's own delta is not measured. Everything below is about the **bytes at
GAME.OVR `0x32392`**. None of it establishes that the routine executes, that the far call reaches it,
or what the far-table entries point at at runtime.

Companion to [por-wall-callee-probe.md](por-wall-callee-probe.md) (the owner's closure and its eight far
calls) and [por-wall-far-target-probe.md](por-wall-far-target-probe.md) (the placement this doc depends on).

`tools/por_wall_32392_trace_probe.py` reuses `por_wall_callee_probe.traverse()` for the closure and its
decode, AH inference and string-token checks, unchanged. It adds memory-operand classification, far-pointer
load and ES-scaled multiply sites, and a path-based check for reads of uninitialised BP slots.
`tests/test_por_wall_32392_trace_probe.py` has 14 synthetic tests (mutated-byte falsifications) and one
retail pin test gated on `OPENUA_POR_INSTALL`.

## Usage

```sh
python tools/por_wall_32392_trace_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-32392-trace-probe/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_wall_32392_trace_probe.py -q
```

Output: `data/work/por-wall-32392-trace-probe/retail/por_wall_32392_trace_probe.json` (schema
`openua.por-wall-32392-trace-probe` v1; sorted keys, no timestamps, no paths; two runs are byte-identical).
Exit `0`: prologue present and near closure complete. The retail run exits `0`. The probe writes nothing to
the install.

## Pinned source

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |

Matched on the retail run and unchanged afterwards (the pin test asserts this).

## What the bytes establish

### 1. The entry and its closure

- Entry `0x32392` begins `55 89 e5` (push bp; mov bp,sp). `sub sp,6`. Arguments are at `[bp+6]`,
  `[bp+8]`, `[bp+10]`, `[bp+12]`, `[bp+14]`.
- **Near closure: one procedure, 127 instructions, no near calls.** The closure is complete.
- **Eight far calls, none followed**: `0464:00FF`, `0AF8:0919`, `0AF8:084A`, `0899:0059`, `0899:0000`,
  `0464:08D4`, `0AF8:1685`, `0464:1951` (sites `0x323FA`..`0x324D7`). Their segment words are the
  loader-fixed values covered in the callee probe. This closure does not follow them.

### 2. Inline DOS I/O and string literals

- **INT 21h inline: 0.** No DOS file function is reached in this procedure. Any file I/O would sit behind
  one of the eight far calls, which are not followed here.
- **WALLDEF / 8X8D / DAX references: 0.** Ten token occurrences exist in GAME.OVR, and none is named by an
  immediate, direct, far-offset or branch operand in this closure.
- **Stride constant 156 (`0x9C`): not present** as an immediate in this closure.

### 3. The record path: a five-way class selection, then a far-table element address

The key is the word argument `[bp+10]` (call it `A`). The routine picks a class `idx` from `A`, then
indexes a record table through a far pointer:

| Step | Bytes (site) | Meaning from the bytes |
| --- | --- | --- |
| class | `cmp` chain at `0x3239B`..`0x323F5` | `idx` = 0 for `A` in 1..0x2D, 1 for 0x2E..0x73, 2 for 0x74..0xB9, 3 for 0xBA..0xFF, 4 for 0x100..0x11E (arm sizes 45, 70, 70, 70, 31) |
| base | `sub [bp+10],ax` after `mov ax,[di+0x2722]` (`0x32444`), `di = idx*2` | `A' = A - W[idx]`, with `W` a word table at DS:`0x2722` |
| far pointer | `les di,[di+0x5E3A]` (`0x32490`), `di = idx*4` | `P = far_ptr(DS:0x5E3A + 4*idx)`, a far-pointer table; non-null is tested at `0x3242E`/`0x32432` |
| element | `es mul [di+0x11]` (`0x324A0`), `add di,ax`, `add di,0x17` | element = `P + 0x17 + A' * word(P+0x11)` |

- When the byte `[bp+8]` is zero (`0x3244B`), the routine copies one element to a second far buffer
  `Q = DS:0x5E4E` (`les di,[0x5e4e]`, at `0x324AF`). The call at `0x324C0` (`0AF8:1685`) takes five pushed
  words: the source far pointer (element), the destination far pointer (`Q+0x17`), and the count word
  `word(P+0x11)`, the stride. By the earlier probe's opcode
  inspection, `1685` is an overlap-safe copy; that identity is not re-verified here.
- When `[bp+8]` is nonzero, the routine instead pushes `P`, `A'`, byte-sized arguments and the far pointer
  at DS:`0x4A20`, then calls `0464:08D4`.

So the bytes **do index a record table**: the element address is computed from a stride read out of the
table, and the table is reached through a far pointer that the code loads from DS. This is a structural
finding. Whether any of these far pointers points at WALLDEF or 8X8D data is **not established**. The
table contents and the DS segment value are runtime data, not in GAME.OVR.

The 156-byte stride of [por-wall-callee-probe.md](por-wall-callee-probe.md) §5 (`0x2EB08`, table at
DS:`0x6A58`) does not appear here. The two routines reference disjoint DS addresses, and nothing in these
bytes ties them together.

### 4. Table and direct DS references

| Kind | Addresses |
| --- | --- |
| indexed DS table bases | `0x2722` (word, `idx*2`), `0x5E3A` / `0x5E3C` (far pointers, `idx*4`) |
| direct DS words | `0x4A20`/`0x4A22` (far pointer, pushed), `0x5E4E`/`0x5E50` (far pointer `Q`, `les` and pushes) |

### 5. Uninitialised BP slot `[bp-1]` (the class index)

`[bp-1]` is written only on the five class arms (`mov byte [bp-1],N` at `0x323A5`, `0x323B5`, `0x323C5`,
`0x323D5`, `0x323E5`). It is read at `0x32423`, `0x3243B`, `0x32463` and `0x32485`. Reads that the walk
reaches with no earlier write:

- **Key `A == 0`** (`jz` at `0x323EE`): falls into the `0x323FA` path, which makes a call with no
  arguments and never writes `[bp-1]`, then reaches `0x32423` unwritten. **Feasible.**
- **Key `A` in `0x11F..0x7FFF`**: falls through `0x323F3`/`0x323F8` into the same `0x323FA` path. **Feasible.**
- **Key `A > 0x7FFF`** (`ja` at `0x323F8`): reaches `0x32423` directly. **Feasible.**
- The walk also lists a `jb` path from `0x323F3`. It is **value-infeasible**: keys 1..0xFF are always taken by
  an earlier arm (each arm ends in a `jmp` that writes the slot first). The walk is path-insensitive and
  does not see this, so the tool lists it and the limit is recorded in its output.

So for every key outside 1..0x11E the class index is never written in this procedure. Whatever the caller
or the stack left in that slot is what the index becomes. Whether any caller passes such a key, and what the
stack holds, is **not established**. The bytes do not show a defect; they show a path that depends on
caller-supplied keys and on uninitialised stack contents.

## Answers to the questions

| Question | Answer from the bytes | Basis |
| --- | --- | --- |
| Inline DOS file I/O? | **No** (0 INT 21h in the closure) | §2 |
| Far calls leaving the closure? | **8**, not followed (conditional on placement for any follow-on) | §1 |
| Literal WALLDEF / 8X8D / DAX? | **No** in the closure | §2 |
| Selects or indexes table or record data? | **Yes, structurally**: class-selected far-table element at `P + 0x17 + A'·stride` | §3 |
| Binds to WALLDEF / 8X8D data? | **Not established**: the table contents are runtime DS data | §3 |
| Uses a constant stride of 156? | **No** in this closure | §2 |

## Limits and unresolved edges

| Edge or question | Status |
| --- | --- |
| Placement of `0x32392` (delta `0x1866`, stub `0x42E3`) | conditional, not measured here |
| Whether any caller reaches this routine | not established |
| Contents of DS `0x2722`, `0x5E3A`, `0x5E4E`, `0x4A20` and what the far pointers name | not in GAME.OVR; runtime only |
| WALLDEF / 8X8D binding of table `P` | not established |
| The eight far-call targets, including `0AF8:1685` and `0464:1951` | not followed here; [por-wall-far-target-probe.md](por-wall-far-target-probe.md) maps some of them conditionally |
| Caller key range and the stack value behind `[bp-1]` for keys outside 1..0x11E | not established |
| Near-call targets as file offsets | assumes the body is loaded at its file position |

## The discriminating observation (not yet taken)

A RAM dump taken while the group containing `0x32392` is resident would give the DS segment value. Reading
the words at DS:`0x2722` (5 entries) and the far pointers at DS:`0x5E3A` (5 entries) would name the table
bases, the strides at `P+0x11`, and whether `P` points into a WALLDEF- or 8X8D-shaped table. That needs the
owner or stub placement to be measured first; it is not done here.

## Tests

`tests/test_por_wall_32392_trace_probe.py` (15 tests): 14 synthetic and the retail pin test, all passing on
2026-11-18 with `OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD"`. The synthetic tests cover: the LES and
ES-multiply classification (with mutations that remove the ES prefix and the LES); the uninitialised-slot walk
(a mutation that writes the slot on the zero arm clears it); the prologue mutation; the conditional placement
block; inline INT 21h with an AH mutation; the WALLDEF token with a mutated operand; the 156 stride with a mutated
operand; determinism; the unpinned refusal; the output-inside-install refusal; and an unpinned probe run that writes
only to its output folder. The retail test asserts the pinned hash, the 127-instruction closure, the eight far-call
sites, the two far-table loads, the one ES-scaled multiply at `0x324A0`, the DS addresses, and the four uninitialised
read sites.
