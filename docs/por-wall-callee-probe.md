# Pool of Radiance: bounded call-edge probe from the GAME.OVR owner at 0x2EEF4

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`.**
**Answer: `no-dos-file-function-found-but-bounded-incomplete`. Selection: not-established.**
The followed closure from the owner (7 procedures, 1,278 instructions) contains **no inline INT
21h at all**. Its only unfollowed outward edges are **8 far calls** (3 distinct `seg:off` targets).
Those are the only edges that could reach DOS or another overlay, and their targets are not resolved
here. No string token (WALLDEF, 8X8D, DAX) is referenced under either literal model. One callee
(`0x2EB08`) does compute a byte-index times 156 into a far-pointer table at `DS:0x6A58`. Nothing here
ties that table to WALLDEF.

`tools/por_wall_callee_probe.py` decodes the owner's bounded direct near-call closure read-only against
the pinned `GAME.OVR`. `tests/test_por_wall_callee_probe.py` checks the traversal, the mutated-byte
falsifications, and the retail anchor (gated on `OPENUA_POR_INSTALL`).

Related: [por-wall-owner-0x2eef4.md](por-wall-owner-0x2eef4.md) (the owner's own decode; this doc
extends it to the callees), [por-wall-group29-target-probe.md](por-wall-group29-target-probe.md) (group 29
and stub 5, a partial scanner row), [por-wall-render-probe.md](por-wall-render-probe.md) (the 780/156
immediate scan, whose `0x2EBA6`..`0x2EBD7` sites are the `mov dx,0x9C` sites analysed below).

---

## Usage

```sh
python tools/por_wall_callee_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-callee-probe/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_wall_callee_probe.py -q
```

Output: `data/work/por-wall-callee-probe/retail/por_wall_callee_probe.json` (schema
`openua.por-wall-callee-probe` v1, sorted keys, no timestamps, no paths). Exit `0` clean, `1` written
with a diagnostic, `2` named refusal (missing or unpinned `GAME.OVR` without `--allow-unpinned`, or an
output folder inside the install). The probe writes nothing to the install.

## Pinned source

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |

Matched on the retail run. `GAME.OVR` was hashed before and after the run and was unchanged.

## Method, and what it can and cannot see

- **Recursive descent, not a linear sweep.** Each procedure is decoded from its entry by following
  fall-through, both arms of every conditional, and unconditional jumps. Undecoded bytes are not reported.
- **Near calls are queued, not inlined.** Each direct `E8` target becomes a new procedure at the next
  depth, up to `--max-depth` (default 3). Depth 0 is the owner. The default procedure budget is 40 and the
  instruction budget per procedure is 1,200. A budget stop is reported as `insn-budget` and makes the
  closure incomplete.
- **Far calls (`9A`) and indirect calls (`FF /2`, `FF /3`) are recorded and not followed.** A far segment
  word is a loader-fixed value and no segment base is known here.
- **INT 21h AH is a straight-line inference, not dataflow.** The nearest preceding `MOV AH,imm8` or
  `MOV AX,imm16` is used, through instructions that write neither AX nor AH (push, flag-only compare/test,
  a memory-destination store, or a MOV to another register). The window stops at a branch target and at any
  other writer. Each INT records its `ah_rule`.
- **Operand inference uses the same window rule.** For `MUL`, `IMUL`, `DIV`, `IDIV` with a register
  operand, the probe reports the straight-line `mov reg,imm` before it. For `SHL`/`SHR` by CL, it reports
  the preceding `mov cl,imm`.
- **String tokens (WALLDEF, 8X8D, DAX).** Two necessary-condition checks: a branch target equal to a
  token's file offset (file model), and an immediate, direct, or far-offset operand equal to a token's low
  16 bits (segment-offset model, where no segment base is known). A match is a candidate only.

## What the bytes establish

### 1. The owner closure

| Procedure | Depth | Insns | Coverage (bytes) | Decode complete | Far calls | INT | Selector sites |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| `0x2EEF4` (owner) | 0 | 827 | 1,975 (`0x2EEF4..0x2F6AB`) | yes | 0 | 0 | 5 |
| `0x2E8F7` | 1 | 149 | 341 | yes | 2 | 0 | 1 |
| `0x2EA6B` | 1 | 68 | 157 | yes | 4 | 0 | 0 |
| `0x2EB08` | 1 | 108 | 270 | yes | 1 | 0 | 2 |
| `0x2EC16` | 1 | 18 | 49 | yes | 0 | 0 | 0 |
| `0x2ED72` | 1 | 103 | 255 | yes | 0 | 0 | 6 |
| `0x2EEEA` | 1 | 5 | 10 | yes | 1 | 0 | 0 |

- Frontier: none. Procedure-budget truncation: no. Overlap conflicts: none. Decode gaps: none.
- The owner's own near calls (39, to six targets) match `EXPECTED_SEEDS` exactly.
- Owner walk: 827 instructions, `retf 6` at `0x2F6A8`, end `0x2F6AB`. Far calls 0. INT 0.
- Callee-to-callee edges (bytes raw): `0x2E8F7`@`0x2E999`→`0x2ED72`, `0x2E8F7`@`0x2E9AF`→`0x2ED72`,
  `0x2E8F7`@`0x2E9C6`→`0x2ED72`, `0x2E8F7`@`0x2E9DD`→`0x2ED72`, `0x2E8F7`@`0x2EA43`→`0x2EEEA`,
  `0x2ED72`@`0x2ED81`→`0x2EC16`.

### 2. The six callees (owner call sites, raw bytes)

| Callee | Owner calls | First call site (`at`, bytes) | Entry bytes |
| --- | ---: | --- | --- |
| `0x2E8F7` | 1 | `0x2EF0E`, `e8 e6 f9` | `55 89 e5 81 ec 0a 01 8a` |
| `0x2EA6B` | 1 | `0x2EF15`, `e8 53 fb` | `55 89 e5 b8 02 00 50 b8` |
| `0x2EB08` | 18 | `0x2F01A`, `e8 eb fa` | `55 89 e5 83 ec 0e 8a 46` |
| `0x2EC16` | 2 | `0x2EFDB`, `e8 38 fc` | `55 89 e5 83 ec 02 80 7e` |
| `0x2ED72` | 16 | `0x2EFCC`, `e8 a3 fd` | `55 89 e5 83 ec 02 8a 46` |
| `0x2EEEA` | 1 | `0x2F6A2`, `e8 45 f8` | `55 89 e5 9a 52 1b 64 04` |

`0x2EEEA` is a one-instruction wrapper: `push bp; mov bp,sp; call far 0x0464:0x1B52`.

### 3. Far calls (the only unfollowed edges that can leave the closure)

| Site | Caller | Bytes | Target (raw) |
| --- | --- | --- | --- |
| `0x2EA03`, `0x2EA3D` | `0x2E8F7` | `9a 2a 00 28 04` | `0x0428:0x002A` |
| `0x2EA8F`, `0x2EAB5`, `0x2EADB`, `0x2EB01` | `0x2EA6B` | `9a 32 26 64 04` | `0x0464:0x2632` |
| `0x2EBF2` | `0x2EB08` | `9a 2a 00 28 04` | `0x0428:0x002A` |
| `0x2EEED` | `0x2EEEA` | `9a 52 1b 64 04` | `0x0464:0x1B52` |

Three distinct `seg:off` pairs, eight sites. The segment words are link-time values the loader fixes.
Resolving them needs the group fixup table and the loader's segment map, and that is outside this
bounded probe. Their identity (a DOS path, an overlay dispatch, or a WALLDEF reader) is **unresolved**.

### 4. INT 21h, DOS file functions, and string tokens

- Inline `INT` sites in the seven procedures: **0**. No `INT 21h` is reached inline, so no AH inference
  is needed and no DOS file function (open, read, seek, close, or find) is reached inline.
- String-token candidates: **0** under the file-offset model and under the low-16 segment-offset model,
  across the seven procedures. Token file offsets in GAME.OVR include `WALLDEF` at `0x2F6AC` (length byte
  `0x2F6AB`), and several `DAX` and `8X8D` strings. None is referenced by a reached immediate, direct
  operand, far offset, or branch target. This is a necessary-condition check only.

### 5. Selector candidates (presence and operand values only)

- **`0x2EB08` `mov dx,0x009C` / `mul dx`** at `0x2EBA6`/`0x2EBA9` and `0x2EBD7`/`0x2EBDA`. Raw:
  `8a 46 08` (`mov al,[bp+8]`), `30 e4` (`xor ah,ah`), `ba 9c 00` (`mov dx,156`), `f7 e2` (`mul dx`),
  `c4 3e 58 6a` (`les di,[0x6a58]`), `03 f8` (`add di,ax`). The multiplicand is the callee's stack word at
  `[bp+8]`, the second byte the owner pushes (see the table below). The routine computes
  `ES:DI = far_ptr(DS:0x6A58) + arg2 * 156`, an index-times-156-byte-stride shape. Whether the table at
  `DS:0x6A58` is WALLDEF, 8X8D, or something else is **not established**.
- **Owner calls into `0x2EB08`: 18.** Every site has the same tail before the call, raw
  `mov al,[bp-N]; push ax; mov al,lit; push ax; push cs; call 0x2EB08` (the check covered these five
  instructions and the `push ax` before them, not the earlier source).
  So the callee's `[bp+6]` (read at `0x2EB0E`) is the literal, and its `[bp+8]` (the multiplicand) is the
  owner's stack local `[bp-N]`:

  | Second arg `[bp-N]` (multiplied) | Sites | Literal arg (`[bp+6]`) values |
  | --- | ---: | --- |
  | `[bp-23]` | 4 | `9`, `9`, `9`, `9` |
  | `[bp-21]` | 8 | `1`, `1`, `2`, `2`, `4`, `5`, `7`, `8` |
  | `[bp-20]` | 6 | `0`, `0`, `3`, `3`, `6`, `6` |

  The owner's value of each local is set by code this probe does not decode, so the record index is not
  established. The literal (0 to 9) is a small selector range that does not by itself name a record.
  Each call site's raw bytes are in the JSON (`call_edges`).
- The `0x2EB08` `mov dx,0x9C` sites are the same `780 / 156` immediates that
  [por-wall-render-probe.md](por-wall-render-probe.md) §4 classified as "outside the owner's range, none
  shown to index a WALLDEF record". That classification is correct about the owner range. This probe adds
  that the two sites sit in a callee the owner calls 18 times, and that each is followed by `mul` and a
  far-pointer load. It does not show that either site indexes a WALLDEF record.
- **Owner selector sites:** `idiv cx` by 8 (`mov cx,8` before `IDIV`) at `0x2EF24`, `0x2EF36`, `0x2EF47`;
  `mul [bp-9]` at `0x2EF82` and `mul [bp-11]` at `0x2EF8D`. The two `mul` sites take a stack local as the
  multiplicand, and the probe does not resolve it.
- **`0x2ED72` shifts by CL** (`shl`/`shr` at `0x2EDD8`–`0x2EE54`), and `0x2E8F7` `shr ax,1` at `0x2EA31`.
  Four of the `0x2ED72` shifts have a straight-line `mov cl,4`; two are `xor ah,ah`-separated and stop
  as "intervening-unknown-writer". Presence only.

## Evidence boundary

- Every edge, call site, and operand listed above is decoded from the pinned bytes with the existing
  PoR decoder (`por_loadpieces_handler.decode`). No callee is inferred from a name, a filename, or a
  GoldBox or CoK rule.
- "Group 29" appears only as a containment label. All 45 call edges fall inside the observed group-29 load
  span (`0x2E8F7` + `0x120B`). That span is one runtime quote, not retail, so the label is a hypothesis.
- The owner's runtime caller is **not** established. This probe starts at the owner and goes down. No
  caller of `0x2EEF4` is shown.
- The 827-instruction owner walk and the recursive closure agree on the 39 near calls and six targets.

## Limits and unresolved edges

| Edge or question | Status |
| --- | --- |
| 8 far calls to `0x0428:0x002A` and `0x0464:0x2632`, `0x0464:0x1B52` | recorded, not followed; targets need the fixup table and loader map |
| Indirect calls | none found in the closure |
| `0F`-prefixed opcodes | none in the closure (a procedure with one stops and is marked incomplete) |
| INT 21h AH | no inline INT, so nothing to infer in this closure |
| DS data `0x6A58` (far-pointer table) | identity not established; `LES` loads it |
| Table behind `DS:0x6A58` at arg×156 | no WALLDEF or 8X8D identity shown |
| Callers of `0x2EEF4` | not established (no caller probe here) |
| Runtime reachability | not established; this is a static bounded closure only |

## Tests

`tests/test_por_wall_callee_probe.py`: 25 tests when `OPENUA_POR_INSTALL` is set (24 plus the retail
anchor, which is skipped otherwise).

- Traversal: near calls queued by depth; the branch-only call on the taken arm of a `JNE` is reached and
  recorded; with `max_depth=0`, callees are frontier and not entered.
- Mutated-byte falsifications: the `JNE` displacement removes the branch-only edge and the DOS read it
  reached; a call displacement moves the edge target; the `AH` immediate changes the DOS function; the
  `INT` vector removes the DOS call; a far-call opcode `9A` replaced by NOPs removes the far edge and flips
  the answer to `no-dos-file-function-in-closure`; `FF D0` replaced by NOPs removes the indirect edge; the
  `MOV DX` immediate changes the operand value; the `MUL` opcode replaced removes the selector; the
  low-16 token immediate is removed by a mutation.
- AH rule: a branch-target join and an intervening writer each make AH unknown; a neutral `PUSH` keeps the
  window open, and `POP AX` does not.
- Budget and decode: an instruction budget of 2 marks the closure incomplete; a `0F` opcode marks the
  procedure incomplete.
- Determinism and refusals: two runs give identical JSON with no path text; an unpinned `GAME.OVR` is
  refused without the flag and marked with it; an output folder inside the install is refused.
- Retail anchor (gated): read-only pin and hash check, the owner 827 / 39 / 0 / 0 counts, seeds match, the
  seven procedures, no frontier, no DOS file hits, the three far `seg:off` pairs, the two `mul dx, 156`
  sites, and byte-identical JSON across two runs.

Retail run (2026-11-17, read-only): `python tools/por_wall_callee_probe.py --install "PATH/TO/POOLRAD" -o
data/work/por-wall-callee-probe/retail` exits `0`, writes a 32,495-byte JSON, and prints
`7 procs, 1278 instructions, 45 call edges, frontier 0, far 8, indirect 0, INT21 file hits 0, INT21 unknown
AH 0, answer no-dos-file-function-found-but-bounded-incomplete, pin pinned`.

## Next evidence needed

1. Resolve the three far `seg:off` targets through the group fixup table and the loader's segment map, to
   see whether any reaches a DOS file function or a WALLDEF reader. This is the one edge that could
   establish a file read from this closure.
2. Identify the table behind `DS:0x6A58` (its initialization, and whether any writer records a WALLDEF
   offset), and check whether the owner's literal argument set (0–9) matches any record count.
3. A decoded caller of `0x2EEF4` (the render and group-29 probes are the starting points), or a runtime
   stop on entry during a dungeon load.
