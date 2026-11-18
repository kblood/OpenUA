# Pool of Radiance: ECL handler cursor probe (diagnostic only)

**Status: DIAGNOSTIC-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`. The stream prefix is not extended.**

Tool: `tools/por_ecl_handler_cursor_probe.py`. Tests: `tests/test_por_ecl_handler_cursor_probe.py` (28 tests: 26
synthetic, 2 retail-gated on `OPENUA_POR_INSTALL`). Static, bounded, read-only. No emulator and no runtime.

Companions (read, not changed): [por-ecl-native-stream-probe.md](por-ecl-native-stream-probe.md) (the 12-byte prefix
this doc re-examines), [por-ecl-native-framing-probe.md](por-ecl-native-framing-probe.md) (the classifier and parser
evidence), [por-ecl-decoder.md](por-ecl-decoder.md) (the DAX container and the pinned block).

---

## Question and answer

> For opcode `0x1B` (the one the stream probe stops at, at block offset 34), does its dispatcher handler consume or
> adjust the stream cursor `[0x49ED]`, and is the dispatcher key `[0x6F7F]` demonstrably the stream byte at the cursor?

| Question | Answer | Status |
| --- | --- | --- |
| Does the handler consume or adjust the cursor? | **Adjusts, by exactly +1, before any branch.** `inc [0x49ED]` at `GAME.OVR:0x189B` is the only cursor write on any path, and it comes before the first branch. The handler reads no stream bytes on any path. | Decoded; every path checked |
| Is the cursor effect settled for the whole record? | **No.** The `0x1B` sub-chain calls a far helper `0x002B:0x008E` when `[0x6F7D] == 0`. The helper's cursor effect is unknown, and the guard's runtime value is not established. | Open: one of two paths unresolved |
| Is the dispatcher key the stream byte at the cursor? | **Yes, on the only dispatcher path that is decoded.** The loop at `0x3EB7` copies `es:[di+0x6700]` (with `di = [0x49DE] + [0x49ED]`) into `[0x6F7F]` at `0x3EE7` and calls the dispatcher at `0x3EEB`. Nothing else writes the key between that store and the dispatcher's read at `0x3C76`. | Decoded for this path. "Is the opcode" is the probe's assumption, not a proof |
| Does this extend the supported ECL prefix? | **No.** It stays at block offset 34 (12 bytes). The `0x1B` record's cursor effect is +1 only on the guard-nonzero path. | Not settled |
| Do `0x16`, `0x15`, `0x2B` settle the same way? | **No, none settles.** `0x16` shares the `0x1B` handler and has the same open far-call path. `0x15` and `0x2B` have far calls and bounded-walk budgets (decoded loops), so they stay open. | Open, by the same method |

---

## Inputs and pins

| Input | Size | SHA-256 | Role |
| --- | ---: | --- | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` | Dispatcher, handlers, loop, classifier (read-only) |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` | Byte census of the key cell: no references |
| `ECL2.DAX` | 19,968 | `6ad6dc5aa53da82f4dba62dbc47d5a02a3f14c14071bec44e81a692615f08a3d` | Container; block 20 (raw 7,679), decoded SHA-256 `a1e1dd7a…7297ec` (matches pin) |

The GOG install is `G:/Games/Pool of Radiance/POOLRAD`. The probe checks all three pins before reading any bytes.
It never writes under the install.

## Evidence labels

- **decoded**: an instruction the decoder produced from a dispatcher walk, a handler path walk, or the loop walk.
  Every decoded branch target was also recomputed from the raw bytes, and the two agree.
- **decodes-at-candidate-start**: a raw byte pattern whose start offset the decoder accepts, but which no walk
  reached.
- **byte-pattern**: a raw byte match only.

## Dispatch branch for 0x1B (decoded)

```
0x3D63  3C 1B        cmp al,0x1B
0x3D65  75 07        jnz 0x3D6E        (the case for 0x1C; raw target agrees)
0x3D67  0E           push cs
0x3D68  E8 2D DB     call 0x1898       (raw recomputation: 0x3D6B - 0x24D3 = 0x1898)
0x3D6B  E9 47 01     jmp 0x3EB5        (dispatcher exit: pop bp; retf)
```

The key is read at `0x3C76` (`mov al,[0x6F7F]`, the dispatcher's first instruction after `push bp; mov bp,sp`). The
path from there to the `0x1B` compare is compare-and-branch only, with no clobber (decoder path check: 28 steps).

The opcodes `0x16`–`0x1A` reach the same block: `je 0x3D67` at each of their compares, so the group
`{0x16, 0x17, 0x18, 0x19, 0x1A}` shares the `push cs; call 0x1898` block, and `0x1B` has its own `jnz` into it. Both
forms are decoded and consistent.

## The 0x1B handler (decoded, `0x1898`)

| Offset | Bytes | Instruction | Role |
| --- | --- | --- | --- |
| `0x1898` | `55 89 E5` | push bp; mov bp,sp | prologue |
| `0x189B` | `FF 06 ED 49` | inc [0x49ED] | **the only cursor write**: +1, before any branch |
| `0x189F` | `A0 7F 6F` | mov al,[0x6F7F] | key re-read: AL := the key (see the key assumption below) |
| `0x18FC` | `3C 1B` | cmp al,0x1B | selects this arm (the other arms are `0x16`–`0x1A`) |
| `0x1900` | `80 3E 7D 6F 00` | cmp byte [0x6F7D],0 | guard cell for this arm |
| `0x1905` | `75 05` | jnz 0x190C | guard non-zero: skip the far call |
| `0x1907` | `9A 8E 00 2B 00` | call far 0x002B:0x008E | segment is fixup-listed; in two RAM dumps this maps through a far-jump thunk to classifier `0x9379` (taken iff guard is 0) |
| `0x190C` | `5D CB` | pop bp; retf | return |

Paths for opcode `0x1B` (the probe's bounded walk; AL is decided by the compares, and the guard forks the path):

| Path | Condition | Cursor | Far calls | Status |
| --- | --- | --- | --- | --- |
| A | guard non-zero (`jnz` taken at `0x1905`) | +1 (`0x189B`) | none | settled |
| B | guard zero (`jnz` not taken) | +1, then enters classifier bytes under the two-dump mapping; resulting cursor depends on the byte at the live stream cursor | `0x002B:0x008E` at `0x1907` | target memory-mapped; execution, guard value, and stream binding unknown |

The handler reads no stream bytes on either path. Its cell references are `[0x49ED]` (once), `[0x6F7F]` (the read at
`0x189F`), and `[0x6F78]`–`[0x6F7D]` (the sub-arm guards).

## Caller path: the stream loop at 0x3EB7 (decoded)

`GAME.OVR:0x3EB7` is the dispatcher's only direct caller (raw scan: one `E8` site, `0x3EEB`, decoded in the loop walk).
It takes its cursor from its stack argument (`mov ax,[bp+6]` at `0x3EBA`, `mov [0x49ED],ax` at `0x3EBD`), and its loop
never advances the cursor (the cursor writes in its walk are that one store).

```
0x3ED3  A0 7F 6F    mov al,[0x6F7F]          previous key
0x3ED6  A2 7E 6F    mov [0x6F7E],al          -> saved as the previous key
0x3ED9  A1 ED 49    mov ax,[0x49ED]          the cursor
0x3EDC  C4 3E DE 49 les di,[0x49DE]          far pointer to the ECL block
0x3EE0  03 F8       add di,ax
0x3EE2  26 8A 85 00 67   es mov al,[di+0x6700]   the stream byte at the cursor
0x3EE7  A2 7F 6F    mov [0x6F7F],al          -> the key
0x3EEA  0E          push cs
0x3EEB  E8 85 FD    call 0x3C73              the dispatcher
0x3EEE  EB D5       jmp 0x3EC5               back to the loop head
```

The sequence is matched as decoded instructions with no gap. The 0x3EB7 loop has nine direct callers, found by a raw
scan of `E8` sites. Each pushes a word from a DGROUP cell immediately before `push cs; call` (the `ff 36` push is
decoded at the candidate start): `0x3B28` pushes `[0x49E7]`, `0x3B45` pushes `[0x49E9]`, `0x3F38` pushes `[0x49EB]`,
`0x4004` pushes `[0x49E3]`, `0x4013` pushes `[0x49E5]`, `0x40AD` pushes `[0x49EB]`, `0x4156` pushes `[0x49E5]`,
`0x419E` pushes `[0x49E3]`, `0x422D` pushes `[0x49E5]`. These are byte-pattern callers. Their run-time arguments are not
established.

**Key-producer accounting.** Writers of `[0x6F7F]` in `GAME.OVR` (every byte reference, classified by its instruction):
the loop's store at `0x3EE7` (decoded), and the classifier's store at `0x938A` (decoded in the classifier's walk). Nine
other references are reads or compares. `START.EXE` has no reference to the key cell.

## Expansion: 0x16, 0x15, 0x2B (same method, same stop rule)

| Opcode | Dispatch edge (decoded) | Handler | Paths | Settled | Open reasons |
| --- | --- | --- | --- | --- | --- |
| 0x16 | `je 0x3D67` (shared group 0x16–0x1A) | 0x1898 | 2 | 1 (+1) | far call `0x002B:0x008E` on the guard-zero path |
| 0x15 | `jnz`, `call 0x1C4E` | 0x1C4E | 22 | 0 | 12 far-call sites; decoded backedge `0x1D3F → 0x1CF5` (step budget) |
| 0x2B | `jnz`, `call 0x1E17` | 0x1E17 | 64 (path budget) | 0 | 18 far-call sites; decoded backedge `0x1F1B → 0x1ECA` (step budget) |

`0x16` is the same handler and the same unresolved far call as `0x1B`, so it does not settle either. `0x15` and `0x2B`
are not settled: they make far calls, and their walks cross decoded loops that the bounded walk cannot close. They stay
open.

## Falsifiers (retail run and synthetic tests)

| Falsifier | Claim it tests | Retail observation | Test |
| --- | --- | --- | --- |
| Wrong branch target | The `0x1B` compare reaches `0x1898` by the decoded branch; raw recomputation agrees; the `jnz` lands on the next case | Consistent: `jnz 0x3D6E`, `call 0x1898`, exit `0x3EB5`, all raw-equal. Not triggered | A `jnz` that lands on the exit instead of the next case is refused |
| Cursor mutation | The handler changes the cursor only by one increment, on every path | One `inc` on every path, no other write. Not triggered | An extra `mov [0x49ED],ax` makes every path open (`cursor-write-other`) |
| Unknown helper | A far callee whose target is not decoded may move the cursor | Far call `0x002B:0x008E` is on path B. **Triggered**: the claim is limited to path A | Removing the far call settles both paths at +1 |
| Key producer | The handler's compares read the stream byte at the cursor (the loop's store), before any far call | The loop's store is immediately before the dispatch call. The writer census is accounted for. Not triggered | A compare on a non-key value (`mov al,[0x1234]`) makes paths open; a loop that stores something other than `es:[di+0x6700]` breaks the sequence |

## Retail block compare (after the byte chain fixes the field)

The field the byte chain fixes is the cursor after the opcode byte: block offset `34 + 1 = 35`. The probe reads the
pinned `ECL2.DAX` block 20 with the read-only container parser.

- Byte at block offset 34: `0x1B`, matching the opcode. Bytes from offset 34: `1b 09 00 08 01 7d 6e 09`.
- The `0x1B` handler reads no stream bytes on any path. So on path A, offset 35 is the next dispatch key, not an operand
  of `0x1B`. The byte there is `0x09`.
- The stream probe's classifier arm for `0x1B` is `inc-only` (one byte). That agrees with the handler's initial +1.
  On path B, the far-call target maps to the classifier in two dumps; its subsequent cursor advance depends on the live
  byte and operand path, so offset 35 is not established as the next key there.

The comparison confirms the field and the +1 on the guard-nonzero path. It does not settle the guard, so it does not
extend the prefix.

## What this changes for the supported prefix

**It does not increase the supported ECL prefix.** The stream probe's 12 bytes (offsets 22–33) and its stop at offset
34 stand. The `0x1B` record increments the cursor by one on entry. On path A (guard nonzero), that is the settled
handler effect. On path B (guard zero), the target maps through a thunk to the classifier in two RAM dumps; the
classifier's next advance depends on the live byte and any operand helper. The guard `[0x6F7D]` is not established.
Its writers `0x8DB3` and `0x8E1B` (raw `C6 06 7D 6F 01`, byte-pattern) store 1, and their reachability is not
established. Without a settled guard and stream binding, the walk cannot claim a boundary at offset 35.

## Cross-finding: direct loop path and conditional classifier route

The stream probe takes its operand framing from the classifier at `0x9379` and the parser at `0x74D3`. In the scanned
bytes:

- The dispatcher loop at `0x3EB7` calls the dispatcher `0x3C73`, not the classifier/parser. No direct near `E8` caller
  of classifier `0x9379` was found in the earlier scan. The separate `0x1B` handler does make a fixup-listed far call
  (`002B:008E`) on its guard-zero path. In both RAM dumps, that call targets a thunk which jumps to the exact
  classifier body at `0x9379` (see [`por-ecl-1b-classifier-dump-probe.md`](por-ecl-1b-classifier-dump-probe.md)).
- The parser `0x74D3`'s only direct callers are the classifier's eight arms and the routine at `0x7689`, and `0x7689`
  has **no** direct caller.
- The dispatcher's only direct caller is the loop at `0x3EB7`, which never calls the classifier or the parser. It reads
  the stream itself, with the same `es:[di+0x6700]` and `[0x49ED]` as the classifier.

So the classifier-based framing is not called directly by the dispatcher loop, but a conditional route from the `0x1B`
handler to the classifier is now byte-mapped in the dumps. The `0x1B` handler itself increments the cursor before the
guard; if guard-zero, the classifier then processes the byte at that cursor. For candidate ECL1 #24, this would parse
the `0x09` record through `0x1DB8` if the block-offset/cursor link holds; neither execution nor that stream binding is
established. The framing doc still says reachability of the classifier path and the `0x7689` routine is not established.
This probe adds that the dispatcher loop's own key and cursor handling is decoded. The framing doc notes that the
`0x7689` routine would store words to
`[0x49E3]`–`[0x49EB]`, which are the cells the loop's nine callers push. That link is a hypothesis, and this probe does
not establish it.

## Tests and runs

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_handler_cursor_probe.py
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_handler_cursor_probe.py
```

- Without the variable: **26 passed, 2 skipped**. Synthetic tests use hand-assembled buffers (a dispatcher case, a shared
  group, a stream loop, a handler), one mutation per falsifier, refusals (missing install, output inside the install,
  unpinned files, output outside `data/work/`), and the operand-role and census classifiers.
- With the variable pointing at the GOG install: **28 passed**. The retail tests check the settlement, the decoded key
  store and dispatch call, and the block compare, and check that two runs give byte-identical output with no
  install-path text.
- The existing stream and framing tests still pass unchanged (`62 passed, 3 skipped`).

Retail report (writes only under `data/work/`):

```sh
tools/.venv/Scripts/python.exe tools/por_ecl_handler_cursor_probe.py \
    --install "G:/Games/Pool of Radiance/POOLRAD" --ecl 2 --block 20 -o data/work/por-ecl-handler-cursor/retail
```

Exit `0`; all 20 self-checks pass. Outputs: `data/work/por-ecl-handler-cursor/retail/por_ecl_handler_cursor_probe.json`
(747,555 bytes, SHA-256 `7f36d6d9c6965418404cfbfd7ec8bdc808e1251b02da4fe358b7e599fb83549a`) and
`por_ecl_handler_cursor_probe.md` (3,248 bytes, SHA-256 `6f7153348180d7232aee8f4fa137b8ef9c903f52fb244a75a0a27e9a287c4ccf`).

## Not established

- Run-time reachability of the stream loop at `0x3EB7`: its nine callers are byte patterns, and the values they push
  (`[0x49E3]`–`[0x49EB]`) are not decoded here.
- The entry cursor's run-time value, and therefore whether the stream origin (block offset 22) is the loop's entry.
- The `0x002B:0x008E` target is memory-mapped through a thunk to the classifier in two dumps; see
  [`por-ecl-1b-classifier-dump-probe.md`](por-ecl-1b-classifier-dump-probe.md). Whether the call executes, the live
  guard and stream byte, and the resulting cursor effect remain unknown.
- The guard `[0x6F7D]`: its initial value and whether writers `0x8DB3` or `0x8E1B` run before the first `0x1B`.
- Whether far callees write the loop exit flag `[0x442E]`, which would end the loop.
- Other overlays and indirect callers. Only `GAME.OVR` and `START.EXE` are scanned.
- The meaning of any opcode, operand, or cursor value. No opcode semantics are used, and no other title's opcode map
  is read.

## Outputs and boundaries

- This cursor probe is read-only. The later `por-ecl-1b-classifier-dump-probe.py` adds a separate memory-byte cross-check;
  neither probe establishes execution or edits the stream/framing tools.
- Outputs go under `data/work/` (git-ignored). The JSON and Markdown contain no absolute paths and no timestamps.
