# Pool of Radiance: ECL menu framing (0x15, 0x2B) and the far targets `2B:2A` / `2B:25`

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`.**

Tool: `tools/por_ecl_menu_framing_probe.py`. Tests: `tests/test_por_ecl_menu_framing_probe.py` (9 tests: 8 synthetic,
1 retail-gated on `OPENUA_POR_INSTALL`).

Companions (read, not changed): [por-ecl-decoder.md](por-ecl-decoder.md) (the `spec-menus` vs `conservative` framing
conflict), [por-candidate-procs.md](por-candidate-procs.md) and [por-farcall-resolution.md](por-farcall-resolution.md)
(the zero-skew stub model), [por-ecl-opcode2d-probe.md](por-ecl-opcode2d-probe.md) (the dispatcher and `0x3EB7`).

---

## Question and answer

> Do PoR's own `GAME.OVR` bytes settle the 0x15 / 0x2B menu operand framing, and what do the far calls `2B:002A` and
> `2B:0025` in the two menu handlers resolve to?

**No, not settled.** The bytes establish the handlers' call shapes, the classifier's default arm for both opcodes, and
the stub run that the `2B` calls enter. They do not establish the far callees' identity or their stream advance, so the
operand count of each menu is not decided. The "zero operands vs. 3 and 2 elements" tension in the handoff is partly a
misreading (see section 4); it does not yet decide anything.

| Question | Answer | Basis |
| --- | --- | --- |
| Does the ECL classifier (`GAME.OVR:0x9379`) parse operands for 0x15 or 0x2B? | **No.** Both take its default arm: `inc [0x49ED]`, one byte, `operands_parsed: 0` | Concrete walk of the `cmp al,imm`/`jcc` chain (`classify`), checked on retail bytes |
| What do the 0x15 and 0x2B handlers pass to the identified targets? | They call the parser `2B:2A` with literal counts 3 and 2, and the lookup helper `2B:25` with the same literal, then decrement `[0x49ED]` and call the parser again with the helper's returned byte | Handler byte walk plus the two-dump target cross-check |
| Are `2B:2A` and `2B:25` resolved? | **Memory-byte identities cross-checked in two dumps:** `2B:2A` reaches the parser at `GAME.OVR:0x74D3`; `2B:25` reaches the adjacent lookup helper at `0x7609`. Execution and net cursor effect remain unestablished | Unique group mapping, live call operands and target bytes; see [the dump-chain probe](por-ecl-21-operand-helper-dump-probe.md) |
| Is `2B:4D` resolved? | In both dumps it reaches the word combiner at `GAME.OVR:0x7B82`; its body combines the low bytes of two arguments and returns 4 argument bytes | Two live call sites, far-jump thunk and exact function-body match in the dump-chain probe |
| What does `2B:2F` (index 22) resolve to? | `0x9379`, the classifier, under the zero-skew model. Its arity matches its callers (none pushed, none declared) | Same model; the arity match is the only positive evidence for it |
| Is the classifier's caller known? | **Lead, not established.** Under the model, `2B:2F` is called at `GAME.OVR:0x40A3`, right before a call to the dispatch driver `0x3EB7`; a second caller is at `0x199B` | Byte sites |

---

## Pinned inputs (read-only; hashes checked by the probe)

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched on the retail run. The probe opens them read-only and refuses unpinned files.

## Reproduce

```sh
python tools/por_ecl_menu_framing_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-ecl-menu-framing/retail
```

Exit `0`: all five checks pass (pins, the group header at `START.EXE:0x45B`, the default arm for both menu opcodes,
and the dispatcher's `0x15` and `0x2B` entries). Output is `por_ecl_menu_framing_probe.json` (schema
`openua.por-ecl-menu-framing-probe` v1), git-ignored under `data/work/`.

---

## 1. The classifier at `GAME.OVR:0x9379` (bytes)

`0x9379` reads the ECL opcode from the stream cell `[0x49ED]` through the far pointer `[0x49DE]`, stores it in the key
byte `[0x6F7F]` (`0x938A`), and then runs a `cmp al,imm` / `jcc` chain from `0x9390`. Each arm pushes a class byte and
calls the operand parser `0x74D3` (a `retf 2` procedure that reads one byte at `[bp+6]`). The chain is the table; it is
not a separate data table.

| Opcode | Arm (concrete walk) | Class pushed to `0x74D3` | Compare-chain location |
| ---: | --- | ---: | --- |
| `0x15` (VERTICAL_MENU) | **`inc-only`** (`inc [0x49ED]`, 0 operands) | — | default at `0x947E` |
| `0x2B` (HORIZONTAL_MENU) | **`inc-only`** (`inc [0x49ED]`, 0 operands) | — | default at `0x947E` |
| `0x27` | push-cs-call | 8 | `0x9464` |
| `0x29` | push-cs-call | 14 | `0x9471` |
| `0x2D` | push-cs-call | 1 | `0x93B0` (set 1) |
| `0x37` | push-cs-call | 3 | `0x9424` |

Chain sets, as the bytes write them: class 1 = `{01,02,0A,0E,11,12,1D,20,2D,32,34,36,38,39,3C}`; class 2 =
`{03,08,09,0C,0F,10,1F,22}`; class 3 = `{04..07 range, 0B,21,28,2A,2F,30,35,37,3B}`; class 4 = `{14,23}`; class 5 = `{2E}`;
class 6 = `{1E,2C}`; class 8 = `{27}`; class 14 = `{29}`. The set boundaries are the `jb`/`jbe` tests at `0x9400`–`0x9406`.
Neither `0x15` nor `0x2B` appears in any class.

The **default arm** is `ff 06 ed 49` (`inc [0x49ED]`) at `0x947E`. It advances the stream by the one opcode byte and
calls no parser. So for these two opcodes the classifier leaves every following byte to whatever code runs next.

`0x9379` has **one** `retf` (plain, `0x9483`) and **no** `[bp+N]` reference anywhere in `0x9379..0x9483`. It takes no
argument bytes.

## 2. The two handlers (bytes)

The dispatcher `0x3C73` (in the overlay that holds `0x3A15`) routes `[0x6F7F]` by a `cmp al,imm` chain. The probe's
`dispatch_cases` reader places case `0x15` at `0x1C4E` and case `0x2B` at `0x1E17`.

**0x15 VERTICAL_MENU (`0x1C4E`).** `mov al,3; push ax; call 2B:2A` (`0x1C68`–`0x1C6B`), then `call 2B:4D` with
`[0x7086]`, `[0x7046]` pushed, then `mov al,3; push ax; call 2B:25` (`0x1C95`–`0x1C98`), `mov [bp-1],al`,
`dec [0x49ED]` (`0x1CA0`), then `push [bp-1]; call 2B:2A` (`0x1CA4`–`0x1CA8`).

**0x2B HORIZONTAL_MENU (`0x1E17`).** `mov al,2; push ax; call 2B:2A` (`0x1E26`–`0x1E29`), `call 2B:4D`, `mov al,2;
push ax; call 2B:25` (`0x1E3E`–`0x1E41`), `mov [bp-1],al`, `dec [0x49ED]` (`0x1E49`), `push [bp-1]; call 2B:2A`
(`0x1E4D`–`0x1E51`).

Both handlers therefore make the same shape of call: a **literal** word, then `2B:2A`/`2B:25` again on a value the
earlier call returned, with `[0x49ED]` pushed back by one byte between the two. The handoff's "3 and 2 elements" is what
the literal says. Whether the literal is an element count, a selector, or a mode is a property of the callee, and the
callee identities were not resolved in the original pass (section 3). The later dump cross-check identifies the parser
and lookup helper, but still does not show that either call executes.

## 3. The far targets `2B:2A` and `2B:25` (stub bytes and dump cross-check)

`START.EXE` holds the overlay stubs (`CD 3F <proc_off> <trailer>`); the image is at file `0x200`. The group whose header
is at `START.EXE:0x45B` has `fileofs 0x74D3`, `codesz 0x221A`, `fixupsz 0x11A`, `jmpcnt 25`, and its stub run starts at
`0x471`. The probe checks this header.

| Far call | Stub (START.EXE) | Run index | `proc_off` | Earlier zero-skew candidate |
| --- | --- | ---: | ---: | --- |
| `2B:25` | `0x4D5`: `cd 3f c3 1c 00` | 20 | `0x1CC3` | `GAME.OVR:0x9196` (superseded by dump cross-check) |
| `2B:2A` | `0x4DA`: `cd 3f f0 1d 00` | 21 | `0x1DF0` | `GAME.OVR:0x92C3` (superseded by dump cross-check) |
| `2B:2F` | `0x4DF`: `cd 3f a6 1e 00` | 22 | `0x1EA6` | `GAME.OVR:0x9379` (the classifier) |
| `2B:34` | `0x4E4`: `cd 3f b1 1f 00` | 23 | `0x1FB1` | `GAME.OVR:0x9484` |
| `2B:39` | `0x4E9`: `cd 3f cc 20 00` | 24 | `0x20CC` | `GAME.OVR:0x959F` |

The stub bytes are exact (`CD 3F` at each run slot). The zero-skew values are the earlier model and are superseded
for indices 20 and 21 by the live-byte chain below. In both RAM dumps, the owning group maps uniquely at `0x45C40`.
The six menu call sites carry live segment `0x1891`: `2B:2A` reaches thunk `1891:002A`, whose far jump lands at
`40CC:0000` / linear `0x40CC0`; `2B:25` reaches `1891:0025`, whose far jump lands at `40CC:0136` / linear
`0x40DF6`. The 310-byte body at the first destination matches `GAME.OVR:0x74D3..0x7608`; the 128-byte body at
the second matches `0x7609..0x7688`. See [the dump-chain probe](por-ecl-21-operand-helper-dump-probe.md).

These are memory-byte identities at unknown capture instants, not register observations or proof that a handler ran.
The matched parser takes its element count at `[bp+6]`; the call sites push literal 3 for `0x15` and 2 for `0x2B`.
The matched lookup helper takes an index byte at `[bp+6]` and reads three indexed DS arrays. The parser/helper arity table is:

| Target | Declared bytes (`retf`) | Argument reads | Callers' pushes before the call | Arity |
| --- | --- | --- | --- | --- |
| `0x9379` (via `2B:2F`) | `retf` 0 (plain, `0x9483`) | none (no `[bp+N]`) | none emitted at `0x199B` or `0x40A3`; the call before each (`2B:34`) took the one word pushed earlier, and whether that word is popped by `2B:34` is not verified | **match** (0 = 0), conditional on that stack state |
| `0x74D3` (via `2B:2A`, dump identity) | `retf 2` (`0x7606`) | element count at `[bp+6]` | literal 3 for `0x15`, literal 2 for `0x2B`; second call receives the prior helper's returned byte | Target and count argument identified in bytes; full menu framing still depends on helper cursor effects and play-path reachability |
| `0x7609` (via `2B:25`, dump identity) | `retf 2` (`0x7686`) | index byte at `[bp+6]`, used for three indexed DS arrays | literal 3 for `0x15`, literal 2 for `0x2B` | Target identified in dumps; bounded near-call closure has no direct absolute `[0x49ED]` reference, but indirect effects are not ruled out |
| `0x7B82` (via `2B:4D`, dump identity) | `retf 4` (`0x7BA3`) | low bytes at `[bp+6]` and `[bp+8]`; returns `(byte [bp+6] << 8) | byte [bp+8]` | two words loaded from `DS:0x7086` and `DS:0x7046` before each call | Word-combining behavior identified; meaning of the result and execution are unestablished |

The zero-skew model remains only a model for `2B:2F`. For `2B:2A` and `2B:25`, the dump cross-check supersedes the
candidate targets. Their matched bodies explain the explicit arguments. Neither match proves execution. The `2B:25`
helper closure is bounded to direct near calls; its lack of a direct absolute `[0x49ED]` reference does not rule out
indirect memory effects, so the total cursor advance remains open.

The `2B:2F` match is one positive result, from one call shape. It is not a proof of the model; the model is still an
assumption.

## 4. What this means for the menu framing

- **The classifier's default arm** gives 0x15 and 0x2B zero *classifier-parsed* operands and a one-byte stream advance.
  That is a byte fact.
- **The handlers call the identified parser** with literal counts 3 and 2, and call the identified lookup helper with those
  values too. This is a byte and dump-cross-check fact; it does not establish the complete menu framing.
- **The two facts do not contradict each other.** Both can hold if the handler's helper calls are the operand parse for
  these opcodes, and the classifier never runs its parser for them. The handoff's "zero-operand table vs. handlers parse
  3 and 2" is therefore not, by itself, a contradiction in `GAME.OVR`.
- **What is open:** (a) whether the classifier runs for 0x15/0x2B on the play path before the dispatcher (its caller is
  not tied to the ECL loop); (b) the net cursor effect of `2B:25` (its target is identified, but indirect memory effects
  and its relationship to stream data are not traced); (c) whether its returned value controls a count or another mode;
  the literal 3 or 2 passed to `2B:2A` is its parser element count, but the complete menu framing and total consumed
  length are not established. Until (b) is settled, this doc does not choose between the `spec-menus` framing
  (3 fixed + count at 2 for `0x15`; 2 fixed + count at 1 for `0x2B`) and the conservative stop.
- **A lead on the caller of the classifier (not established):** under the model, `2B:2F` (the classifier) is called at
  `GAME.OVR:0x40A3`, right after `2B:34` and immediately before `push [0x49EB]; push cs; call 0x3EB7` at `0x40AD`. `0x3EB7`
  is the dispatch driver already in [por-ecl-opcode2d-probe.md](por-ecl-opcode2d-probe.md). A byte sequence "classify,
  then dispatch" is what the lead predicts. The second `2B:2F` caller is at `0x199B`, in the routine that ends at
  `0x19B2`. Neither caller's loop is traced here.

## 5. Not established

- Whether the identified `2B:2A` parser, `2B:25` lookup helper and `2B:4D` word combiner execute at these call sites.
  Their identities are memory-byte cross-checks, not execution observations.
- The net stream advance of `2B:25` and the full combined cursor effect of each menu handler. The bounded helper closure
  lacks a direct absolute reference to `[0x49ED]`, but indirect memory effects are not ruled out.
- Whether the parser's count argument corresponds to the full menu operand count and whether the classifier's default
  increment is also on the play path.
- Whether the classifier runs before the dispatcher for 0x15 and 0x2B in play, and what its caller's loop is.
- The meaning of the stores into `[0x6F7F]` (the key) and `[0x49ED]` (the stream cell), beyond what the arms show.

## 6. The runtime observations that would discriminate the hypotheses

The static bytes cannot close the remaining execution and net-cursor questions. These Hatari observations would, and none needs a new mapping:

1. **Execution and stack.** Break at stubs `0x4DA` (`2B:2A`) and `0x4D5` (`2B:25`) while a menu handler runs. Record whether
   each call executes, its actual callee address, SS:SP, caller BP and the words around the return frame and explicit
   pushes. The dump matches identify candidate bodies, but only this observation establishes execution and live arguments.
2. **Classifier path.** Break at `GAME.OVR` `0x9390` and log `[0x6F7F]` (the opcode) and `[0x49ED]` before and after the
   `inc` at `0x947E`. Expect `0x15` or `0x2B` on entry and `[0x49ED]` advanced by exactly 1 when the default arm runs.
   Also log whether the call to `0x9379` comes from `0x40A3` or `0x199B` on a menu opcode.
3. **Helper advance.** Log `[0x49ED]` immediately before and after each `2B:25` and `2B:2A` call inside the two handlers
   (`0x1C6B`, `0x1C98`, `0x1CA8`, `0x1E29`, `0x1E41`, `0x1E51`). The difference is the helper's net stream advance, which settles (b) and
   with it the operand count.

Existing hooks for these breaks are in [por-hatari-load-trace.md](por-hatari-load-trace.md) and
[por-int3f-live-dispatch.md](por-int3f-live-dispatch.md). This doc does not run them.

---

## Note on prior work

`data/work/por-ecl-menu-framing/scratch/` (git-ignored) holds an earlier pass with the same handler listing (`walk_menus`,
`walk_table`, `walk_targets`, `walk_callers`). It was used only as a pointer to where to look. Every fact above is
re-derived from the pinned bytes by this probe or by the decoder in `tools/por_loadpieces_handler.py`.
