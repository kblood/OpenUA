# Pool of Radiance GAME.OVR 0x37 handler, dispatch and parser: what the bytes establish

**Status: STATIC-PROBE-ONLY. `playable: false`.** `tools/por_loadpieces_handler.py` reads the
user-supplied retail `GAME.OVR` read-only and reports what those bytes establish about three
things: the dispatcher's compare chain for opcode `0x37`, the `0x37` handler at file offset
`0x19ba`, and the operand parser entry at `0x74d3`. It does not give opcode `0x37` a meaning,
does not name any far-call target, does not bind WALLDEF blocks, and does not emit a module.

Handler structure is not opcode semantics. The probe reports structure and lists every
semantic question it cannot settle under `not_established`.

---

## Usage

```sh
# user-supplied install, read-only; output under data/ (git-ignored)
python3 tools/por_loadpieces_handler.py --install "PATH/TO/POOLRAD" \
    -o data/work/por-loadpieces-handler/retail
```

Outputs in `OUT`: `por_loadpieces_handler.json` (schema `openua.por-loadpieces-handler`,
version 1, `playable: false`) and `por_loadpieces_handler_report.md`. The tool is stdlib-only.
It refuses a `GAME.OVR` that does not match the pinned size and SHA-256 unless
`--allow-unpinned` is given, and that flag marks the output as not retail evidence. It refuses
an output folder inside the install. Output is deterministic, with no timestamps and no
absolute paths.

Exit codes: `0` every structural check passed and every walk was complete; `1` output written
with a diagnostic (a check failed or a walk was incomplete); `2` named refusal.

---

## Pinned source

| Field | Value |
| --- | --- |
| File | `GAME.OVR`, 206,105 bytes |
| SHA-256 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |

The hash was taken before and after the run; it is unchanged.

---

## Method

- **Decoder.** A small 8086/80186 real-mode length and flow decoder is in the tool. Unknown
  opcodes, two-byte `0F` opcodes and 386+ prefixes stop a walk, and the walk is marked
  incomplete. Cross-checked once against an external disassembler in a scratch directory,
  outside the repo: all 823 instructions in the dispatcher, handler and parser regions matched
  on length and branch target. That cross-check is not a dependency of the tool.
- **Near calls** (`E8 rel16`) are resolved to file offsets. This assumes that near-call targets
  share the file-offset space. The tool records this assumption in its output and does not
  prove it.
- **Far calls** (`9A seg:off`) are reported as literal operands. Their segments are not file
  offsets, and the overlay manager's stub or fixup table is not parsed, so they stay unresolved.

---

## What the retail bytes establish

Numbers below are from the retail run; the tool writes them to the JSON.

1. **Dispatcher `0x3c73`.** Its linear sweep reaches the first `ret` after 273 instructions,
   which matches the count in `docs/engine/research/pool-ecl-dispatch-map.md`. The first
   instruction after `push bp; mov bp,sp` is `mov al,[0x6f7f]`, so the key is DGROUP byte
   `0x6f7f`. The chain holds 60 structured case blocks and one unstructured `cmp al` site, at
   `0x3ead`, which is not classified.
2. **Case `0x37`.** The chain contains `cmp al,0x37; jne +7; push cs; call near 0x19ba; jmp`
   at `0x3d9e`. The `jne` skips exactly the 7-byte block, and `push cs` before a near call
   is consistent with the handler's `retf` return, i.e. a far-returning procedure called near.
3. **Not-equal path.** Following the path on which `AL` differs from every earlier case value,
   from the key load to the `0x37` compare, passes 34 steps. Only `cmp al,imm` and conditional
   jumps run on it, so `AL` still holds the key at that compare. The claim is about this path
   only.
4. **Handler `0x19ba`.** The reachable set is 129 instructions, all decoded, with no
   overlap conflicts. It has no near calls, no indirect transfers, and one `retf`. It makes
   11 literal far calls to segments `0x2b`(43, 2 calls), `0xba`(186, 2), `0x3d5`(981, 5),
   `0x3e9`(1001, 1) and `0xaf8`(2808, 1). It has two backward branches, both preceded by
   `cmp byte [bp-4],3`, which is the shape of a three-iteration loop. That loop shape is a
   structural observation; whether it reads three operand bytes is not established.
5. **Parser `0x74d3`.** The entry is `push bp; mov bp,sp`, as the prologue check confirms. The
   reachable set is 119 instructions, all decoded, and it ends in `retf 2`. Its stack reads
   are at `bp+6` (positive, the first argument word) and at negative offsets. Its only
   stack argument is one word, consistent with the `retf 2` return and the `push cs` calling
   form. The argument's meaning is not established.
6. **Callers of `0x74d3`.** Thirteen `E8` byte-pattern sites resolve exactly to `0x74d3`. Every
   one is preceded by `push cs`. Their boundaries were not checked against a decoded instruction
   stream, so they are candidates.
7. **The handler does not call the parser by near call.** None of the handler's reachable
   instructions is a near call to `0x74d3`, and no literal far call names offset `0x74d3`.
8. **Overlay header.** The first four bytes are `FBOV`, followed by raw bytes
   `11 25 03 00 1c` and an ASCII error string. The header is reported raw; its layout is not
   parsed.

## What the bytes do not establish

- **What opcode `0x37` means in PoR.** The name `LOAD_PIECES` comes from the CoK schema and
  is not PoR evidence.
- **Which function the handler's far calls reach.** The `0x2b:0x2a` call receives the literal
  `3`, and the handler then runs a three-iteration loop of `0x2b:0x25` calls. The parser
  takes one word argument and branches on its low byte as a loop bound. This is
  signature-compatible with the parser, but the far-call target is unresolved, so the link is not
  established.
- **Whether the handler reaches the parser at all.** The handler has no near call to `0x74d3`.
  The dispatch map's structural pairing of handler and parser is a similarity claim, not a
  call edge in these bytes.
- **The meaning and width of the three operand bytes**, and of the DGROUP fields the handler
  touches (`0x4431`–`0x4434`, `0x49d2`, `0x49d6`, `0x5d92`, `0x5d94`, `0x6f7f`).
- **Whether `0x19ba` runs for opcode `0x37` at runtime.** The bytes show a static path. A
  runtime CS:IP hit would be needed. The CS:IP evidence in `docs/engine/research` covers only
  the operand parser on one proven natural route, and it excludes other branches.
- **Completeness** of the ECL dispatch for every opcode, of the framing model, or of any walk.

## Relation to the other PoR evidence

- The 35 framing-tagged `0x37` occurrences in `docs/por-loadpieces-census.md` and
  `docs/por-loadpieces-trace.md` are CoK-schema-framed. This probe does not confirm that
  framing, and the three-iteration loop is not evidence for it.
- The Treasures `0x37` `wordSet` override is retracted in the GoldBox research record. It is
  not used here.
- The GoldBox dispatch map's structural pairing of `0x37` with `0x19ba` and of the parser with
  `0x74d3` is consistent with these bytes for the dispatcher-to-handler edge. The handler-to-
  parser edge is not present in the bytes.

## Next evidence that would settle the open questions

1. Parse the overlay manager's stub or fixup table, from `GAME.OVR` or `START.EXE`, so that
   the literal far-call segments map to file offsets. This would settle whether `0x2b:0x2a`
   or `0x2b:0x25` is the parser.
   **Partly done:** see [por-farcall-resolution.md](por-farcall-resolution.md). Under a zero-skew
   image model, `0x2b:0x2a` and `0x2b:0x25` land on VROOMM stubs for overlay `0x74d3` at procs
   `0x1df0` and `0x1cc3`, not on the parser (proc 0). Nine of the eleven far calls do not fit that
   model, and the model is an assumption. The call-to-parser question is therefore still open.
2. A runtime CS:IP breakpoint on entry to `0x19ba` during a `0x37` dispatch, and separately on
   `0x74d3`, to confirm the path at execution time. Neither has been taken.
3. Only after 1 and 2 agree, a decision on whether the 35 occurrences' three operand codes
   correspond to the bytes this handler reads. No WALLDEF binding should follow from this
   document alone.

---

## Tests

`tests/test_por_loadpieces_handler.py` runs on synthetic bytes. Decoder checks use hand-encoded
instructions. Dispatcher, handler and caller checks use synthetic blobs with the retail shapes.
Refusal, output-location and determinism checks run against a temporary folder. The retail
structural test runs only when `OPENUA_POR_INSTALL` names a PoR install; it is skipped
otherwise. It does not test PoR semantics.
