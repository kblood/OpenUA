# PoR ECL 0x21 operand-helper dump chain

**Status: memory-byte chain cross-check only. `playable: false`.** This probe follows the `002B:0025`
far call in the PoR opcode-0x21 handler through the bytes in two existing RAM dumps. It also
cross-checks the `002B:002A`, `002B:0025`, and `002B:004D` call sites in the `0x15` and `0x2B` menu
handlers, and records the getter's bounded direct near-call closure. It does not show that any handler
or helper executed.

## Finding

In both pinned dumps, the handler group's unique mapped base is `0x45C40`. Its call site at
`GAME.OVR:0x19DA` is then at linear `0x468D4`. The live bytes there are `9A 25 00 91 18`, giving
`1891:0025` / linear `0x18935`. The five bytes at that address are `EA 36 01 CC 40`, a far jump to
`40CC:0136` / linear `0x40DF6`. From there, `0x80` bytes match exactly and uniquely the pinned
`GAME.OVR:0x7609..0x7688` procedure. Both dumps contain that complete body at the same address.

The procedure decodes linearly through 57 instructions and returns at `0x7686` with `retf 2`.
It reads a byte argument from `[bp+6]`, uses the sign-extended value as an index into three
DS-relative arrays at `0x7085`, `0x7045`, and `0x7005`, and has tag-dependent result paths. One path
calls near routine `0x82DF`; another calls `0x7B82`. The return value is assembled in a local and
returned in AX. These are byte-level observations. The arrays' runtime contents and the returned
byte's meaning are not known.

The enclosing 0x21 handler calls `002B:0025` for indices 1 through 3 and stores each returned AL in
locals `[bp-3]`, `[bp-2]`, then `[bp-1]`. It later pushes the first result as a word before its separate
`03D5:0043` call. The first helper result therefore reaches that later call as an argument candidate.
This does not establish that the result is an ECL stream byte or a GEO block id.

## Menu-call cross-check

The six `002B:002A`/`002B:0025` sites in the `0x15` and `0x2B` handlers are in the same overlay group
as the opcode-0x21 call above. In both dumps, all six live segment words are `0x1891`; the `002A`
calls reach the thunk at linear `0x1893A` (`EA 00 00 CC 40`), and the `0025` calls reach `0x18935`
(`EA 36 01 CC 40`). The first thunk jumps to `40CC:0000`, linear `0x40CC0`; its complete 310-byte
body is byte-identical to `GAME.OVR:0x74D3..0x7608`. The second jumps to `40CC:0136`, linear `0x40DF6`,
where the complete 128-byte helper matches `GAME.OVR:0x7609..0x7688`. The parser and helper are
adjacent in the pinned file.

This cross-check identifies the two menu call targets in these memory images. It is stronger than the
earlier zero-skew guess, but remains a memory-byte match at unknown capture instants, not a register
trace or proof that the menu handlers ran. The parser at `0x74D3` is the procedure previously decoded
with an element-count argument at `[bp+6]`; the menu call sites push literal 3 for `0x15` and 2 for
`0x2B` before calling it.

The two `002B:004D` calls (`GAME.OVR:0x1C78` and `0x1E36`) also map in both dumps. Their live
segment is `0x1891`; thunk `1891:004D` at linear `0x1895D` jumps to `40CC:06AF`, linear `0x4136F`.
The 36-byte body there exactly matches `GAME.OVR:0x7B82..0x7BA5`, decodes to 16 instructions, and
returns with `retf 4`. It zero-extends the low byte at `[bp+6]`, shifts it left eight bits, then ORs
the low byte at `[bp+8]`. The call sites push values loaded from `DS:0x7086` and `DS:0x7046`, so
the helper returns `(byte DS:0x7046 << 8) | byte DS:0x7086`. This identifies a word-combining
operation; the resulting word's meaning is unknown.

The lookup helper at `0x7609` and its direct near-call closure contain six complete procedures
(`0x7609`, `0x82DF`, `0x7B82`, `0x7BCE`, `0x7C8F`, `0x7C29`; 494 instructions total). The decoder
reports no far or indirect calls and no direct absolute reference to `[0x49ED]` in this bounded
closure. That does **not** prove the helper's net cursor effect: indirect memory effects are not ruled
out. The menu handlers' explicit `dec [0x49ED]` remains a separate byte fact, and the total stream
advance through their combined helper sequence is not established.

## Results

| Check | Both dumps |
|---|---|
| Handler group mapping | unique at `0x45C40` |
| Live `002B:0025` operand | `1891:0025` |
| Target thunk | `EA 36 01 CC 40` |
| Thunk destination | `40CC:0136`, linear `0x40DF6` |
| Destination body | exact `0x80`-byte match to GAME.OVR `0x7609` |
| Body end | `0x7689`, final instruction `retf 2` at `0x7686` |
| Body SHA-256 | `0dd25983c54922e1ebe6f9f1b693f32c6a1c2b69199ddf110fc7d040134ec42b` |
| Menu call sites | all six `0x15`/`0x2B` calls map to live `002A` parser and `0025` helper thunks in both dumps |
| Parser body | 310-byte exact match to GAME.OVR `0x74D3..0x7608` |
| `002B:004D` calls | both menu sites map to thunk `1891:004D`, then exact 36-byte body match to `0x7B82` |
| `002B:004D` behavior | two low argument bytes combined as `arg6 << 8 | arg8`; `retf 4` |
| Helper near closure | 6 complete procedures, 494 instructions, no far/indirect calls or direct absolute `[0x49ED]` reference |

The tool's output is written under `data/work/por-ecl-21-operand-helper-dump-probe/` and contains
addresses, matched bytes, hashes and checks only.

## Evidence boundary

Established for these pinned files and dumps: the static far-call bytes and fixup membership; the
unique group mapping; the observed live call operand; the far-jump bytes at its target; and the exact
memory-body match to the complete pinned procedure. This is memory content at two unknown capture
instants, not a register trace or execution trace.

Not established: that any call ran; the values in the DS arrays; indirect memory effects on the cursor;
which result branch ran; what returned AL represents; the relationship of that value to an ECL stream,
GEO archive, block or area; and any gameplay behavior.

## Verification

`tests/test_por_ecl_21_operand_helper_dump_probe.py` includes synthetic falsifiers for the static call,
fixup entries, all six menu call sites, both `002B:004D` calls, the live segment, all three thunks,
parser/getter/word-helper bodies, and a direct absolute cursor reference in the helper closure, plus a
retail-gated check against the two local dumps.
The procedure bytes are decoded using the repository's 8086 decoder. No emulator, DOSBox, GameLink,
codewheel, or GoldBox data is used.
