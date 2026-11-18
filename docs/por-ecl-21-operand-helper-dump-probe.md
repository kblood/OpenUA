# PoR ECL 0x21 operand-helper dump chain

**Status: memory-byte chain cross-check only. `playable: false`.** This probe follows the `002B:0025`
far call in the PoR opcode-0x21 handler through the bytes in two existing RAM dumps. It does not show
that the handler or helper executed.

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

The tool's output is written under `data/work/por-ecl-21-operand-helper-dump-probe/` and contains
addresses, matched bytes, hashes and checks only.

## Evidence boundary

Established for these pinned files and dumps: the static far-call bytes and fixup membership; the
unique group mapping; the observed live call operand; the far-jump bytes at its target; and the exact
memory-body match to the complete pinned procedure. This is memory content at two unknown capture
instants, not a register trace or execution trace.

Not established: that the call ran; the values in the DS arrays; the behavior of the helper callees;
which result branch ran; what returned AL represents; the relationship of that value to an ECL stream,
GEO archive, block or area; and any gameplay behavior.

## Verification

`tests/test_por_ecl_21_operand_helper_dump_probe.py` includes synthetic falsifiers for the static call,
fixup entry, live segment, thunk, destination body and pinned helper body, plus a retail-gated check
against the two local dumps. The procedure bytes are decoded using the repository's 8086 decoder. No
emulator, DOSBox, GameLink, codewheel, or GoldBox data is used.
