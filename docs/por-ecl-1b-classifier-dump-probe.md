# PoR ECL `0x1B` helper target in RAM dumps

**Status: memory-byte call-chain cross-check only. `playable: false`; execution is not established.**
The probe checks the far call at `GAME.OVR:0x1907` against two existing RAM dumps. It identifies a
conditional byte path from the `0x1B` handler to the ECL classifier, but it does not show that the
guard path ran or that a particular ECL block was loaded.

## Result

The call at `0x1907` is `9A 8E 00 2B 00` (`002B:008E`); its segment word is in the handler overlay's
fixup table. In both dumps, the handler group maps uniquely at linear `0x45C40`. The live call bytes
are `9A 8E 00 91 18`, targeting `1891:008E` / linear `0x1899E`. That address contains the far-jump
thunk `EA A6 1E CC 40`, which targets `40CC:1EA6` / linear `0x42B66`.

The 267 bytes at that destination match `GAME.OVR:0x9379..0x9483` exactly. A complete decode of that
span contains 133 instructions and ends with `retf` at `0x9483`. All 133 instruction byte spans match
in both dumps. The classifier body hash is
`a18580355e2e8766ca756e3e562e3fdde0ffe89dc65e9312dbe72f7074b0e2df`.

This resolves the target's **memory-byte identity** as the classifier body. It refines the earlier
`por-ecl-handler-cursor-probe.md` finding that called `002B:008E` unresolved. It remains a memory
match at two unknown capture instants, not proof that the call executed.

## Conditional cursor implication

The handler bytes at `0x189B..0x190C` increment `[0x49ED]`, compare `[0x6F7D]` with zero, skip the far
call when the guard is nonzero, and call `002B:008E` when the guard is zero. The target match above
shows that this call reaches the classifier bytes in the dumps. The classifier reads the stream byte
at the cursor; its PoR class chain assigns class 2 to byte `0x09` and calls the operand parser with
that count. The parser's two operands use the PoR byte rules described in
[`por-ecl-native-framing-probe.md`](por-ecl-native-framing-probe.md).

This gives a conditional, PoR-derived interpretation of the ECL1 #24 candidate at `0x1DB1`:

| Block offset | Bytes / decoded form | Cursor role under the candidate framing |
|---:|---|---|
| `0x1DB1` | `0x1B` | handler increments from this opcode to `0x1DB2` |
| `0x1DB2` | `0x09 00 08 01 7E 6E` | if `[0x6F7D] == 0`, the classifier sees `0x09`, class 2, and parses its two operands through `0x1DB8` |
| `0x1DB8` | `0x37 00 01 00 03 00 05` | candidate `LOAD_PIECES` with literal-code values `1, 3, 5` |

The six bytes at `0x1DB2..0x1DB7` tile as opcode `0x09` plus a 2-byte operand and a 3-byte operand,
so the classifier/parser path lands at `0x1DB8`. This explains how the candidate flow can pass the
`0x09` record on the guard-zero path. It does **not** establish that the ECL1 #24 buffer is the live
stream, that its cursor is linked to these block offsets, or that `[0x6F7D]` is zero. On the
guard-nonzero path the helper is skipped and the outer loop resumes at `0x1DB2`; the complete
cursor effect of the `0x09` dispatch handler is not established here.

## Limits

- No register capture shows the `0x1B` handler or helper executing.
- The runtime value and meaning of `[0x6F7D]` are unknown.
- `ECL1.DAX` block 24's candidate base, framing and branch assumptions remain conditional; the
  candidate CFG crosses an unresolved branch.
- The `0x37` operand values are not proven to be WALLDEF block IDs, and no WALLDEF archive is
  selected. The matching ID sets across multiple WALLDEF archives are only a structural
  compatibility result (see [`por-ecl-cfg-loadpieces-census.md`](por-ecl-cfg-loadpieces-census.md)).
- Nothing shows that the classifier-to-parser route is reached from a live ECL root.

## Reproduction

```sh
python -I tools/por_ecl_1b_classifier_dump_probe.py \
  --install data/work/por-geo-run/POOLRAD \
  --out data/work/por-ecl-1b-classifier-dump-probe/retail
python -m pytest tests/test_por_ecl_1b_classifier_dump_probe.py -q
```

The retail probe exits 0 with status `ok` for both pinned dumps. The focused suite reports 11 passed
on this checkout, including the local retail gate. Output is under ignored `data/work/`.

Files: `tools/por_ecl_1b_classifier_dump_probe.py`,
`tests/test_por_ecl_1b_classifier_dump_probe.py`, and this document. The install and dumps are
read-only inputs; no emulator or other game title was used.
