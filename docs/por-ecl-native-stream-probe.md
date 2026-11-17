# Pool of Radiance: ECL stream walk under the PoR-native framing (diagnostic only)

**Status: DIAGNOSTIC-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`. `complete: false`.**

Tool: `tools/por_ecl_native_stream_probe.py`. Tests: `tests/test_por_ecl_native_stream_probe.py` (46 tests:
44 synthetic, 2 retail-gated on `OPENUA_POR_INSTALL`).

Companions (read, not changed): [por-ecl-native-framing-probe.md](por-ecl-native-framing-probe.md) (the framing
evidence this tool uses, and nothing else for framing), [por-ecl-decoder.md](por-ecl-decoder.md) (the DAX container,
RLE and 22-byte header, validated on retail `ECL2.DAX`), [por-ecl-menu-framing-probe.md](por-ecl-menu-framing-probe.md),
[por-ecl-opcode2d-probe.md](por-ecl-opcode2d-probe.md).

---

## Question and answer

> Walking one retail ECL block from its header end, how far can the walk go using only the record boundaries the
> pinned PoR-native framing supports, and where does it have to stop?

**The walk stops at block offset 34.** The first two records cover **12 of 7,657** stream bytes. The next byte is
opcode `0x1B`, which the classifier advances by one byte but which also has a PoR dispatcher case. Since the
handler's additional cursor effect is unknown, the tool stops before it and reports no later offsets. The `0x80`
counted-string and `0x81` post-step paths remain open, but this block's conservative walk does not reach them.

| Question | Answer | Basis |
| --- | --- | --- |
| Which opcode classes and operand kinds are used? | Only the framing probe's JSON: 43 classified opcodes, 213 default-arm opcodes, five operand kinds that tile the tag/value space | `por_ecl_native_framing_probe.py` JSON, 25/25 checks |
| What does a classified record advance by? | `1 + sum(delta_i)`: the opcode byte, then each operand's 2 or 3 bytes. Operand `i`'s tag is at cursor+1 | Probe's operand-kind table (cursor delta = read extent, checked in code) |
| What does a default-arm opcode advance by? | The classifier increments the cursor once. For default opcodes with a `0x3C73` dispatch case, the overall handler cursor effect is unresolved, so the stream walk stops before that opcode | Probe classifier and dispatch list |
| Where does the walk stop? | Before an operand of an OPEN kind: tag `0x81`, or tag `0x80` with count `> 0`. Or before a truncated operand. Or at the end of the stream | Probe's `open` flags |
| Is the program boundary known? | **No.** The walk never claims completion; `claims.complete` is always `false` | Not established: EXIT/RETURN semantics, handler reads, X |

---

## Inputs and pins

| Input | Size | SHA-256 | Role |
| --- | ---: | --- | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` | Framing evidence (via the framing probe; pins checked there) |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` | Framing evidence (via the framing probe) |
| `ECL2.DAX` | 19,968 | `6ad6dc5aa53da82f4dba62dbc47d5a02a3f14c14071bec44e81a692615f08a3d` | Container; matches [por-ecl-decoder.md](por-ecl-decoder.md) |

Selected block: `ECL2.DAX` TOC index 2, block id 20, raw 7,679 bytes, compressed 7,824 bytes. Decoded SHA-256
`a1e1dd7a7ffc07f6e3c3ce7fad25d373270c10edd06ec3fa1f1d0edc9a7297ec`, the value recorded in the decoder doc (checked).
Header: magic `0x1388`, five pointers, all segment `0x0101`.

The install is opened read-only. The framing probe checks its pins before and after; this tool never writes under the
install and refuses an output folder inside it. Outputs go to `data/work/` (git-ignored).

## Evidence and provenance

- **Framing** comes only from `tools/por_ecl_native_framing_probe.py`. The tool calls its `probe()` and uses the
  resulting JSON as the sole source of opcode classes, the default-arm dispatch list, and operand kinds. It refuses if
  any probe check fails, if an opcode has no arm, if the kinds do not tile the tag/value space, or if a closed kind's
  delta differs from its read extent. Probe JSON as written for this run: sha256
  `f6687fc3704ef70bc88128b3f79b0321cb5cc9b1121e04874a8febdb4d45bd13`, 25/25 checks.
- **Container and header** come from `tools/por_ecl.py` (read-only import): the DAX TOC, contiguity, EOF closure,
  signed-byte RLE with exact `raw_size`, and the 22-byte header. Basis: GoldBox `docs/dax-format.md` sections 1-2 and
  `ecl-krynn-gen1-opcodes.md` 3.2 are cited for provenance only, validated on retail `ECL2.DAX` in
  [por-ecl-decoder.md](por-ecl-decoder.md). The repo's own `docs/dax-format.md` has uncommitted changes from another
  task and is not relied on.
- **Stream origin** is block offset 22 (header end). This is **inherited** from `por_ecl.py` and not established by the
  framing probe. The framing is cursor-relative, so the walk does not depend on the absolute cursor. The entry cursor
  and the `0x6700` displacement of the stream read (`es:[di+0x6700]`) are open. Every output says so.

## The walk rules

| Case | Rule | Output |
| --- | --- | --- |
| Default-arm opcode with no dispatch case | Advance 1 byte | `kind: default`, `advance: 1`, `no-dispatch-case` |
| Default-arm opcode with a dispatch case | Stop before the opcode; only the classifier's one-byte increment is known, handler cursor effect is unresolved | `stop.reason: unresolved-handler-read` |
| Classified opcode, class `c` | `c` operands; operand `i` tag at cursor+1, value at cursor+2 | `kind: classed`, `advance: 1 + sum(delta_i)`, operands listed |
| Closed operand: tags 1, 2, 3 | 3 bytes; extra is the third byte | `closed-3-byte`, raw tag/value/extra |
| Closed operand: ordinary tags (`0x00`, `0x04`-`0x7F`, `0x82`-`0xFF`) | 2 bytes | `closed-2-byte`, raw tag/value |
| Closed operand: tag `0x80`, count 0 | 2 bytes; count is the value byte | `closed-0x80-count0-2-byte` |
| **Open operand: tag `0x81`** | **Stop before the operand** (no value needed) | `stop.label: open-0x81-post-step` |
| **Open operand: tag `0x80`, count > 0** | **Stop before the operand** | `stop.label: open-0x80-count-gt-0` |
| Operand bytes past the end of the stream | Stop as truncated, before the operand | `stopped-truncated-operand` |
| End of stream | Status `reached-end-of-stream`; not a program boundary | `claims.complete` stays `false` |

A stopped record is not listed in `records`. Its opcode byte is the first unsupported offset (`supported_prefix_end`).
The classifier's increment alone does not establish the cursor position after the handler finishes.

## Retail result (block 20)

Command (writes only under `data/work/`):

```sh
tools/.venv/Scripts/python.exe tools/por_ecl_native_stream_probe.py \
    --install "G:/Games/Pool of Radiance/POOLRAD" --ecl 2 --block 20 -o data/work/por-ecl-native-stream/ecl2-20
```

Exit `0`. Outputs: `data/work/por-ecl-native-stream/ecl2-20/por_ecl_native_stream_probe.json` (4,766 bytes),
`por_ecl_native_stream_probe.md`, and `framing-evidence/por_ecl_native_framing_probe.json`.

| Measure | Value |
| --- | --- |
| Status | `stopped-unresolved-handler-read` |
| Covered | 12 of 7,657 stream bytes (1 permille); block offsets 22 to 33 |
| Records | 2, both classed |
| First unresolved boundary | block offset 34: default-arm opcode `0x1B` (`IF_GE` dispatcher case) |
| Supported prefix | ends at block offset 34 (2 records, 12 bytes) |
| Operand labels in prefix | two `closed-2-byte`, two `closed-3-byte` |
| Stop | block offset 34 before opcode `0x1B`; handler cursor effect unresolved |

Self-checks (all `ok`): `framing_probe_checks_all_pass`, `every_opcode_has_framing`,
`operand_kinds_tile_tag_value_space`, `records_contiguous_from_header_end`,
`stop_at_open_operand_or_unresolved_handler_or_truncated`,
`stop_at_open_operand_or_unresolved_handler_or_truncated`, `covered_within_stream`, `output_path_free`.

**Independent cross-check.** A separate re-walk, written as a short script that reads only the probe JSON and the
decoded bytes, reproduces the two records, the 12-byte prefix, and the stop at opcode `0x1B` at block offset 34. The
tool itself was not reused for this check.

## Tests

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_native_stream_probe.py                      # Windows
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_native_stream_probe.py
```

Local results after the conservative handler-stop correction: **`44 passed, 2 skipped`** without the variable;
**`46 passed`** with it.

- **Operand counts and advance**: class 1, 2, 3 counts; `1 + sum(delta)` with mixed tags; raw bytes and extra byte
  only for 3-byte kinds.
- **Tag cases**: ordinary tags (`0x00`, `0x04`, `0x7F`, `0x82`, `0xFF`) two-byte; tags 1-3 three-byte; `0x80` count 0
  closed and decoded.
- **Stop positions**: `0x80` with count `0x01`, `0x05`, `0xFF`; `0x81` (without needing a value); stop at the second
  operand keeps the record out of `records`; stop offsets relative to the stream and the covered end.
- **Truncation**: no tag byte; no value byte; closed operand runs past the end. Each is a named stop, not a completion.
- **Default arm**: one-byte advances for no-dispatch defaults; stop before a dispatch-case default, with the opcode and
  cursor boundary recorded; no false completion; supported prefix excludes the stopped opcode.
- **Framing evidence refusals**: failed or empty probe checks; an opcode without an arm; tiling not complete; a closed
  kind whose delta differs from its read extent; zero or two operand-kind matches.
- **Container and header**: block shorter than the header; wrong magic; truncated DAX (through `por_ecl`); ambiguous
  block id without an index; a synthetic DAX loaded and walked end to end.
- **Refusals and paths**: missing install (exit 2); unpinned `GAME.OVR` and `START.EXE` (exit 2, from the framing probe);
  output inside the install; output outside `data/work/` (CLI); a failed framing-probe check (run refuses).
- **Determinism and path-free output**: two runs give identical JSON; no drive-letter or absolute path appears.
- **Retail-gated** (`OPENUA_POR_INSTALL`): block 20 run to `exit 0`, with the source, decoded and size pins, first record
  at offset 22 with opcode `0x09`, stop at block offset 34 / opcode `0x1B`, the install path absent from the JSON; and the probe's
  class sets matching the tool's table (including `0x2D`→1, `0x27`→8, `0x29`→14, `0x37`→3, and `0x15`/`0x2B` as
  dispatch-case defaults).

## Limitations

- **Only a small prefix is boundary-supported.** The 12 bytes are conditional on the inherited header-end stream
  origin and on the classifier path being used. No handler boundary is crossed.
- **Open operand paths remain unresolved.** The X effect of `0x8626` and the post-step of `0x87CE` are open (framing
  probe, section 2); block 20's conservative walk stops earlier and does not make a claim about its later `0x80` bytes.
- **Default-arm handler reads.** Dispatch-case defaults (including `0x15` and `0x2B`) may consume more bytes. The walk
  stops before the first such opcode rather than parsing potentially shifted data after it.
- **Stream origin inherited.** The header end (22) is the existing decoder's assumption. The entry cursor and the
  `0x6700` displacement are not established.
- **One block, one file.** The result is for `ECL2` block 20 only. No other block was walked, and no claim is made about
  reachability or runtime behaviour.
- **Coverage is not the GoldBox coverage.** `por-ecl-decoder.md` reports coverage under the GoldBox spec framing, which is
  a different framing. The numbers are not comparable.

## Not claimed

- No runtime claim: reachability, the classifier's use at run time, and the `0x7689` routine are not established.
- No operand or opcode meaning. Raw bytes are reported, and nothing is decoded into a value, string, address or event.
- No FRUA event mapping, module, campaign or route claim.
- No use of GoldBox CoK/CoAB/DoK operand or opcode rules. No GoldBox table, mnemonic or count is used.
- No program boundary. `complete` is always `false`.

## Next evidence that would settle it

1. Resolve the far callees of `0x8626` and `0x87CE` (`0x0AF8:xxxx`). Their cursor effect decides the framing of
   open operands if earlier handler boundaries are resolved and the walk reaches them.
2. Find handler-level reads and cursor writes for dispatch-case defaults, starting with `0x1B` (IF_GE), `0x16` (IF_EQ),
   and `0x15`/`0x2B` (the menu opcodes). This can extend the boundary-supported prefix.
3. Pin the entry cursor and the `0x6700` displacement, so the stream origin stops being inherited.
