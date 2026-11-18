# Pool of Radiance inline-string (0x80) census: status and evidence

**Status: census only. `playable: false`.** `tools/por_ecl_strings.py` walks every
retail ECL1-8 TOC block with the existing decoder (`tools/por_ecl.py`) and records
every inline-string operand (operand code `0x80`) it reaches. Each record keeps the
raw payload bytes as hex and base64. The census does not decode any payload as
text, does not apply a charset, does not map a string to a FRUA message or event,
and does not produce a module. It is a provenance-keeping inventory of where the
decoder finds `0x80` operands and what bytes they hold.

This slice does not change `tools/por_ecl.py`, `tools/por_loadpieces_census.py`,
or any other existing `por_*` file. It is a standalone addition. The census writes
only under `data/` (git-ignored) and never writes to the install.

---

## Usage

```sh
# GOG-style install: ECL<n>.DAX here or in its POOLRAD subfolder
python3 tools/por_ecl_strings.py --install "G:/Games/Pool of Radiance" \
    -o data/work/por-ecl-strings/retail

# the same census with the decoder's test suite (synthetic by default)
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_strings.py        # Windows
OPENUA_POR_ECL_STRINGS_INSTALL="G:/Games/Pool of Radiance" \
    tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_strings.py    # adds the retail anchor
```

Exit codes: `0` every archive present and every block decoded; `1` census written
but an archive is absent or a container, RLE, header, or magic check failed (listed
under `diagnostics`); `2` named refusal (bad install folder, ambiguous archive,
unsafe output location). An incomplete walk is never read as an absence.

Outputs in the output folder:

- `por_ecl_strings.json`: schema `openua.por-ecl-strings`, version 1,
  `status: census-only`, `playable: false`. Sorted keys, no timestamps, no absolute
  paths. Sections: `summary`, `archives` (file SHA-256, container status, every TOC
  entry with its id, repeat flag, offsets and sizes, and per-framing walk coverage),
  `string_frames`, `skipped_frames`, `diagnostics`, `not_claimed`.
- `por_ecl_strings_report.md`: counts only. It contains no payload bytes.

### Fields on each string frame

| Field | Meaning |
|---|---|
| `archive`, `source_sha256` | the ECL file name and the SHA-256 of the whole file as read |
| `toc_index`, `block_id`, `data_offset`, `raw_size`, `comp_size` | the TOC entry (by index; ids can repeat) |
| `decoded_sha256` | SHA-256 of the decompressed ECL block (the "decompressed" coordinate system) |
| `framing`, `framing_status` | which walk found it, and whether the walk's framing is contested (see below) |
| `instruction_index`, `instruction_offset`, `opcode`, `mnemonic` | the instruction that carries the operand |
| `instruction_complete` | `false` only for a string read inside the instruction where the walk stopped |
| `operand_kind`, `operand_slot` | `operand` (fixed operand slot) or `count` (count-driven entry), and its index |
| `operand_offset`, `operand_total_length` | block offset of the `0x80` byte, and 2 + declared length |
| `declared_length`, `payload_offset`, `payload_length` | the `high` byte, and the payload's block offset and length |
| `payload_hex`, `payload_base64`, `payload_sha256` | the raw payload bytes, exactly as in the block |
| `zero_length` | the declared length is 0 (kept, not dropped) |
| `frame_id` | `ARCHIVE/toc<index>/<framing>/0x<operand offset>` |

Skipped entries (one per incomplete walk) carry `reason`, `walk_stop_kind`,
`block_offset`, `opcode`, the count of valid strings before the failure, and the
undecoded tail's offset, length and SHA-256. A malformed string frame also carries
its declared length, the bytes that were actually available, and those bytes as hex.

---

## Method

- **Container and block.** The DAX container and the signed-byte RLE come from
  `por_ecl` (GoldBox `docs/dax-format.md` sections 1-2). Each block is checked for
  the `0x1388` magic and a 22-byte header, as in the decoder.
- **Walk.** Each block is walked from byte 22 with `por_ecl.walk_block`, in both
  framings the decoder supports, `conservative` and `spec-menus`. The census does
  not re-implement the walk for complete instructions. It reads the instruction
  list the decoder returns.
- **Strings.** Any operand with code `0x80` in a decoded instruction (fixed or
  count-driven) is a frame. The payload is the `high` byte count after the
  two-byte operand. The census re-reads those bytes from the block, because the
  decoder keeps only their SHA-256.
- **Stopped instruction.** The one instruction where a walk stopped
  (`truncated-operand` or `ambiguous-count`) is probed operand by operand. The
  probe uses the decoder's operand reader and opcode table, and mirrors its walk
  order, so the failure point agrees with the walk. The synthetic tests pin that. Valid strings before the failure are kept as
  `instruction_complete: false`. A string that overruns the block is a malformed
  frame: it is reported with the bytes that existed, and never completed.
- **Tail.** Bytes after a stop are raw. They are never scanned for `0x80`, and
  they are never counted as strings, even when they look like one. A test pins this.

### Framing status

| `framing_status` | Meaning | Confidence |
|---|---|---|
| `before-first-menu` | precedes the first menu opcode (0x15 or 0x2B) in the walk | both framings agree on this prefix; still subject to the opcode table |
| `spec-menu-frame` | belongs to a menu decoded under `spec-menus` | census-supported, not proven (second GoldBox source) |
| `after-spec-menu` | follows a menu decoded under `spec-menus` | depends on the unproven menu framing |

`conservative` stops at the first menu, so it has only `before-first-menu` frames.
`spec-menus` carries the other two statuses. The 185 conservative frames are
therefore the same frames as the spec-menus `before-first-menu` set.

### Byte-count reading and the CoK hypothesis (kept as hypothesis)

- The census uses the decoder's byte-count reading of `0x80`: `high` = number of
  packed payload bytes after the operand. `docs/por-ecl-decoder.md` records that
  a 6-bit-character reading of the same operand stops much earlier in the same
  probe, so the byte-count reading was kept there. PoR's own 0x80 arm passes
  that same byte as the unpacker's count (`docs/por-ecl-length-xref.md`). The census
  does not test the 6-bit reading again, and it applies no CoK string rule.
- The `0x80` byte is a code in the GoldBox operand framing, not a verified
  string type for PoR. Where a `0x80` appears in a position the decoder did not
  actually parse, it is not a string. The census can only show that the decoder,
  under its stated framing, reads a `0x80` operand there.

---

## Retail census (read-only, 2026-11-17)

Source: local GOG DOS install, `POOLRAD/ECL1.DAX` to `ECL8.DAX`. All eight archives
are present and every one of the 29 TOC blocks decodes (container ok, magic and
header ok). No TOC id repeats within an archive (`blocks_with_repeated_id: 0`).
The install was hashed and stat-checked before and after the run. Nothing changed.
The archive SHA-256s are in the output JSON, not repeated here.

| Framing | Walks | Complete | Incomplete | Body bytes decoded / total | String frames | Zero-length | Malformed |
|---|---|---|---|---|---|---|---|
| conservative | 29 | 0 | 29 | 21,107 / 175,627 (12.0%) | 185 | 21 | 0 |
| spec-menus | 29 | 1 | 28 | 113,655 / 175,627 (64.7%) | 1,656 | 124 | 0 |

String frames by framing status (spec-menus): 185 before the first menu, 395 spec
menu frames, 1,076 after a spec menu. Conservative has 185 before-first-menu frames
and nothing else. Of the 1,656 spec-menus frames, 886 have a declared length over
20 bytes, and the largest is 154. Of the 185 conservative frames, 108 are over 20.

| Archive | conservative frames | spec-menus frames |
|---|---|---|
| ECL1 | 0 | 122 |
| ECL2 | 27 | 280 |
| ECL3 | 25 | 237 |
| ECL4 | 53 | 208 |
| ECL5 | 15 | 124 |
| ECL6 | 32 | 340 |
| ECL7 | 16 | 104 |
| ECL8 | 17 | 241 |

### Skipped and ambiguous walks

- Conservative: 25 walks stop at a menu (`ambiguous-framing`, the census's
  reason for a menu it will not decode), and 4 stop at an unknown opcode.
- Spec-menus: 26 walks stop at an unknown opcode, and 2 at a truncated fixed
  operand. The truncated ones are ECL2 #20 (offset 7674, opcode `0x06`) and
  ECL3 #14 (offset 7331, opcode `0x08`). In both cases the failure is a fixed
  operand, not a string, so no malformed string frame was found anywhere.
- Unknown-opcode stops include several opcodes that are `0x80` or `0xFF` (ECL7 #22
  and #23 at `0x80`, ECL1 #18 and ECL6 #28 at `0xFF`). A `0x80` stop is itself
  suspicious, because `0x80` is the string code: it suggests the walk has
  desynchronised, not that a string follows. Those frames are reported as
  skipped, not reinterpreted.

### What the numbers do and do not show

- Strings are not rare. Under the spec-menus framing, 27 of 29 blocks carry at least
  one `0x80` operand. Those walks decode 64.7% of the body bytes. The conservative
  prefix holds 185 frames, and those are the strongest of the set.
- Only 1 of the 58 walks reached end-of-block (ECL6 #19 under spec-menus, as in the
  decoder doc). The census therefore establishes no absence of strings in any
  block, and says so per block in the output.
- 124 spec-menus frames are zero-length (21 of them in the conservative prefix).
  These are kept, not dropped. Whether `0x80 0x00` is a terminator, padding, or a
  real empty string is not established.
- No payload is interpreted. The payload SHA-256 values are the means of
  comparing a repeated payload across blocks. The census does not assert that two
  equal payloads are the same message.

---

## Tests

`tests/test_por_ecl_strings.py`: 20 synthetic tests pass by default, and the
retail anchor is skipped unless `OPENUA_POR_ECL_STRINGS_INSTALL` is set. The
synthetic tests cover:

- payload extraction: exact offsets, declared and total lengths, hex and base64
  round trip, payload SHA-256, source SHA-256, TOC index and block id, and the
  `frame_id` format;
- count-driven strings (ON_GOTO), including a zero-length entry;
- agreement with `por_ecl.walk_block` on the number of `0x80` operands;
- duplicate block ids: every TOC entry walked, flagged, and never merged;
- malformed frames: an overrun string is reported with its available bytes and no
  frame is emitted; a valid string before a failure in the same instruction is kept
  as incomplete; an ambiguous count is reported, and no count entry is guessed;
- menu framing: conservative stops with `ambiguous-framing`; spec-menus reads menu
  strings as `spec-menu-frame`; strings after a spec menu are `after-spec-menu`;
- tail bytes after an unknown opcode are never counted as strings;
- determinism (byte-identical JSON and report across runs), no path leakage, the
  refusals (missing install, output inside the source, output in the repo outside
  `data/`, ambiguous archive), exit codes 0/1/2, case-insensitive archive lookup
  under `POOLRAD`, and source immutability (bytes, size, and mtime unchanged).

The retail anchor checks the ECL2 file hash, the decoded hash of ECL2 #20
(`a1e1dd7a...`, the same value as `docs/por-ecl-decoder.md`), the spec-menus stop at
offset 7674, and a regression pin on the frame counts (185 conservative, 1,656
spec-menus) from this run. The pins are a snapshot, not an independent check of
PoR's string format.

---

## Not claimed

- No string is decoded as text. No charset, text table, dictionary, or 6-bit
  character reading is applied.
- No string is mapped to a FRUA message, STRG resource, event, or ECL dispatch.
- No playable module, conversion, reachability, or route is produced.
- A `0x80` operand under the decoder's framing is not proof that a string exists
  there in PoR. The framing is the decoder's, and it is unproven for the spec-menus
  case.
- An absent string is not established by an incomplete walk.
- The byte-count reading of `0x80` matches the count the retail 0x80 arm passes to its
  unpacker, by static code reading (`docs/por-ecl-length-xref.md`). That the ECL walk reaches
  that code at run time is not shown.

---

## Usefulness and limitations

Useful: the census gives a deterministic, hash-anchored list of every `0x80` operand
the decoder reaches in all eight retail archives. Each entry keeps the exact bytes
and their position, so a later text or charset study can start from the raw data
without re-running the walk. It also separates the high-confidence conservative
prefix from the framing-dependent spec-menus frames, and it lists every place the
walk stopped, with the bytes it could not decode.

Limitations: most walks stop early (only 1 of 58 reached end-of-block), so most
blocks are only partly covered. The spec-menus framing is unproven. The byte-count
reading of `0x80` is code-evidenced for PoR (`docs/por-ecl-length-xref.md`), but the
walk's run-time reach of that code is not shown. Some `0x80` operands may be data, desync artefacts,
or mis-framed; the census cannot tell those apart. The census is an inventory, not
a semantic result.

## Next steps (not done here)

1. Settle the menu framing (`0x15`, `0x2B`) with a source other than the two
   GoldBox documents, as `docs/por-ecl-decoder.md` already requires.
2. Explain the unknown-opcode stops, including the `0x80` desync cases, before
   trusting any `after-spec-menu` frame.
3. Only if a charset or string format is evidenced, test the conservative 185
   frames against it, and keep the result as a separate, labelled experiment.

---

## Source files

- `tools/por_ecl_strings.py` (this slice)
- `tests/test_por_ecl_strings.py` (synthetic tests; retail anchor opt-in)
- `docs/por-ecl-strings-census.md` (this file)
- Reused, unchanged: `tools/por_ecl.py`, `tools/por_walls.py` (archive lookup),
  `tools/por_convert.py` (output guard), `tools/por_map.py` (error type)
- GoldBox read-only references: `docs/dax-format.md`,
  `docs/engine/research/ecl-opcode-spec-for-asm.md` (2.2, string operand),
  `docs/engine/research/ecl-krynn-gen1-opcodes.md`
