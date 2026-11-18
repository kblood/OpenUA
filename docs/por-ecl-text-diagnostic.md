# Pool of Radiance 0x80 payloads: diagnostic 6-bit decode of the census

**Status: diagnostic-unaccepted. `playable: false`.** Tool: `tools/por_ecl_text_diagnostic.py`.
Tests: `tests/test_por_ecl_text_diagnostic.py`. Input: the string census written by
`tools/por_ecl_strings.py` (`openua.por-ecl-strings` v1). The census is read, never written.

This report shows what the PoR-retail-verified 6-bit codec gives for each census
payload. **It is not text.** Every frame is `accepted: false`. Nothing in the output is
shown as Pool of Radiance screen or message text, and no decoded string has been matched
to an on-screen run.

---

## What it does

For each census `0x80` payload, the tool:

1. checks the payload against the census record (length, hex, base64, SHA-256);
2. decodes it with the PoR codec (below), skipping zero values;
3. writes a JSON record and a Markdown summary, keeping each frame's census framing,
   framing status, and offsets.

It does not write to the census, the install, or any tracked path.

## Codec (from the PoR retail bytes)

Source: `docs/por-ecl-codec-static-probe.md`, which cites `GAME.OVR:0x8626` (the unpacker)
and `GAME.OVR:0x7BA6` (the char map).

- **Layout:** the payload is split MSB-first into 6-bit groups. `floor(8n/6)` values come
  out for an `n`-byte payload. The leftover 1 to 4 bits at the end are dropped and
  recorded as `dropped_tail_bits`.
- **Zero handling:** a value of `0` is **skipped**, and decoding continues. It is never a
  terminator. The GoldBox stop-at-zero reading is not used on this path. The retail code
  does this at `0x08701` (`cmp [bp-5],0 / jz`).
- **Char map:** value `1..31` maps to `value + 0x40` (`0x41..0x5F`); value `32..63` maps to
  itself (`0x20..0x3F`). Every decoded character is printable ASCII.

Implementation: a pure, stdlib-only bit accumulator in `decode_payload()`. It is not
imported from `tools/por_ecl_codec_static.py`; the tests cross-check against that module's
reference (`ref_values`, `expected_skip_zero`) and against its retail-executed unpacker
(`run_unpack`).

## Run

```sh
python3 tools/por_ecl_text_diagnostic.py \
    --census data/work/por-ecl-strings/retail/por_ecl_strings.json \
    -o data/work/por-ecl-text-diagnostic/retail
```

Both `--census` and `-o` are required. The output lands in two files:

- `por_ecl_text_diagnostic.json`, schema `openua.por-ecl-text-diagnostic` v1
- `por_ecl_text_diagnostic_report.md`, the human summary

Re-running on the same census gives byte-identical files. Outputs contain no timestamps
and no absolute paths. The census is recorded by file name and SHA-256 only.

Tests:

```sh
python -m pytest tests/test_por_ecl_text_diagnostic.py -q
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_ecl_text_diagnostic.py -q
```

Exit codes: `0` outputs written. `2` named refusal (see below).

## Refusals

The tool refuses, with exit `2` and nothing written, when:

- the census file is missing, is not UTF-8 JSON, or is not `openua.por-ecl-strings` v1
  with status `census-only` and `playable: false`;
- any frame lacks a required key, has an unknown `framing` or `framing_status`, has
  undecodable hex or base64, or has a payload whose length, base64, or `payload_sha256`
  disagrees with its record;
- a `frame_id` repeats;
- the output folder is inside the census folder (or is the census folder);
- the output folder is inside the repository but not under `data/` (`validate_output_dir`,
  shared with the other PoR tools);
- the output path exists and is not a folder, or would overwrite the census.

## Output schema

`por_ecl_text_diagnostic.json`, keys written sorted:

| Key | Meaning |
| --- | --- |
| `schema`, `version` | `openua.por-ecl-text-diagnostic`, `1` |
| `status` | `diagnostic-unaccepted` |
| `playable` | `false` |
| `tool` | `tools/por_ecl_text_diagnostic.py` |
| `source_census` | `file` (name only), `sha256`, census `schema`, `version`, `status`, `string_frames` count |
| `codec` | layout, zero handling, char map, evidence pointer |
| `summary` | totals, `by_framing`, `by_framing_status`, distinct payload count |
| `unresolved` | the unresolved reasons, each with its scope |
| `not_claimed` | what the output does not claim |
| `frames` | one record per census frame, sorted by framing, archive, TOC index, operand offset, frame id |

Each `frames[]` record:

- identity and provenance: `frame_id`, `archive`, `toc_index`, `block_id`, `framing`,
  `framing_status`, `operand_offset`, `instruction_offset`, `mnemonic`, `opcode`,
  `payload_sha256`;
- lengths: `declared_length`, `payload_length`, `dropped_tail_bits`;
- decode: `values_total` (all 6-bit values, zeros included), `values` (nonzero only),
  `zero_values_skipped`, `zero_then_nonzero` (true if a nonzero value follows a zero),
  `char_codes`, `text`;
- status: `accepted: false`, `status: diagnostic-unaccepted`, and `unresolved`, a list of
  reason codes (see below).

`summary` has `frames_total`, `distinct_payload_sha256`, `chars_decoded_total`,
`zero_values_skipped_total`, `by_framing` (per framing: frames, zero-length frames,
frames with a dropped tail, characters, frames with zero skips, frames with zero-then-
nonzero), and `by_framing_status`.

The Markdown report carries the same counts, the unresolved list, and a per-frame table
of frame, framing, status, byte count, value count, and text. The JSON is the complete
record.

## Unresolved reasons

Every frame carries `runtime-text-binding`. A frame whose census status is `spec-menu-frame`
or `after-spec-menu` also carries `census-framing-speculative`.

- **`runtime-text-binding`.** Nothing shows that a decoded string appears on a PoR screen
  or maps to a message. No matched on-screen run exists.
- **`census-framing-speculative`.** The census spec-menus framing is a census result, not
  proof. Frames at or after the spec menu are flagged.

The `0x80` byte count is not an unresolved reason. The retail 0x80 arm passes the census
`declared_length` (the operand's `high` byte) to the unpacker. That is static code evidence,
from the writer at `GAME.OVR:0x07526` and the read at `0x07577`, reconciled with the census
offsets in `docs/por-ecl-length-xref.md`. Its caveat, that the ECL walk's reach of that parser
at run time is not shown, is listed under "Not claimed".

## Evidence boundaries

- **Established (from the probe doc, not re-proven here):** the MSB-first 6-bit layout,
  zero skipping, and the char map, from retail bytes and retail-executed emulation.
- **Established by static code reading (`docs/por-ecl-length-xref.md`):** the count the
  retail 0x80 arm gives the unpacker is the census `declared_length`. Not executed, and the
  parser's caller is not shown to run.
- **Not established:** that the ECL walk reaches the length parser at run time; that any
  payload is a complete PoR string; any on-screen or runtime binding; that any decoded text
  is what the game shows.
- **Zero handling is a PoR reading.** The retail code skips zero. The GoldBox
  stop-at-zero reading is not used, and no GoldBox material is evidence here.
- **Decoded text is a reading.** Some decoded strings look like ordinary English prose.
  That is observation, not verification. Do not promote a string to accepted because it
  reads well.

## Result on the current census (2026-11-17)

Run on `data/work/por-ecl-strings/retail/por_ecl_strings.json` (git-ignored output):

- 1841 frames; 1203 distinct payload hashes.
- 85,938 characters decoded; 414 zero values skipped.
- 0 frames with a nonzero value after a zero, which matches the census's own observation.
- The 185 `before-first-menu` frames under `conservative` are the same payloads, with the
  same SHA-256 and operand offsets, as the 185 `before-first-menu` frames under
  `spec-menus`. The report counts them per framing and does not de-duplicate. The 370
  `before-first-menu` entries are 185 distinct frames.

Test results:

- Without `OPENUA_POR_INSTALL`: 107 passed, 2 skipped (the retail tests).
- With `OPENUA_POR_INSTALL="/g/Games/Pool of Radiance/POOLRAD"`: 109 passed in about 27 s.
  This includes the retail unpacker cross-check on edge and random vectors, and on every
  census payload (zero disagreements; every payload consumed exactly its length).

## Not claimed

- No decoded string is accepted, verified, or shown as Pool of Radiance text.
- No string is mapped to a message, event, or STRG resource.
- The 0x80 count is read from retail code (`GAME.OVR:0x07526`, `0x07577`). That the ECL walk
  reaches that parser at run time (its caller is a far call) is not shown.
- Zero is skipped because the retail code skips it, not because it is a terminator.
- No playable module, conversion, or route is produced.

## What would move this further

- Show that the ECL walk reaches the length parser (`GAME.OVR:0x074D3`) at run time. The
  writer is already found (`docs/por-ecl-length-xref.md`), so the open item is the caller.
- Match one decoded string to an on-screen run, under the rules in
  `docs/por-ecl-codec-candidates.md`. Until then every frame stays `accepted: false`.
