# Pool of Radiance ECL decoder (slice 3): status and evidence

**Status: decode only. `playable: false`.** `tools/por_ecl.py` reads one ECL block
from an explicit PoR DAX, validates the container, decompresses the block, checks
the 22-byte ECL header, and walks the instruction stream from the header end. It
does not map anything to FRUA events and does not write a module. This slice does
not claim playable conversion, route reachability, or any FRUA equivalence.

The map slice (`tools/por_map.py`, see `docs/por-converter.md`) is separate. This
slice does not change FRUA GEO compatibility and does not write to the install.
The tool is listed in `tools/README.md`. For the downstream `LOAD_PIECES` opcode
trace across ECL1-8, see [`por-loadpieces-trace.md`](por-loadpieces-trace.md).

---

## Usage

```sh
# TOC of an explicit ECL DAX (no output)
python3 tools/por_ecl.py --dax PATH/TO/ECL2.DAX --list

# GOG-style install: ECL<n>.DAX here or in its POOLRAD subfolder
python3 tools/por_ecl.py --install "D:/PoR" --ecl 2 --index 2 \
    -o data/work/por-ecl/ecl2-20 --framing spec-menus --vbase 0x98FE

# choose by block id (refused if the id repeats; then use --index)
python3 tools/por_ecl.py --dax PATH/TO/ECL2.DAX --block 20 -o data/work/por-ecl/ecl2-20

# opt-in, CONDITIONAL PoR-derived base 0x98FE (not promoted; cannot be combined with --vbase)
python3 tools/por_ecl.py --install "D:/PoR" --ecl 2 --index 2 \
    -o data/work/por-ecl/ecl2-20-por --framing spec-menus --por-vbase
```

| Option | Meaning |
|---|---|
| `--dax FILE` / `--install DIR --ecl N` | source: one explicit DAX, or `ECL<N>.DAX` in an install |
| `--block ID` / `--index I` | block by id (must be unique) or by TOC index |
| `--list` | print the TOC and exit |
| `--framing conservative` (default) | stop at the two menu opcodes `0x15` and `0x2B`, keeping the rest raw |
| `--framing spec-menus` | decode the menus with the count-driven framing of the second GoldBox source (see below) |
| `--vbase HEX` | resolve jump targets as `offset = vaddr - vbase`. Without it, targets stay `unresolved-no-base` |
| `--por-vbase` | **opt-in, evidence level CONDITIONAL, not promoted.** Resolve targets as `offset = (vaddr - 0x98FE) mod 65536`, label targets inside the 22-byte header `in-header`, and write `vbase_evidence` (see section 6). Never the default. Refused with exit 2, with nothing written, when combined with `--vbase` |
| `-o OUT` | output folder. Must not be inside the source; inside the repository it must be under `data/` |

Outputs in `OUT`:

- `por_ecl.json`: schema `openua.por-ecl`, version 1, `status: decode-only`,
  `playable: false`. Holds the source hash, TOC index, block id, offsets and sizes,
  the header, decoded instructions with raw numeric operands, control-flow edges,
  stop reason, the unsupported tail as raw bytes, and the candidate-base
  diagnostic. Keys are sorted, nothing is timestamped, and there are no absolute
  paths. String operands store length and SHA-256 only, never text.
  Only with `--por-vbase`: a `vbase_evidence` object (mode, rule, `wrap16: true`,
  `evidence_level: "conditional"`, `promoted: false`, a per-block header check,
  the basis and the not-established list). Default output has no such key.
- `por_ecl_report.md`: human-readable summary of the same, with the "not claimed"
  list. With `--por-vbase` it also has a "PoR-derived vbase (opt-in, CONDITIONAL,
  not promoted)" section.

Exit codes: `0` success; `2` named refusal (bad container, bad RLE, ambiguous
block id, non-ECL block, unsafe output location, bad arguments).

Nothing is written under the source. Run it on `data/work/` outputs only; never
commit them.

---

## Evidence levels

| Claim | Level | Basis |
|---|---|---|
| DAX container: 2-byte TOC size, 9-byte entries, contiguous chain, EOF closure | validated on local retail `ECL2.DAX` (3 blocks, chain closes exactly at EOF) | GoldBox `docs/dax-format.md` section 1 |
| Signed-byte RLE; output must equal `raw_size` exactly | validated: block 20 decompresses to 7679 bytes, the TOC size | GoldBox `docs/dax-format.md` section 2 |
| ECL header: magic `0x1388`, five 4-byte far pointers (segment `0x0101`, vaddr), body from byte 22 | validated on all 29 retail blocks: magic and 0x0101 segments present | GoldBox `ecl-krynn-gen1-opcodes.md` 3.2 |
| Opcode table (wordSet and mnemonics, `0x00`-`0x40`) | source-backed table, not re-derived here; `0x1F` has no known semantics | GoldBox `ecl-krynn-gen1-opcodes.md` section 2 |
| Operand framing: 2 bytes, or 3 for codes `{1,2,3,0x81}`; code `0x80` inline string | consistent with retail census: operands parse through long runs of code | GoldBox `ecl-krynn-gen1-opcodes.md` 3.4, `ecl-opcode-spec-for-asm.md` 2.2 |
| Code `0x80` string: `high` = number of packed bytes that follow | census: this reading advances much further than the 6-bit-character reading (see census note). PoR code: the retail 0x80 arm's unpacker count is the byte after the code (`GAME.OVR:0x07526`, `0x07577`; `docs/por-ecl-length-xref.md`), static only | GoldBox `ecl-opcode-spec-for-asm.md` 2.2 (wording ambiguous) |
| `ON_GOTO` (`0x25`) / `ON_GOSUB` (`0x26`): `count` = literal operand 1; `count` extra operands follow | observed on retail block 20: the count operand is a literal and the entries parse | GoldBox `ecl-opcode-spec-for-asm.md` 2.4 |
| Menu framing: `0x15` and `0x2B` | **sources disagree** (table: wordSet 0; spec: count-driven). `spec-menus` mode is census-supported, not proven. Default mode stops | see Findings |
| Jump-target vbase for PoR ECL, default | **not established.** The default has no base; `--vbase` is user-supplied. `0x7FFE` (CoK rule) does not fit | see Findings |
| Jump-target vbase `0x98FE`, opt-in `--por-vbase` | **CONDITIONAL, not promoted.** Rests on the fetch bytes, the loader's `+2` skip, a 29-block header check, and a diagnostic. Open: the loader source `R` and the copy body | Findings section 6; [`por-ecl-base-probe.md`](por-ecl-base-probe.md); [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md) |
| Fetch arithmetic `index = (vaddr + 0x6700) mod 65536` from `[0x49DE]` | **Established by bytes** (GAME.OVR `0x3EDC..0x3EE7`, pinned SHA-256 `872964a3...28614`) | [`por-ecl-base-probe.md`](por-ecl-base-probe.md) |
| Header table maps to block bytes `2..21` under `(vaddr - 0x98FE) mod 65536`, ending at vaddr `0x9914` (block byte 22) | **Retail-measured** on 29 of 29 ECL1-8 blocks; the loader source is not located, so it stays conditional | [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md) (retail check) |
| Loader source `R` starts at block byte 0, and the copy is a byte copy | **Not established.** Callee bodies `0x0802:0x0716` and `0x0AF8:0x1685` are not located | [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md) items 1-2 |
| Decoded instruction starts under `0x98FE` | **Retail diagnostic, not proof.** ECL1-8: 2899 of 3260 header and literal targets are starts, against 68 under `0x9900` and 17 under `0x7FFE` | Findings section 6 |
| Runtime reachability, event semantics, playable conversion | **Not established** | none of these slices |
| Instruction semantics | **not implemented.** Only framing is walked | this slice |
| FRUA event equivalence | **not established.** No mapping is emitted | this slice |

---

## Findings (retail `ECL2.DAX`, read-only, 2026-11-16)

Source: local GOG DOS install `ECL2.DAX`, SHA-256
`6ad6dc5aa53da82f4dba62dbc47d5a02a3f14c14071bec44e81a692615f08a3d`, 19968 bytes.
TOC: block 9 (index 0), 15 (index 1), 20 (index 2). The chain closes exactly at EOF.
The source was opened `"rb"`; the hash was checked before and after.

Block 20 (TOC index 2): raw 7679, compressed 7824, decoded SHA-256
`a1e1dd7a7ffc07f6e3c3ce7fad25d373270c10edd06ec3fa1f1d0edc9a7297ec`.
Header magic `0x1388`; five pointers, all segment `0x0101`:
vaddrs `0x9914`, `0x9975`, `0x9A0E`, `0x9A49`, `0x9A5E`.

### 1. CoK entry invariant does not hold for PoR

The GoldBox CoK doc says the entry pointer (slot 4) is always `0x8014` (body byte 22),
with vbase `0x7FFE`. Here slot 4 is `0x9A5E`, and under `0x7FFE` the header
pointers land on non-opcode bytes (for example `6E 24 01 01...` and `EE 9E 0A...`). So
the CoK base is not used by the decoder.

### 2. A PoR-wide base `0x98FE` fits best (diagnostic only)

Slot 0 is `0x9914` in most blocks, and `0x9914 - 22 = 0x98FE`. Testing that base
against the decoded instruction starts (census below): the literal jump targets and
header pointers land on instruction starts at a high rate in nearly every block,
much higher than at `0x7FFE`. This is the best fit found, not proof. The tool
never resolves targets without `--vbase`, and the tool's candidate list is
diagnostic only.

### 3. Menu framing conflict (`0x15`, `0x2B`)

The table in `ecl-krynn-gen1-opcodes.md` gives wordSet 0 for both. `ecl-opcode-spec-for-asm.md`
2.4 gives `VERTICAL_MENU` 3 fixed with count at operand 2, and `HORIZONTAL_MENU`
2 fixed with count at operand 1, followed by that many inline-string items.
Under conservative framing, block 20 stops at offset `1751` (`0x2B`), covering
22.6% of the body (212 instructions). Under the spec framing, block 20 covers
99.9% (762 instructions); the last 5 bytes are an operand that runs past EOF.
This is census evidence for the spec framing, not proof of it. The default stays
conservative.

### 4. Retail anchors (GoldBox `persistent-natural-routes.md`, ECL2#20)

Checked with `--framing spec-menus --vbase 0x98FE`:

| Cited vaddr | Cited meaning | Decoded at `vaddr - 0x98FE` | Result |
|---|---|---|---|
| `0xAB90` | COMBAT (middle route, selector-13 checkpoint) | `0x24` COMBAT | instruction start, matches |
| `0xABF7` | COMBAT (selector-14 cell, `(1,5)`) | `0x24` COMBAT | instruction start, matches |
| `0xAB91` | resume, GOSUB `0xB69C` | `0x02` GOSUB | instruction start, matches |
| `0xAB49` | checkpoint branch start (descriptor 13) | `0x03` COMPARE (guard) | instruction start |
| `0xB69C` | shared treasure/victory narration | `0x03` COMPARE | instruction start |
| `0xB6BC` | shared "press on" menu | `0x2B` HORIZONTAL_MENU | instruction start; menu, so conservative mode cannot reach it |

The `ON_GOTO` selector for ECL2#20's search loop is a variable (`[0x9800]`, a
bounded linear search), not a GEO cell descriptor. This slice does not equate the
two, and the decoder records the operand raw. The anchor check confirms
instruction boundaries only. It does not confirm that these routes are reachable.

### 5. Census (all retail ECL1-8 blocks, read-only)

Coverage is decoded body bytes over body bytes (header excluded). The "stop" column
is the first place the walk stopped. Run under spec-menus, unless noted.

| Block (file, TOC index) | Body coverage: conservative / spec | Spec stop | Targets on starts under 0x98FE / total |
|---|---|---|---|
| ECL1 #18 (0) | 4.4% / 99.0% | unknown `0xFF` | 212 / 212 |
| ECL1 #24 (1) | 1.9% / 1.9% | unknown `0xFF` | 3 / 7 |
| ECL2 #9 (0) | 12.4% / 100% | unknown `0x4B` | 196 / 200 |
| ECL2 #15 (1) | 1.8% / 89.9% | unknown `0xF5` | 109 / 132 |
| ECL2 #20 (2) | 22.6% / 99.9% | truncated operand at 7674 (5 bytes) | 187 / 188 |
| ECL3 #0 (0) | 6.1% / 24.8% | unknown `0x63` | 34 / 78 |
| ECL3 #8 (1) | 20.2% / 98.8% | unknown `0xFA` | 193 / 193 |
| ECL3 #11 (2) | 10.8% / 99.6% | unknown `0x6C` | 65 / 65 |
| ECL3 #14 (3) | 10.2% / 100% | truncated operand at 7331 (opcode 0x08, last bytes) | 222 / 225 |
| ECL4 #2 (0) | 29.0% / 52.7% | unknown `0x64` | 82 / 108 |
| ECL4 #10 (1) | 33.5% / 71.8% | unknown `0x63` | 78 / 158 |
| ECL4 #21 (2) | 13.6% / 99.3% | unknown `0x71` | 127 / 128 |
| ECL5 #3 (0) | 3.9% / 11.7% | unknown `0x81` | 13 / 39 |
| ECL5 #4 (1) | 4.0% / 44.9% | unknown `0x4E` | 84 / 92 |
| ECL5 #5 (2) | 5.4% / 10.2% | unknown `0x79` | 5 / 10 |
| ECL5 #6 (3) | 9.3% / 62.7% | unknown `0x80` | 50 / 65 |
| ECL5 #7 (4) | 0.4% / 11.2% | unknown `0x6C` | 18 / 28 |
| ECL6 #1 (0) | 20.2% / 100% | unknown `0xF7` | 181 / 181 |
| ECL6 #19 (1) | 8.3% / 100% | end of block | 38 / 38 |
| ECL6 #25 (2) | 15.5% / 96.9% | unknown `0x77` | 186 / 192 |
| ECL6 #28 (3) | 20.4% / 100% | unknown `0xFF` | 151 / 161 |
| ECL7 #17 (0) | 14.0% / 14.0% | unknown `0x9D` | 29 / 38 |
| ECL7 #22 (1) | 3.6% / 3.6% | unknown `0x80` | 3 / 7 |
| ECL7 #23 (2) | 1.7% / 1.7% | unknown `0x80` | 3 / 7 |
| ECL7 #26 (3) | 12.3% / 90.3% | unknown `0x5D` | 211 / 214 |
| ECL8 #13 (0) | 2.6% / 55.4% | unknown `0x64` | 72 / 117 |
| ECL8 #16 (1) | 5.8% / 26.8% | unknown `0x60` | 26 / 44 |
| ECL8 #27 (2) | 14.3% / 95.8% | unknown `0x49` | 180 / 186 |
| ECL8 #29 (3) | 20.2% / 98.9% | unknown `0x4B` | 146 / 147 |

Reading this table: many blocks reach 90-100% under the spec framing, but a
large number stop at an opcode above `0x40` (`0x4B`, `0x63`, `0xFA`, ...). Those
are not in the table, so they may be data, a framing gap in an operand form not yet
tested (for example `0x7F`, `0x09` or a `0x81` string), or a PoR-only extension. They are
unexplained; the decoder keeps them raw.

Note on the string length: under the 6-bit-character reading of `0x80` the walks
stop far earlier (for example ECL2 #20 at offset 527, against 1751 under the byte
count reading in the same conservative probe), so the byte-count reading is kept.

### 6. Opt-in PoR-derived base (`--por-vbase`): CONDITIONAL, not promoted

Source: the pinned retail install (`GAME.OVR`, 206,105 bytes, SHA-256
`872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614`; ECL1-8.DAX read
`"rb"`). Nothing was written under the install. Base `0x98FE` is a conditional
equation, not a promoted fact. Its evidence, by level:

| Level | Meaning | Items |
|---|---|---|
| **Established by bytes** | PoR code bytes in the pinned `GAME.OVR` | Fetch `les di,[0x49de]; add di,ax; mov al,es:[di+0x6700]` at `0x3EDC..0x3EE7`, so index `= (vaddr + 0x6700) mod 65536`. Loader `add di,0x0002` (`81 c7 02 00`) at `0x78B4` in the copy of `len-2` bytes from record+2 (`0x78B1..0x78C6`). Cursor literal `0x9900` at `0x076C8`. |
| **Retail-measured** | Counted on all 29 ECL1-8 blocks | Magic `0x1388` in 29/29. Header segments `0x0101` in 29/29. Every header pointer `>= 0x9914` (table end, block byte 22) in 29/29. Under `(vaddr - 0x98FE) mod 65536` each pointer lands at block offset `>= 22` and inside the block. |
| **Retail diagnostic (not proof)** | Decoded-start hits, `spec-menus` walk from byte 22 | Header pointers plus literal edge targets: 2899 of 3260 land on decoded instruction starts under `0x98FE`; 68 under `0x9900`; 17 under the CoK `0x7FFE`. 361 targets do not land on a start. |
| **Conditional (what the opt-in uses)** | Needed for `0x98FE`, not shown by the bytes above | (a) the loader's record source `R` starts at block byte 0, so buffer index `k` is block byte `k+2`; (b) the copy is a contiguous byte copy, so the linear map extends past the header; (c) block byte 22 begins the instruction stream. |
| **Not established** | Not claimed | Loader source `R` (callee `0x0802:0x0716`); copy body (`0x0AF8:0x1685`); that block byte 22 is an instruction start (PoR never reads the cursor after the table parse, and the five entry slots are the VM's entries); that every target lands on a start; compatibility with PoR revisions other than the pinned GOG build; runtime reachability; event semantics; playable conversion. |

The opt-in is not version-locked: it accepts an ECL DAX without checking a matching
`GAME.OVR`. Its evidence comes from the pinned GOG `GAME.OVR` and the 29 blocks in
that install. Treat it as conditional for other user-supplied PoR revisions unless
their executable bytes are checked separately.

**What the opt-in changes (only with `--por-vbase`):**

- Edges resolve as `target_offset = (vaddr - 0x98FE) & 0xFFFF` (`wrap16`). A target
  inside the 22-byte header is labelled `in-header`, not `mid-instruction`. Other labels
  (`instruction-start`, `mid-instruction`, `beyond-decoded-region`, `out-of-block`) keep
  their meaning.
- `vbase_evidence` is written with `promoted: false`, `evidence_level: "conditional"`,
  and a per-block structural check: `segments_0101`, `pointers_at_or_after_table_end`,
  `pointers_inside_block`. A failed check is recorded as `conditional-checks-fail`,
  not refused.
- `--vbase` and `--por-vbase` cannot be combined: exit 2, nothing written.
- Default output is unchanged. Verified byte-identical to the committed `HEAD` decoder
  on 174 retail decodes (29 blocks x 2 framings x base `none` / `0x98FE` / `0x7FFE`).

**Why the base is 0x98FE and not 0x9900 or 0x7FFE:** the fetch displacement `0x6700`
(fetch bytes) plus the loader skip `+2` gives `0x6702`, which equals `-0x98FE mod 65536`.
In the retail header grid only skip `+2` passes all 29 blocks; every other skip passes
none (see [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md), retail check).
The decoded-start diagnostic points the same way. Neither tests the source `R`, so neither
promotes the base.

**Open links that would promote or refute it:**

1. Locate the record source `0x0802:0x0716` and the copy `0x0AF8:0x1685`. If `R[0]` is
   not block byte 0, the base is wrong. See
   [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md), not-established items 1-2.
2. Explain the 361 non-start targets (a framing gap, data, or a wrong base).
3. Trace the cursor and the VM entry slots to show block byte 22 is an entry. See
   [`por-ecl-base-probe.md`](por-ecl-base-probe.md), "What would settle the origin".

---

## Tests

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl.py        # Windows
tools/.venv/bin/python -m pytest tests/test_por_ecl.py                # POSIX
OPENUA_POR_ECL_DAX="PATH/TO/ECL2.DAX" tools/.venv/bin/python -m pytest tests/test_por_ecl.py  # adds the retail anchor test
```

Synthetic fixtures (no retail data needed by default): a DAX writer with the
writer envelope from `dax-format.md` 2a, an ECL block writer, and a
test-only RLE encoder. Covered: container refusals (TOC multiple of 9, TOC past
EOF, broken chain, data not ending at EOF, block past EOF), RLE refusals, block
selection (repeated ids refused without `--index`), header magic and segments,
instruction offsets and lengths, `ON_GOTO` count entries, edge resolution (instruction
start, mid-instruction, out-of-block, unresolved, indirect), unknown-opcode stops
keeping the tail raw, menu framing in both modes, non-literal count refusal,
truncated operands and strings, `0x1F` semantics flag, string operands not
leaking text, deterministic JSON, no absolute paths, source hash unchanged, output
guards, source resolution, and CLI exit codes.

Local result after integration: 34 tests pass, including the opt-in retail
anchor test against the local `ECL2.DAX` with the env var set.

Opt-in `--por-vbase` tests (added 2026-11-18), in the same file:

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl.py -q           # 41 passed, 5 skipped
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl.py -q  # 46 passed
```

- Without the install: option conflict (`--por-vbase` with `--vbase`, exit 2, nothing
  written), default-off output with no `vbase_evidence` key, wrap-aware edge labels
  (`instruction-start`, `in-header`, `mid-instruction`, `out-of-block`, wrap mod 65536),
  a base falsifier (the same GOTO under `0x9900` changes its label), and determinism.
- Retail-gated (`OPENUA_POR_INSTALL`): `GAME.OVR` SHA-256 pinned, with the fetch and
  loader bytes checked; all 29 ECL1-8 blocks checked against the header equation; the
  edge equation checked on all 29; the measured counts (2899 of 3260; 68; 17) pinned; and
  a CLI run writing 29 evidence outputs under `tmp_path`.
- Mutation checks on a scratch copy of the decoder (not the repo): base set to `0x9900`
  fails 5 tests; the wrap removed fails 3.

---

## Not claimed

- No FRUA event mapping, no translation candidate, no module. There is no
  source-to-FRUA equivalence evidence, so the brief's conditional step was not met.
- No instruction semantics: the decoder checks framing only.
- No reachability, route, or campaign claim. Anchor checks confirm instruction
  boundaries under the diagnostic base, not reachability.
- No promotion of `0x98FE` to the PoR vbase. It is the best fit in a diagnostic, and the
  opt-in `--por-vbase` mode is labelled CONDITIONAL with `promoted: false`.
- No claim that the loader's source `R` starts at block byte 0. That is a stated condition.
- No claim that other PoR revisions use this relation. The mode does not check the
  supplied DAX against a matching executable revision.
- No claim that every target lands on an instruction start. 361 of 3260 retail targets do not.
- No claim that the menu framing is the spec one; it is a census result.
- No claim about GEO selector equality. The ECL selector is a variable, not assumed
  to match a GEO cell descriptor.

---

## Next conversion blocker

1. **Settle the menu framing** (`0x15`, `0x2B`) against a source that is not the
   two conflicting GoldBox docs, for example a semantic check on a block with a menu
   whose items must parse exactly.
2. **Promote or refute the vbase.** `--por-vbase` (`0x98FE`) is conditional. The open
   link is the loader's record source `R` and copy body (`0x0802:0x0716`,
   `0x0AF8:0x1685`). If `R[0]` is not block byte 0, the base is wrong. See
   [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md) and
   [`por-ecl-base-probe.md`](por-ecl-base-probe.md). Findings section 6 lists the evidence.
3. **Explain the stops above `0x40`** (`0x4B`, `0x63`, `0xFA`, ...). Decide whether
   they are data, a missing operand form, or PoR-only opcodes, with evidence per
   case.
4. **Build an opcode-semantics table** for the PoR dialect, and only then a source-
   to-FRUA equivalence table for the events that matter (text, combat, party
   checks, transitions). Each row needs evidence before any translation candidate
   is emitted.

Until 1-4 are closed, the output of this slice is raw structure, not an event
translation.

The batch census of opcode `0x37` (LOAD_PIECES) across ECL1-8 is a separate, read-only
tool built on this decoder: `tools/por_loadpieces_census.py`, see
`docs/por-loadpieces-census.md`. Its coverage results show that the walk stops early in
most retail blocks, so absence of `0x37` is not established there.

---

## Source files

- `tools/por_ecl.py` (this slice; `--por-vbase` is opt-in and conditional)
- `tests/test_por_ecl.py` (synthetic tests; retail anchor and `--por-vbase` retail checks opt-in)
- `docs/por-ecl-decoder.md` (this file)
- Evidence for the opt-in base: [`por-ecl-base-probe.md`](por-ecl-base-probe.md),
  [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md) (read-only; their tools are not changed here)
- `tools/por_loadpieces_census.py` and `docs/por-loadpieces-census.md` (batch census that reuses this decoder)
- GoldBox read-only references: `docs/dax-format.md`,
  `docs/engine/research/ecl-krynn-gen1-opcodes.md`,
  `docs/engine/research/ecl-opcode-spec-for-asm.md`,
  `docs/engine/research/persistent-natural-routes.md` (ECL2#20 section),
  `docs/engine/research/pool-ecl-dispatch-map.md` (not used for numbers here)
