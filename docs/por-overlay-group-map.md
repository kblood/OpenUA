# Pool of Radiance: one overlay group in a RAM dump, and what its far calls reach

**Status: MEMORY-MAP-PROBE-ONLY. `playable: false`.** The probe reads one RAM dump and the
pinned retail files, read-only. Every result below is "these bytes are present in memory". Nothing
here says a routine was **executed or called**, and nothing says what the wheel prompt's answer is.

Tool: [`tools/por_overlay_group_map.py`](../tools/por_overlay_group_map.py). Tests:
[`tests/test_por_overlay_group_map.py`](../tests/test_por_overlay_group_map.py). Output (git-ignored):
`data/work/por-overlay-group-map/por_overlay_group_map.json`.

Builds on [por-farcall-resolution.md](por-farcall-resolution.md) (the VROOMM stub model) and
[por-wheel-prompt-trace.md](por-wheel-prompt-trace.md) (the prompt routine at GAME.OVR `0x0AA9`).

---

## Inputs and pins

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a3…7928614` |
| `START.EXE` | 65,231 | `d825df2b…0a6b07bd` |
| dump `data/work/por-wheel-live-capture/ram-000000-100000.bin` | 1,048,576 | `3788787c…0516fa` |

Both pins match exactly (checked before and after the run). There is no override: an unpinned file is
refused. The dump is named `ram-000000-100000.bin`, so its base `0` comes from the name. The
capture's PID and status are recorded as **unverified caller metadata**: `pid=34644`, status
"program START, GameLink v4, 640x400 frame seq 102 at wheel prompt", and `dump_capture=non-atomic`.
They do not change any status.

## Usage

```sh
python tools/por_overlay_group_map.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    --meta pid=34644 --meta "status=program START, GameLink v4, 640x400 frame seq 102 at wheel prompt" \
    --meta "dump_capture=non-atomic (caller-declared)"
```

Stdlib-only. `--descriptor` defaults to `0x39E`, the START.EXE header of the accepted group. The output
folder must be under `data/work`. Exit `0` = every far-call target resolves to one pinned file offset;
`1` = the group maps uniquely but at least one target is absent, ambiguous, or out of the dump;
`2` = a named refusal (unpinned input, group absent or ambiguous, malformed descriptor or fixup table,
dump bounds).

The retail run exits `1`: the group maps, and 12 of 30 targets have no unique pinned match (below).

## Method

1. **Descriptor.** START.EXE `0x39E`: `CD 3F 00 00`, `fileofs = 0x9AC`, `codesz = 0x35E`,
   `fixupsz = 0x3C` (30 words), `jmpcnt = 2`. The fixup table is at GAME.OVR `0x9AC+0x35E`.
2. **Group map by stable bytes.** Every code byte except the two bytes of each fixup word is compared.
   The loader rewrites those words, so they are masked. The group maps to dump linear **`0x49150`**,
   unique: 802 stable bytes match, 60 fixup bytes are excluded. Zero hits is "absent" and more than one
   is "ambiguous"; both refuse. Base `0x49150` is paragraph aligned.
3. **Far-call sites.** A fixup word preceded by `9A` is a `CALL FAR seg:off` operand. There are 30, and
   every `9A` in the group whose segment is a group raw segment is among them (checked by scanning the
   group code, 0 missing). The offset word is stable, and the live operand is read from the dump.
4. **Relocation.** For all 30 fixup words, live segment = raw + **`0x1866`**. The delta is uniform.
   Raw `0AF8`→`235E`, `0709`→`1F6F`, `03F1`→`1C57`, `0899`→`20FF`.
5. **Targets.** Real-mode linear = `seg_live*16 + off`. The 32 bytes there are matched exactly in
   GAME.OVR and START.EXE. A target is `unique-<file>` only if the window occurs exactly once across
   both pinned files.
6. **Displacement** (consistency only). For each unique hit, `file_offset − segment_offset`. Within one
   live segment the displacements are reported and should agree if the hits are one contiguous block.

**Limit of exact matching.** A 32-byte window is "unique" as bytes, not as the call's intended target.
If the window is a sub-run of pinned bytes, it can match at a shifted offset. A wrong operand can then
still report `unique-`. The synthetic test for a wrong segment operand hit exactly this when its filler
repeated the window's bytes; the fixture now uses pseudo-random filler. On retail, the displacement check
is the guard: a shifted false match would break the uniform displacement within `235E` and `1F6F`, and
it does not (14 of 14 and 4 of 4 agree).

## Result on the retail dump

| Live segment | Sites | Result | START.EXE displacement |
| --- | ---: | --- | --- |
| `235E` (raw `0AF8`) | 14 | all unique in START.EXE | `0xAC76` (uniform) |
| `1F6F` (raw `0709`) | 13 | `1F6F:01DF` (4 sites) unique in START.EXE, at `0x72A8`; the other 9 absent | `0x70C9` (uniform, 4 sites) |
| `1C57` (raw `03F1`) | 1 | absent from both pinned files | n/a |
| `20FF` (raw `0899`) | 2 | absent from both pinned files | n/a |

The 12 absent sites are 6 distinct targets: `1F6F:0626` (7 sites), `1F6F:09E3`, `1F6F:0D68`,
`1C57:02E8`, `20FF:0000`, `20FF:0104`.

The 14 `235E` sites call: `11C0` (START `0xBE36`), `0B0B` ×10 (`0xB781`), `0B25` (`0xB79B`),
`0B98` (`0xB80E`), `0C10` (`0xB886`). Those five START offsets are the targets the brief named.

**The `0xAC76` block.** Every `235E` target is START.EXE file offset `segment_offset + 0xAC76`. The
two other raw-`0AF8` offsets named in the brief (`0254`→`0xAECA`, `16A8`→`0xC31E`) are not far-call
sites of this group. Checked directly, their dump windows at `235E:0254` and `235E:16A8` are
byte-identical to START at those offsets, each unique. So the segment is a shifted copy of a START.EXE
block. It is a consistency result, not a claim about who copied it.

**The 12 absent targets are not an error in the match.** Their live windows start with Borland
prologues (`55 89 E5`), so they are real routine code, and each contains a `9A` whose segment word was
patched by the loader. Exact matching against the raw pinned files therefore fails. A separate
diagnostic (not in the tool, not a result) masked the 16-bit segment word after each `9A` and found
exactly one START.EXE hit for each of the 6 distinct targets (`0x423A`, `0x76EF`, `0x7AAC`, `0x7E31`,
`0x89C7`, `0x8AB3`), with zero GAME.OVR hits. That suggests these routines are START.EXE code under a
different displacement. It rests on the masking assumption, so it is a lead for a follow-up, not a
mapping.

## What the START targets do (static bytes only)

All read from the pinned START.EXE, file offset = image offset `+ 0x200`, labelled here as
`235E:xxxx` using the `0xAC76` block. Disassembled with capstone in 16-bit mode, then read by hand.

**`0xBE36` (235E:11C0) — random in range `0..n-1`.** It calls the generator at `0xBE85` first, always,
even for `n = 0`. It then returns `hi16(x') mod n` in AX, or `0` when `n = 0`. `retf 2` pops the one-word
argument. The only caller in the group pushes `n = 13` at GAME.OVR `0xAB9`, so the value is `0..12`,
and it is stored at `[bp-42]` (`0xAC2`). The wheel routine uses that byte as a record index.

**`0xBE85` (235E:120F) — the generator.** It is a 32-bit linear congruential step on the state in
DS:`4428` (low word) and DS:`442A` (high word): `x' = x·0x08088405 + 1 (mod 2^32)`, returned in DX:AX.
I checked this by emulating the 16-bit instruction sequence (`mul` by `0x8405`, shifts and adds for the
high part, `add ax,1 / adc dx,0`) against the closed form on 200,000 random states: 0 mismatches.

**`0xBEBD` (235E:1247) — a seeder, present in START.EXE.** `mov ah,2Ch; int 21h` (DOS system time), then
`mov [4428],cx; mov [442A],dx; retf`. So a seed is set from the clock if this routine runs. No far call
among the group's 30 reaches it, and whether any other code calls it is **not established**.

**`0xB781` (235E:0B0B) — Pascal string copy.** Source far pointer at `[sp+4]`, destination at `[sp+8]`.
It copies a length-prefixed string (the length byte, then `length` bytes). Its `retf 4` pops 4 bytes,
but it reads 8 bytes of arguments (see the stack note).

**`0xB79B` (235E:0B25) — bounded Pascal string copy.** Maximum length word at `[sp+4]`, destination
far pointer at `[sp+6]`, source far pointer at `[sp+10]`. It writes `min(srclen, max)` as the length
byte and copies that many bytes. `retf 0Ah` matches its 10 bytes of arguments. The cap compares only the
low byte of the maximum (`cmp al,cl`), so a maximum above 255 is truncated.

**`0xB80E` (235E:0B98) — Pascal string append, capped at 255.** Destination far pointer at `[sp+8]`,
source at `[sp+4]`. It adds the source length to the destination length byte; on carry it sets the length
to `0xFF`, then copies `min(srclen, 255 − oldlen)` bytes. `retf 4`, the same stack mismatch as `0xB781`.

**`0xB886` (235E:0C10) — Pascal string equality, result in flags.** Destination pointer at `[sp+4]`,
source at `[sp+8]`. It compares the two strings and returns **only in the flags**: ZF = 1 iff the lengths
are equal and the bytes are equal. `retf 8` matches its arguments. Whether the caller tests ZF, and which
strings it compares, is **not established** here.

**Stack note (observed, not resolved).** The call at GAME.OVR `0xAE1` (target `0AF8:0B0B`) pushes six
words and two far pointers, 20 bytes, with no cleanup after the call. `0xB781` pops 4. The routine's own
epilogue might restore SP, which I did not check. Whether this is an original-code stack effect or a
misread convention is open.

**Caller context.** The `0xB781` call's source is `CS:0000` (`push cs; push di` with DI = 0). Its linear
address depends on the caller's CS, which is not established.

## What is proven, and what is not

**Proven, by the dump and the pinned bytes (memory presence only):**

- The group `fileofs 0x9AC` is in RAM at linear `0x49150`. Its 802 stable bytes match GAME.OVR exactly,
  and the 30 fixup words are relocated by one uniform delta, `+0x1866`.
- Every far-call operand of the group is in the fixup table, and 14 of the 30 call into `235E`.
- The bytes at 14 `235E` call targets, and at `1F6F:01DF` (4 sites), are exact unique copies of
  START.EXE bytes at the offsets above, with the displacements shown.
- The 12 remaining targets' bytes are present in RAM but do not match a pinned file exactly.
- The static semantics of the five START routines above, and of the generator and the seeder.

**Not proven:**

- That any of these routines **ran** or was **called** at the dump moment (the dump is caller-declared
  non-atomic, and presence is not execution).
- The RNG seed value, and whether the seeder at `0xBEBD` ever ran.
- The value of the random index `[bp-42]`, or the record table it indexes.
- The answer table, the input comparison (`0xB886` is not shown to be called from the prompt path), and
  the prompt state. The screen's "INPUT THE CODE WORD" state is not read from this dump.
- What the 12 absent targets do, and which pinned file (if any) they come from.
- The stack convention for `0xB781`, `0xB80E` and the caller's SP.

## Tests

`tests/test_por_overlay_group_map.py` has 29 synthetic tests and one retail test. The synthetic
fixtures generate their own GAME.OVR, START.EXE and dump, inject the pins, and filler is pseudo-random so
no shifted window matches by accident. They cover: the positive path; masked fixup words (patched and
unpatched dumps both map); caller metadata; runtime-claim separation; group absent (one stable byte
changed; no group at all; group past the dump end); group ambiguous (two copies); a wrong offset operand
(the group stops matching); a wrong segment operand (the window goes absent, a diagnostic); a non-far
fixup; an unsorted or out-of-range fixup table; nonunique code targets; a target absent from both
files; a target outside the dump (bounds); unpinned START and GAME.OVR; a missing or wrong descriptor;
a group past the end of GAME.OVR; dump name and base mismatches; the output-folder rule; and malformed
`--meta`. The retail test runs only when `OPENUA_POR_INSTALL` is set and the local dump exists. It
checks the counts (30 sites, 18 unique, 12 absent), the displacements, and the five START offsets.

```sh
python -m pytest tests/test_por_overlay_group_map.py -q
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_overlay_group_map.py -q
```

## Reproduce the disassembly

The START targets were disassembled with capstone 5.0.7 (16-bit x86). The scratch scripts live under
`data/work/por-overlay-group-map/scratch/` (git-ignored, not committed). They are not part of the tool:
`disasm_start.py` lists the five START offsets, `rng_check.py` emulates the generator, `absent_check.py`
is the masked-operand diagnostic above, and `site_completeness.py` checks the 30-site claim.
