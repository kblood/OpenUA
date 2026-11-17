# Pool of Radiance: the far copy helper 0x0AF8:0x1685 (observe-only)

**Status: observe-only. `playable: false`. `executed: not_established`. `fill_established: false`.**

Tool: `tools/por_geo_copy_helper_probe.py`. Tests: `tests/test_por_geo_copy_helper_probe.py` (23 tests:
20 synthetic with falsifiers, 3 retail-gated; all 23 pass on this run, the retail ones against the pinned
`data/work/por-geo-run/POOLRAD` and both pinned dumps). Read-only on the install and dumps. It writes only
under `data/work/por-geo-copy-helper-probe/`. It refuses unpinned `GAME.OVR` or `START.EXE` (no override).

Follows [por-geo-buffer-fill-probe.md](por-geo-buffer-fill-probe.md), which left open two things about the
four fill copies to `0x0AF8:0x1685`: which bytes that helper is, and which pushed pointer it reads as the
source. This note answers both from evidence, and says what that does not settle.

## Question and answer

> Do the pinned dumps and the pinned files identify the far helper `0x0AF8:0x1685`, and what ABI do its
> bytes show?

**Answer: the helper's bytes are identified, and its ABI is decoded from them, with dump corroboration.**
The target bytes at the helper's live address match one START.EXE file offset (`0xC2FB`, 35 bytes, unique in
the file) in both pinned dumps. Those bytes are a far-pointer `rep movsb` copy that reads its **source from
the first far pointer pushed** and its destination from the second, and returns with `retf 0x0A`. That
matches the fill's five pushed words. Nothing here shows the helper runs, that the fill runs, or what the
loader `0x0802:0x0716` returns.

## Evidence labels

- **File-byte (established by the bytes).** The copy body at `0xC2FB`, its exact opcode sequence, and the
  uniqueness of that sequence in START.EXE. The routine-B handler pattern `b8 d0 00 83 c4 06 eb 03`, which
  occurs once, at `0xAD4D`.
- **Memory-dump, unknown instant (memory-present, not executed).** The copy body at the live address
  `235E:1685` in each pinned dump. The copy's link word. The resident call instructions. The group map.
- **Quoted (not re-observed here).** The module handler IP `0x00D7` for routine B, from
  [por-int3f-runtime-capture.md](por-int3f-runtime-capture.md) (a PoR capture, not a GoldBox fact). The
  DOSBox load segment `0x0824` from the same note. The probe tests the `0x0824` candidate in the pinned
  dumps; it does not rely on it.
- **Derived.** The module load segment `0x1866` and the module base `0xAC76`, each computed from the bytes
  above. The derivations are shown below.

## Chain from the raw call to the target bytes

| Link | How it is checked | Result |
| --- | --- | --- |
| The four fill copy calls are `9A 85 16 F8 0A`, seg word at `+3` | File bytes, GAME.OVR `0x2FA70..0x2FAD6` | Established. The seg word is listed in the owner group's fixup table (31 of 31 static call sites) |
| The loader adds one load segment to the raw seg word | Resident call bytes: `9A 85 16 <seg>` in each dump | `<seg>` is `0x235E` in all 45 copy-call sites and all 42 allocator sites, in both dumps. `0x235E = 0x0AF8 + 0x1866` |
| The load segment is `0x1866` | The START copy's link word at `copy_seg:0004` | Memory-checked in both dumps: the copy's link word `2925:0004` is `0x1866`. The copy's own segment `0x2925` would give `0x19B3` instead, which is not the load segment the module uses (see the grid) |
| The module base in the file is `0xAC76` | Routine-B handler at `0xAD4D` minus quoted IP `0xD7`; unique in the file | Derived. Its anchor (16 bytes at `module+0xD0`) occurs once in each dump, at `235E:00D0` |
| The target `235E:1685` holds the file's `0xC2FB` bytes | Dump bytes at `0x24C65` equal the file's 35 bytes at `0xC2FB` | **Memory-agrees in both dumps.** Unique file placement of the full 35 bytes. The module base is therefore checked at `0x1685`, not only at its anchor |
| The overlay groups' seg words follow the same rule | Uniquely-mapped resident groups that hold copy calls (`map_group`) | 16 of 34 groups map uniquely in each dump. The copy-call sites lie in 11 groups; 4 of those map uniquely, holding 7 call sites, all fixup-listed, with live seg `0x235E` |

The fill group itself (`0x2E8F7`) is **absent** from both dumps. So the fill's own code is not in memory,
and the probe claims nothing about whether the fill runs.

## Translations considered (the fail-closed grid)

Each row is one load-segment source crossed with one file mapping, checked against each pinned dump.

| Load source | File mapping | File `0xC2FB` / `0xC805` | Dump `0x24C65` / `0x26135` / `0x14845` | State |
| --- | --- | --- | --- | --- |
| module anchor in dump, `0x1866` | contiguous MZ (`hdr + seg*16 + off`) | `0xC805` is `FIRE GIANT` (text) | `0x24C65` | **rejected: file data** |
| module anchor in dump, `0x1866` | routine-B module base `0xAC76` | `0xC2FB` is the copy body | `0x24C65` agrees | **identified** (both dumps) |
| copy-entry segment, `0x19B3` | contiguous MZ | text | `0x26135` is zeros and `Scimitar` | rejected: file data, memory disagrees |
| copy-entry segment, `0x19B3` | routine-B module base | copy body | `0x26135` disagrees | rejected: memory disagrees (the relocated copy's own segment is not the load base) |
| quoted DOSBox `0x0824` | contiguous MZ | text | `0x14845` | rejected: file data |
| quoted DOSBox `0x0824` | routine-B module base | copy body | `0x14845` disagrees | rejected: memory disagrees |

Exactly one file offset survives every gate: `0xC2FB`. Two rows that a naive reading would favour fail: the
contiguous MZ map lands on text, and the copy's own segment lands on bytes that are not code. The probe does
not choose between candidates by preference. It reports a distinct second surviving offset as `ambiguous`.

The module-base mapping is **not** contiguous with the file in general. The START windows in each dump fall
into several linear bases (the file-to-memory delta is per segment), so the module base is evidence for this
module only. The existing [por-overlay-group-map.md](por-overlay-group-map.md) output (wheel dump) agrees
with it independently: 14 far-call targets in segment `235E` have a uniform displacement of `0xAC76`
(offsets `0x0B0B` to `0x11C0`). That output is git-ignored; this probe does not depend on it.

## ABI at `0xC2FB` (exact opcode sequence)

```text
8B DC              mov bx,sp
8C DA              mov dx,ds
36 C5 77 0A        lds si,[ss:bx+0x0a]     ; src far pointer: off at +10, seg at +12
36 C4 7F 06        les di,[ss:bx+0x06]     ; dst far pointer: off at +6,  seg at +8
36 8B 4F 04        mov cx,[ss:bx+0x04]     ; count at +4
FC                 cld
3B F7              cmp si,di
73 07              jnb +7                  ; SI >= DI (offsets): forward path
03 F1 03 F9        add si,cx ; add di,cx
4E 4F FD           dec si ; dec di ; std   ; backward path
F3 A4              rep movsb
8E DA              mov ds,dx
CA 0A 00           retf 0x0a               ; callee pops 10 bytes = five pushed words
```

- **Entry layout** (after the far return address at `+0` and `+2`): count `+4`, dst off `+6` / seg `+8`,
  src off `+10` / seg `+12`.
- **Caller** (`GAME.OVR` fill, read by the buffer-fill probe): pushes `src.seg, src.off, dst.seg, dst.off,
  count`, which is the callee's read order `+12, +10, +8, +6, +4`. The four copies are
  `BLK+0x002`, `BLK+0x102`, `BLK+0x202`, `BLK+0x302` to `BUF+0x000`, `+0x100`, `+0x200`, `+0x300`, 256 bytes
  each.
- **Copy semantics.** `dst[i] = src[i]` for `i < count`. The forward/backward choice compares offsets only;
  for regions that do not overlap, either direction gives the same bytes.
- **Byte facts, not claims about PoR.** The backward path sets DF and nothing clears it before `retf`. The
  forward path leaves DF clear.

So, **conditional on this identity**, the fill probe's open question "which pointer is the source" is
answered: the first pushed far pointer, `BLK + 2 + 256k` (the loader's block), is copied to `BUF + 256k`.

## What the evidence does not establish

- That the helper runs, or that the fill (`GAME.OVR 0x2F9BE`) or any caller runs, at any instant. The
  dumps show code as memory-present only, and the fill's own group is absent from both dumps.
- That the live segment `235E` is the value the loader rewrote at any instant after the dump. The dump
  and the rewrite both show `0x235E`, but the probe does not prove the rewrite happened for the fill's call.
- That the module is the file's module at every offset. Only the anchor window, the target body, and the
  linked segment words are compared. Six bytes in `0..0x1684` differ: three segment-literal words at `0x1`, `0xEE` and `0x7EF`, each the file word plus `0x1866`;
  the module has 1,774 differing bytes in `0..0x1FFF`, mostly beyond `0x1878`, which were not classified.
- What the loader `0x0802:0x0716` returns, the id byte, the TOC block, and whether `[bp-6]` is a GEO block.
- That the copied bytes are GEO plane 2, or any PoR meaning of the copy.
- Copy semantics across two segments, where the offset comparison picks the direction.

## Commands and results

```sh
python tools/por_geo_copy_helper_probe.py
python -m pytest tests/test_por_geo_copy_helper_probe.py -q
python -m pytest tests/test_por_geo_buffer_fill_probe.py -q
```

- Probe: `wrote data/work/por-geo-copy-helper-probe (identity=identified-by-bytes-in-pinned-dumps,
  abi matched=True)`, exit 0.
- `tests/test_por_geo_copy_helper_probe.py`: **23 passed** (no skips; the 3 retail tests ran).
- `tests/test_por_geo_buffer_fill_probe.py`: **18 passed** (unchanged; run to confirm the reused reader).

Pins (checked before and after; both matched exactly):

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a3…7928614` |
| `START.EXE` | 65,231 | `d825df2b…60b6a07bd` |

Dumps (both `ram-000000-100000.bin`, base 0; labelled by folder in the output):

| Dump | SHA-256 (prefix) |
| --- | --- |
| `data/work/por-live-memory-pid34644` | `f8191750ea6c672e` |
| `data/work/por-wheel-live-capture` | `3788787cd795f1f5` |

## Files and side effects

- New, tracked: `tools/por_geo_copy_helper_probe.py`, `tests/test_por_geo_copy_helper_probe.py`,
  `docs/por-geo-copy-helper-probe.md`.
- New, ignored output: `data/work/por-geo-copy-helper-probe/por_geo_copy_helper_probe.json` and
  `por_geo_copy_helper_probe_report.md`.
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, and the existing probes it imports
  (`por_farcall_resolve`, `por_overlay_group_map`, `por_geo_callee_identity_probe`, `por_geo_buffer_fill_probe`).
  The buffer-fill probe's `probe()` is called, which writes nothing.
- No edits to existing source or docs. No emulator, GameLink, DOSBox, codewheel, retail-file write, or
  GoldBox access. No CoK rule or address is used for PoR.

## Next discriminating observations

1. A live register or memory capture at `235E:1685`, taken on entry, showing the stack words (count, dst, src)
   and the 256 bytes before and after. A match of `src` to the copied bytes confirms the direction.
2. A live capture of the fill's call at `GAME.OVR 0x2FA70` (the fill group `0x2E8F7` must be resident), to
   confirm the call runs and the group's seg word is `0x235E`.
3. The loader `0x0802:0x0716` (see the buffer-fill doc), to see whether `[bp-6]` is the block the copy reads.
