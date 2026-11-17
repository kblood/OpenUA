# Pool of Radiance: the loader target 0x0802:0x0716 (observe-only)

**Status: target identity is conditional; caller-frame accounting is consistent at six walked sites and unknown at four.**
`playable: false`. `geo_output: not_established`. `plane2_binding: not claimed`.

Tool: `tools/por_geo_loader_target_probe.py`. Tests: `tests/test_por_geo_loader_target_probe.py` (24 tests:
23 synthetic with falsifiers, 1 retail-gated that also pins the positive control; all 24 pass on this run). Read-only:
it reads the pinned `GAME.OVR` and `START.EXE` and the two pinned memory dumps, and writes only under
`data/work/por-geo-loader-target-probe/`. It refuses unpinned `GAME.OVR` or `START.EXE` (no override).

Follows [por-geo-buffer-fill-probe.md](por-geo-buffer-fill-probe.md) and
[por-geo-copy-helper-probe.md](por-geo-copy-helper-probe.md), which left the loader
`0x0802:0x0716` open. Caller-frame accounting is supplemented by
[por-geo-loader-caller-frame-probe.md](por-geo-loader-caller-frame-probe.md). The question remains whether
the loader's returned far pointer (the fill's `[bp-6]`) points at a decompressed GEO block.

## Question and answer

> Which code does the call `0x0802:0x0716` reach, and what do the static caller bytes establish about its stack contract?

**Answer: the target bytes conditionally match START.EXE, but execution and loader role are unproven.**
The live call operand segment is `0x2068` (`0x0802 + 0x1866`) at the two uniquely-mapped GAME.OVR call sites
in both dumps. The live bytes at `2068:0716` place uniquely in START.EXE at file `0x876D`. Its bytes show
`retf 0x12` (18 cleanup bytes), while each call site explicitly pushes 10 bytes.
That difference alone is not a prototype conflict: the supplemental caller-frame probe finds eight leftover
bytes at six sites, including the fill site, and maps `[bp+16]`/`[bp+20]` into caller-frame buffers there.
Four sites remain unwalked. The target identity remains conditional on the dump-derived segment mapping;
the output pointer is not traced to a GEO block. No plane 2 binding is claimed.

## Caller-frame accounting (supplemental evidence)

The body reads `[bp+16]` (`les di,[bp+16]` at `0x8787`) and `[bp+20]` (`les di,[bp+20]` at `0x8774`). The first
probe compared these offsets only with the ten explicit argument bytes and incorrectly treated the caller's
frame as unavailable. The supplemental walk models local allocation, pushes, callee cleanup and branch joins.
At six sites, `retf 0x12` consumes the ten explicit bytes plus eight earlier caller-pushed bytes and lands on
the caller's allocation floor. At `0x2FA17`, the two earlier far pointers address local Pascal buffers for
`GEO` and `.dax`. Four sites remain unknown. This is static accounting only; it does not show these calls ran.

## What the bytes establish

- **Call sites (file bytes).** `9A 16 07 02 08` occurs at eight GAME.OVR sites (`0x279E`, `0x78A6`,
  `0x1EF0D`, `0x1F0A8`, `0x1F190`, `0x2E246`, `0x2F767`, `0x2FA17`) and two START.EXE sites (`0x47E0`,
  `0x7276`). Each is preceded by the same push shape: an id word (`mov al,[bp+X]; push ax`, or `mov al,imm;
  push ax` at `0x7276`), then `lea di,[bp+Y]; push ss; push di`, then the same for the output pointer. That
  is `2 + 4 + 4 = 10` bytes. The shape regex matches 10 of 10. The GAME.OVR owner groups list the seg word
  in their fixup tables (`seg_word_fixup_listed: true` at all eight).
- **Body (file bytes, `0x876D`).** `push bp; mov bp,sp; sub sp,0x23E`. A single return, `retf 0x12` at
  `0x899E`, reached by `jmp 0x899B` (`mov sp,bp; pop bp`). Its 242 decoded instructions contain one `0x0899:0x0000`
  far call (at `0x88A4`) and nine `0x0AF8:*` calls, which are not identified here.
- **Body parameters (file bytes).** `les` loads far pointers from `bp+6`, `bp+10`, `bp+16` and `bp+20`.
  `bp+14` is read by `cmp [bp+14]`. Stores through the pointers: `bp+10` (`es mov [di]`, 1 word, at
  `0x87D8` and `0x88E8`), `bp+6` (`es mov [di]` and `es mov [di+2]`, 2 words, at `0x87E0`/`0x87E3`,
  `0x88F0`/`0x88F3`, `0x8924`/`0x8927`). The decoder text does not show the stored register, so the stored
  values are not traced.
- **Contiguous MZ candidate (rejected).** `0x200 + 0x0802*16 + 0x0716 = 0x8936`. The file bytes there are
  `d2 03 46 d0 ...`, not a prologue, and the live window disagrees with them. Rejected.
- **Routine-B base (not applicable).** `0xAC76 + 0x0716 = 0xB38C` would need the routine-B base for another
  segment. [por-geo-copy-helper-probe.md](por-geo-copy-helper-probe.md) establishes that base for segment
  `0x0AF8` only. Not applied.

## What the dumps establish (memory-present, unknown instant)

- **Load.** Two uniquely-mapped GAME.OVR call sites per dump (groups `0xD46` at `0x279E` and `0x74D3` at
  `0x78A6`) hold live seg `0x2068` in both dumps. `0x2068 - 0x0802 = 0x1866`, the same START load the
  copy-helper probe found (`0x0AF8 + 0x1866 = 0x235E`). The rewritten seg word is consistent across all four
  unique sites.
- **Target bytes.** The 256 bytes at linear `0x20D96` (`2068:0716`) are the same in both dumps. Against
  START they match under one rule: a 16-bit segment literal may differ by the load. There are 12 such
  spans (the `f8 0a` → `5e 23` far-call literals, `0x0AF8` → `0x235E`). Every other byte is equal. The
  placement is unique in START.EXE (file `0x876D` only), in both dumps.
- **Positive control.** The same masked matcher, on the copy helper's live body at `0x235E:1685` (64 bytes),
  places it uniquely at START `0xC2FB` in both dumps, with no literal spans. The matcher reproduces the
  copy-helper identity. This validates the matcher on a known case; it does not validate the loader identity.

## Evidence labels

- **File-byte.** The ten call sites and their push shape; the body's prologue, its single `retf 0x12`, its
  parameter reads and its `es`-prefixed stores; the rejected contiguous candidate.
- **Memory-dump, unknown instant.** The live seg `0x2068` at four call operands (two per dump); the 256 live
  bytes at `2068:0716` placing at START `0x876D`; the positive control at `0xC2FB`.
- **Derived.** The load `0x1866` (from the rewrite); explicit-push comparison (caller-frame conclusions are in
  the supplemental probe).
- **Not established.** Everything in "Not established" below.

## Not established

- That `0x0802:0x0716` runs, or that the fill or any of the ten callers runs, at any instant.
- That the body at START `0x876D` executes as the loader; its identity is conditional on an unknown-instant dump.
- Caller-frame balance at four of the ten static sites; see the supplemental probe.
- What the output far pointer holds at any instant, and whether it is a decoded GEO block. The body writes
  two words through `bp+6` on three paths, but the stored values are not traced, and none is tied to a
  GEO block.
- The status `0x402` meaning beyond the fill's gate, and the meaning of the id byte.
- That the live seg `0x2068` is the one the CPU uses at call time (the dumps are of unknown instant).
- Any PoR meaning of the body's helper calls (`0x0AF8:0x023F`, `0x0B0B`, `0x0B25`, `0x0B98`, `0x14FB`,
  `0x04A9`, `0x1366`, `0x1563`, `0x1593`, `0x0899:0x0000`).
- Plane 2 binding, any consumer of the buffer, and any area or descriptor mapping.

## Next discriminating observations

The probe lists these as `next_discriminating_observations` in its JSON.

1. **A live capture at the fill's loader call** (GAME.OVR `0x2FA17`, or START `0x47E0` and `0x7276`): capture
   the caller frame, SP and CS:IP to test the static stack accounting and the conditional target identity.
2. **A byte capture of linear `0x20D96` taken at the moment of that call**, to exclude a later overwrite of
   the resident image. The two dumps are of unknown instant.
3. **The status word and the output far pointer after the call returns**, to see which return path the
   fill takes (the body writes zero to both on one path) and whether the output is non-NULL.

These need a live run. The probe does not run one.

## Commands and results

```sh
python tools/por_geo_loader_target_probe.py
python -m pytest tests/test_por_geo_loader_target_probe.py -q
```

- Target probe after correction: identity `identified-by-memory-bytes-conditional-on-live-segment`, explicit-push assessment `None` (caller-frame accounting required), exit 0.
- Supplemental caller-frame probe: six of ten sites walked and balanced; four remain unknown; exit 0.
- Tests: `24 passed` (the retail-gated test ran; no skips).

## Pins and inputs

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

| Dump (`ram-000000-100000.bin`, base 0) | SHA-256 (prefix) |
| --- | --- |
| `data/work/por-live-memory-pid34644` | `f8191750ea6c672e` |
| `data/work/por-wheel-live-capture` | `3788787cd795f1f5` |

Install: `data/work/por-geo-run/POOLRAD` (or `OPENUA_POR_INSTALL`). Both pins matched.

## Files and side effects

- New, tracked: `tools/por_geo_loader_target_probe.py`, `tests/test_por_geo_loader_target_probe.py`,
  `docs/por-geo-loader-target-probe.md`.
- New, ignored output: `data/work/por-geo-loader-target-probe/por_geo_loader_target_probe.json` and
  `por_geo_loader_target_probe_report.md`.
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, and the existing helpers it imports
  (`por_farcall_resolve`, `por_overlay_group_map`, `por_geo_callee_identity_probe`, `por_loadpieces_handler`).
- No edits to existing source or docs. No emulator, GameLink, DOSBox, codewheel, retail-file write, or GoldBox
  access. No CoK rule or address is used for PoR.

## Not claimed

- No loader identity, no output-pointer identity, no GEO block, no plane-2 consumer, no transform, no
  descriptor-to-event mapping, no area mapping.
- No segment-base model beyond the load `0x1866` that the rewritten call sites show.
