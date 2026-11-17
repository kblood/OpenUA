# Pool of Radiance: resolving the owner closure's far targets through overlay evidence

**Status: STATIC-PROBE-ONLY. `playable: false`.** Answer: **conditional on a sibling-consensus delta; the owner's own delta is not measured.** The probe resolves all three raw far targets under the consensus delta `0x1866`. The owner group is absent from both RAM dumps, so that delta is not measured for the owner. For the `0x0428:0x002A` target, a byte-level stub-run check singles out `0x1866` among the sweep alternatives. The two `0x0464` targets are not singled out by bytes. Nothing here establishes reachability, execution, the owner's caller, or WALLDEF ownership.

Companion to [por-wall-callee-probe.md](por-wall-callee-probe.md) (which found the eight far calls and three raw `seg:off` pairs), [por-overlay-group-map.md](por-overlay-group-map.md) (the group mapper this reuses), [por-farcall-resolution.md](por-farcall-resolution.md) (the stub-run model and the zero-skew image assumption), and [por-ecl-fixup-probe.md](por-ecl-fixup-probe.md) (the loader's delta is not established there).

`tools/por_wall_far_target_probe.py` reads the pinned retail `GAME.OVR` and `START.EXE` and the two RAM dumps read-only. It writes only under `data/work/por-wall-far-target-probe/`. `tests/test_por_wall_far_target_probe.py` checks the logic on synthetic blobs (default) and on retail (gated on `OPENUA_POR_INSTALL`).

---

## Pinned and measured inputs

| Input | Size | SHA-256 (prefix) | Note |
| --- | ---: | --- | --- |
| `GAME.OVR` | 206,105 | `872964a3…7928614` | pinned, matched |
| `START.EXE` | 65,231 | `d825df2b…60b6a07bd` | pinned, matched |
| `data/work/por-live-memory-pid34644/ram-000000-100000.bin` | 1,048,576 | `f8191750…27dea4895` | RAM dump, base 0 |
| `data/work/por-wheel-live-capture/ram-000000-100000.bin` | 1,048,576 | `3788787c…0516fa` | RAM dump, base 0 |

The two dumps differ byte-for-byte, but every uniquely mapped group gives the same segment deltas in both. They count as two captures, not as one repeated.

## Usage

```sh
python tools/por_wall_far_target_probe.py --install "PATH/TO/POOLRAD" \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-wall-far-target-probe/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_wall_far_target_probe.py -q
```

Output: `data/work/por-wall-far-target-probe/retail/por_wall_far_target_probe.json` (schema `openua.por-wall-far-target-probe` v1, sorted keys, no timestamps, no paths; two runs are byte-identical). Exit `0` only if the owner delta is measured and every target resolves uniquely. Exit `1` (the retail result) writes the diagnostic. Exit `2` is a named refusal (unpinned input, missing dump, owner not in exactly one group, unsafe output folder).

---

## What the bytes establish

1. **The owner group.** The one `CD 3F 00 00` header whose span holds `0x2EEF4` is at START `0x3DD7`: `fileofs 0x2E8F7`, `codesz 0x120B`, `fixupsz 0x50` (40 fixup words), `jmpcnt 8`. Ten other `CD 3F 00 00` headers fail the descriptor bounds check (for example an odd `fixupsz`), and they are reported, not used.
2. **All eight far-call segment words are fixup-listed.** The callee probe's eight unfollowed sites (`0x2EA03`, `0x2EA3D`, `0x2EA8F`, `0x2EAB5`, `0x2EADB`, `0x2EB01`, `0x2EBF2`, `0x2EEED`) each have their `seg` word (site+3) in the owner's fixup table. So the loader rewrites them; the raw values are link-time.
3. **The owner is absent from both dumps.** Its stable-byte mapping has zero anchor hits (`absent`). Its own live segment words are therefore not measured. No owner delta is measured.
4. **Sibling consensus.** 17 other uniquely mapped groups in each dump (of 45 descriptors, 10 refused, 17 mapped, the owner absent) all give one delta across every fixup word: `0x1866` (live = raw + `0x1866`). This is a model applied to the owner, not a measurement of it.
5. **Resolution under `0x1866`.** The three raw targets, with the owner group not resident:

| Raw target (file sites) | Live linear | Live bytes (first 8) | Result under `0x1866` | Evidence type |
| --- | --- | --- | --- | --- |
| `0428:002A` (3 sites) | `0x1C90A` | `ea 5d 01 7d 32 00 08 47` | **VROOMM stub, patched**: far JMP `327D:015D` over START `0x42E3` (`cd 3f 5d 01 00`) | stub identity by byte match |
| `0464:2632` (4 sites) | `0x1F2D2` | `55 89 e5 83 ec 24 c4 7e` | **masked**: START `0x6CAB`, one 9A-operand word `0AF8` vs live `235E` (differs by exactly `0x1866`) | masked byte match, one word |
| `0464:1B52` (1 site) | `0x1E7F2` | `55 89 e5 83 ec 0a a0 1e` | **exact**: START `0x61CB`, 32 bytes, unique | exact byte match |

- **`0428:002A` → group `0x42C2` stub #2, GAME.OVR `0x32392`.** The JMP's segment `0x327D` is the resident base of group `0x42C2` (mapped uniquely, 17 groups). The JMP's offset `0x015D` is body offset `0x15D` (`0x32235 + 0x15D`), which begins `55 89 e5`. START `0x42E3` is the stub's file position (`cd 3f 5d 01 00`, header `0x42C2` + `0x17` + 2×5, the stub-run slot the farcall-resolution model gives). A `CD 3F` stub is patched by the overlay manager to `EA off16 seg16`, and that is what is in RAM.
- **`0464:1B52` → START `0x61CB`** (exact, prologue `55 89 e5`). **`0464:2632` → START `0x6CAB`** (masked, prologue `55 89 e5`). The two START positions give the same linear-to-file offset (`file = linear − 0x18627`), but that base is not the zero-skew image base (`0x200`). Its cause is not established.

## Discriminators: what the bytes single out, and what they do not

- **Sweep, all deltas `0x0000..0xFFFF` (sensitivity, per target).** A delta gives a JMP-patched stub to a mapped group, or an exact-unique START/GAME.OVR window, at many values:
  - `0428:002A`: 18 JMP alternatives, 5,549 exact-unique windows.
  - `0464:2632` and `0464:1B52`: 12 JMP alternatives each, about 5,550 exact-unique windows each.
  Exact-window matches are not discriminating at all, because START's loaded image covers much of the dump.
- **Stub-run discriminator (`0428:002A` only).** Of the 18 JMP alternatives for `0428:002A`, **only `0x1866` also has a START stub at a valid stub-run slot** (`header + 0x16 or 0x17`, stride 5, within `jmpcnt`, proc_off matching the JMP). The other 17 have no stub in START's file with that tail. This singles out `0x1866` for this target, under the stub-run layout the resolver documents (a model, recorded as such).
- **The `0x0464` targets are not discriminated.** They are code, not stubs, so the stub-run test does not apply, and the exact sweep gives thousands of alternatives. Their resolution rests on the consensus delta alone.

## Zero-skew comparison (a disagreement, not a conclusion)

[por-farcall-resolution.md](por-farcall-resolution.md) resolves a far call to `hdr + seg*16 + off` with `hdr = 0x200` (zero skew). Applied to the owner's raw targets, zero skew gives START `0x44AA` (`00 09 07`), `0x6E72` (`f2 89 46`), and `0x6392` (`8b 46 fc`). None of the three is a Borland prologue or a stub. Under the consensus model, the two code targets are prologues and the stub is a stub. So the bytes favour the consensus model here, but the resolver's zero-skew assumption was made for a different (small-segment) far-call set, and this probe does not settle which model the loader uses in general.

## Bounded closures, conditional on the consensus

Each closure is decoded with the callee probe's routine from the resolved file offset. These are **conditional on `0x1866`** and are not evidence of reachability.

| Target | Decoded from | Procs | Instructions | Far calls not followed | INT 21h file hits | String tokens | Selector candidates |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `0428:002A` (stub) | GAME.OVR `0x32392` | 1 | 127 | 8 | 0 | 0 | 8 |
| `0464:1B52` | START `0x61CB` | 1 | 305 | 6 | 0 | 0 | 26 |
| `0464:2632` | START `0x6CAB` | 2 | 429 | 6 | 0 | 0 | 34 |

No closure reaches an INT 21h file function, a literal `WALLDEF`/`8X8D`/`DAX` token, or a record-selection table in the bytes decoded. Each has far calls that were not followed, so each is bounded-incomplete. Selector candidates are presence only.

### Conditional far-call follow-up (bounded, still not a runtime trace)

The retail report now adds `far_call_followups_conditional`, following the far-call sites in those
conditional closures for at most three far-call hops. A non-module target is accepted only when its
live 32-byte window from **both** dumps matches one unique pinned-file window (exact, or one
delta-consistent 9A-segment mask). A `0AF8` target uses the independently documented `0xAC76`
module base and must also match its START window in both dumps. These remain mappings under the
sibling consensus `0x1866`; the owner is still absent, so none establishes the owner's delta or
execution. The decoder starts at the mapped offset; byte identity alone does not prove that a target
was entered as an instruction boundary.

For the conditional `0428:002A` body at GAME.OVR `0x32392`, the follow-up maps three `0464` targets
to unique START windows: `0464:00FF` → `0x4778`, `0464:08D4` → `0x4F4D`, and `0464:1951` →
`0x5FCA`. Its two `0899` targets map to candidate windows at `0x8A08` and `0x89C7`. The bounded
decoded walks at these mapped offsets report no DOS file-function INT and no WALLDEF/8X8D/DAX
token candidate. One `0A32:000B` child maps to START `0xA024`; one `08AE:00DC` child maps to
`0x8BD3`, whose `0A32:00A2` child maps to `0xA0BB`. These are exact byte-window relationships
under the consensus model, not named loader or renderer routines.

The three conditional `0464` code windows and the `0428` group body call module helpers that match
the pinned dumps: `0AF8:0A3F` → START `0xB6B5`, `0AF8:0919` → `0xB58F`, `0AF8:084A` → `0xB4C0`,
`0AF8:1685` → `0xC2FB`, and `0AF8:16A8` → `0xC31E`. Their bounded walks also contain no DOS
file-function INT or string-token candidate. Opcode inspection identifies `0A3F` as a forward
copy, `1685` as an overlap-safe copy, and `16A8` as a byte fill. Those helper identities say
nothing about what WALLDEF record, if any, the caller selected.

One further call, `0AF8:00E9`, has the candidate START offset `0xAD5F` under the module-base rule,
but its 32-byte window does not match both dumps. The report leaves it `module-base-not-cross-checked`.
The follow-up therefore narrows several far edges to memory and output helpers but still leaves the
owner delta, code reachability, remaining far-call descendants, WALLDEF table identity, and slot-to-art
selection unresolved. Its retail output is under ignored `data/work/por-wall-far-target-probe-followup/`.

## Model assumptions (recorded, not proved)

1. **One delta for the owner.** The owner's delta is assumed equal to the 17 siblings' common `0x1866`. The sibling groups agree across both dumps, but the owner is not measured.
2. **Stub-run layout.** The stub-run check assumes the header+`0x16`/`0x17`, stride-5 run documented in [por-farcall-resolution.md](por-farcall-resolution.md).
3. **Linear address of the stub.** `EA off16 seg16` at the live address is taken as the patched stub; this assumes the overlay manager writes the JMP in place.
4. **Masked match.** A single 16-bit word after a `9A` is allowed to differ by exactly the delta; it is not a fixup of a known group (START has no fixup table).

## Limits and unresolved edges

| Edge or question | Status |
| --- | --- |
| Owner group `0x3DD7` own delta | **not measured**: absent in both dumps |
| Which delta is the true one for the `0x0464` targets | **not established**: exact-window sweep is ambiguous (about 5,550 alternatives) |
| Zero-skew versus consensus model | disagreement recorded; the bytes favour the consensus for these three targets, the loader model is not established |
| Implied START base `0x18627` for the `0x0464` targets | consistent across two exact/masked windows; cause not established |
| Caller of the owner `0x2EEF4` | not established |
| Reachability or execution of any target | not established |
| WALLDEF / 8X8D / DAX binding, record-selection table | not established; no literal token in any closure |

## The concrete discriminating observation

A RAM dump taken while the owner group `0x3DD7` (file `0x2E8F7`) is resident would measure the owner's own delta directly. In that dump the owner maps uniquely; each of its eight far-call words (owner group offsets `0x10F`, `0x149`, `0x19B`, `0x1C1`, `0x1E7`, `0x20D`, `0x2FE`, `0x5F9`) gives `live − raw`. If the owner's delta is `0x1866`, the live word at owner offset `0x10F` (site `0x2EA03`, raw `0x0428`) reads `0x1C8E` (`0x0428 + 0x1866`). A different value overturns the consensus for the owner and every target that depends on it.

## Tests

`tests/test_por_wall_far_target_probe.py`: 11 synthetic tests and 1 retail test (gated). The synthetic tests cover: owner refusal; far-site fixup listing, with a mutation that drops the listing; consensus uniform, then broken by a one-off sibling word; owner absent and owner ambiguous (not measured); a JMP stub resolving to a group body, with a mutation that restores `INT 3Fh`; the stub-run discriminator, with a mutation that changes the stub's proc_off; a delta-consistent masked match, with a mutation that changes the delta by one; an exact window in two files (ambiguous); out-of-dump; closure at a resolved body; refusal of unpinned input and of an empty dump list; and a full synthetic run. The retail test asserts the facts above (owner `0x3DD7`, eight fixup-listed sites, consensus `0x1866`, owner unmeasured, the stub-run singling-out, the exact `0x61CB`, and the masked `0x6CAB`).

Results (2026-11-17): `python -m pytest tests/test_por_wall_far_target_probe.py -q` → `11 passed, 1 skipped` (retail skipped, no env). With `OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD"` → `12 passed in 52.28s`. Retail tool run → exit `1`, `status=diagnostic`, `answer=conditional-on-sibling-consensus-delta; owner-delta-unmeasured; no-unique-delta-for-all-targets`, JSON 41,100 bytes, deterministic across two runs.
