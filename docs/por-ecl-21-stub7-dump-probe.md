# Pool of Radiance: ECL 0x21 far call `0x1A27` vs. START stub 7, against the RAM dumps

**Status: MEMORY-BYTE-CROSS-CHECK-ONLY. `playable: false`.** `tools/por_ecl_21_stub7_dump_probe.py` is a
read-only probe. It re-checks the far call at `GAME.OVR:0x1A27` (raw `03D5:0043`, the seg word fixup-listed
in the group at descriptor `START:0x3C3`, group fileofs `0xD46`) and the stub it names (START `0x3E11`,
stub 7), against the two pinned RAM dumps.

Question: do the two dumps hold the bytes that the stub-7 identity predicts at the live call target, and
does the dump agree with the file on the stub's proc word and trailer?

**Answer: partly.** In both dumps the live target `1C3B:0043` (linear `0x1C3F3`) starts with the stub's
four bytes `CD 3F C7 10`. The fifth byte differs: `00` in RAM, `27` in START. The 16-byte windows are not
identical, so this is **not** exact full-stub identity. The match is a memory-byte match at an unknown
capture instant. It is not evidence that the call executes or is reached.

---

## Pinned inputs

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both are the tool's existing pins (`tools/por_overlay_group_map.py`), and the probe refuses any other file.

| Dump | Size | SHA-256 | Base |
| --- | ---: | --- | --- |
| `data/work/por-live-memory-pid34644/ram-000000-100000.bin` | 1,048,576 | `f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895` | `0x0` |
| `data/work/por-wheel-live-capture/ram-000000-100000.bin` | 1,048,576 | `3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa` | `0x0` |

The dump hashes are recorded and labelled against a known list (`KNOWN_DUMPS`). A dump outside that list is
still analysed, but it is marked `known_dump: null`. The probe does not refuse on it.

## Usage

```sh
python tools/por_ecl_21_stub7_dump_probe.py --install "PATH/TO/POOLRAD" \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin
```

Without `--dump`, the two known dumps above are used. Output: `data/work/por-ecl-21-stub7-dump-probe/
por_ecl_21_stub7_dump_probe.json` (schema `openua.por-ecl-21-stub7-dump-probe` v1). It is git-ignored.
Exit `0` every check holds, `1` a check fails (diagnostic), `2` a named refusal (unpinned or missing input,
unreadable structure, dump name without a base or with a size mismatch, output outside `data/work/` or
inside the install).

---

## Result

### 1. File side (pinned `GAME.OVR` and `START.EXE`): all 12 checks hold

| Check | Value |
| --- | --- |
| Group header `START:0x3C3` fileofs | `0xD46` |
| Far call `GAME.OVR:0x1A27` opcode | `9A` |
| Offset word / raw seg word | `0x0043` / `0x03D5` |
| Seg word (group body `0xCE4`) fixup-listed | yes (group fixup count 402) |
| Stub 7 at `START:0x3E11` bytes | `CD 3F C7 10 27` |
| Stub 7 proc word | `0x10C7` |
| Stub run start (header `0x3DD7` + `0x17`) | `0x3DEE`; slot `(0x3E11-0x3DEE)/5 = 7` |
| Owner header `0x3DD7` fileofs | `0x2E8F7` (codesz `0x120B`) |
| Proc `0x10C7` inside owner codesz | yes |
| Proc file offset `GAME.OVR:0x2F9BE` prologue | `55 89 E5` |
| Control stub 4 at `START:0x3E02` slot in run | yes |

The fill's proc `0x10C7` under owner `0x2E8F7` gives file `0x2F9BE`, which is the GEO fill entry in the
existing docs. The probe only checks that the bytes are there. It does not decode what the routine does.

### Candidate call-frame shape

The file bytes at `0x1A23..0x1A2B` are `8A 46 FD 50 9A 43 00 D5 03`: load AL from
`[bp-3]`, push AX, then call `03D5:0043`. At the candidate procedure `0x2F9BE`, the code reads
AL from `[bp+6]` at `0x2FA09` and returns with `retf 2` at `0x2FAFA`. The one pushed word
therefore matches the candidate procedure's byte argument and cleanup shape.

This is a **conditional stack-shape match**, not target identity or execution evidence. The dump
still matches only the first four bytes of stub 7, its trailer differs, and the capture does not
show that `0x1A27` ran. The value in `[bp-3]` is not recovered here.

### 2. Dump side: identical result in both dumps

| Item | Both dumps |
| --- | --- |
| Group `0xD46` (stable bytes, fixups excluded) | **unique**, base `0x45C40`, 0 rejected candidates |
| Live far call at `0x45C40 + 0xCE1` (linear `0x46921`) | `9A`, offset `0x0043`, seg `0x1C3B` |
| Live target `1C3B:0043` | linear **`0x1C3F3`** |
| Live seg minus raw seg | `0x1866` (an observation, not a model) |
| Target 16 bytes (dump) | `cd 3f c7 10 00 00 00 00 00 00 00 00 00 55 89 e5` |
| Stub 7 16 bytes (START `0x3E11`) | `cd 3f c7 10 27 00 b2 00 09 00 b0 55 89 e5 5d cb` |
| First four bytes match | **yes** |
| Trailer byte (5th) | `00` in RAM, `27` in START |
| Leading equal bytes vs the file's 16 | 4 |
| Exact 16-byte identity | **no** |
| Window in pinned files (16-byte presence check) | absent in both `GAME.OVR` and `START.EXE` |
| `0x55 89 E5` (prologue) positions in window | dump `+0xD`; file `+0xB`. Not a shift |
| Positive control: START `0x3E02` (stub 4) at `0x1C3E4` | **exact 16-byte match** (the callee-identity match) |
| Owner group `0x2E8F7` in the dump | **absent** (as in the copy-helper doc) |
| Window result | `prefix4-match-trailer-differs` (the expected result) |

Both dumps give the same reading. Each dump's `dump_status` is `ok`, and the file side is `ok`. Overall
status `ok`, exit `0`.

---

## The discrepancy (kept, not resolved)

- **The stub is not reproduced exactly.** The dump's trailer is `00` and the file's is `27`. The 16-byte
  windows also differ further in: the dump has zeros at `+4..+12`, where START has `27 00 b2 00 09 00 b0`
  at `+4..+10`.
  The prologue `55 89 E5` sits at `+0xD` in the dump and `+0xB` in START, so the dump is not a plain
  shift of the file either.
- **So no exact identity is claimed.** The probe's `exact_full_stub_identity` is `false` in both dumps. The
  result is named `prefix4-match-trailer-differs`, not "identical" or "stub 7 confirmed".
- **Why it is recorded and not reconciled.** The trailer `27` is malformed for a stub (the callee doc
  and the farcall doc both note it). The dump may reflect a loader's rewrite, a different stub, or memory
  that was never a stub. Two dumps at unknown instants cannot tell these apart. The probe flags any change
  (`exact-16-match`, `stub5-match`, `prefix-absent`) as a diagnostic, so a future dump that differs is seen.

---

## Evidence boundary

What this probe establishes, for the pinned files and the two dumps:

- **File bytes:** the far call at `0x1A27`, its fixup-listed seg word, stub 7 at `0x3E11` with proc
  `0x10C7`, the owner `0x2E8F7`, and the prologue at `0x2F9BE`.
- **Memory bytes (unknown instant):** the `0xD46` group sits at linear `0x45C40` in both dumps. The live
  target is `1C3B:0043` (`0x1C3F3`). Its first four bytes are the stub's proc word. The trailer differs.

What it does **not** establish:

- that the `0x1A27` call executes, or is reached from the ECL `0x21` dispatch, at any instant;
- that the dump window is the call target at any instant, or that group `0x2E8F7` was resident (it is absent);
- that the trailer `00` (RAM) or `27` (START) is meaningful, or that the 16 bytes are one stub;
- the capture instant or atomicity of either dump (the group-map tool records caller metadata as unverified);
- that the far call reaches candidate proc `0x10C7`, despite the compatible file-side stack shape;
- the value or meaning of the byte passed from `[bp-3]`, or any GEO meaning of the call;
- the segment model. `0x1866` is an observation at these sites and is not used as a rule.

The probe does not read any GoldBox file, does not use an emulator, and writes only its JSON under
`data/work/` (git-ignored).

---

## Tests

`tests/test_por_ecl_21_stub7_dump_probe.py`: 25 tests, all passing. Four tests cover the candidate
stack shape and falsify it by changing the caller push, callee byte-load displacement, or `retf`
pop count; these checks remain conditional on the dump target identity.

- **Synthetic falsifiers (20).** A small self-consistent layout with its own pins. Positive case: the
  prefix-only match, with trailer `00` and the control exact. Falsifiers: trailer equal to the file
  (`exact-16-match`, flagged), stub-5-only match (flagged), proc word changed (`prefix-absent`), group absent
  or ambiguous, live seg moved (seg expectation fails), far-call opcode changed (group unmapped), control
  mismatch, seg word not fixup-listed, stub trailer changed in the file, owner fileofs mismatch, proc outside
  owner codesz. Refusals: pin mismatch, dump name with no base, name/size mismatch, no dump, output outside
  `data/work/`, output inside the install, `main` with no install.
- **Retail-gated (1).** Runs `run()` on the pinned install and both known dumps, and asserts every value in
  section 2. Skips when the install or a dump is absent. It writes nothing.

Sibling suites checked: `test_por_overlay_group_map.py` and `test_por_geo_callee_identity_probe.py` pass
(50 passed, 2 skipped). The probe imports `por_overlay_group_map` and `por_convert` read-only and edits
neither.

## Risks and open items

- **Dumps have unknown instants.** Any reading of "the dump shows X" is a snapshot claim with no time. Only
  a dump taken at the moment the stub is called, with its registers recorded, would test the call target.
- **Trailer discrepancy is open.** `27` in START is malformed. The probe does not resolve it.
- **Owner group absent.** The fill group is not in either dump, so the proc `0x10C7` is checked only on file
  bytes. A capture with `0x2E8F7` resident is needed for any memory-side check of the proc.
- **Sensitivity to the 5-byte stride.** Stub 7's position comes from the stub-run stride, which the callee
  doc took from stub 4's `03D5:0034`. The probe checks the stride arithmetic against the file, not the
  identity of stub 4's call.
- **Known-dump list is a hash list.** A re-captured dump with the same name but new bytes is labelled
  `known_dump: null` and still analysed. It is not refused.
