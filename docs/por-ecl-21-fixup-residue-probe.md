# Pool of Radiance: do the 0x21 far-call fixup records reach the GEO stub at START 15884?

**Status: STATIC-PROBE-ONLY. `playable: false`, `di_established: false`.** `tools/por_ecl_21_fixup_residue_probe.py`
reads the pinned retail `GAME.OVR` and `START.EXE` read-only. It takes the nine model-dependent far calls of the
`0x19BA` handler (see [por-ecl-21-dispatch-probe.md](por-ecl-21-dispatch-probe.md)), and asks whether any overlay
fixup record ties one of them to a base that resolves its target to the GEO stub at `START.EXE` offset `15884`
(`0x3E0C`, stub index 6 of group `0x3DD7`, proc `0x0E08` into the GEO body `GAME.OVR:0x2F6FF`). Only PoR bytes
are used. No GoldBox or other-title rule was read or used, and nothing was run against an emulator or DOSBox.

---

## Answer

**No fixup record ties any far call to the GEO stub.** Under a paragraph-aligned resident image, no listed site
can reach `15884` for any value of the fixup delta. So the question is closed for the paragraph-aligned model.
What stays open is narrow: a sub-paragraph placement of the image, for which the bytes give no support.

| Question | Answer | Evidence class |
| --- | --- | --- |
| Does a record name a base? | **No.** Each table entry is a bare, sorted, in-range body offset (`table_facts`). The only other input is the delta `DI`, which is not in the table. | table-membership, structure |
| Is `DI` established? | **No.** `[0x4422]` has one store, at `0xAC7B`, whose ES is not in the bytes (`docs/por-ecl-fixup-entry-probe.md`). | decoded (not established) |
| Can any listed site reach `15884` for some `DI`? | **No.** The image address is `hdr + (seg+DI)*16 + off`. `DI` moves it only in multiples of 16, so the site needs `off ≡ 0xC (mod 16)`. None of the eleven offsets is `≡ 0xC`. | arithmetic |
| Do the sub-paragraph skews that the literature quotes close the gap? | **No.** The seven skews the sites need are `{1,2,3,5,7,9,14}`. None is `15` (the CoK `-1` skew) and none is `10` or `6` (the quoted `0x50A` displacement, either sign). | arithmetic |
| `geo_status` | **`no-site-reaches-geo-under-paragraph-base`** | verdict |

---

## Method

1. **Header.** `START.EXE` `0x3C3` reads `CD 3F 00 00`, fileofs `0x0D46`, codesz `0x350D`, fixupsz `804`, jmpcnt `2`.
   The group is therefore `GAME.OVR:0x0D46..0x4253`, with its fixup table at `0x4253` (402 words).
2. **Table.** 402 sorted 16-bit words, all `< codesz`, no duplicates. The table has no field other than the body offset.
3. **Applier.** `START.EXE:0xA9E8` is `AD 8B D8 26 01 3F E2` (`lodsw; mov bx,ax; add es:[bx],di; loop`). Each listed
   word receives `+DI`. This is the only write that the table drives, and it adds to the seg word alone.
4. **Residue.** For a listed seg word, the call's image address is `0x200 + (seg+DI)*16 + off`, where `0x200` is the
   MZ header size. The GEO stub is at `15884 = 0x200 + 0x3C0C`. So the required sub-paragraph skew is
   `k = (0x3C0C - off) mod 16`. `k = 0` means the site is paragraph-consistent: a `DI` value exists, but `DI` is not
   established. `k ≠ 0` means no `DI` can reach the stub under a paragraph-aligned image.
5. **Preconditions** (any failure gives `precondition-failed`, never a verdict): header matches; applier bytes match;
   GEO stub bytes `CD 3F 08 0E 00` at `15884` and the candidate row is index 6 of `0x3DD7`; eleven far calls from a
   complete walk; every offset word is not listed; the table is bare offsets.

The tail copy in the START entry starts at file `0xF920` (`docs/por-ecl-fixup-probe.md`), above `15884`. The stub
is in the head, so the head-paragraph model applies to it.

---

## Per-site result (retail run)

Each seg word is listed in the fixup table (`seg_word_listed: true`). No offset word is listed. The skew is the sub-paragraph
base a site would need. None is `0`.

| Site | seg:off | seg body | skew mod 16 | GEO candidate |
| --- | --- | ---: | ---: | --- |
| `0x19C3` | `002B:002A` | `0xC80` | 2 | no |
| `0x19DA` | `002B:0025` | `0xC97` | 7 | no |
| `0x1A27` | `03D5:0043` | `0xCE4` | 9 | no |
| `0x1A53` | `0AF8:0B0B` | `0xD10` | 1 | no |
| `0x1A5E` | `03E9:0025` | `0xD1B` | 7 | no |
| `0x1A77` | `03D5:003E` | `0xD34` | 14 | no |
| `0x1A9E` | `03D5:003E` | `0xD5B` | 14 | no |
| `0x1AAA` | `03D5:003E` | `0xD67` | 14 | no |
| `0x1AD6` | `03D5:003E` | `0xD93` | 14 | no |
| `0x1B1A` | `00BA:27D9` | `0xDD7` | 3 | no |
| `0x1B27` | `00BA:0767` | `0xDE4` | 5 | no |

The first two rows are the 0x21 probe's stub-group calls (`0x19C3`, `0x19DA`). The other nine are the model-dependent
set. All eleven are classed here by the same residue rule.

---

## Falsifiers and controls

`tests/test_por_ecl_21_fixup_residue_probe.py`: 40 tests with the retail env, 31 passed and 9 skipped without it.

- **Positive control** (retail, in-memory): `0x19C3` set to `9A 0C 00 C0 03` (the 0x21 probe's control). Status becomes
  `candidate-given-di-not-established`, candidate `0x19C3`, `DI = 0`. The synthetic residue test shows `off = 0x0C`
  is paragraph-consistent and `off = 0x0D` gives skew 15.
- **Negative control, offset** (retail): the same call set to `9A 0D 00 C0 03` loses the candidate.
- **Negative control, stub** (retail): the GEO stub's proc low byte in `START.EXE` changed `0x08 → 0x09`. The stub
  disappears and the verdict is `precondition-failed`.
- **Table falsifier** (retail): the first table word replaced by the `0x19C3` offset word `0xC7E`. The table is no
  longer sorted, and the offset word is listed, so the verdict is `precondition-failed`.
- **Synthetic falsifiers**: unsorted table, word `≥ codesz`, duplicates, wrong magic, wrong `fixupsz`, short overlay,
  listed offset word, unlisted literal seg (exact hit only), and the output refusals.

## Commands and results

- `python -I tools/por_ecl_21_fixup_residue_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" -o data/work/por-ecl-21-fixup-residue-probe/retail`
  → `geo_status=no-site-reaches-geo-under-paragraph-base self_checks=pass`, exit `0`. The output JSON is 9,007 bytes,
  SHA-256 `f3f44350ad3a005e3143c814f3441cb74efa2f18a68e21ebf2a2be254366d7ea`.
- `python -m pytest tests/test_por_ecl_21_fixup_residue_probe.py -q` (no retail env) → 31 passed, 9 skipped.
- `OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_ecl_21_fixup_residue_probe.py -q`
  → 40 passed.
- (`python3` is not on this shell's PATH; `python` is Python 3.13.7 and was used.)

Self-checks: `preconditions_hold`, `listed_seg_words_expected` (11), `fixup_records_give_base_false`,
`di_not_established`, `never_established`, `inputs_unchanged`. All pass.

---

## Unresolved edges

1. **`DI` value.** Not established. The table-based residue test does not need it, because it holds for any integer `DI`.
   A `DI` would only matter for a site that is paragraph-consistent, and none is.
2. **Sub-paragraph placement.** The result assumes a paragraph-aligned resident image (the DOS EXE load at `PSP+0x10`).
   The fixup-entry doc quotes a `0x50A` head displacement that no byte in START.EXE describes. It is not a multiple of
   16, so it would change the residue. Its two signs give skews `10` and `6`, and no site needs either. Other
   sub-paragraph skews would need bytes that are not in the file.
3. **Direct edge to the GEO body.** A far call to `GAME.OVR:0x2F6FF` (not via the stub) is not analysed here. That needs
   the overlay's own load base, which is a separate unknown.
4. **Other stubs.** The probe asks only about `15884`. Whether a listed site reaches another stub under some `DI` is
   not analysed. The group `0x3C3` has its own two stubs at `0x3D9` and `0x3DE`, which no listed site targets.
5. **Runtime reachability.** Not established. The `0x3EB7` loop's callers are byte-pattern only, as the 0x21 probe
   records. A later [stub-7 dump cross-check](por-ecl-21-stub7-dump-probe.md) observes that the live target bytes
   for `0x1A27` begin with the first four bytes of START stub 7 in two dumps, but the fifth byte and the 16-byte
   window differ. This is not full target identity and does not show execution. The paragraph-residue conclusion
   above remains a file-model result; the memory prefix does not establish a sub-paragraph placement rule.

The 0x21 doc's "discriminating next step" named two branches: a record giving a base (not found), or no base (closed as
model-dependent). The result here is the first branch's negative: no record ties a site to the stub under the paragraph
model. The runtime far-call trace at `0x1A27..0x1B27` is the remaining evidence path, and it is outside this slice.

---

## Files

- `tools/por_ecl_21_fixup_residue_probe.py`: the probe. It reads `por_ecl_21_dispatch_probe`, `por_farcall_resolve`
  read-only. It edits none of them.
- `tests/test_por_ecl_21_fixup_residue_probe.py`: 40 tests (31 input-free, 9 install-gated retail tests; 40 pass with the env var).
- `docs/por-ecl-21-fixup-residue-probe.md`: this document.
- Output (git-ignored): `data/work/por-ecl-21-fixup-residue-probe/retail/` (`.json` and `.md`).

No existing file was edited. Nothing was staged, committed or pushed. The retail install was read only, and its
files were hashed before and after the run (`inputs_unchanged: pass`).
