# Pool of Radiance: far-call census toward START stub 6 (WALLDEF wrapper)

**Status: STATIC-PROBE-ONLY. `playable: false`, `established: false`, `mappings: []`.**

Tool: `tools/por_geo_stub_farcall_census.py`. Tests: `tests/test_por_geo_stub_farcall_census.py` (23 synthetic,
7 retail-gated; 30 pass with `OPENUA_POR_INSTALL` set). Output (git-ignored):
`data/work/por-geo-stub-farcall-census/retail/` (`.json`, `.md`).

> **Reassessment (2026-11-18).** Stub 6 enters the WALLDEF wrapper, not the GEO loader. This census is not a GEO result. See [`por-geo-farcall-census.md`](por-geo-farcall-census.md) for the withdrawn GEO conclusion.

> **Name collision.** A tool and test with the names `por_geo_farcall_census.py` /
> `test_por_geo_farcall_census.py` are already committed (`01363944`, Kasper Olesen). This census
> does not use or modify them. The committed test file was briefly overwritten in the working tree
> by this work and has been restored to HEAD. The earlier overwrite is kept at
> `data/work/por-geo-stub-farcall-census/overwritten-test-backup.py`. The retail output under
> `data/work/por-geo-farcall-census/retail/` was produced by the committed tool, not by this one.

## Question and answer

> Across every parsed GAME.OVR overlay body, which instruction-decoded far calls could resolve to the
> stub 6 at `START.EXE` offset `15884` (`0x3E0C`, group `0x3DD7` index 6, proc `0x0E08` into
> the WALLDEF wrapper `GAME.OVR:0x2F6FF`)?

**Answer: 181 of 3,993 decoded far-call sites pass the residue rule, and none of them is a
binding.** Every one is a listed-seg-word site whose offset happens to be `≡ 0xC (mod 16)`, so the
DI delta is not established for any of them. The literal test is never exercised: all 3,993 sites
have a listed seg word. No decoded near `E8` reaches the WALLDEF wrapper body. The result is a base-rate
effect of the rule, not evidence about the stub.

| Question | Answer | Class |
| --- | --- | --- |
| Parsed groups | 34 (24 well-formed, 10 partial) | decoded |
| Decoded far-call sites | 3,993 (3,615 strong, 378 weak-only) | decoded |
| Distinct `seg:off` operands | 326 | decoded |
| Sites with listed seg word | 3,993 of 3,993 | table-membership |
| Sites with listed offset word | 0 | table-membership |
| Residue-compatible (`off ≡ 0xC`) | 181 (166 strong) | arithmetic |
| Literal exact hit (unlisted seg) | 0 (not reached) | arithmetic |
| Near `E8` to the WALLDEF wrapper `0x2F6FF` | 0 | decoded |
| Owner group `0x2E8F7` (stub 6's) parsed, body decoded | yes (40 far, 24 strong, 48 near) | decoded |
| `stub6_status` | `candidate-given-di-not-established` | verdict |

The verdict label is the rule's own output. Read it as "181 sites are arithmetically possible
given an unknown DI", not as a target.

## Method

1. **Groups.** `por_farcall_resolve.scan_all` gives the parsed descriptor groups (accepted and partial).
   Each body is `[fileofs, fileofs+codesz)`; its fixup table is `fixupsz/2` words at `fileofs+codesz`.
2. **Decode.** Per group, two passes of `por_loadpieces_handler.decode`:
   - **Strong:** recursive descent seeded only from the group's well-formed stub procs.
   - **Weak:** seeded from every `55 89 E5` / `55 8B EC` byte pattern, skipping instructions the strong
     pass already decoded.
   The descent follows fall-through, `jcc`/`jmp`, and `E8` targets inside the body, and stops at
   `ret`/`retf`/far or indirect jumps. A far call is `strong` if the strong pass reached it.
3. **Owner tables.** A far call's seg word sits at body offset `at+3-fileofs` and its offset word at
   `at+1-fileofs`. Both are tested against the owner group's own fixup table only.
4. **Residue rule, per (site, owner).** The resident MZ image is at file `0x200`. A listed seg word
   receives an unknown `DI`, so the image is `0x200 + (seg+DI)*16 + off`. It reaches `15884` only if
   `off ≡ 0xC (mod 16)`. The DI it would need is recorded as a constraint (`di_constraint_mod64k`), not
   a value. An unlisted seg word is tested for an exact literal hit. An offset word that is listed gets
   `DI` itself, so that row is `undecided-*` and never a candidate.
5. **Near calls.** `E8` decoded inside a body with target `0x2F6FF` is reported with its owner. The
   target is body-relative and only reaches bytes of its own body.

## Controls

- **Handler control.** The eleven far calls of the `0x19BA` handler are all decoded inside group `0x0D46`,
  and each per-site skew matches `por_ecl_21_fixup_residue_probe.residue_for` (skews `2,7,9,1,7,14,14,14,14,3,5`).
- **Stub 6.** Bytes `CD 3F 08 0E 00` at `15884`, group `0x3DD7`, index 6, proc `0x0E08`, owner
  `0x2E8F7`. Every structural check holds, so no `precondition-failed` is returned.
- **WALLDEF wrapper decode.** `0x2F6FF` is a decoded instruction start in group `0x2E8F7`.

## Coverage labels

- `strong-walk-clean`: 32 groups.
- `strong-walk-incomplete`: 2 groups, `0x9807` and `0xABC0` (strong-path decode errors). Their far calls
  are still listed, but their coverage is not clean.
- `no-strong-seed`: 0 groups.
- Partial groups (10) are labelled `partial`. Their malformed slot is never a seed.

## Falsifiers

Synthetic (`tests/test_por_geo_stub_farcall_census.py`):

- `off = 0x0D` with seg listed: `residue-incompatible`, skew 15.
- Unlisted seg with `off = 0x0D`: `literal-miss`.
- Offset word listed: `undecided-offset-listed`, never a candidate. Both words listed: `undecided-both-words-listed`.
- The same site listed in one owner's table and not another: the owner decides.
- A far call reached only from a prologue pattern: `strong: false`.
- An out-of-body `E9` on the strong path: `strong-walk-incomplete`.
- A malformed stub slot is never a seed.
- Decode is deterministic.
- Output inside the install, or outside `data/work/`: refused.

Retail (gated): pins, 34/24/10 group counts, 3,993 far sites and owner rows, zero near calls to the WALLDEF
wrapper body, status counts limited to the two listed-seg statuses, 181 candidates, the eleven handler skews,
and the two incomplete groups.

## Commands and results

```sh
python -m pytest tests/test_por_geo_stub_farcall_census.py -q                             # 23 passed, 7 skipped
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_geo_stub_farcall_census.py -q   # 30 passed
python -I tools/por_geo_stub_farcall_census.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-geo-stub-farcall-census/retail                                       # exit 0, self_checks=pass
```

Output hashes (retail run): `por_geo_stub_farcall_census.json`
`b82b867fcb8931035e13dd60b2ca5ffd35dd7c36be780c6d21d55234f31710eb`; `.md`
`9c4b50fa6c64572e2a7508f6efbf4b542a8dc1a2428dde079c40a2f3c27cbcfb`; tool
`4ac473fa2a7aa3f841d35b538d7bf9945ddef2db2b54de02378eef916602abf8`.

Inputs were not written. Both pins matched and the install was hashed before and after the run.

## Limits

- Only groups with a stub run (accepted or partial) are parsed. An overlay body with no stub run is
  outside the census.
- Weak sites come from prologue byte patterns and may be data decoded as code.
- The DI delta is unknown, and the table stores only body offsets, so a candidate is an arithmetic
  possibility, not a binding.
- The MZ paragraph model is assumed, not verified.
- Nothing here maps an overlay to a GEO archive, a block, an area, or a runtime call.

## Not touched

- No existing file was edited, committed, or pushed. The tracked `tools/por_geo_farcall_census.py` and
  `tests/test_por_geo_farcall_census.py` were not modified, and the test file's working-tree overwrite
  was restored to HEAD.
- No GoldBox or other-title source was read. No emulator, DOSBox, GameLink, or codewheel was run. No
  retail write was made.

## Next evidence that would settle it

1. A runtime CS:IP or INT 3Fh trace at a candidate site, recording the overlay index actually loaded.
2. The fixup-applier's DI value at load time, which would turn the residue constraint into a single check.
3. For the handful of strong, residue-compatible sites, a decode of the argument pushes before the call.
