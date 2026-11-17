# Pool of Radiance: indirect calls into stub 1 of group 0x166CB (static, observe-only)

**Status: STATIC-PROBE-ONLY. `playable: false`. The trigger is NOT established.**
Tool: [`tools/por_door_indirect_probe.py`](../tools/por_door_indirect_probe.py). Tests:
[`tests/test_por_door_indirect_probe.py`](../tests/test_por_door_indirect_probe.py) (24 tests: 20 synthetic
with falsifiers, 4 retail-gated; all 24 pass). Output (git-ignored):
`data/work/por-door-indirect-probe/por_door_indirect_probe.json` and `..._report.md`.

This is the step the open edge in [por-door-caller-probe.md](por-door-caller-probe.md) asked for: stub 1 of
group `0x166CB` (START file `0x0089C`, proc `0x0D6D` = file `0x17438`) is the only stub whose closure reaches
the plane-3 writer `0x167D4` and clearer `0x166CB`, and no literal far call (`9A`) reaches it. The question
here is whether an **indirect** call (`FF /2` near, `FF /3` far) can. Answer: no decoded indirect call reaches
it, and no indirect table can be resolved from these bytes.

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Checked before the run (`sha256sum`) and again after it (`sha256sum`): both unchanged. The probe also
re-hashes both files after its own walk and refuses if either changed (`recheck_pins`). Unpinned input is
refused with no override (`dc.load_pinned`, reused from `por_door_caller_probe.py`). No dumps, no emulator,
no GoldBox, no retail writes.

## Method

1. **Owner groups** from `por_farcall_resolve.scan_all` (24 well-formed + 10 partial = 34 groups).
2. **Closure (class I domain A).** For each valid stub of each group, walk the stub's proc and follow in-group
   near calls (`por_door_caller_probe.GroupWalks`, read-only reuse).
3. **Prologue sweep (domain B).** Every Borland-prologue offset in a group body that no stub closure reaches.
4. **START.EXE image (domain S).** Closure from the MZ entry point (`CS:IP = 0F72:0012`, file `0x0F932`) following
   near calls inside the image, then a prologue sweep of the unreached prologues from the image base `0x200`.
5. **Decoder.** `por_loadpieces_handler.walk` / `decode`. `FF /2` is `indirect_call`, `FF /3` is `indirect_callf`.
   A site counts only if a walk reached it as an instruction start.
6. **Raw census.** Every `FF` byte whose ModRM reg is 2 or 3, classed as decoded start, inside a decoded
   instruction (immediate, displacement, or operand), or raw (not covered by any walk). Raw is never counted.
7. **Stub-1 reach.** Decoded `E8` to `0x0089C`, decoded `9A` under M0 and M1. Instruction starts only.
8. **Raw candidates** for the target `0x0089C`, under both models (below), by byte pattern only.
9. **Table resolution (class T).** A decoded `direct-DS` operand is resolved only through a DS base the caller
   states. None is stated on the retail run, so none is resolved.

## Address models (neither promoted)

- **M0** zero-skew: `image = hdr + seg*16 + off`, `hdr = 0x200`. Value for the target: `0x089C - 0x200 = 0x069C`.
- **M1** dump-anchored: `file = seg*16 + off + 0x7E`. Value for the target: `0x089C - 0x7E = 0x081E`.

Near indirect words are offsets in a code segment whose base is not established. The near candidates assume
base 0 and are raw only.

## Evidence classes (kept separate)

| class | meaning | retail count |
| --- | --- | --- |
| **I** decoded instruction start | FF /2 or FF /3 reached by a walk | FF /2 near: **0**; FF /3 far: **5** |
| **I** stub-1 reach | decoded `E8` to `0x089C`, or decoded `9A` under M0 / M1 | near **0**, M0 **0**, M1 **0** |
| **R** raw byte pattern | not a decoded start; never a caller or table | see below |
| **T** table resolved | decoded operand read through a stated DS base | **0** (no DS base stated) |

### Class I: the five decoded `FF /3` sites (no `FF /2` site exists)

| site | domain | operand | text |
| --- | --- | --- | --- |
| `0x0AA40` | START.EXE (prologue sweep, fn `0x0A9FC`) | direct-DS `disp 0x43F0` | `callf [0x43f0]` |
| `0x27D88` | group `0x27018` (closure, fn `0x27C38`) | direct-DS `disp 0x6B84` | `callf [0x6b84]` |
| `0x2A157` | group `0x27018` (closure, fn `0x2A0F1`) | direct-DS `disp 0x6B84` | `callf [0x6b84]` |
| `0x27ED5` | group `0x27018` (closure, fn `0x27C38`) | base-index `[di+...]` | `callf [di+27524]` |
| `0x2AF08` | group `0x2AEEA` (closure, fn `0x2AEEA`) | base-index `[di+...]` | `callf [di+26664]` |

None of the five has a DS base, and each is decoded in a walk that the stubs or prologue sweep reached. The
operand classes are: direct-DS (3), base-index (2), bp-based (0), register (0), invalid far register (0).

The START site `0x0AA40` sits in a function that does `push ds; push es; mov ds, ax` at `0x0AA0A`. The `AX`
value is set outside the decoded window and is not traced here, so its DS is a run-time value. The
`[di+...]` operands take a DI value that is not traced either.

### Class R: raw byte-pattern candidates (not callers, not tables)

- Stub-1 identity bytes `cd 3f 6d 0d 00`: START **1** (`0x0089C`, the stub itself), GAME.OVR **0**.
- Near word `0x069C` (M0 value): START **2**, GAME.OVR **2**.
- Near word `0x081E` (M1 value): START **0**, GAME.OVR **1**.
- Group-relative proc word `0x0D6D`: START **2**, GAME.OVR **0**.
- Far pairs `seg:off` with `seg*16+off = 0x069C` (M0, 106 pairs tested): **0** hits.
- Far pairs with `seg*16+off = 0x081E` (M1, 130 pairs tested): **0** hits.
- Raw `FF` /2 or /3 bytes not covered by any walk: START **57**; in group bodies **0**; outside every group body,
  **1** (GAME.OVR `0x06CB6`, ModRM `13`, call near `[bp+di]`, not walked).

None of the near-word hits is a decoded operand and none is in a table that a decoded operand names.

## Coverage

- **Groups (GAME.OVR).** 34 groups, 678 walks, 675 complete. Covered 186,681 of 197,451 group-body bytes
  (94.6%). The 3 incomplete walks are `unsupported-opcode-0x65`, `unsupported-fe-reg-2`, and
  `target-out-of-range`. Group `0x166CB` (the target group): 14 walks, 14 complete, 4184 of 4268 bytes
  (98.0%), no indirect site. Bytes outside all group bodies (headers, descriptors, stubs, data): 8,654, not walked.
- **START.EXE image.** Covered 34,699 of 64,719 bytes (53.6%), 173 walks (172 complete). The 1 incomplete walk is
  `unsupported-opcode-0x0f`. The image holds data as well as code, so the low figure is expected.
- **FF census** (every `FF` with ModRM reg 2 or 3 in the groups): decoded start **4**, inside a decoded
  instruction **360**, raw **0**. In START: decoded start **1**, inside **119**, raw **57**.

## Result, with exact evidence

- **Stub 1 has no decoded direct caller** (`E8` or `9A`, under either model) in the walked code.
- **Stub 1 has no decoded indirect caller that resolves to it.** There are 0 decoded `FF /2` sites. The 5 decoded
  `FF /3` sites have operands that need a DS, BP, or DI base the bytes here do not establish, so no table is
  read and nothing resolves.
- **Verdict: `trigger_established: false`.** The indirect route is open only for the five `FF /3` sites above,
  and only if their DS or base-index values can be fixed by a trace this probe does not do.

## What is not established

1. **The DS base** of the START caller `0x0AA40` and of the group `0x27018` / `0x2AEEA` callers. The DS load at
   `0x0AA0A` takes its value from `AX`, whose source is not decoded here. The entry's `push cs; pop ds`
   (`0xF937`-`0xF938`) sets DS only for the startup code, not for these functions.
2. **The table contents** at DS `0x43F0` and `0x6B84`. They cannot be read without (1).
3. **The run-time segment mapping.** The entry copies a block with `rep movsb` and `retf`s to `seg:0x38` (the
   pushed segment comes from `AX`, set earlier in the startup), so the segment for file `0x0089C` is not fixed by
   these bytes. M0 and M1 remain unproven, and neither the
   near candidates nor the far pairs can be promoted.
4. **Runtime.** Every row is a static decode. Nothing shows a call ran.
5. **Coverage gaps.** 8,654 group-external bytes and about 46% of the START image are not walked as code. Three
   group walks and one START walk stop at an unsupported opcode. A call inside those unwalked bytes would be
   missed, though the raw census shows no `FF /2` in groups at all.

## Commands

```sh
sha256sum data/work/por-geo-run/POOLRAD/GAME.OVR data/work/por-geo-run/POOLRAD/START.EXE   # before and after
OPENUA_POR_INSTALL="C:/Modding/OpenUA/data/work/por-geo-run/POOLRAD" \
  /c/Python313/python -m pytest tests/test_por_door_indirect_probe.py -q -p no:cacheprovider  # 24 passed
/c/Python313/python -I tools/por_door_indirect_probe.py --install data/work/por-geo-run/POOLRAD \
  -o data/work/por-door-indirect-probe                                                       # exit 0
```

## Next step

Static, no emulator: trace the DS value at the one START caller that has a direct-DS operand. Find the callers
of the START function `0x0A9FC` (decoded `E8` and `9A` sites, both already in the census), and decode what
`AX` holds at `0x0AA0A` on each path. If that fixes DS, read the table word at `DS:0x43F0` and check it against
the M0 and M1 near values `0x069C` and `0x081E`. The overlay sites (`DS:0x6B84`) need their own DS trace.
Only a table word that equals a stub-1 value, reached through a traced DS, would establish the indirect
trigger. A live capture is still blocked by copy protection (see
[por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md)).

## Limits

- Stdlib-only static analysis plus the existing decoder and the read-only helpers of `por_door_caller_probe.py`.
  No emulator, no live register capture, no dump check.
- 8086 decoder: unsupported opcodes stop a walk and mark it incomplete. The census is a floor, not a count of
  every call in the image.
- Class R counts are byte-pattern counts with no instruction context. They are for orientation only.
- GoldBox and other-title material was not used. Nothing here is PoR semantics beyond the bytes listed.
- Not edited by this slice: the existing converter, `tools/README.md`, `tools/por_door_caller_probe.py`, the
  door and loader docs, and `por-geo-door-semantics.md`.
