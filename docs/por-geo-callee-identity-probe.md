# Pool of Radiance: callee identity of the far call 03D5:0034

**Status: observe-only. `playable: false`. `consumer_established: false`. `mappings: []`.**

Tool: `tools/por_geo_callee_identity_probe.py`. Tests: `tests/test_por_geo_callee_identity_probe.py`
(22 tests: 21 synthetic, and 1 retail anchor gated on `OPENUA_POR_INSTALL` and the pid34644 dump;
without the variable, 21 pass and 1 skips). Read-only: it reads the pinned `GAME.OVR`, `START.EXE` and one RAM
dump, and writes only under `data/work/por-geo-callee-identity-probe/`.

## Question and answer

> What does the far call `9A 34 00 D5 03` (seg `0x03D5`, off `0x0034`) reach? Five writers of
> DGROUP `0x6AB1` call it and store `AL`. Can its target be named from PoR bytes, and can its
> return be read as a bounded consumer?

**Identity: established by live bytes, for the two caller groups that map uniquely in the dump.**
The call reaches VROOMM stub 4 of the descriptor header at START.EXE `0x3DD7` (overlay file offset
`0x2E8F7`, codesz `0x120B`), whose procedure is at proc `0x057A` (GAME.OVR file `0x2EE71`).

**Consumer: the callee's read is decoded, and its pointer's target is not.** The callee returns
either `0` or `ES:[DI+0x200]`, where `ES:DI` is the far pointer at DGROUP `0x6A5C` and
`DI = 16*Y + X`. The pointer is set from a 1 KiB allocation. Whether it points at a GEO block
(and whether `+0x200` is GEO plane 2) is **not established**.

## Retail run (2026-11-17)

```sh
python tools/por_geo_callee_identity_probe.py --install data/work/por-geo-run/POOLRAD \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    -o data/work/por-geo-callee-identity-probe/retail
```

Exit 0; status `ok`. The inputs are the pinned copies under `data/work/por-geo-run/POOLRAD`
(`GAME.OVR` 206,105 bytes, `872964a3…7928614`; `START.EXE` 65,231 bytes, `d825df2b…60b6a07bd`).
The probe refuses an unpinned file; there is no override. The install under `G:` was not opened.
The primary dump is the GameLink RAM dump from PID 34644 (`f8191750…4895`), labelled non-atomic in
[por-live-dump-identity.md](por-live-dump-identity.md). A second existing dump,
`data/work/por-wheel-live-capture/ram-000000-100000.bin` (`3788787c…0516fa`), gives the same result when
the probe is run on it (output `retail-wheel-dump/`). Two snapshots agree; neither is a register capture.

## Evidence labels

- **Retail bytes (decoded, pinned).** The literal, its group membership, the stub run, the
  callee, the helper and the pointer store. All are from the pinned files.
- **Dump bytes (memory observation).** The live segment words at the caller sites and the live
  target bytes. These are memory bytes, not register observations. The dump is a snapshot whose
  execution point is unknown.
- **Recorded run (OpenUA, cross-check only, not evidence).** The DOSBox-X group-29 load in
  [por-geo-run-capture-2026-11-17.md](por-geo-run-capture-2026-11-17.md) recorded a seek to
  `0x2E8F7` with `codesz 0x120B`. That agrees with the header found here. It is not used to establish
  the identity.

## Static: the five literal sites

| Site (GAME.OVR) | Group (fileofs) | Body offset | Seg word fixup-listed | Dump |
| --- | --- | --- | --- | --- |
| `0x3A4C` | `0xD46` | `0x2D06` | yes | mapped uniquely |
| `0x3F08` | `0xD46` | `0x31C2` | yes | mapped uniquely |
| `0x8F1A` | `0x74D3` | `0x1A47` | yes | mapped uniquely |
| `0x16E8D` | `0x166CB` | `0x7C2` | yes | absent from the dump |
| `0x2DD22` | `0x2DB87` | `0x19B` | yes | absent from the dump |

The loader patches the segment word, so the file alone names no target. Every site's seg word is
in its group's fixup table.

## Dump: the caller groups and the live target

`por_overlay_group_map.map_group` (the existing mapper, read-only) finds the groups by their
stable bytes. The `0xD46` group maps at linear `0x45C40` and the `0x74D3` group at `0x40CC0`, each
unique with no rejected candidates. In both, the live offset word at every `03D5` site is `0x0034`.
The live segment word is `0x1C3B` at all three mapped sites. So the live target is `1C3B:0034`,
linear `0x1C3E4`.

`0x1C3B` is `0x03D5 + 0x1866` (the same uniform delta the existing overlay map records for group
`0x9AC`). That delta is an observation at these sites. It is **not** promoted as a segment-base
model. The identity below does not use it.

The two unmapped sites are not used. Their groups are absent from both dumps. The `0x2DD22` site's
code range is that of the accepted `+0x17` group `0x2DB87` (see the discrepancy below).

## Identity by bytes

The 16 live bytes at `1C3E4` are `cd 3f 7a 05 00 | cd 3f fd 05 00 | cd 3f 08 0e 00 | cd 3f c7 10`.
Those 16 bytes occur **exactly once** in START.EXE, at file offset `0x3E02`, and occur once in the
dump. `0x3E02` is stub 4 of the stub run that starts at `0x3DEE`, header `0x3DD7`:

| Stub | File | Proc | Well-formed |
| ---: | --- | --- | --- |
| 4 | `0x3E02` | `0x057A` | yes (**the matched stub**) |
| 5 | `0x3E07` | `0x05FD` | yes |
| 7 | `0x3E11` | `0x10C7` | no (file trailer `0x27`) |

The header's fileofs is `0x2E8F7`, codesz `0x120B`, fixupsz `0x50`. The group is **partial**
(7 of 8 stubs well-formed; the partial rule is the farcall resolver's, and it is a candidate rule,
not a verdict). The stub's trailer byte is `0x00`, and the stub's proc `0x057A` reaches
`GAME.OVR:0x2EE71`, which starts `55 89 e5`.

**Two points are not reconciled and are recorded, not used:**

1. The live slot 7 holds trailer `00` where START.EXE holds `27`. The 32-byte comparison therefore
   agrees for 19 bytes only. The identity rests on the 16 bytes that agree.
2. Linear-to-file mapping is not one base. The stub run matches at `linear = file + 0x185E2`, and
   the entry window of the relocated START copy (`2925:0012`, from
   [por-live-dump-identity.md](por-live-dump-identity.md)) matches at a different base. No single
   START base is claimed. The identity is byte identity at one offset only.

## Callee: `GAME.OVR:0x2EE71` (decoded, `tools/por_loadpieces_handler.py` decoder)

The procedure walks 45 instructions to `retf 4`. Its arguments are the two caller pushes. The caller
at each site runs `mov al,[0x6AAD]; push ax; mov al,[0x6AAE]; push ax; call far`, so `[bp+8]` is
X from `0x6AAD` and `[bp+6]` is Y from `0x6AAE` (checked at all three mapped sites).

1. **Gate (helper `0x2EC16`).** It returns `1` only when `0 ≤ X ≤ 15` and `0 ≤ Y ≤ 15`. Its compares
   are `[bp+8] ≤ 15`, `[bp+8] ≥ 0`, `[bp+6] ≤ 15`, `[bp+6] ≥ 0`, in that order, and it returns
   `1` or `0`.
2. **Fall-through (out of range).** Then `[DGROUP 0x84DC]` decides. `0` or `0x0A` returns `0`.
   Any other value takes the read path with the wrap below.
3. **Wrap (read path only).** `X > 15 → 0`, `X < 0 → 15`, and likewise for `Y`. For in-range
   values the wrap does nothing.
4. **Read.** `les di,[0x6A5C]`; `DI = 16*Y + X` (`mov cl,4; shl ax,cl; add di,ax; add di,dx`);
   `mov al, es:[di+0x200]`; the byte is stored to `[bp-1]` and returned by `retf 4`.

So the return is `0` or `ES:[ptr + 0x200 + 16*Y + X]`, with `ptr` the far pointer at `DGROUP 0x6A5C`.

**Checks (all pass on the retail bytes):** prologue; wrap compares on both arguments; a single
`les` from `0x6A5C`; `shl ax,cl` (`cl=4`) before the load; a single ES read with displacement
`0x200`; guard compares with `0` and `0x0A`; `retf 4`; the range-gate shape of helper `0x2EC16`.

## The far pointer at DGROUP `0x6A5C`

A byte-led sweep of `GAME.OVR` finds 30 references to `0x6A5C`. Twenty-nine are `les` loads (the
callees). **One is a store**, `mov [0x6A5C],ax` at file `0xE670`, paired with `mov [0x6A5E],dx`
at `0xE673`. The sequence is `mov ax,0x400; push ax; call 0x0AF8:0x023F` at `0xE667..0xE66B`. So the
pointer is the DX:AX result of a far call that is given `0x400` (1,024 bytes). The store is in
group `0xE5D3`, a different group from the five writers.

Two consequences, both recorded as observations:

- The read `+0x200 + 16*Y + X` (at most `+0x2FF`) stays inside a 1,024-byte allocation.
- If the buffer is filled from `block + 2`, plane 2 (`block + 514`) lands at `+0x200`. The fill is not
  decoded, so `ptr = block + 2` is not established.

## Consumer chain

| Link | Status | Falsifier |
| --- | --- | --- |
| Caller literal `03D5:0034` → live `1C3B:0034` | established by dump bytes (3 mapped sites) | a mapped site whose live segment word differs |
| Live `1C3E4` → START stub 4 (`0x3E02`, header `0x3DD7`) | established by unique byte match | a second START offset matching the 16 bytes |
| Stub 4 → `GAME.OVR:0x2EE71` (group `0x2E8F7`) | established by the stub's proc word and a prologue | a different group whose fileofs owns this stub run |
| `0x2EE71` return → `ES:[ptr+0x200+16Y+X]` or `0` | decoded (retail bytes) | a read path that is not the one listed |
| `ptr` (DGROUP `0x6A5C`) → GEO block base | **not established** | a live value of `ptr` that is not a GEO block |
| `ptr + 0x200` → GEO plane 2 (`514 + 16y + x`) | **not established** | the fill of the 1 KiB buffer from another source |
| Returned `AL` → DGROUP `0x6AB1` → ECL `0xC04F` | established by retail bytes (the store and the getter) | see [por-geo-descriptor-probe.md](por-geo-descriptor-probe.md) |

## Discrepancy with the farcall doc

[por-farcall-resolution.md](por-farcall-resolution.md) says the fifth call at `0x2DD22` "lies
outside every stub-carrying overlay". The containment check here puts `0x2DD22` inside the code range
of the accepted `+0x17` group `0x2DB87` (codesz `0x2A5`, three stubs). The farcall doc calls that group
"not established as a real descriptor". So the two statements do not agree. This probe does not resolve
it: that group is absent from the dump, and its three stubs were not examined here.

## What remains unknown

- The live value of `ptr` (DGROUP `0x6A5C`). The DGROUP segment is not in any register observation.
- The fill of the 1 KiB buffer, and so whether `ptr` is a GEO block or `block + 2`.
- The meaning of guard `0x84DC`, beyond the two values `0` and `0x0A`.
- ECL opcode `0x2D`, which reaches the writers through the dispatcher
  (see [por-geo-descriptor-probe.md](por-geo-descriptor-probe.md)).
- Whether any caller or the callee executed. The dump is not a register capture.

## Next discriminating observations

1. **The buffer fill.** Find the code that writes `1 KiB` into the buffer returned by the
   `0x0AF8:0x023F` call at `0xE66B`, and check whether its source is `block + 2`. Static, decodable.
2. **A register capture at `0x2EED9`.** At the `es:[di+0x200]` read, record `ES:DI`, `X`, `Y` and the
   returned `AL`, then compare `ES:DI + 0x200` with the plane-2 byte of the party's cell for several
   cells. A single mismatch falsifies "plane 2". This needs a run (out of scope here).
3. **The live `0x84DC` value** over the same run, to test the fall-through.

These need a runtime observation or a further static decode. The probe reports what it can and does
not run one.

## Not claimed

- No plane-2 consumer, no transform, no descriptor-to-event mapping, no area mapping.
- No segment-base model. The `+0x1866` delta is an observation at three sites.
- The stub's partial status is the farcall rule's candidate status. The identity rests on the stub's
  bytes and its prologue-checked proc, not on the group's full validity.
- No reachability from entry is claimed for any caller or the callee.

## Tests

```sh
OPENUA_POR_INSTALL='data/work/por-geo-run/POOLRAD' python -m pytest tests/test_por_geo_callee_identity_probe.py -q
```

Result on this run: **21 passed, 1 skipped** without the variable; **22 passed** with it (the retail
anchor checks the five sites, the three mapped callers and `1C3E4`, the stub owner `0x2E8F7` stub 4
proc `0x057A`, the callee checks, the range-gate entry `0x2EC16`, and the store context at `0xE66B`).
The synthetic tests build hand-encoded 8086 procedures, a stub run, a dump and an argument push
sequence, and check the refusals and the output location.

## Not touched

- No emulator, GameLink, DOSBox or codewheel run. No input was sent.
- No write to the install or to `C:\Modding\GoldBox`.
- No existing file changed. The probe and its tests are new files. `tools/README.md` and the other
  uncommitted `por_*` work are left as found.
- No commit, no push.
