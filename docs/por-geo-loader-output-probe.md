# Pool of Radiance: the loader body's output far pointer (observe-only)

**Status: archive-and-id-not-established. `playable: false`. `geo_output: not_established`. `plane2_binding: not claimed`.**

Tool: `tools/por_geo_loader_output_probe.py`. Tests: `tests/test_por_geo_loader_output_probe.py` (41 tests:
30 synthetic with falsifiers, 11 retail-gated; all 41 pass on this run, none skipped). Read-only: it reads the
pinned `GAME.OVR` and `START.EXE`, the two pinned memory dumps and the pinned GEO archives. It writes only under
`data/work/por-geo-loader-output-probe/`. It refuses unpinned inputs, outputs outside `data/work` and outputs inside
the install, and it refuses if the target probe does not identify the body at `0x876D`.

Follows [por-geo-loader-target-probe.md](por-geo-loader-target-probe.md) (identity of `0x0802:0x0716` as START
`0x876D`, conditional on the live segment) and [por-geo-loader-caller-frame-probe.md](por-geo-loader-caller-frame-probe.md)
(the fill's pushed arguments). It asks what the body writes to its output far pointer, and whether the bytes fix
the GEO archive, the block, or the output contents.

## Question and answer

> Do the loader body's bytes and the PoR archive layout fix the requested GEO archive and block, and the contents
> of the output buffer?

**Answer: no. The bytes fix the shape of the output and the way it is filled, not its identity.** The output far
pointer (the body's `[bp+6]` variable, which the fill reads back as `[bp-6]`) is written on six paths. Four write NULL.
Two write the allocator's returned pointer, and that is the only path that produces output. The output is taken
only when a TOC record's id byte equals the caller's id byte. The archive name is built from literal pieces the bytes
do not close, and the requested id is a caller byte the bytes do not fix. So no area, block or output identity is
established, and no plane 2 binding is claimed.

## The output far pointer (file bytes, `0x876D` body)

Eight stores through the output and status variables, with the value's provenance taken from the nearest preceding
writer of the register (a linear scan; no CFG):

| Store | Var | Field | Reg | Provenance | Gate |
| --- | --- | --- | --- | --- | --- |
| `0x87D8` | status (`bp+10`) | +0 | ax | `xor ax,ax` | `or al,al` at `0x87CF`; `jnz 0x87EA` at `0x87D1` not taken (call `0x8624` returned 0) |
| `0x87E0`, `0x87E3` | output (`bp+6`) | +0, +2 | ax | `xor ax,ax` | same gate |
| `0x88E8` | status | +0 | ax | `xor ax,ax` | `cmp al,[bp+14]` at `0x88DE`; `jz 0x890A` at `0x88E1` not taken (id differs) |
| `0x88F0`, `0x88F3` | output | +0, +2 | ax | `xor ax,ax` | same gate, not taken |
| `0x8924`, `0x8927` | output | +0 (ax), +2 (dx) | ax, dx | the allocator's return: `call 0x0AF8:0x023F` at `0x891C` | same gate, taken: `jz` to `0x890A` |

- **Output is NULL** on the failure path (`0x87E0`) and on the id-mismatch path (`0x88F0`). **Output is the allocator's
  returned far pointer** only on the id-match path (`0x8924`/`0x8927`).
- The store census is exact: the probe finds these eight stores and no others through `bp+6` or `bp+10`.
- After the return, the output variable is not written by the RLE decoder (`0x8566` contains no `es`-prefixed store
  at all). So the output far pointer after the body returns is the allocator's pointer, not an advanced cursor.

## The id gate and the record read (file bytes)

The body's TOC loop reads one 9-byte record per pass through the DOS read wrapper `0x0AF8:0x14FB`, in this order:

| Read site | Destination | Count | TOC field (by read order) |
| --- | --- | ---: | --- |
| `0x87FE` | `[bp-49]` | 1 | id (u8) |
| `0x881C` | `[bp-48]` | 4 | offset (u32) |
| `0x883A` | status var (`bp+10`) | 2 | u16, the first after the offset |
| `0x8858` | `[bp-44]` | 2 | u16, the second after the offset |

The read order matches `parse_dax`'s `<BIHH` (id, offset, raw, comp) and the body's own checks (below). The match
is `cmp al,[bp+14]` on the record id (AL loaded from `[bp-49]`, `0x88A9`/`0x88DB`). So the non-NULL output needs
the **TOC record's id byte to equal the caller's `[bp+14]` byte**.

The compare follows the reads directly on every PoR record. Gate C (`cmp [bp-44],0x8CA0` at `0x8862`, `jbe 0x88A9`
at `0x8867`) skips the clamp block `0x8869`–`0x88A8` whenever the comp count is at or below `0x8CA0`. The clamp block
holds the `"tempsize "` literal, a `0x0AF8:0x1366` field and a far call to `0x0899:0x0000`. The pinned comp counts
top out at 982 (`0x3D6`), so no PoR record reaches that block. The clamp block is not decoded beyond its bytes.

On the match path the allocation size is the status word the read just wrote (`0x8919`, `es push [di]`). The
caller's status is therefore the TOC's first u16 after the offset, which is the raw size on the GoldBox-style TOC
order the probe checks against all 29 PoR blocks: every block's raw size is `1026 = 0x402`, the fill's gate.

## Output contents (file bytes, with a memory-present helper set)

On the match path the body:
1. calls `0x8077`, which allocates `comp` rounded up to a multiple of 8 and stores the far pointer in `DS:0x557E`
   (its bytes: `and ax,0xfff8`, `call 0x0AF8:0x023F`, `es mov [di]`/`[di+2]`);
2. allocates the output with `0x0AF8:0x023F`, size = status (`0x8919`, `0x891C`);
3. seeks (see below), then reads `comp` bytes into `DS:0x557E` through `0x0AF8:0x14FB` (`0x895D`);
4. calls the near RLE decoder `0x8566` with four far-pointer arguments: the input variable (`DS:0x557E`), the output
   variable, the comp count `[bp-44]`, and the status variable. `0x8566` ends in `retf 0x10`.

The decoder's control rule is read from its own compare immediates at fixed offsets (`0x858A` `cmp al,0`, `0x858E`
`cmp al,0x7E`, `0x85CB` `cmp al,0x81`, `0x85CF` `cmp al,0xFF`):
- controls `0x00` to `0x7E` copy `c+1` literal bytes (`inc ax` after `cbw`, via `0x0AF8:0x1685`);
- controls `0x81` to `0xFF` repeat the next byte `256-c` times (`cbw; neg ax`, via `0x0AF8:0x16A8`);
- controls `0x7F` and `0x80` fall through to a no-op. The body does not decode them.

This is the rule `tools/por_map.py` `rle_decode` applies, except for `0x7F`/`0x80`, where `rle_decode` reads a literal
or a repeat. The probe checks the two on all 29 pinned PoR blocks: the body rule equals `rle_decode` on 29 of 29, with
no undefined control hit. A synthetic stream with `0x7F` shows the divergence (test).

So **if** the compressed bytes are the matched record's block, the output is the RLE decode of that block. The
decoder's loop compares a running counter with the word at its comp-count argument (`cmp ax,es:[di]`, `jnb`, at
`0x8614`). The body does not check the decoded length against the raw size, and the counter's meaning is not
identified. The probe does not establish that the decode fills 1026 bytes at run time.

## The seek (file bytes; the term is not established)

On the match path, before the read, the body calls `0x0AF8:0x1563` with the 32-bit sum `[bp-309] + [bp-48]`
(`mov ax,[bp-309]`, `xor dx,dx`, `add ax,[bp-48]`, `adc dx,[bp-46]`, `push dx; push ax`). The probe's trace of
`AX` before the add:
- `[bp-309]` has **no store in the body**. Its references are two loads (`0x88C5`, `0x8931`) and one `lea` at
  `0x87B9`, which passes its address to the near routine `0x8624`, a few instructions before the call at `0x87CC`.
- So `[bp-309]` is an output of `0x8624`, and the probe did not decode that routine's store. A data-section base
  of `2 + TOC bytes` (the `base` that `por_map.parse_dax` returns) would fit, but this is a hypothesis: it is not
  checked here.

## Archive name and requested id (what the bytes do not fix)

- **Name pieces.** The fill passes `"GEO"` (`P20`, copied with count `0x14` at `0x8774`) and `".dax"` (`P16`, `0x8787`)
  into the body's frame (`[bp-21]`, `[bp-42]`). On the normal path the name buffer `[bp-573]` is built by a copy of the
  `DS:0x547C` literal (`0x87A0`, `DS` not established), then two `0x0AF8:0x0B98` calls, each pushing a source
  (`[bp-21]` then `[bp-42]`) after the destination. The copy helper pops only its source, so the destination stays on
  the stack (the pattern the caller-frame probe reads for the fill). The `0x0B98` append is not decoded. The leftover
  destination would be consumed by the open routine `0x8624` (`retf 0x14`). That reading is derived from the pop
  pattern, not observed.
- **The `"tempsize "` literal is on the clamp path, not the normal one.** `CS:0x070C` (`0x888B`) is the Pascal string
  `"tempsize "` (9 bytes). It is at file `0x8763` and the mapped bytes agree in both pinned dumps (linear `0x20D8C`).
  It sits inside the clamp block (gate C), which no pinned record takes. It is not part of the normal name.
- **The `DS:0x547C` prefix** cannot be placed: the `DS` value is not established by these bytes.
- **The archive digit** is not in any literal the normal path copies. No number selecting `GEO1`..`GEO8` is fixed,
  and whether `[bp-573]` is the name the open routine opens is not established.
- **The requested id** is `[bp+14]`. The fill passes a byte from its own argument; the stub-7 callers pass a local and
  a DGROUP-pointer byte (see the buffer-fill probe). No caller value is fixed here.

## Mapping table (structure, not a block mapping)

The eight pinned GEO archives hold 29 TOC records, and all 29 ids are distinct across the archives. So an id names at
most one `(archive, record)` pair, **given the archive**. The archive is not established, so the probe reports the
lookup table and nothing more: `toc.id_archive_lookup` in the JSON. It is not a mapping from a requested id to an area
or a block.

## Helpers and their memory placement

Module helpers (segment `0x0AF8`, base `0xAC76`, the routine-B base from the copy-helper probe) and near callees (the
body's segment, file-contiguous with the body) are each placed in both dumps by a masked match (the
segment-literal rule, load `0x1866`). Every one places uniquely at its expected file offset in both dumps:

| Callee | File | Bytes establish | Not established |
| --- | --- | --- | --- |
| `0x0AF8:0x14FB` | `0xC171` | INT 21h at `0xC19F`; `mov bl,0x3F` and `mov bl,0x40` select read or write | the handle, destination and count mapping beyond the pushes above |
| `0x0AF8:0x023F` | `0xAEB5` | one word argument; near call into the module; `retf 2` | the near allocator it calls |
| `0x0AF8:0x1563` | `0xC1D9` | an INT 21h site at `0xC1FE` | which DOS function it runs (the seek is the body's order, not a decoded function) |
| `0x0AF8:0x1685` | `0xC2FB` | `rep movsb`, `retf 10` (the copy-helper identity) | — |
| `0x0AF8:0x16A8` | `0xC31E` | `rep stosb`, `retf 8` (fill) | — |
| near `0x8077` | `0x8077` | allocates `(comp+7)&~7` through `0x023F`, stores into `[bp+8]`, `retf 6` | — |
| near `0x8566` | `0x8566` | RLE rule (above); `retf 0x10`; no `es` store | — |
| near `0x8624` | `0x8624` | `retf 0x14`; calls `0x0AF8:0x13E2`, `0x1410`, `0x14FB`, `0x1563` | its open call and the name it opens |
| near `0x8057` | `0x8057` | calls `0x0AF8:0x0254` (release, not decoded) | — |

## Not established

- The archive opened: the name buffer is built from the `DS:0x547C` literal (DS unknown), `"GEO"` and `".dax"`. No
  archive number is fixed, and the open routine `0x8624` (which takes that buffer as a leftover argument) is not decoded.
- The requested block id: `[bp+14]` is a caller byte the bytes do not fix.
- That the seek lands on the matched record's data: the `[bp-309]` term is an output of `0x8624`, not decoded.
- The clamp block (comp above `0x8CA0`): its `"tempsize "` literal, the `0x0AF8:0x1366` field and the far call
  `0x0899:0x0000` at `0x88A4` are not decoded. No pinned record reaches it, so nothing in this probe depends on it.
- Whether `[bp-49]` (the id compared at `0x88DE`) is still the record id at the compare: the normal path makes no call
  between the id read at `0x87FE` and the compare, so the byte is the read's, but the read helper's own writes are
  not decoded beyond its INT 21h site.
- The DOS open call and its file name (`0x8624` and its callees `0x13E2`, `0x1410` are not decoded).
- Whether `0x8077`, `0x14FB` and `0x8566` run as decoded, and with which arguments at any instant.
- The contents of the output buffer at any instant. No dump holds a decoded GEO block (see the buffer-fill probe).
- Any GEO block identity, area mapping, descriptor, event, plane 2 binding or playability.

## Evidence labels

- **File-byte.** The eight stores, their gates and provenance; the four TOC reads and their order; the id compare and
  its branch; the allocator and its argument; the RLE control compares and the copy and fill calls; the seek's add
  and its `[bp-309]` slot; the literals `"tempsize "` (CS) and the `DS` offset; the helper bytes listed above.
- **Memory-dump, unknown instant.** The helper and near-callee placements in both dumps; the `"tempsize "` literal in
  both dumps. Neither says the code runs.
- **Derived.** The store census equality; the read order's match to `parse_dax`'s `<BIHH`; the RLE agreement on 29 blocks;
  the TOC id uniqueness; the 1026 raw sizes; the `0x402` gate.
- **Not established.** The list above.

## Next discriminating observations

The probe lists these as `next_discriminating_observations` in its JSON.

1. A live capture at the compare `0x88DE` (`cmp al,[bp+14]`), for each record scanned: AL (the record id), `[bp+14]`
   (the requested id), `[bp-44]`, `[bp-48]` and `[bp-309]`. This fixes the requested id and the seek term together.
2. A live capture of the DOS open call's file name and handle (INT 21h reached through `0x8624`), to fix which GEO
   archive the name selects, and whether the `"tempsize "` literal is part of it.
3. A live capture of the output far pointer, the status word and the decoded byte count after the return at `0x899B`,
   to see which of the three store paths ran and whether the output is non-NULL.

These need a live run. The probe does not run one.

## Commands and results

```sh
python -I tools/por_geo_loader_output_probe.py
python -m pytest tests/test_por_geo_loader_output_probe.py -q
python -m pytest tests/test_por_geo_loader_target_probe.py tests/test_por_geo_loader_caller_frame_probe.py tests/test_por_geo_buffer_fill_probe.py -q
```

- Probe: `wrote data/work/por-geo-loader-output-probe (stores_match=True, rle_equal=29/29,
  status=archive-and-id-not-established)`, exit 0. About 1 second.
- `tests/test_por_geo_loader_output_probe.py`: **41 passed**, none skipped (the 11 retail tests ran against the pinned
  install and both dumps).
- Neighbouring suites (target probe, caller-frame probe, buffer-fill probe): **65 passed**, unchanged code.

## Pins and inputs

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

| Dump (`ram-000000-100000.bin`, base 0) | SHA-256 (prefix) |
| --- | --- |
| `data/work/por-live-memory-pid34644` | `f8191750ea6c672e` |
| `data/work/por-wheel-live-capture` | `3788787cd795f1f5` |

GEO archives: `GEO1.DAX` to `GEO8.DAX` in `data/work/por-geo-run/POOLRAD` (resolved by `por_map.resolve_geo`), with the
SHA-256 prefix of each recorded in the JSON. Install: `data/work/por-geo-run/POOLRAD` (or `OPENUA_POR_INSTALL`).

## Files and side effects

- New, untracked (for the parent to review and commit): `tools/por_geo_loader_output_probe.py`,
  `tests/test_por_geo_loader_output_probe.py`, `docs/por-geo-loader-output-probe.md`.
- New, ignored output: `data/work/por-geo-loader-output-probe/por_geo_loader_output_probe.json` and
  `por_geo_loader_output_probe_report.md`. Exploratory scratch scripts used while reading the bytes are in
  `data/work/por-geo-loader-output-probe-scratch/` (ignored; safe to delete).
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, the GEO archives, and the existing helpers it imports
  (`por_loadpieces_handler`, `por_geo_loader_target_probe`, `por_overlay_group_map`, `por_map`).
- No edits to existing source, tests, `por_map.py`, the pipeline, or the converter docs. No emulator, GameLink, DOSBox,
  codewheel, retail-file write, or GoldBox access. No CoK rule or address is used for PoR; the control rule and the
  TOC order are checked against PoR's own archives and PoR's own `por_map` decoder.

## Not claimed

- No archive identity, no requested-id mapping, no GEO block, no output-contents identity, no plane-2 consumer, no
  transform, no descriptor-to-event mapping, no area mapping, and no execution at any instant.
- No segment-base model beyond the `0xAC76` module base for segment `0x0AF8` and the load `0x1866`, and the body's own
  contiguous segment for near callees (both checked in the dumps).
