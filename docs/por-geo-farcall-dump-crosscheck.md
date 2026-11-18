# PoR GEO far-call candidate dump cross-check

**Status: capture-scoped diagnostic. `playable: false`; no GEO binding is established.**
The cross-check compares conditional far-call candidates from the static census with
far-call segment words and target windows in two existing RAM dumps. A mapped byte
window establishes memory presence only. It does not establish execution, reachability,
or that the GEO loader ran.

## Retail inputs and method

The run used the pinned Pool of Radiance files:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

The static census (`tools/por_geo_farcall_census.py`) reports 181 conditional
far-call candidates to the GEO loader stub at START.EXE `0x3E0C`; it found no
direct near calls to the GEO body at GAME.OVR `0x2F6FF`. For each dump, this
probe maps overlay groups using `tools/por_overlay_group_map.py`, reads the
live segment at each mapped candidate callsite, computes the observed
16-bit relocation delta, and compares the live target window with the stub.

## Results

Both dumps are 1 MiB snapshots covering `0x00000..0xFFFFF`. Their content hashes
and short capture identifiers are:

| Capture id | SHA-256 | Mapped groups | Candidate owner rows observed | Observed delta matches candidate constraint | Target windows matching GEO stub |
| --- | --- | ---: | ---: | ---: | ---: |
| `f8191750ea6c` | `f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895` | 16 / 34 | 90 / 181 | 0 | 0 |
| `3788787cd795` | `3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa` | 16 / 34 | 90 / 181 | 0 | 0 |

All 90 mapped candidate callsites in each dump have observed delta `0x1866`.
For those mapped sites, that observed delta does not satisfy the candidate's
required-delta constraint, and none of the resulting target windows matches
the GEO stub bytes. The remaining 91 candidate rows belong to absent or
unmapped groups and remain unobserved. This does not rule out candidates in
those groups.

## Limits

- The conclusion is limited to these two captures and the 90 mapped candidate
  callsites in each. It is not generalized to absent overlay groups.
- The static candidates depend on the paragraph-aligned MZ image model described
  in `por-geo-farcall-census.md`; this cross-check does not independently prove
  that model.
- The dump files have no established atomic-snapshot guarantee. A target window
  match, if present, would still show only bytes in memory, not a call or its
  reachability.
- No archive, block, area, argument binding, or gameplay mapping is emitted.

## Reproduce

```powershell
$install = 'G:\Games\Pool of Radiance\POOLRAD'
python tools/por_geo_farcall_dump_crosscheck.py `
  --install $install `
  --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin `
  --dump data/work/por-wheel-live-capture/ram-000000-100000.bin `
  -o data/work/por-geo-farcall-dump-crosscheck
```

The command reads the install and dumps and writes path-free JSON and Markdown
only under `data/work/`. Two runs on 2026-11-18 produced byte-identical JSON
and Markdown. The focused tests are `tests/test_por_geo_farcall_dump_crosscheck.py`.
