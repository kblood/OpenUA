# Pool of Radiance GAME.OVR group-29 load: one debugger run (2026-11-17)

**Status: one boot-only run. `playable: false`. `mappings: []`. Not an area mapping.**

Companion of [por-geo-capture-aid.md](por-geo-capture-aid.md). The aid defined the checklist; this
note records what one DOSBox-X debugger run observed, and where it stopped.

## What was observed (one run)

Temporary copy of the retail `POOLRAD` folder, all pins matching before and after. DOSBox-X
`2026.07.02` (pin `3f548183…4d509`), debugger, `DEBUGBOX START.EXE`, `LOADFIX -64`, breakpoints
`BPINT 21 3D`, `BPINT 21 42`, `BPINT 21 3F`, `BP 33E7:0E08`, `RUN`. No gameplay input was sent.

| Item | Observed | Check |
| --- | --- | --- |
| Open of `game.ovr` (AH=3D, mode 00/02) | repeated per overlay load | name read with `D DS:DX` |
| Seek to absolute `0x2E8F7` on that handle (AH=42, AL=00, CX:DX=0002:E8F7) | stop 19 | matches group 29 seek |
| Read of `0x120B` bytes (AH=3F, CX=120B) to `33E7:0000` | stop 20 | matches group 29 `code_size` |
| Dump at `33E7:0000` after the read | `55 89 E5 81 EC 0A 01 8A 46 0A 98 2D 05 00 88 46` | identical to retail bytes at `0x2E8F7` (16 of 16) |
| Overlay seek sequence, all 36 seeks (header + 35 descriptors) | reproduced | matches the GoldBox overlay map offsets |
| Breakpoint `33E7:0E08` (retail `0x2F6FF`, the WALLDEF wrapper, not the GEO loader) | not reached | breakpoint never fired |
| GEO open (`GEO<n>.DAX`) and GEO seek | not reached | no GEO open occurred during boot |

**Superseded (2026-11-18).** The version-1 check of this observation reported `Owner CS:IP: 33E7:0E08`,
`Owner stop observed: False`, `GEO seek observed: False`, `TOC block bound: False`, `mappings: []`, and
exited 1. That result tested the WALLDEF wrapper (`0x2F6FF`), not the GEO fill, so it is superseded. The
current aid (schema version 2) targets the GEO fill and refuses version-1 observations. Re-running
`por_geo_capture_aid.py check --observation data/work/por-geo-run/observation-run3.json` now exits 2 with
`schema_version 1 targeted the WALLDEF wrapper`. The overlay-read rows above are this run's own
observations and the retarget does not change them. No checker result stands for the owner or the GEO
fill in this run.

## What this does and does not establish

- **Establishes (this run only):** the group-29 overlay read lands at `33E7:0000` in this run,
  with the file bytes at `0x2E8F7`. The GoldBox candidate destination `23A5` (snapshot 7, another
  route) does **not** hold for this run. The load segment is route- and run-specific.
- **Does not establish:** any GEO binding, any TOC block, the GEO fill's behaviour or its argument
  `[bp+6]`, or any area meaning. No block is bound.

## Blocker

Neither the GEO fill (`0x2F9BE`) nor the GEO open/seek is reached during boot. The run stops at the title
phase after the overlay sequence and waits for input. Reaching the GEO fill and the GEO open needs
an in-game route (keyboard input into the game). This debugger helper injects text into the
debugger console, not into the game's keyboard buffer, and the only documented key-delivery
route is the GameLink client, which is outside this run. No input route was verified, so the
run stopped here.

Correction (2026-11-18): `33E7:0E08` (`0x2F6FF`) is the WALLDEF wrapper, reached from START stub 6. It
is not the GEO loader. The GEO fill is `0x2F9BE`, group-relative `0x10C7`, which is `33E7:10C7` under
the same buffer-0 placement. That placement is predicted, not observed. This run's `BP 33E7:0E08`
therefore tested the wrong routine, and the GEO open it was meant to pair with is not evidence about
the GEO fill.

**Not observed in this run: a stop at the GEO fill (`0x2F9BE`, predicted `33E7:10C7`).** Its entry is
UNESTABLISHED. The only static candidate is START stub 7 at `0x3E11` (`CD 3F C7 10 27`, proc `0x10C7`),
and its fifth byte `0x27` differs from the `0x00` the RAM dumps record there (see
[por-ecl-21-stub7-dump-probe.md](por-ecl-21-stub7-dump-probe.md)). Treat the predicted entry as a
candidate. It is not an established entry, and this run does not establish it.

Next step, when a verified input route exists: repeat the same boot, add `BP 33E7:10C7` (GEO fill,
predicted) and `BPINT 21 3D` for a `GEO<n>.DAX` name, and check the GEO fill stop and GEO seek with the
current aid (`tools/por_geo_capture_aid.py`, schema version 2, which targets the GEO fill). Its `plan`
emits the fill breakpoints only with `--load-seg`, each labelled UNVERIFIED. Keep `BP 33E7:0E08` only as
a WALLDEF-wrapper check.
