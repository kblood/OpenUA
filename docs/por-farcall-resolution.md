# Pool of Radiance GAME.OVR far-call resolution: what the stub bytes establish

**Status: STATIC-PROBE-ONLY. `playable: false`.** `tools/por_farcall_resolve.py` reads the
user-supplied retail `GAME.OVR` and `START.EXE` read-only and checks whether the handler's
literal far calls (`9A seg:off`, GAME.OVR:0x19ba) land on Borland VROOMM `CD 3F` stubs. It
reports the stub each call would name, and what the bytes do and do not settle. It does not
choose a resolution model as proven, does not give opcode `0x37` a meaning, does not bind WALLDEF
blocks, and does not emit a module.

Companion to [por-loadpieces-handler.md](por-loadpieces-handler.md), whose "next evidence" item 1
(parse the stub or fixup table) is now partly done here.

Related: [por-wall-group29-target-probe.md](por-wall-group29-target-probe.md) reads the group at
fileofs `0x2E8F7`, whose stub run is at header+`0x17`. This scanner now reports that group as a
**partial** candidate (see "Stub-group alignment" below). It does not establish a caller, and it
does not establish the WALLDEF mapping.

Follow-up: [por-int3f-handler.md](por-int3f-handler.md) locates the START.EXE INT 3Fh install sites
that the stubs enter through. It does not establish the handler's CS base or stack effect, so the
stub-to-procedure mapping in this document is unchanged.

---

## Pinned sources

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched their pins on the retail run. After the runs both were re-hashed and still match, and
their modification times are unchanged (2021-03-21). The tool opens them read-only.

## Usage

```sh
python3 tools/por_farcall_resolve.py --install "PATH/TO/POOLRAD" \
    -o data/work/por-farcall-resolve/retail
```

Outputs: `por_farcall_resolve.json` (schema `openua.por-farcall-resolve` v1, `playable: false`) and
`por_farcall_resolve_report.md`. Stdlib-only. It refuses a file that does not match its pin unless
`--allow-unpinned` is given, which marks the output as not retail evidence. It refuses an output
folder inside the install. Exit `0` clean, `1` output written with a diagnostic, `2` named refusal.
A far call that lands on a partial group's stub, well-formed or malformed, is a diagnostic (exit `1`).
The retail run's exit is still `0`: no handler far call lands there.

---

## What the retail bytes establish

1. **The resident image is an MZ at file `0x200`.** `cparhdr = 32`, `nreloc = 0`. The overlay
   error strings (`Overlay error, program abort!`, `Please insert startup disk.`) are in the
   resident image, so `START.EXE` is the VROOMM resident.

2. **A stub group is a descriptor header plus a run of stubs.** The header is `CD 3F 00 00`, then
   `fileofs` (dword), `codesz`, `fixupsz`, `jmpcnt` (words). The stub run holds `jmpcnt` five-byte
   stubs, each `CD 3F <proc_off word> 00`. The run starts at header+`0x16` for the original groups
   and at header+`0x17` for the group at `0x2E8F7` (and for others, listed below). Each header is
   scored at both distances. A group is accepted only if every stub in its run has that shape at one
   distance; a run with a strict majority of such stubs is a partial candidate.

3. **The group at header `0x45b` is the operand parser's overlay.** `fileofs = 0x74d3`,
   `codesz = 0x221a`, `fixupsz = 0x11a`, `jmpcnt = 25`. Those values match the GoldBox runtime map
   for descriptor 7 (`docs/engine/research/pool-runtime-overlay-map.md`); this is cited, not
   re-derived. Its stub run is `0x471`–`0x4ee`.

4. **Every stub in that group lands on a Borland prologue.** For each of its 25 `proc_off` values,
   `0x74d3 + proc_off` in GAME.OVR begins `55 89 E5` or `55 8B EC`: 25 of 25. The check is
   discriminating: the other accepted groups score 1/2 (four of them) or pass in full, and several
   candidate headers are rejected because their stub runs are malformed. The 0x74d3 group is the
   only group the handler's far calls reach, and it passes in full.

5. **Two of the handler's eleven far calls land exactly on group-0x74d3 stub starts.** Under the
   zero-skew image address `hdr + seg*16 + off` (file `0x200 + 0x2b*16 + off`):

   | Call site (GAME.OVR) | seg:off | Image address | Stub | proc_off | GAME.OVR target | Target prologue |
   | --- | --- | --- | --- | ---: | ---: | --- |
   | `0x19c3` | `2b:2a` | `0x4da` | group 0x74d3, index 21 | `0x1df0` | `0x92c3` | yes |
   | `0x19da` | `2b:25` | `0x4d5` | group 0x74d3, index 20 | `0x1cc3` | `0x9196` | yes |

   Both proc targets are real functions with Borland frames: `0x92c3` begins
   `55 89 e5 83 ec 0a`, and `0x9196` begins `55 89 e5 c4 7e 06`.

6. **The CoK `-1` skew does not hold here.** With `hdr + seg*16 + off - 1`, both `2b` calls miss the
   stub grid (`0x4d9` and `0x4d4` are stub trailing bytes). The probe reports this as
   `skew_minus_1_is_stub: false` for both. The GoldBox CoK resolver's skew is therefore not
   carried over to PoR.

7. **The operand parser is stub index 2 of group 0x74d3 (proc 0).** Its stub is at image
   `0x47b`, file `0x47b`, bytes `cd 3f 00 00 00`. No far call in the handler hits `0x47b`
   under the zero-skew model, so the handler's far-call set does not include the parser's stub.

8. **Every segment word of the eleven far calls is listed in overlay 3's fixup table.** The table
   is the `fixupsz` bytes after the code (`0x4253`, 402 sorted 16-bit words), and each entry is the
   location of a segment-valued word. The eleven seg words are at body offsets `0xc80`, `0xc97`,
   `0xce4`, `0xd10`, `0xd1b`, `0xd34`, `0xd5b`, `0xd67`, `0xd93`, `0xdd7`, `0xde4`, and all eleven
   are listed. The three offset words checked (`0xc7e`, `0xc95`, `0xd0e`) are not listed. So the
   literal segment values are loader-fixed-up selectors. The file literal is the link-time value.
   The fixup table does not say which target each entry refers to.

9. **Nine of the eleven far calls do not land on a stub.** They are `3d5:43`, `af8:b0b`, `3e9:25`,
   `3d5:3e` (four sites), `ba:27d9`, and `ba:767`. Under the zero-skew model the five `3d5` calls
   land on image addresses `0x3f8e` (four calls) and `0x3f93` (one call), which are not stub starts.
   The probe does not check whether those addresses begin a function. So the zero-skew model explains
   two of the eleven calls and does not explain nine.

## Stub-group alignment and partial candidates

Each descriptor header is scored at header+`0x16` and header+`0x17`. The rules:

- **Accepted** (`status: well-formed`): every stub in the run is well-formed at one distance. The
  row records `stub_delta` and a per-slot `stub_valid` list.
- **Partial** (`status: partial`, in `partial_groups`, never in `groups`): at least 2 stubs and a strict
  majority are well-formed at one distance, and that distance beats the other. This threshold is a
  judgement, not a derived bound. A partial group is a candidate, not a verdict.
- The current zero-only tail criterion is not validated as a VROOMM rule. A separate static probe
  found ten nonzero tails, all on the last slot of partial groups, but could not determine whether
  the byte is a field or invalid data; see [por-stub-tail-byte.md](por-stub-tail-byte.md). The
  scanner classifications below describe the criterion it applies, not a proven runtime format.
- A malformed slot is never a stub in either list. A call that lands on one is `malformed-stub`, with
  no target. A call on a well-formed slot of a partial group is `partial-stub-candidate`, with a
  diagnostic saying it is not a resolved target.
- At most one row per header. The two distances cannot both be fully well-formed at one header (slot 0
  at `+0x16` needs `3F` at header+`0x17`; slot 0 at `+0x17` needs `CD` there). At most one row per
  fileofs across both lists: the first accepted header wins, then the first partial header.

**Retail result** (the same bytes; the scan has no other input):

- Accepted at `+0x16`: the 19 groups the scanner accepted before, unchanged. The operand parser's
  `0x74d3` group (header `0x45b`, stub run `0x471`) is 25 of 25 at `+0x16`, and it is not a partial.
- **Accepted at `+0x17` (new in this scanner; all stubs well-formed):** fileofs `0x2db87` (header
  `0x3d44`, 3 stubs), `0x2de38` (`0x3d6b`, 3), `0x31a6c` (`0x3ee9`, 6), `0x3211f` (`0x3f2c`, 2 stubs,
  1 of 2 prologues), `0x32235` (`0x42c2`, 3). These five now appear in `groups`, so every probe that
  calls `scan_groups` sees them. None of the handler's eleven far calls lands on them, so the
  classifications in the table above are unchanged. Whether they are real overlay descriptors is not
  established here.
- **Partial under the scanner's zero-only tail criterion** (10 rows; tail semantics unresolved):

  | Header | fileofs | Stub delta | Well-formed | Malformed slot(s) |
  | ---: | ---: | --- | ---: | --- |
  | `0x586` | `0xec5b` | `+0x16` | 116 of 117 | 1 |
  | `0x8cd` | `0x1997f` | `+0x16` | 3 of 4 | 1 |
  | `0x979` | `0x2103a` | `+0x16` | 12 of 13 | 1 |
  | `0xbb8` | `0x2aa87` | `+0x16` | 4 of 5 | 1 |
  | `0xbed` | `0x2aeea` | `+0x16` | 22 of 23 | 1 |
  | `0x3d00` | `0x2c8cf` | `+0x16` | 7 of 8 | 1 |
  | `0x3d92` | `0x2e0ce` | `+0x17` | 7 of 8 | 1 |
  | `0x3dd7` | **`0x2e8f7`** | **`+0x17`** | **7 of 8** | **slot 7** (trailer `0x27`) |
  | `0x3e28` | `0x2fb52` | `+0x17` | 6 of 7 | 1 |
  | `0x3e68` | `0x3073a` | `+0x17` | 19 of 20 | 1 |

**The group at `0x2E8F7` (header `0x3DD7`).** Its stub run is at `0x3DEE`, at `+0x17`. Stubs 0–6 pass
the scanner's zero-tail test; slot 7 at `0x3E11` has tail `0x27` and is classified malformed by that
test. The tail probe does not establish that this byte invalidates the slot, so slot 7's status as a
runtime stub remains open. Stub 5
(file `0x3E07`) names proc `0x05FD`, which is file `0x2EEF4`, a Borland prologue. That is a partial
entry candidate. No handler far call lands on file `0x3E07`, and no decoded in-group call reaches
`0x2EEF4` (see [por-wall-group29-target-probe.md](por-wall-group29-target-probe.md)). **The stub does
not establish a caller, and it does not establish the WALLDEF wall mapping.**

## What the bytes do not establish

- **Which resolution model is correct.** The zero-skew image model is an assumption. It is
  supported by the exact stub-start hits and the 25/25 prologue group, but nine of eleven calls
  do not fit it, so the other segments are not resolved and may use a different convention.
- **Whether `2b:2a` and `2b:25` reach stub 21 and stub 20, rather than stubs 22 and 21.** A skew
  of +5 also puts a call on a stub start. Exact stub-start alignment does not exclude it. Only the
  convention that a call lands on the stub's first byte, which is the one assumed, selects index 21.
- **That the handler reaches the parser.** These two resolved calls go to group-0x74d3 procs
  `0x1df0` and `0x1cc3`, not to proc 0. Under the zero-skew model, the handler's calls do not
  reach the parser stub. This is a structural statement, not a runtime one.
- **What procs `0x1df0` and `0x1cc3` do**, or what opcode `0x37` does.
- **That a partial group is one overlay, or that anything calls it.** The `0x2E8F7` partial's stub 5
  is a candidate entry. Slot 7 fails the scanner's zero-tail criterion, but the tail probe does not
  decide whether the slot is invalid. The `+0x16` partials (`0x586` and others) are candidates on the
  same footing.
- **That the five new `+0x17` accepted groups are real descriptors.** They pass the same well-formed
  test as the `+0x16` groups, but they are small (2 to 6 stubs), and no retail call is tested against
  them beyond the eleven handler calls.
- **Whether the handler runs for opcode `0x37` at runtime.** The GoldBox corpus has no runtime hit
  for `0x1df0` or `0x1cc3`; its only PoR CS:IP confirmation is the parser route.
- **The fixup-table semantics.** Which target each fixup entry refers to, and how the loader rewrites
  the segment word, are not decoded here.

## Consequence for the handler probe

`docs/por-loadpieces-handler.md` says the far-call targets are unresolved and that the handler's
`2b` calls might be the parser. The resolved stubs point the other way: under the zero-skew model,
the `2b` calls go to overlay 0x74d3's procs `0x1df0` and `0x1cc3`, not to the parser at proc 0.
The handler's "three-iteration loop of `2b:25` calls" is therefore a loop of calls into overlay
0x74d3 at proc `0x1cc3`, which is a different question from the parser question. The handler doc's
claim that these calls are "signature-compatible with the parser" is weakened: the parser is not
among their targets.

## Next evidence that would settle it

1. A runtime CS:IP breakpoint, or INT 3Fh trace, at the handler's `2b:2a` call (`0x19c3` in the
   overlay), recording the stub's proc word and the overlay index actually loaded. This would test
   the zero-skew model and the index 21 choice at once.
2. The fixup-table semantics: which segment each listed word refers to, and how the overlay manager
   rewrites it. Needed before the nine non-stub calls can be resolved.
3. Only then, opcode `0x37` semantics. No WALLDEF binding should follow from this document.

---

## Tests

`tests/test_por_farcall_resolve.py` runs on synthetic bytes (MZ header, descriptor header, stub
run, overlay with prologues, fixup table). It covers stub resolution, the skew check, malformed
stubs, the fixup membership check, the parser stub called and uncalled, refusal of unpinned files,
output-location refusal, and determinism. Synthetic tests added with the alignment work cover:
`+0x16` and `+0x17` acceptance, the off-alignment call, partial groups and their status, malformed
slots (never classified as stubs), the duplicate-fileofs and cross-list suppression, and the
mutation of a slot between accepted, partial, and malformed.

The retail tests run only when `OPENUA_POR_INSTALL` names the install, and pin the facts above. The
new ones pin the `0x2E8F7` partial (stub 5 as candidate, stub 7 malformed), the `0x74D3` control
staying accepted at `+0x16` (25 of 25), and the five new accepted `+0x17` fileofs.

Result: `OPENUA_POR_INSTALL='G:\Games\Pool of Radiance\POOLRAD' python -m pytest -q
tests/test_por_farcall_resolve.py`: 41 passed. Without the variable: 36 passed, 5 skipped.
