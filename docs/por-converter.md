# Pool of Radiance -> FRUA converter: status

**Status: eight analysis slices (1 to 8), plus a supplementary ECL census, a pipeline and retail static probes; none is a playable conversion.**

- **Slice 1** (`tools/por_convert.py`): read-only source inventory and a
  normalized-IR skeleton for a decoded PoR workspace.
- **Slice 2** (`tools/por_map.py`): decodes **one Gen1 GEO map block** from an
  explicit DAX file and emits a normalized map and, on request, a **map-only**
  local `.DSN` design. It carries walls and a start cell. It has no events, text,
  monsters, items, art or campaign logic.
- **Slice 3** (`tools/por_ecl.py`): decodes one ECL block's container, header,
  instruction framing and candidate control-flow edges. It does not implement
  instruction semantics, map events, or FRUA equivalence. See
  [`por-ecl-decoder.md`](por-ecl-decoder.md) for evidence and limitations.
- **Slice 4** (`tools/por_walls.py`): a read-only **wall census** across GEO,
  WALLDEF and 8X8D. It binds **no** slot to art. Every slot is unresolved, with
  the reasons recorded. See "Slice 4" below.
- **Slice 5** (`tools/por_8x8d.py`): checks every `8X8D1`-`8X8D8` block against the
  DAX standard-frame rule (17-byte header, 8x8 items, exact length) and decodes
  palette indices only for blocks that pass. Its PNG previews use an assumed palette.
  It binds **no** tile to a slot. See [`por-8x8d-blocks.md`](por-8x8d-blocks.md).
- **Slice 6** (`tools/por_wall_candidates.py`): applies the CoK WALLDEF-to-8X8D
  pairing and raw-index rules as labelled hypotheses, producing local candidate
  previews. The raw-index reading has many out-of-range entries; no PoR art mapping
  is established. See [`por-wall-candidates.md`](por-wall-candidates.md).
- **Slice 7** (`tools/por_index_relation.py`): scores several plausible WALLDEF-byte
  readings (raw; CoK set-offset routing, cited as a hypothesis; naive set-base
  subtraction) against the paired 8X8D block. It reports valid, out-of-range and
  routed-elsewhere counts for each reading and selects none. Counts alone do not
  decide the index rule. See [`por-index-relation.md`](por-index-relation.md).
- **Slice 8** (`tools/por_mapping_gate.py`): applies explicit hard gates (in range,
  non-negative, own bank, and a fixed-bank-0 research assumption) to the slice-7
  readings. A reading is named only when exactly one passes, and then it is marked
  `gate-candidate-unverified`. The retail run is `unresolved` (exit 1): every reading
  fails at least one gate. It binds no tile. See
  [`por-mapping-gate.md`](por-mapping-gate.md).
- **ECL census** (`tools/por_loadpieces_census.py`): scans the ECL archives for
  reachable `LOAD_PIECES` (0x37) instructions in both framing modes. It preserves
  operands and marks the CoK interpretation as a hypothesis; most walks stop early.
  See [`por-loadpieces-census.md`](por-loadpieces-census.md).
- **GEO-loader far-call census** (`tools/por_geo_farcall_census.py`): decodes
  bounded paths in parsed GAME.OVR groups and checks far-call operands against
  their fixup tables. The pinned retail run found 181 arithmetic candidates but
  no established caller or GEO mapping. See
  [`por-geo-farcall-census.md`](por-geo-farcall-census.md).
- **GEO far-call dump cross-check** (`tools/por_geo_farcall_dump_crosscheck.py`):
  compares those conditional candidates with two captured RAM dumps. The 90
  mapped sites per dump have delta `0x1866`, with no candidate-constraint match
  or target window matching the GEO stub; 91 candidate rows remain unobserved in
  absent or unmapped groups. This is capture-scoped memory evidence, not proof
  that a call ran. See
  [`por-geo-farcall-dump-crosscheck.md`](por-geo-farcall-dump-crosscheck.md).
- **Pipeline** (`tools/por_pipeline.py`): one repeatable run over a user install:
  GEO map-only designs (optional plan: one area per design, or a multi-area
  map-only design, see below), and with `--with-ecl-text` the ECL string
  census plus the diagnostic-unaccepted text decode. Nothing is accepted as text
  and nothing is playable. See "Pipeline run" below.
- **Test-only all-GEO container** (`tools/por_geo_all_map_group.py`): takes all 29
  decoded retail GEO blocks into one grouped `TGALLMAP.DSN` with invented area ids.
  It is a container check, not a conversion. See
  [`por-geo-all-map-group.md`](por-geo-all-map-group.md) and "All-GEO grouped
  container check" below.

Every output says what it is. Each file carries `"playable": false`, or a
MAP-ONLY banner in the report. A test-only AREATEST sweep has now read and
parsed all 29 generated GEO files through OpenUA's real loader in Hatari. It
does not validate a playable module or the maps' authored behavior. See the
all-GEO test section and "What is not claimed" below.

This follows the proposal in the GoldBox repository
(`docs/engine/research/pool-of-radiance-to-frua-module-plan.md`), adapted to
OpenUA. That document is a plan, not a spec. It is not reproduced here.

---

## Retail static probes (GAME.OVR, START.EXE, WALLDEF)

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. No events are emitted.**
These tools read the pinned retail install read-only. They are not converter slices,
and none of them feeds `por_map.py` output. Labels from CoK, DoK and Greybox are
cross-checks only; none of them is used as a PoR fact.

- **ECL dispatch value 0x2D** (`tools/por_ecl_opcode2d_probe.py`, see
  [`por-ecl-opcode2d-probe.md`](por-ecl-opcode2d-probe.md)). The control flow of the
  routine at `GAME.OVR:0x3A15` is closed (16 paths, one `retf`). The dispatcher's
  `0x2D` arm calls it. Its far callees are fixup-listed, and the fixup delta is not
  established, so none is mapped. Whether the dispatch key `[DS:0x6F7F]` is the ECL
  opcode byte is not established. Opcode semantics are not assigned.
- **ECL menu framing (0x15/0x2B)** (`tools/por_ecl_menu_framing_probe.py`, see
  [`por-ecl-menu-framing-probe.md`](por-ecl-menu-framing-probe.md)). The pinned
  classifier defaults both opcodes to a one-byte advance with zero classifier-parsed
  operands. Their handlers also push 3 and 2 to far helpers `2B:2A` and `2B:25`,
  whose targets and stream advances remain unresolved. These facts do not yet define
  the menu framing or assign opcode semantics.
- **ECL opcode 0x21 dispatch** (`tools/por_ecl_21_dispatch_probe.py`, see
  [`por-ecl-21-dispatch-probe.md`](por-ecl-21-dispatch-probe.md)). The dispatcher
  arm has a direct `E8` edge to handler `0x19BA`, which makes eleven far calls.
  Two are VROOMM stubs under the zero-skew model; the other nine have fixup-listed
  segment words and remain model-dependent. No GEO target, argument binding, or
  root reachability is established. The follow-up fixup-residue probe finds that
  none of the eleven far-call offsets can reach the GEO stub under a paragraph-
  aligned resident-image model, for any fixup delta; direct calls to the GEO body
  and runtime reachability remain unexamined.
- **ECL dispatcher cursor (`0x1B`)** (`tools/por_ecl_handler_cursor_probe.py`, see
  [`por-ecl-handler-cursor-probe.md`](por-ecl-handler-cursor-probe.md)). The handler
  increments the cursor once before branching, but one path calls unresolved
  `0x002B:0x008E`; the whole effect remains open. Under the unvalidated MZ-image
  far-call model, that target lands at START.EXE `0x053E` (`00 D1 C5 00 00`), outside
  the accepted and partial VROOMM stub runs. This rejects that model candidate only;
  it does not identify the callee. The dispatcher loop does not call the classifier
  directly, so the 12-byte stream prefix is only a classifier-model diagnostic and is
  not established as the live stream boundary.
- **ECL entry origin** (`tools/por_ecl_entry_origin_probe.py`, see
  [`por-ecl-entry-origin-probe.md`](por-ecl-entry-origin-probe.md)). PoR code parses
  five class-1 header records from vaddr `0x9900` to `0x9914`; retail bytes are
  consistent with that table ending at block offset 22. The loader's source and copy
  behavior are unresolved, and the VM's instruction origin is not established.
- **Overlay fixup loader entry** (`tools/por_ecl_fixup_entry_probe.py`, see
  [`por-ecl-fixup-entry-probe.md`](por-ecl-fixup-entry-probe.md)). The INT 3Fh install
  and handler chain in `START.EXE` (file `0xA7CB`..`0xAAC0`) is byte-checked. Its
  last hop, the `callf [0x8504]` pointer, reaches the loader at file `0xA97E` only
  under the quoted window placement. No contiguous placement makes the program's
  pointers address their targets, so the placement is unresolved. The caller route
  into the chain is not closed. ES at the store `0xAC7B` is not established, since
  routine B has no byte-level caller. The `0x0824` delta is a hypothesis only and is
  not promoted.
- **VROOMM stub groups** (`tools/por_farcall_resolve.py`, see
  [`por-farcall-resolution.md`](por-farcall-resolution.md)). The shared scanner accepts
  only groups whose complete stub run is well-formed. It also lists heuristic partial
  candidates separately; group 29 (`fileofs 0x2E8F7`) is 7 of 8 at `+0x17`, with
  malformed slot 7. Its valid slot 5 names the WALLDEF layout candidate, but no caller,
  runtime target placement, or wall mapping is established.
- **WALLDEF render path** (`tools/por_wall_render_probe.py`, see
  [`por-wall-render-probe.md`](por-wall-render-probe.md)). All 38 retail WALLDEF blocks
  have raw sizes that are multiples of 780 (5 x 156), read from the TOC. No renderer
  caller, slot-to-8X8D index, set or bank, or relocation is established. No wall is
  mapped.
- **START 8X8D layout candidate** (`tools/por_8x8d_loader_probe.py`, see
  [`por-8x8d-loader-probe.md`](por-8x8d-loader-probe.md)). The routine at `0x7180`
  is an EGA rectangle fill with no pixel-source operand, and its bounded decoded
  caller chain selects no 8X8D block or tile. The adjacent `8X8d1` literal remains
  a layout-only candidate; no archive or tile binding is established.
- **8X8D archive-reader candidates** (`tools/por_8x8d_archive_chain_probe.py`, see
  [`por-8x8d-archive-chain-probe.md`](por-8x8d-archive-chain-probe.md)). A bounded
  static trace found a START routine that requests block 201 beside `8X8d1` and a
  VROOMM routine that reads the GEO selector and calls an unresolved loader-shaped
  target. A follow-up entry walk found START's DOS open helper and four DOS read
  sites, but did not connect them to an 8X8D archive; the five unresolved DOS-call
  AH sites and far-call image model remain open. A subsequent direct-jump and
  indirect-transfer census still finds no established caller of START `0x7245`,
  stub `0x42DE`, GAME.OVR `0x32270`, or the open-chain root `0x0A728`; indirect
  table slots remain unlinked. No 8X8D caller, file handle, or DAX block read is
  established. This is a bounded negative, not evidence that PoR never reads 8X8D
  or that these routines cannot run. See
  [`por-8x8d-dos-sites-probe.md`](por-8x8d-dos-sites-probe.md) and
  [`por-8x8d-entry-call-probe.md`](por-8x8d-entry-call-probe.md).
- **Group-29 WALLDEF target** (`tools/por_wall_group29_target_probe.py`, see
  [`por-wall-group29-target-probe.md`](por-wall-group29-target-probe.md)). The one
  runtime run observed a `0x2E8F7` seek and `0x120B`-byte read. The `33E7:05FD`
  placement of the layout candidate is predicted from that run, not observed in the
  CPU. The probe cross-checks the partial stub row and excludes malformed slot 7 from
  its entry walks. It finds no caller and maps no wall.
- **GEO load-site layout** (`tools/por_area_evidence.py`, see
  [`por-area-evidence.md`](por-area-evidence.md)). The GEO load routine's layout owner
  is `GAME.OVR:0x2F6FF`, found by layout only. After the walk bound was corrected, the
  probe also detects a WALLDEF layout owner at `GAME.OVR:0x2EEF4`. That owner is a
  layout candidate only. No reference, caller or art binding is shown. Block-to-area,
  start area and start entry remain unknown.
- **GEO plane-2 observer** (`tools/por_geo_plane2_observe.py`, see
  [`por-geo-plane2-observe.md`](por-geo-plane2-observe.md)). It censuses all 29 decoded
  GEO blocks and records per-cell descriptor-byte distributions, hashes and five labelled
  anchors. It emits no event, zone or mapping. A PoR-specific GoldBox route and the local
  ECL1#18 bytes are consistent with `plane2 & 0x7F` acting as one encounter selector, but
  the loader's source block and an OpenUA event binding remain unestablished. A separate
  dump-backed probe identifies the copy helper and confirms the fill's `block+2` copy geometry,
  but the loader's returned pointer is not tied to a GEO block, so plane 2 is still not claimed;
  see [`por-geo-copy-helper-probe.md`](por-geo-copy-helper-probe.md) and
  [`por-geo-buffer-fill-probe.md`](por-geo-buffer-fill-probe.md).
- **GEO selector filename path** (`tools/por_geo_selector_format_probe.py`, see
  [`por-geo-selector-format-probe.md`](por-geo-selector-format-probe.md)). PoR bytes establish a
  decimal formatter whose leading digit is appended to the `GEO` stem and carried into the
  composed open path, conditional on module/loader/wrapper identities. The DS prefix and runtime
  selector are unresolved, so no archive, block or area mapping follows.
- **GEO source loader target** (`tools/por_geo_loader_target_probe.py`, see
  [`por-geo-loader-target-probe.md`](por-geo-loader-target-probe.md) and
  [`por-geo-loader-caller-frame-probe.md`](por-geo-loader-caller-frame-probe.md)). Existing dumps
  conditionally place the live target `0x2068:0x0716` at START.EXE `0x876D`; that body reads two far
  pointers above the ten explicit shape bytes and returns with `retf 0x12`. A caller-frame walk finds
  eight earlier stack bytes at six of ten call sites, including the GEO fill site, so those six balance;
  four sites remain unknown. This removes the stated prototype conflict but does not prove the target
  identity or execution, and the output is not tied to a GEO block. No plane-2 or descriptor-to-event
  mapping is claimed.
- **Plane-3 door reader branches** (`tools/por_door_reader_branch_probe.py`, see
  [`por-door-reader-branch-probe.md`](por-door-reader-branch-probe.md)). Under the
  still-conditional reader identity, one caller gates forward movement on return
  value `1`; value `0` does not step, while `2/3` depend on unresolved callees.
  Since `1` is also the reader's default, this does not establish the meaning of
  the field or justify a door-flag conversion. The separate INT 3F dispatch-entry
  trace remains unresolved and is documented in
  [`por-door-ds-entry-probe.md`](por-door-ds-entry-probe.md).
- **Plane-3 writer trigger** (`tools/por_door_entry_route_census.py`, see
  [`por-door-entry-route-census.md`](por-door-entry-route-census.md)). The bounded
  decoded-transfer census finds no new route to stub 1 or to the writer/clearer;
  only the six previously known near calls reach the latter two. The four stop
  records are classified as text, an operand, an out-of-range proc entry, or
  fall-through into stub data, so no decoder extension is justified. Candidate
  root `0x0A087` adds no transfer rows. Unknown group proc entries, unwalked bytes and data-driven
  dispatch remain outside the census; the trigger and general door semantics
  remain unresolved.

The module is still map-only and unplayable. Area and start mapping are unknown, and
events, text, art and campaign behaviour are absent.

The OpenUA-local [`por_gamelink.py`](por-gamelink-client.md) provides a guarded
DOSBox-X GameLink v4 client for a future interactive capture. Its protocol checks are
synthetic; no live PoR input, screen or memory capture has been performed with it.

---

## Pipeline run (`tools/por_pipeline.py`)

**Status: map-only pipeline, plus an optional ECL text diagnostic. `playable: false`.**
One run over a user-supplied install. It fingerprints the members it depends on,
decodes every GEO block, round-trips any planned design, runs the loader-equivalent
host checks on each emitted `NAME.DSN` folder, and writes a manifest.
With `--with-ecl-text` it also runs the ECL string census and the
diagnostic-unaccepted 6-bit decode over ECL1..ECL8. Neither stage runs the game,
binds art, or makes a string accepted text.

### Usage

```sh
# map-only (unchanged default)
python3 tools/por_pipeline.py --install "G:/Games/Pool of Radiance" \
    -o data/work/por-pipeline/retail [--plan plan.json]

# map-only plus the ECL census and unaccepted text diagnostic
python3 tools/por_pipeline.py --install "G:/Games/Pool of Radiance" \
    -o data/work/por-pipeline/retail-ecl --with-ecl-text
```

- The install folder may be the folder above `POOLRAD` (GOG) or the flat layout.
- Outputs go to `OUT`, which must be outside the install and, inside this
  repository, under `data/`.
- Exit codes: `0` clean; `1` degraded (a refused block, a failed design, or an ECL
  census with diagnostics; the manifest is still written); `2` named refusal
  (missing or ambiguous member, including any `ECL1..8.DAX` with
  `--with-ecl-text`; bad plan; unsafe output; install changed during the run).

### Multi-area designs (map-only)

**Status: MULTI-AREA, MAP-ONLY, `playable: false`.** This is not a full-game
module. It assembles several decoded GEO blocks into one `NAME.DSN` folder. It
adds no events, art, text, STRG, monsters, shops or campaign logic.

A plan row with an `areas` list is one design. A row without `areas` is a flat
row, the v0 form, and is unchanged. Both forms can share one plan:

```json
{"schema": "openua.por-pipeline-plan", "version": 0,
 "designs": [
   {"name": "TWOAREA", "title": "two areas", "start_area": 5, "start_entry": 1,
    "areas": [{"geo": 2, "index": 2, "area": 5, "entry": [13, 8], "facing": "east"},
              {"geo": 3, "index": 0, "area": 6, "entry": [1, 2], "facing": "south"}]}
 ]}
```

- `geo` (1..8), `index` (TOC index), `area` (1..999), `entry` (`[x, y]`, each 0..15)
  and `facing` (`north`, `east`, `south`, `west`) are required on every area.
  Nothing defaults in a group. `title` is optional.
- `areas` is a non-empty list. Area numbers are unique within the design. Each
  `(geo, index)` pair is used once per design, since a repeat is ambiguous.
  Design names are unique across flat and grouped rows.
- `start_area` must be one of the area numbers.
- **`start_entry` means one thing: 1.** Each generated area has exactly one entry
  point, at GEO table index 0, placed at that area's `entry` and `facing`. GAME001
  byte 49 is 1-based, so `start_entry: 1` names it. Any other value is refused.
  The start area is the `start_area` GEO, entered at its own `entry`.
- Unknown keys are refused on both the design and each area. A grouped row that
  also has flat fields (`geo`, `index`, `area`, `entry`, `facing`) is refused.

What is emitted: one `designs/NAME/NAME.DSN/` folder holding `GAME001.DAT` and one
`GEO<NNN>.DAT` per area. The folder is written by `tools/dsn.py` (`Design`). It is
all or nothing: if any area is refused, no folder is written and the design is
`refused`. The manifest records one design row with `kind:
"multi-area-map-only"`, `playable: false`, `start_area`, `start_entry`, the folder
and its files (path, bytes, SHA-256), and per-area sources (`block_id`,
`raw_size`, `decoded_sha256`), entry values, statuses and checks. The design-level
checks are `files_exact`, `game001_bytes_match`, `game001_start_area` (byte 48) and
`game001_start_entry` (byte 49). Each area's checks are `parses`,
`byte_round_trip`, `entry_point` and `file_equals_built`. Every GEO is read back
with `geo.Geo.parse`. Standalone `maps/` reports are still written for every source
block.

Not claimed: the GEO header keeps the same art-binding bytes that flat rows
already use (`ART_BLOCK`, copied from a HEIRS area, not from Pool of Radiance). The
GAME001 XP, platinum, gems, jewelry and equipment fields are the `dsn.Design`
writer defaults, recorded in the design row as `game001_writer_defaults`. None of
these values is recovered from the install. Door mapping records one cited PoR
DOS route with a flag-2 locked door and successful Bash crossing. The
GEO-to-reader binding and general flag-2 rule remain unproven; flag 3 is a
CoK/other-title hypothesis. Flags 2 and 3 currently map to OpenUA passability
15. The manifest and report stay `playable: false`.

### Loader-equivalent checks (per emitted DSN)

Every emitted `NAME.DSN` folder, flat or grouped, is passed to
`por_dsn_load_smoke.validate_folder` (`tools/por_dsn_load_smoke.py`) inside the
staging folder, before anything is published. The pipeline does not restate the
engine rules; it reads the validator's report. Those checks are host readings of
the bytes that the engine's loader tests. They are not an engine run.

- Each design row gets a `loader_equivalent` record: `verdict` (`pass`, `fail` or
  `refused`), the validator's `checks` (id, status, detail, source),
  `failed` (the failing check ids), `start_area` and `start_entry` as the
  validator read them, `engine_area_max` (255), `areas_above_engine_range`,
  `runtime_loaded: false` and `engine_executed: false`.
- **Failure policy.** A design is `ok` only when its round-trip checks pass and
  the loader verdict is `pass`. A loader failure makes the design `failed`, so the
  run exits `1`. As for a round-trip failure, the folder is still published, and
  the manifest and report are still written. The design is not degraded to a
  warning.
- **Areas above the engine range.** The engine passes the area number as one byte
  (`boot.c` jt127), so only areas 0..255 can be addressed. The plan accepts areas
  1..999. An area above 255 always fails the validator's `geo-addressable` check
  and is never silently accepted. The record names those areas in
  `areas_above_engine_range`, and the report shows
  `areas above engine range 0..255: N`. GAME001 keeps only the low byte of the
  start area, so the validator's `start-geo-present` check can also fail for that
  design. The explicit field, not that check, is the reason to read.
- A grouped design is checked over its whole folder (`GAME001.DAT` and every
  `GEO<NNN>.DAT`). The group check still runs only after every area decodes; a
  refused area writes no folder and is not loader-checked.
- The report's summary gains `Loader-equivalent host checks passed (engine NOT
  run)`. The manifest summary gains `designs_loader_passed`. The `UNSUPPORTED`
  list gains a line that says the engine is not run.

Still not checked by the validator (its own limitations, carried into this run's
reading): the start.dat name, GEO event and string contents, monster and item
references, art resolution, and the start entry against the area's entry table.

### Output replacement (staged publish)

Every stage writes into a fresh staging folder, `.por-pipeline-staging-*`, created
beside `OUT` (same parent, same volume). The install is fingerprinted before the
stages and again after the manifest is written, just before publishing:

- **Install changed, or any stage fails:** nothing is published. `OUT` is left as it
  was, byte for byte, including any unrelated files. The staging folder is removed,
  and so is any folder the run itself created (only if it is empty).
- **Clean run:** each pipeline-owned entry of `OUT` is renamed into the staging
  folder and the staged entry is renamed into `OUT`. The owned entries are `maps/`,
  `designs/`, `ecl-census/`, `ecl-text-diagnostic/`, `por_pipeline.json` and
  `por_pipeline_report.md`. A rerun therefore replaces them wholesale. Stale owned
  entries from an earlier run are removed, so a map-only rerun into an ECL output
  folder drops `ecl-census/` and `ecl-text-diagnostic/`. Anything else in `OUT` is
  never moved or deleted.
- **A rename fails during publish:** every rename already made is reversed, which
  restores the previous output. If that reversal also fails, the previous owned
  entries are kept in the staging folder, the error says so, and the staging folder
  is not deleted.
- Replacing a folder means the owned entries' previous contents are gone. Files a
  user placed *inside* `maps/`, `designs/` or the ECL folders are replaced with them;
  put anything you want to keep outside those names.
- Publishing is not atomic across the whole set: a crash in the middle of the
  renames can leave `OUT` partly replaced. Rollback covers errors the run can see,
  not a power loss or a killed process.

### What the ECL stage writes

With `--with-ecl-text`, the run writes two subfolders of `OUT`:

| Folder | Files | Source tool | Status |
| --- | --- | --- | --- |
| `ecl-census/` | `por_ecl_strings.json`, `por_ecl_strings_report.md` | `tools/por_ecl_strings.py` | `census-only`, `playable: false` |
| `ecl-text-diagnostic/` | `por_ecl_text_diagnostic.json`, `por_ecl_text_diagnostic_report.md` | `tools/por_ecl_text_diagnostic.py` | `diagnostic-unaccepted`, `playable: false`, every frame `accepted: false` |

`por_pipeline.json` gains an `ecl_text` section, and the report gains an
"ECL text" section. The section holds the file counts, per-framing string-frame
counts, census exit code, the unresolved codes, and the SHA-256 and size of each
output file. Only the `ecl-*` folders are written for ECL. No DSN, FRUA STRG,
event or message is produced.

- All eight `ECL1..8.DAX` are required and fingerprinted before and after the run,
  like the GEO members. A change during the run is a refusal, and no manifest is
  written.
- The census reads its archives with the same lookup (install or `POOLRAD`).
  Census diagnostics (for example a container error, or an absent archive) make
  the census exit `1`. The run is then degraded, and the diagnostic still runs over
  the frames that were found.
- Without the flag the manifest is exactly the map-only manifest, with no
  `ecl_text` key, and no `ecl-*` folder is created.

### Status and limits (read before using the ECL output)

- The ECL diagnostic is **diagnostic-unaccepted**. It applies the retail-verified
  6-bit codec (`docs/por-ecl-codec-static-probe.md`) to every census payload. It
  does not show that any decoded string appears on a PoR screen or maps to a
  message.
- The 0x80 byte count is code-evidenced for PoR: the retail 0x80 arm passes the census
  declared length to its unpacker (`docs/por-ecl-length-xref.md`). That the ECL walk reaches
  that code at run time is not shown.
- The census framing `spec-menus` is a census result, not proof. Frames after a
  spec menu are flagged `census-framing-speculative`.
- No runtime text binding exists (`runtime-text-binding`).
- The tests and the retail anchor check containers and counts only. Nothing here
  checks gameplay or on-screen text.

### Retail anchor (local GOG install, 2026-11-17)

`python3 tools/por_pipeline.py --install "G:/Games/Pool of Radiance" -o
data/work/por-pipeline/retail-ecl --with-ecl-text` decodes 29/29 GEO blocks and
exits `0`. The ECL census reports 185 conservative and 1656 spec-menus string
frames, and the diagnostic covers all 1841 of them, with none accepted. The same
census counts are pinned in `tests/test_por_ecl_strings.py`.

### Tests

`tests/test_por_pipeline.py` runs on synthetic fixtures and needs no install. It
covers the enabled and disabled paths, missing and changed ECL members, census
exit 1 with diagnostics, output statuses, path hygiene, byte-identical reruns, the CLI
exit codes, and the staged publish: a mid-run change during the map or ECL stage
publishes nothing and leaves an existing `OUT` byte-identical, a clean rerun keeps
unrelated files, a failed rename rolls back, and no staging folder survives a refusal.
The loader-equivalent tests cover a pass on flat and grouped designs, an area of
300 failing the design (flat and grouped) with the area named, a loader failure
that fails a design whose round-trip passed, a loader refusal, a read-only check
that runs on the staged copy before publish, deterministic path-free output, and
`runtime_loaded` and `engine_executed` staying false. The multi-area tests cover a two-area design as one folder with two
round-tripped
GEOs (and GEO bytes equal to the flat-row output), malformed groups, duplicate area
numbers and block references, a missing start area, a refused area that writes no
folder, and a playable=false check that no events, art, text or STRG is emitted. A
retail-gated test runs only when the local install has the ECL archives. Run only
this file with `python -m pytest tests/test_por_pipeline.py`.

---

## All-GEO grouped container check (TEST-ONLY)

**Status: TEST-ONLY CONTAINER CHECK. `playable: false`. Nothing here is a conversion.**
Tool: `tools/por_geo_all_map_group.py`. Tests: `tests/test_por_geo_all_map_group.py`.
Full notes and limits: [`por-geo-all-map-group.md`](por-geo-all-map-group.md).

- **What it does.** It reads the flat map-smoke plan from `tools/por_geo_smoke_plan.py`
  (one design per decoded GEO TOC block, see
  [`por-geo-smoke-plan.md`](por-geo-smoke-plan.md)). It writes one grouped
  `por_pipeline.py` plan design, `TGALLMAP`, that holds all 29 decoded retail GEO
  blocks as areas of a single `TGALLMAP.DSN` folder. The existing pipeline then emits
  that folder.
- **What is invented.** The area numbers 1..29 are sequential test ids, assigned in
  (GEO, TOC index) order. They are not recovered from the install, and no
  block-to-area mapping is claimed. The start area is 1 and the start entry is 1
  (the pipeline's rule), both placeholders. Every area sits at one placeholder test
  position, `0,0,north`. None of these is an authentic start, entry or facing.
- **Retail run (2026-11-17, local GOG install, read-only).** All 29 blocks decoded.
  The host loader-equivalent validator (`tools/por_dsn_load_smoke.py`, run by the
  pipeline) passed for all 29 GEO files, each the engine's 12962-byte size, and each
  parses back through `geo.Geo.parse`. The run records `runtime_loaded: false` and
  `engine_executed: false`.
- **Repeatability check (2026-11-18).** I reran the checked-in pipeline against
  the same pinned install and the existing test-only all-GEO plan into two fresh
  output folders. Both runs decoded 29/29 blocks, emitted one 29-area design, and
  passed the host loader-equivalent check. All 90 output files had identical
  SHA-256 values between runs. The manifest keeps the invented area/start labels
  and `runtime_loaded: false`; this is not a gameplay or runtime-load claim.
- **Corrected-converter rerun (2026-11-18).** Regenerated the test-only all-GEO
  plan from the pinned retail install with one `14,10,west` test position, then
  ran the current pipeline. It decoded 29/29 blocks; the grouped design passed
  loader-equivalent checks with 29 files of 12,962 bytes. Parsing them back
  yields `(row=10,col=14,facing=6)` in each. Area ids and start area remain
  invented placeholders; this does not establish authentic mappings or
  playability. Output: `data/work/por-pipeline-retail-20261118/pipeline/`.
- **Bounded Hatari parse run (run-e, 2026-11-17).** A separate `FRUA_AREATEST`
  harness run used the generated `TGALLMAP.DSN/GEO001.DAT` (12,962 bytes,
  SHA-256 `C96DFDFB743AD1967E37A36BF538EA9DF307B5D18F143F66BD7E1AB5C14B1624`).
  Hatari 2.3.1 logged two `== GEO level1` markers with 16x16 dimensions. The
  `FRUA_CELLSCAN` log site runs after `jt198`'s exact-size check and successful
  `l720a` parse, so this verifies that one generated GEO file was read and
  parsed in OpenUA. The 45-second run ended at its bound without `ERRMODAL`.
  Build SHA-256: `B4B5620B0E29403AC01396595E4F2224F5460A8DC19A8318411415E9509B4F16`.
  Full run setup and evidence: [`por-areatest-group19-modal.md`](por-areatest-group19-modal.md).
- **Second bounded Hatari parse run (area 29, 2026-11-17).** Using the same
  test-only build and staged `TGALLMAP.DSN`, I temporarily set `GAME001.DAT`
  byte 48 to 29, then restored the original file in a `finally` block. The
  resulting `DBG.LOG` records `== GEO level29` twice, each with 16x16
  dimensions, through the same post-parse `FRUA_CELLSCAN` site. The staged
  `GAME001.DAT` is restored to start area 1 and its original SHA-256
  `BBD3E236FF9A3DA3497167D48A56D265A781ED6EFD7959B91C1641B7C350C01C` was
  verified afterward. Capture: `data/work/por-openua-areatest-20261117e/DBG-area29-retry.LOG`.
  This adds one more test-file parse, not a sweep of all 29 maps.
- **One-run all-GEO Hatari sweep (2026-11-17).** The opt-in
  `FRUA_GEO_SWEEPTEST` harness loaded GEO001..GEO029 through `jt198` in one
  bounded run: `loaded 29 skipped 0 failed 0`. Each returned successfully from
  the same loader path that checks the exact engine byte count and parses with
  `l720a`; the harness then reloaded entry area 1 and logged that it continued
  into `jt948`. The test-only ids remain invented and the sweep does not walk
  or execute events in those maps. Executable SHA-256:
  `367717BEED5E9AEE562EFAFD62221E9F7A99E5BA524F0E268BB6038CB92D4AE9`.
  Capture and harness limits: [`por-geo-sweeptest.md`](por-geo-sweeptest.md),
  `data/work/por-openua-areatest-geosweep-run/DBG-geosweep.LOG`.
- **Corrected-converter all-GEO rerun (2026-11-18).** An isolated current
  build loaded and parsed all 29 generated GEO files: `loaded 29 skipped 0
  failed 0`; every map reported 16×16, 256 cells and zero specials, and the
  harness reloaded the entry area. Hatari exited with status 1 after the final
  `continuing into jt948` marker, so no post-handoff behavior is claimed. The
  build reused a staged `frua.rsc` because `UnlimitedAdventures.rfork` was
  absent. Details and hashes: [`por-geo-sweeptest.md`](por-geo-sweeptest.md).
- **Separate Hatari startup trace (2026-11-17, disposable stage).** Hatari 2.3.1
  executed `frua.prg` (SHA-256
  `AD786159AB110844ABA108A34BD1C875FE7B4A5795E6C03B12383494B6FDAFB8`) with a
  staged copy of the current 29-area `TGALLMAP` design. OpenUA read `GAME001.DAT`,
  then opened `PORALL29.DSN\\GEO001.DAT` and immediately closed that handle without
  an `Fread` on it. The staged GEO file's SHA-256 matched the pipeline output
  (`C96DFDFB743AD1967E37A36BF538EA9DF307B5D18F143F66BD7E1AB5C14B1624`). The
  trace checker reports **open-only**. This proves the current design path is
  selected and its GEO file can be opened; it does not prove the GEO bytes were
  loaded or that a map was displayed. Logs and report are under
  `data/work/por-openua-runtime-allmap-smoke-20261117/` and
  `data/work/por-hatari-load-trace-review-20261117/`.
- **Not established.** Playability; whether the engine loads or walks any of the
  other 28 blocks; authentic area numbers, start location, facing, transitions,
  art, events, text or monsters. The retail pipeline run's validator is a set of
  static host checks. The separate Hatari parse run covers only `GEO001.DAT` and
  does not establish any of those gameplay behaviors.

---

## Slice 2: one GEO block -> map-only design (`tools/por_map.py`)

### Usage

```sh
# list the TOC of an explicit GEO DAX (no output written)
python3 tools/por_map.py --dax PATH/TO/GEO1.DAX --list

# normalized map + report only (no design)
python3 tools/por_map.py --dax PATH/TO/GEO1.DAX --block 18 -o data/por-map/geo1-18

# GOG-style install: resolves GEO1.DAX in the folder or its POOLRAD subfolder
python3 tools/por_map.py --install "D:/PoR" --geo 1 --index 0 -o data/por-map/geo1-0 \
    --entry 3,5 --facing north --area 5 --name PORMAP

# check documented PoR facts against the decoded block (repeatable)
python3 tools/por_map.py --dax PATH/TO/GEO8.DAX --block 29 -o data/por-map/geo8-29 \
    --expect 7,8=0x02/0x7f --expect 7,7=0x01/0x7f
```

| Option | Meaning |
| --- | --- |
| `--dax FILE` / `--install DIR --geo N` | the source: one explicit DAX, or `GEO<N>.DAX` in an explicit install |
| `--block ID` / `--index I` | choose the block by id, or by TOC index (required when an id repeats) |
| `--list` | print the TOC and exit |
| `--expect X,Y=VALUE[/MASK]` | check plane 2 (the descriptor byte) of cell `(X,Y)`: pass when `(plane2 & MASK) == (VALUE & MASK)`; MASK defaults to `0xFF` |
| `-o OUT` | output folder; required unless `--list` |
| `--entry X,Y` | party start, **column,row** (row 0 north), the convention of `tools/find_geo_path.py`. Required before a `.DSN` is written |
| `--facing` | `north`/`east`/`south`/`west` (default `north`) |
| `--area N` | start area number, 1..999 (default 5, as `dsn.demo_design`) |
| `--name NAME` | design name, 1..8 of `A-Z 0-9 _` (default `PORMAP`) |
| `--title T` | `GAME001.DAT` title, truncated to 31 bytes |

Outputs in `OUT`:

- `por_map.json`: schema `openua.por-map`, version 1, status `map-only`,
  `playable: false`. It holds the source provenance (file name, SHA-256 of the
  file, TOC index, block id, raw and compressed sizes, decoded SHA-256), the 256
  cells with their four planes and decoded edges, diagnostics, and expectation
  results. It contains no absolute paths. Keys are sorted and nothing is
  timestamped, so runs are byte-identical.
- `por_map_report.md`: source table, edge mapping counts, diagnostics,
  expectation PASS/FAIL, warnings, the full unsupported/lost list, and the
  design summary.
- `NAME.DSN/` (only with `--entry`): `GAME001.DAT` and `GEO<area>.DAT`, written
  by OpenUA's `tools/dsn.py` (`Design.write`) and `tools/geo.py` (`Geo.build`).

Exit codes: `0` success; `1` success, but an `--expect` check FAILED (outputs are
still written); `2` named error (bad source, malformed block, out-of-range
argument, refused output location).

### Refusals

- A DAX whose TOC is not a positive multiple of 9, whose TOC runs past EOF, whose
  data chain is not contiguous from offset 0, or whose data section does not end
  exactly at EOF (truncated or trailing bytes).
- An RLE block that overruns its input, has no value byte, or does not produce
  exactly the TOC `raw_size` bytes.
- A block whose size is not 1026, or whose `uint16` size field is not 1024.
- An ambiguous block id (use `--index`), an index out of range, a missing id.
- An output folder inside the source folder, or inside the repository outside
  `data/` (the guard from `por_convert.py`).
- Coordinates outside 0..15, an area outside 1..999, a design name that does not
  fit 8.3 rules, or an expectation that does not parse.

The source is opened `"rb"` and never written. The tests check this by hashing
the install folder before and after a run.

### Evidence level (read this before trusting the output)

| Claim | Level | Basis |
| --- | --- | --- |
| DAX container (9-byte TOC, contiguous chain, EOF closure) | validated on local Pool of Radiance DOS `GEO2.DAX` and `GEO8.DAX` files; general rule is corpus-checked in GoldBox | GoldBox `docs/dax-format.md` §1; local runs recorded under ignored `data/work/por-retail-validation/` |
| Signed-byte RLE | decoded the selected retail blocks to their declared 1026-byte size; decoder is byte-identical to DaxDump in GoldBox corpus checks | `docs/dax-format.md` §2; local runs recorded under ignored `data/work/por-retail-validation/` |
| Gen1 GEO block: 1026 bytes, size field 1024, 16 x 16, four planes, nibble-packed walls, door flags 2 bits/edge | documented decode; the Gen1 model used by GoldBox `tools/find_geo_path.py`; its CoK basis is in `docs/engine/research/geo-map-format-cok.md` (the "RESOLVED" section; the older §3/§4 are superseded) | GoldBox research, applied to the Gen1 family |
| Pool-specific use of that decode | the selected retail GEO2#20 plane-2 value at `(1,5)` equals `0x8e`; GEO8#29 values at `(7,8)` and `(7,7)` masked by `0x7f` equal `2` and `1`; all three checks PASS | Local DOS install checked 2026-11-16 against facts cited in GoldBox `persistent-natural-routes.md` and `pool-natural-encounter-route.md`; no source files changed |
| Edge mapping (slot, door) -> OpenUA wall byte | **mapping decision in this tool**, derived from `find_geo_path.py`'s passability rule and OpenUA's `dsn.py` byte meanings | see table below |
| FRUA side (GEO and GAME layout, 16 x 16 area, start byte) | OpenUA's own `geo.py`/`dsn.py`, round-tripped by tests | tests |
| Runtime: the design loads and is walkable in OpenUA | **not verified** | not run |

The local GOG DOS install provides a first retail check of DAX block extraction
and the documented plane-2 cell coordinates. This does **not** establish that
all four planes or wall/door meanings are correct for PoR, and it does not prove
the emitted design loads or walks in OpenUA. Run the documented `--expect`
checks on other map blocks before making broader claims.

### Retail check performed 2026-11-16

Against the user's local GOG DOS installation, without modifying any source
files:

| Input | Selected block | Raw / compressed bytes | Decoded block SHA-256 | Result |
|---|---:|---:|---|---|
| `GEO2.DAX` (`2035246014efdb26de3114f4737d52a935ad8834f79b4a8e4880da2922b6d595`) | 20 (TOC index 2) | 1026 / 911 | `8fc671263b8606861bcfac3a6ff33476e2ad1d0d1c1592bf20643aebf8519663` | `(1,5)` plane 2 = `0x8e`: PASS |
| `GEO8.DAX` (`050cd0316ebf339f6b36233156eb99129c8eaa689df89e05fbfa13d72e89c045`) | 29 (TOC index 3) | 1026 / 982 | `e18ececf36fd38cb28ecf7e0310841f7e7adfd0ece211867011a7d57e1bd8e62` | `(7,8)&0x7f = 2` and `(7,7)&0x7f = 1`: PASS |

The eight `GEO*.DAX` source hashes matched before and after the reads. A local
map-only `PORMAP.DSN` was also emitted from GEO2#20 with an explicitly supplied
test entry `(13,8)` facing east; its `GEO005.DAT` parsed back as a 16×16 FRUA
area with that entry. The entry is a test position, not a recovered original
campaign start. Reports and generated module files are under ignored
`data/work/por-retail-validation/`; no generated game content is tracked.
This validates DAX extraction, block size and the cited plane-2 coordinates on
these files. Wall semantics, artwork mapping and in-engine load/walk behavior
remain unverified.

### Plane layout (decoder model implemented in `decode_gen1_geo`)

This is the Gen1 layout model used by the converter, not a complete PoR
semantic finding. PoR's static plane-3 probe confirms that direction codes
0/2/4/6 select the successive 2-bit pairs, but does not establish compass
labels for those codes. The runtime observation for one door route is cited
separately below; it does not bind the native reader to these decoded fields.

```
raw[0:2]        uint16 LE = 1024 (size field; checked)
raw[2:258]      plane 0: Gen1 model: N = high nibble, E = low nibble
raw[258:514]    plane 1: Gen1 model: S = high nibble, W = low nibble
raw[514:770]    plane 2: per-cell descriptor (event/backdrop byte; kept raw)
raw[770:1026]   plane 3: Gen1 model: N bits 0-1, E 2-3, S 4-5, W 6-7
cell index = y * 16 + x   (row 0 = north)
```

The plane-3 probe's PoR-specific result is the numeric pairing
`direction 0 -> bits 0-1`, `2 -> bits 2-3`, `4 -> bits 4-5`, and
`6 -> bits 6-7`. Its compass names above remain the Gen1 model; see
[`por-plane3-field-layout-probe.md`](por-plane3-field-layout-probe.md).

Each wall is `(slot 0..15, door 0..3)`. Slot 0 means no wall graphic.

### Edge mapping: Gen1 `(slot, door)` -> OpenUA wall byte

OpenUA's wall byte is `passability << 4 | texture group` (`dsn.py`: 0 open,
1 secret door, 14 solid, 15 "Blocked: force/knock/pick"). A read-only GoldBox
reference records a native PoR DOS runtime route where one flag-2 edge required
LOCKED/BASH/PICK interaction and successful Bash crossed it. That supports one
recorded case; the plane-3 reader's GEO-buffer binding remains unestablished.
Flag 3 remains a provisional CoK-derived hypothesis. See
[`por-geo-door-semantics.md`](por-geo-door-semantics.md). The converter still
emits the same wall bytes, while its output distinguishes the observed flag-2
case from the unresolved flag-3 mapping.

| Gen1 edge | OpenUA byte | Meaning in OpenUA |
| --- | --- | --- |
| slot 0 (any door) | `0x00` | open |
| slot S, door 0 | `0xE0 \| S` | solid wall, texture group S |
| slot S, door 1 | `0x10 \| S` | passable secret-door edge (engine says "A SECRET DOOR!") |
| slot S, door 2 | `0xF0 \| S` | OpenUA Blocked menu; PoR DOS trace supports interaction-gated crossing for one flag-2 route |
| slot S, door 3 | `0xF0 \| S` | same current byte, but unresolved for PoR; CoK-only Bash/Knock hypothesis |

The texture group S is the Gen1 slot used unchanged. That is **not verified**
against PoR's WALLDEF art. Door flags 2 and 3 have distinct diagnostic labels
(`locked`, status `supported-single-route`; `door3-unresolved`, status
`provisional`) but currently emit the same byte. Per-rule provenance is in
`por_map.json` under `edge_mapping_evidence.rules`. Every rule keeps
`geo_reader_binding: unproven` and `general_rule_proven: false`. The per-cell
descriptor and zone bits are not written.

### Coordinate and wall mapping (tested)

Under the Gen1 decoder model, source cell `(x, y)` maps to OpenUA
`cell(col=x, row=y)` and source edge labels are N, E, S, W. The OpenUA
runtime trace below establishes its target edge order as N/E/S/W; `por_map.py`
writes the model-labelled values in that order. The entry is
`set_entry_point(0, row=y, col=x, facing)`. `tests/test_por_map.py` checks that
the mapping is not transposed and that `Geo.parse(Geo.build())` round-trips.

Entry facings use OpenUA's 3-bit compass codes, not the four edge-order indices:
N=0, E=2, S=4, W=6 (odd codes are diagonal headings). The engine normalizes 0
to 8 and uses the direction tables in `jt297`; `jt210` selects the facing edge
with `(dir & 6) >> 1`. A runtime trace of the test-only flag-2 area exposed two
old fixture errors: the 0/1/2/3 facing codes sent cardinal labels to diagonal
headings. Under the Gen1 source-label model, writing W/S/E/N put west at slot 0
while the engine's west heading reads slot 3. `tools/por_map.py` now writes
that model's N/E/S/W values in the runtime-verified OpenUA slot order and uses
the engine's cardinal heading codes. The PoR probe confirms the bit-pair
selection by numeric direction code but does not independently verify those
source compass labels. One assumption remains open:
OpenUA may consult only one side of a shared edge. The source stores both
sides, so that choice is OpenUA's. The diagnostics report how often the two
stored slots agree.

### What the design contains, and what is not claimed

The `.DSN` is a single area with the block's walls, OpenUA's generic header
`ART_BLOCK` binding (not a PoR art mapping), one start entry, and the `GAME001.DAT`
defaults. Everything listed under "Unsupported and lost" in the
report is absent. In particular it has **no event records, no strings, no
monsters, no items, no PoR art, no transitions** and no campaign. Its status is
**a geometry artifact**. It is not a playable PoR module, and this slice claims
nothing about play.

### Tests

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_map.py    # Windows venv
tools/.venv/bin/python -m pytest tests/test_por_map.py            # POSIX
```

All fixtures are synthetic. `tests/test_por_map.py` writes its own DAX container
and GEO block to `tmp_path`, using the layout documented above, and includes a
test-only RLE encoder. The suite pins the decoder to that layout. It does not
prove that a retail block decodes this way.

Covered: RLE round-trip and envelope controls; each container refusal; TOC index
and id selection; plane layout at a known cell; GEO size refusals; every edge
rule; coordinate mapping (not transposed) and round-trip through `geo.py`;
reachability and disagreement diagnostics; expectation parsing and FAIL exit;
output and install refusals, which must not create the repository folder; an
end-to-end run that leaves the source hash unchanged and is deterministic
across two runs; and an emitted `.DSN` that OpenUA's own `geo.py`/`dsn.py` parse
back.

### Next missing conversion layer (in order)

Retail GEO checks against the supplied local install passed for GEO2 block 20
and GEO8 block 29. ECL2 block 20 also passes the current container/header and
instruction-boundary anchor checks under the explicitly unproven `spec-menus`
framing. That ECL result is a framing census, not an opcode-semantics or route
validation; see [`por-ecl-decoder.md`](por-ecl-decoder.md).

1. **Art binding.** Still open. Slice 4 inventoried GEO, WALLDEF and 8X8D;
   slice 5 decoded palette indices from 44 of 45 8X8D blocks, leaving one block
   unsupported. The ECL census records 35 framing-tagged `LOAD_PIECES` records
   (25 unique locations), but only one block's walk reaches end-of-block. These
   are not verified area-to-WALLDEF bindings. A PoR tile-to-screen reference and
   PoR-validated ECL framing are still needed. Slice 6's raw-index preview also
   leaves many references out of range. Slice 7 compares the raw, CoK and naive
   readings by count and selects none. See the wall, tile, candidate and
   index-relation reports.
2. **Descriptor and zones.** Decode plane 2 (the search/event dispatch key) into
   OpenUA events or zones. Do not invent it, and report what cannot be
   represented.
3. **ECL semantics and mapping.** Establish PoR opcode behavior, unknown opcode
   framing, menu formats, and pointer bases; then map only behaviors with
   source-to-OpenUA equivalence evidence. The current decoder implements
   framing only.
4. **Text (STRG), monsters, items and encounters**, each against a known layout.
5. **Start and transitions**, from the source's entry data rather than the
   `--entry` argument, and multi-area coverage with a capacity report.
6. **Runtime** validation: load and walk the design in OpenUA, then compare it
   with original FRUA. Until that happens, no runtime claim is made.

---

## Slice 4: wall-art census (`tools/por_walls.py`)

**Status: census only. No Pool of Radiance wall slot is bound to OpenUA art.**
Every output says `"playable": false` and `"binding": null`.

### Usage

```sh
python3 tools/por_walls.py --install "D:/PoR" -o data/por-walls/pool
python3 tools/por_walls.py --install "D:/PoR" -o data/por-walls/pool --area 2
```

- `--install` is the DOS folder (or its `POOLRAD` subfolder). Each `GEO<n>`,
  `WALLDEF<n>` and `8X8D<n>` `.DAX` is opened `"rb"`. Symlinks are not followed.
- `-o` must lie outside the install folder, and inside the repository only
  under `data/`. The guard is `validate_output_dir` from `por_convert.py`.
- Outputs: `por_walls.json` (schema `openua.por-walls`, version 1, status
  `census-only`) and `por_walls_report.md`. Both are deterministic, carry no
  timestamps, contain no absolute source path, and hold no tile bytes. They
  store only file names, SHA-256 hashes, counts, and per-row min/max/distinct
  values.
- Exit codes: `0` a clean census; `1` the census was written but at least one
  archive or block failed to decode (see `diagnostics`); `2` a named refusal.

### What it reads

| Family | What the census records |
| --- | --- |
| `GEO<n>.DAX` | Every block, decoded with `por_map.decode_gen1_geo`. The number of edges per wall slot (0..15), the slots used, and the wallsets they fall in. |
| `WALLDEF<n>.DAX` | Every block. Its 780-byte records, and for each of the 5 rows the min, max and distinct count of its 156 values. |
| `8X8D<n>.DAX` | TOC inventory only (block id and sizes). Tile banks are **not** decoded. |

For each area it cross-references the used slots with the WALLDEF archive. It
also lists the CoK/COAB candidate 8X8D ids (`B*10+k`) and whether each one is
present. Those candidates are not verified for PoR.

### Evidence level

| Claim | Level | Basis |
| --- | --- | --- |
| GEO block layout and slot nibble | documented Gen1 decode, already checked on GEO2#20 and GEO8#29 | slice 2 above |
| WALLDEF blocks are 780-byte (5 x 156) record multiples | consistent with all 38 retail WALLDEF blocks (census); layout from CoK/COAB source | GoldBox `firstperson-wall-geometry-cok.md` §0, §6 |
| Slot index: row `(slot-1) % 5`, wallset `(slot-1) // 5` | CoK/COAB source only; **not checked against PoR art** | GoldBox `firstperson-wall-geometry-cok.md` §2 |
| WALLDEF block `B` with `k` records pairs with 8X8D `B*10+1..B*10+k` (k>1), or 8X8D `B` (k=1) | CoK/COAB `LoadWalldef` rule; **candidate only** | same, §6.1 |
| OpenUA renderer index: group `(w-1) // 5`, facet `(w-1) % 5` | OpenUA runtime (`src/engine/boot.c`, `wall_slot_for_edge`). It is an index, not an art binding | OpenUA source |
| Slot -> PoR art, or slot -> OpenUA texture group | **not established** | none |

### Why no binding is emitted

1. **No validated area-to-WALLDEF mapping exists.** The ECL census finds
   framing-tagged `LOAD_PIECES` operands, and its CoK dispatch is explicitly a
   hypothesis. Most PoR ECL walks stop at unknown framing; the archive-to-GEO
   relationship and runtime flag values are not established. The tool therefore
   does not assign those operands to a PoR area or WALLDEF set.
2. **No PoR tile has been compared with a screen.** Even with a block id, no
   retail WALLDEF tile id or 8X8D tile has been checked against the wall art
   PoR draws.
3. **OpenUA draws its own art.** `wall_slot_for_edge` maps the nibble to one of
   three FRUA wall sets. Those sets are FRUA's art, not PoR's. The module plan
   says PoR art conversion is a separate step.

Items 1 to 3 mean the slot index above cannot yet become a binding. The census
records it as an index only.

### Retail census (local GOG DOS install, 2026-11-16)

The census read 24 archives (`GEO1`-`8`, `WALLDEF1`-`8`, `8X8D1`-`8`) with no
absent file. It decoded 29 GEO blocks with no errors, 38 WALLDEF blocks
(42 records), and 111 area-slot rows, all unresolved. The source hashes
were checked before and after the run. Full per-file hashes are in the
ignored `data/work/por-walls/pool/por_walls.json`.

Slice 5 separately checked all 45 8X8D blocks: 44 passed the standard-frame
length/header checks (3,016 8×8 tiles) and block 201 remained unsupported. Its
palette-index files and previews are ignored under `data/work/por-8x8d/`.
The ECL census found 35 framing-tagged LOAD_PIECES records: 10 in conservative
mode and 25 in spec-menus mode, covering 25 unique archive/block/offset
locations. Records present in both modes are duplicates across the two framing
views, not independent confirmations. Only one block reaches end-of-block under
spec-menus; see [`por-loadpieces-census.md`](por-loadpieces-census.md).

### Next evidence needed

- PoR-validated ECL framing and `LOAD_PIECES` semantics, plus evidence linking
  ECL archives and blocks to GEO areas. The current batch census is an incomplete
  prefix walk with a CoK hypothesis only.
- A PoR screen-to-tile reference (for example, a screenshot from a legitimate
  local run), so a WALLDEF tile id can be checked against the art it draws.
- A verified WALLDEF-to-8X8D block and tile-order mapping. The current 8X8D
  decoder establishes a candidate item layout, not screen placement.
- The CoK set relocation and loaded-set interpretation checked against PoR data;
  the current candidate tool tests only the raw-index hypothesis.
- Only then a per-slot OpenUA texture group, with a test that the mapped
  slot draws the intended art.

### Tests

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_walls.py     # Windows venv
tools/.venv/bin/python -m pytest tests/test_por_walls.py             # POSIX
```

All fixtures are synthetic and written to `tmp_path`. They cover resolution
(case, `POOLRAD`, ambiguity), per-edge slot counts, a bad block not stopping the
census, WALLDEF record and row statistics, 8X8D inventory only, the index
arithmetic, the `B*10+k` candidates, the all-unresolved and no-binding policy,
absent archives, determinism, the path-free output, source hashes unchanged,
the output guard, and exit codes.

---

## Slice 1: source inventory (`tools/por_convert.py`)

**Status: a read-only source inventory and a normalized-IR skeleton. It does not
convert Pool of Radiance.**

Its output says so in every file it writes (`"playable": false`, and a banner
in `por_report.md`). Nothing it emits can be loaded by OpenUA or by FRUA.

### What slice 1 does

- Reads a user-supplied PoR source folder strictly read-only. Every source file
  is opened `rb`. Nothing under the source is written, renamed or deleted.
  Symlinks are recorded and never followed.
- Hashes (SHA-256) and classifies every file: `bmp`, `game-dat`, `text`, `item`,
  `symlink`, `unknown`.
- Parses only the headers it can verify:
  - **BMP** (`BITMAPINFOHEADER`): width, height, bits-per-pixel, compression,
    pixel offset, and a declared-size check. Pixels are never decoded.
  - **`Game.dat`**: two prefix bytes (recorded as hex) and the NUL-terminated
    ASCII title. The body is not decoded.
  - **Text**: line count and line-ending style. Content is not kept.
- Refuses an input folder that lacks `Game.dat`, `Levels.txt` or `World.bmp`
  (case-insensitive, top level), and a required member whose probe fails.
- Writes `por_ir.json` (schema `openua.por-source-ir`, version 0) and
  `por_report.md` into an explicit output folder. The output is deterministic:
  no timestamps, sorted paths, and only the source's folder name as a label, so
  no absolute path leaks into the output.

### Usage

```sh
python3 tools/por_convert.py SOURCE_DIR -o OUT_DIR
```

- `OUT_DIR` must not be inside `SOURCE_DIR`.
- `OUT_DIR` inside this repository must be under `data/` (git-ignored).
- Exit codes: `0` success; `2` named error.

### Source layout slice 1 accepts

A **decoded workspace layout**: `Game.dat`, `Levels.txt` and `World.bmp` at the
top, plus `Items/*.itm` and text dumps. It does not recognise the retail DOS PoR
file layout (the `.DAX` and `ECL` data files). Slice 2 covers `.DAX` GEO blocks
only; slice 3 covers ECL framing only.

The provenance of any workspace is the user's to establish. The converter does
not verify it against a retail release, and the output must not be presented as
if it had been.

### What the first real run found

Run once, read-only, against a local workspace (folder label only). The output
went to `data/work/`, which is git-ignored.

- 153 files; all required members present; no probe failures.
- `World.bmp` is a **1056×1056, 24 bpp raster** (BI_RGB). It is map art, not a
  cell grid. A FRUA GEO area is at most 576 cells (see `docs/geo-format.md`), so
  the overland image cannot be used as a cell map as it stands. Slice 2 does not
  read it, and it must not be converted into geometry.
- `Game.dat` begins with a length-prefixed title, `Pool of Radiance`. Its
  remaining layout is not decoded.
- `Levels.txt` is character level progression. It is not a map.

### Not used

- The Game39 fan module. It is not an implementation source, and nothing from it
  was read or copied.
- The OpenUA DOS art converter (`tools/art_convert.py`). Art conversion is a
  separate problem.
