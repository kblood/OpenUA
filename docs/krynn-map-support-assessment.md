# Krynn map support in OpenUA: GEO format assessment

**Date:** 2026-11-16  
**Scope:** Static review of OpenUA's documented FRUA GEO format and authoring tooling, compared with the repository's Krynn map research. No game-data files or executables were opened; no tests, build, emulator, or runtime were run.

## Conclusion

**Do not enlarge OpenUA's native FRUA GEO format to accommodate Krynn maps.** OpenUA reads and edits FRUA designs. Its GEO file is a fixed-size FRUA structure: 12,962 bytes total, with a 3,456-byte MAP chunk for 576 six-byte cell slots. The event and string chunks also occupy fixed offsets. The documented parser rejects dimensions whose product exceeds 576, matching the native format contract.

Krynn GEO is a different source format. Champions of Krynn and Death Knights of Krynn use fixed 16×16 four-plane map blocks. The Dark Queen of Krynn uses variable-size four-plane blocks; documented retail maps reach 28×28 (784 cells). These are not FRUA GEO files just because they describe maps.

OpenUA could be extended to consume Krynn maps, but that would be a new capability above or alongside its FRUA loader. It would need a source-specific importer and a runtime model capable of representing and rendering the source geometry. For playable campaigns, map geometry is only one part: Krynn area scripts, data libraries, rules, art and campaign flow must also be handled.

## What OpenUA currently supports

OpenUA's [GEO format reference](geo-format.md) documents:

- A fixed **12,962-byte** `GEOnnn.DAT` container.
- A fixed **3,456-byte MAP** chunk containing 576 slots × 6 bytes.
- Column-major cells with four wall-edge bytes, a cell event index and zone/flags.
- A fixed **100 × 20-byte** event table and fixed string table.
- A dimension check requiring `width × height` in **1..576**.

The host-side [GEO reader/writer](../tools/geo.py) mirrors that format and enforces `MAX_CELLS = 576`. The [in-engine GEO editor](geo-editor.md) edits and saves the same container. The [GEO tests](../tests/test_geo.py) pin fixed chunk sizes and the 576-cell capacity.

This is intentional compatibility behavior, not merely a UI setting. Changing the FRUA file's MAP chunk length would move the following fixed chunks and produce a nonstandard file that the original FRUA runtime and existing tools do not understand.

## How Krynn maps differ

The comparative map research in [Greybox Combined Goldbox](https://github.com/kblood/Greybox_CombinedGoldbox/blob/main/docs/engine/research/krynn-frua-map-capacity-port-comparison-2026-11-16.md) records the source differences:

| Source | Geometry and storage | Implication for OpenUA |
|---|---|---|
| Champions of Krynn / Death Knights of Krynn (DOS) | Fixed 16×16, four-plane GEO blocks (256 cells) in DAX-family game data | Fits numerically under FRUA's cell count, but its encoding, events, and source libraries are not FRUA GEO. |
| The Dark Queen of Krynn (DOS) | Variable-size four-plane GEO blocks in HLIB; retail maps reach 28×28 = 784 cells | Thirteen of twenty documented maps exceed FRUA's 576-cell GEO capacity. |
| FRUA | Fixed GEO container, 576 cell slots, six-byte FRUA cells, local event table and strings | Native OpenUA loader/editor must keep this contract for FRUA compatibility. |

Cell capacity is only one difference. Krynn's four-plane cells encode walls, backdrop/zone, and door flags differently. Krynn scripts are not FRUA's per-map event records. The shared HLIB container family in some releases does not make their internal library records or game behavior interchangeable.

## Options

### 1. Preserve OpenUA's FRUA path — recommended baseline

Keep `GEOnnn.DAT`, `tools/geo.py`, and the in-engine editor strict to the FRUA layout. Keep rejecting maps over 576 cells at the FRUA boundary. This maintains the project's stated purpose: play FRUA data supplied by the user.

### 2. Add a lossy Krynn-to-FRUA converter

A converter could map some CoK/DoK geometry into legal 16×16 FRUA areas and possibly map subsets of DQK geometry that fit within 576 cells. This would be an adaptation, not a faithful native Krynn mode. It would need explicit rules for translating cell planes, entry points, events, strings and area transitions. DQK maps over 576 cells would need splitting or redesign, and ECL behavior and Krynn rules would not become FRUA semantics automatically.

This path is useful only if the goal is to produce FRUA-compatible modules with acknowledged losses.

### 3. Add a separate OpenUA Krynn input/runtime path

A faithful support effort should keep the source formats separate and introduce a Krynn-specific loader plus a runtime map representation that can hold at least the verified 784-cell DQK examples. It should not serialize those maps as ordinary FRUA `GEOnnn.DAT` files. The editor would either remain FRUA-only or gain a distinct authoring/import mode for Krynn maps.

This is the suitable direction if the goal is for OpenUA itself to play Krynn content. It is a substantial engine feature, not a GEO-size patch: scripts, area-to-map associations, rules, monsters/items, art, campaign transitions and saves need their own compatibility plan.

## Recommended first implementation slice

Before changing OpenUA runtime code:

1. Define the product target: FRUA-compatible conversion, or native OpenUA support for one Krynn title and edition.
2. Build a source-format-only map importer that preserves source dimensions, all four planes, entry points, source IDs and provenance without writing FRUA GEO.
3. Use synthetic fixtures to test CoK/DoK 16×16 and DQK rectangular and 28×28 map shapes, header ordering, plane lengths and malformed-size rejection.
4. Audit OpenUA consumers for assumptions tied to the FRUA 576-cell buffer: rendering, automap, movement/pathfinding, event dispatch, area transitions, editing and save/reload.
5. Only after the map path is proven, trace one small playable route and scope scripts, game databases, art and campaign behavior.

## Evidence limits

This is a source/documentation assessment, not an implementation result. The comparative Krynn dimensions are drawn from the linked Greybox research note and were not re-derived from retail files in this pass. OpenUA runtime support for maps beyond 576 cells was not tested. The note does not claim full Krynn game compatibility.
