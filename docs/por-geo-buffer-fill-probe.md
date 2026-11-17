# Pool of Radiance: what fills the 1 KiB buffer at DGROUP 0x6A5C (observe-only)

**Status: observe-only. `playable: false`. `fill_established: false`. `plane2_binding: not claimed`.**

Tool: `tools/por_geo_buffer_fill_probe.py`. Tests: `tests/test_por_geo_buffer_fill_probe.py`
(18 tests: 14 synthetic with falsifiers, 4 retail-gated; all 18 pass on this run, the retail ones
against the pinned `data/work/por-geo-run/POOLRAD`). Read-only: it reads the pinned `GAME.OVR` and
`START.EXE` and the decoded pinned GEO archives, and writes only under
`data/work/por-geo-buffer-fill-probe/`. It refuses unpinned `GAME.OVR` or `START.EXE` (no override).

Builds on [por-geo-callee-identity-probe.md](por-geo-callee-identity-probe.md), which decodes the
callee `GAME.OVR:0x2EE71` as returning `0` or `ES:[ptr + 0x200 + 16*Y + X]` with `ptr` at DGROUP
`0x6A5C`. This doc asks what fills `ptr`'s 1 KiB, and whether the fill is GEO `block + 2`.

## Question and answer

> Is the 1 KiB buffer at DGROUP `0x6A5C` filled from a GEO block at `block + 2`? If so, is `+0x200`
> GEO plane 2 (`514 + 16y + x`)?

**Answer: the copy geometry is decoded from bytes and matches `block + 2`. A follow-up probe uniquely
matches the far helper `0x0AF8:0x1685` to START.EXE bytes at `0xC2FB` in two pinned dumps and decodes
its ABI: first pushed far pointer is source, second is destination, count is the third argument, and
the routine returns with `retf 0x0A`. Thus the four calls copy `BLK+2+256k` to `BUF+256k`, 256 bytes
each, conditional on that dump-backed helper identity. The loader's returned pointer is still
unidentified, so whether `BLK` is a GEO block and whether plane 2 lands in `BUF+0x200` remain
unestablished. See [por-geo-copy-helper-probe.md](por-geo-copy-helper-probe.md).**

What the bytes establish (file-byte control and dataflow):

- The buffer is four 256-byte planes. The fill function at `GAME.OVR:0x2F9BE` makes four calls to
  `0x0AF8:0x1685`. Each call's pushed source is `block + 2 + 256k` and its pushed destination is
  `6A5C + 256k`, count `0x100`, for `k = 0..3`. So plane 2 (`buf + 0x200`) would take its bytes from
  `block + 0x202` (`block + 514`), the same offset the existing decoder calls plane 2.
- The loader call is followed by the status test `0x402`. `0x402` is 1026, the Gen1 decoded GEO
  block size in `tools/por_map.py`. That is a structural match, not proof the loader returns a GEO
  block.

What stays unproved (see "Not established"): what the loader `0x0802:0x0716` is, whether its
returned pointer is a GEO block, and what id byte it is given. No dump shows GEO plane bytes at the
buffer, and nothing executes.

## Allocation (file bytes)

| Site | Bytes | Meaning |
| --- | --- | --- |
| `0xE667` | `b8 00 04` `50` | `mov ax,0x400; push ax` |
| `0xE66B` | `9a 3f 02 f8 0a` | `call 0x0AF8:0x023F` (allocator; one pushed word) |
| `0xE670` | `a3 5c 6a`, `89 16 5e 6a` | `mov [0x6a5c],ax; mov [0x6a5e],dx` |

The enclosing function is at `0xE600` (prologue `55 89 e5`, decoder walk covers `0xE670`). The store
is the only store to `0x6A5C` in `GAME.OVR` (the census of literal `5c 6a` and `5e 6a` finds one store
to each slot and 29 `les di,[0x6A5C]`: 31 literal references in all). No `push` or `mov` of the slot
appears, so the pointer is never passed by value. The census covers literal addresses only. `0x0AF8:0x023F` is shared by
many call sites with other sizes, so it is not a GEO-specific routine on its own.

## The 29 `les [0x6A5C]` sites: roles by bytes

Each site's function is found by prologue scan plus a decoder walk that covers the site. The
access is the first ES-prefixed `[di+disp]` that follows.

| Function | Sites | Access (plane displacement) | Gate | retf |
| --- | --- | --- | --- | --- |
| `0x166CB` | 8 | read and write at `+0x300` (plane 3): `and` with `0x3F/0xCF/0xF3/0xFC` | none | 6 |
| `0x167D4` | 8 | read and write at `+0x300`: `and` then `or 0x40/0x10/0x04/0x01` | `0 <= X,Y <= 15` | 6 |
| `0x2EC47` | 4 | read at `+0x300` | `Y` compares in the first 0x40 bytes | 6 |
| `0x2ED72` | 4 | read at `+0x000` and `+0x100` | `Y` compares in the first 0x40 bytes | 6 |
| `0x2EE71` (callee) | 1 | read at `+0x200` (`0x2EED9`) | `X` compares; `Y` range is helper `0x2EC16` (callee doc) | 4 |
| `0x2F9BE` (fill) | 4 | none: each `les` pointer is pushed as the copy's destination | none | 2 |

So planes 0 to 2 are never written by a field accessor. Plane 3 holds four 2-bit fields per cell.
`0x166CB` clears a field and `0x167D4` sets a field to `01`. Those are mask-only writes: they change
bits of an existing byte and take no source byte. The only writes that bring bytes into planes 0 to
2 are the four copies in the fill.

The callee's `+0x200` read is plane 2 by layout (`1 KiB = 4 planes * 256`). That is the layout, not
a proof that the bytes are GEO plane 2. The consumer question stays open.

## The fill function `GAME.OVR:0x2F9BE` (owner group `0x2E8F7`, status partial)

Entry is a prologue at file `0x2F9BE` (group body `0x10C7`). It takes one byte argument `[bp+6]`.

1. **Loader call** (`0x2FA17`, `9a 16 07 02 08`, `0x0802:0x0716`). Arguments: `mov al,[bp+6]; push ax`,
   then `lea di,[bp-2]; push ss; push di` (status out), then `lea di,[bp-6]; push ss; push di`
   (far-pointer out). The argument pattern is checked byte by byte.
2. **Gate** (`0x2FA1C`): `cmp [bp-2],0; jz 0x2FA29; cmp [bp-2],0x402; jz 0x2FA57`. The `0x402`
   jump reaches the copy at `0x2FA57` directly. The other path (`0x2FA29`) makes several calls and
   then falls through to `0x2FA57`, so the copy is reached on every status value. The probe does not
   decode those calls. From the listing, none of their pushed pointers is `[bp-6]`, but a callee could
   still write that local through another route; that is not excluded.
3. **Copy window** (`0x2FA57..0x2FAD8`, decoded by a symbolic walk that fails closed on any opcode it
   does not model). The walk tracks `[bp-8]`, `DI` and `ES`:

| Call | Pushed src (`ES:DI`) | Pushed dst (`ES:DI`) | Count | Plane |
| --- | --- | --- | --- | --- |
| `0x2FA70` | `BLK + 0x002` | `BUF + 0x000` | `0x100` | 0 |
| `0x2FA92` | `BLK + 0x102` | `BUF + 0x100` | `0x100` | 1 |
| `0x2FAB4` | `BLK + 0x202` | `BUF + 0x200` | `0x100` | 2 |
| `0x2FAD6` | `BLK + 0x302` | `BUF + 0x300` | `0x100` | 3 |

`BLK` is the far pointer the loader writes to `[bp-6]`. `BUF` is the far pointer at `0x6A5C`. The
pushed order is src, then dst, then count. Read left to right, that is `copy(src, dst, count)`.

**The copy direction and ABI are now decoded, conditional on the dump-backed identity.**
[`por-geo-copy-helper-probe.md`](por-geo-copy-helper-probe.md) maps live `235E:1685` to the unique
35-byte routine at START.EXE `0xC2FB` in both pinned dumps. Its bytes load source from `[ss:bx+0x0A]`,
destination from `[ss:bx+0x06]`, and count from `[ss:bx+0x04]`, execute `rep movsb`, and return with
`retf 0x0A`. This matches the five words pushed by the fill. The conclusion depends on the identified
helper being the target of the fill's call; it does not prove the fill ran.

## Stub 7 and the fill's callers (file bytes)

The fill's proc `0x10C7` is the proc word of stub 7 at START `0x3E11`: `cd 3f c7 10 27`. Stub 7 is
malformed (its trailer is `0x27`, not `0x00`); the callee doc records the same. So the fill's
identity rests on the stub's proc word, not on a well-formed stub. The group `0x2E8F7` owns it (the
same group as the callee).

The far literal that names stub 7 is `03D5:0043`. That offset is a candidate: it assumes the
5-byte stride from stub 4's identified literal `03D5:0034`. Two sites use it:

- `0x1A27` in function `0x19BA`: `mov al,[bp-3]; push ax`. The id is a local.
- `0x1FBC4` in function `0x1F5E8`: `les di,[0x49D2]; es mov al,[di+0x18A]; push ax`. The id is a byte
  read from a DGROUP far pointer at `0x49D2`, offset `+0x18A`. That pointer is not decoded further.

Only far literals are searched. Near calls, indirect calls and other stub offsets are not searched.

## Dumps: memory bytes at an unknown instant

Two pinned dumps were tested: `data/work/por-live-memory-pid34644` (`f8191750ea6c`) and
`data/work/por-wheel-live-capture` (`3788787cd795`). Both give the same reading.

- **Positive control.** The 16 START bytes at `0x3E02` (stubs 4 to 7) are found at `0x1C3E4` in both
  dumps. The search works, and this is the identity the callee probe already established.
- **GEO planes.** All 29 pinned GEO blocks were decoded with `tools/por_map.py` (`parse_dax`,
  `rle_decode`). Each block gives four 256-byte planes at `raw[2+256k]`. For every plane, 1,611
  non-mostly-zero 16-byte windows were searched. **No window occurs in either dump.** So neither dump
  shows decoded GEO plane bytes at any location. That does not disprove the fill. It means these
  snapshots do not contain the buffer's contents at any instant observed.

The dumps are not register captures and their instant is unknown, so no conclusion about the
running buffer is drawn from them.

## Evidence labels

- **File-byte control and dataflow (established by the bytes).** The allocation and store; the
  29 `les` sites and the roles of their functions; the loader argument pattern and the `0x402` gate;
  the four copy calls and their pushed src, dst and count; the stub 7 proc word; the two stub 7
  literal sites and their id sources.
- **Memory-dump byte observation.** The positive control at `0x1C3E4` (both dumps). No GEO plane
  window in either dump.
- **Unproved (recorded, not used).** Whether the dump-identified `0x0AF8:0x1685` helper is reached by
  the fill at runtime; the identity of `0x0802:0x0716` and whether `[bp-6]` is a GEO block; the meaning of the id; the meaning of the
  `0x49D2` pointer; whether the fill or either caller runs; the value of the buffer at any instant;
  the meaning of `0x402` beyond being 1026.

## Chain: buffer to plane 2

| Link | Status | Falsifier |
| --- | --- | --- |
| Store `0xE670` sets `ptr` (DGROUP `0x6A5C`) to the allocator's result of 1024 bytes | established by bytes | another store to `0x6A5C` (none in `GAME.OVR`) |
| Only the fill writes planes 0 to 2 | established for literal addressing of `0x6A5C`: no `les` site writes those planes. Indirect access to the slot is not excluded | a field accessor that writes `+0x000..+0x200` |
| Fill copies `block+2+256k` to `buf+256k`, count `0x100`, for `k=0..3` | established by bytes (the symbolic walk) | a changed cursor immediate (tested) or a missing push (tested) |
| Copy `src` is the first pushed pointer | **established by the exact helper bytes, conditional on dump-backed identity** | a call target at `0x0AF8:0x1685` whose bytes/ABI differ from START `0xC2FB` |
| `BLK` is the loader's pointer and a 1026-byte GEO block | **not established**: loader unidentified | a live `[bp-6]` whose 1026 bytes are not a decoded GEO block |
| `buf + 0x200` is GEO plane 2 (`block + 514`) | **not established** until the loader pointer is tied to a GEO block | a live buffer whose `+0x200` plane differs from the decoded plane 2 of the block the loader returned |
| `0x2EE71` returns `buf + 0x200 + 16Y+X` | established by bytes (the callee probe) | a read path that is not the one listed |

## Not established

- That the fill executes or that its call reaches the dump-identified helper at `0x0AF8:0x1685`.
- The identity of the loader `0x0802:0x0716`, and that its `[bp-6]` pointer is a GEO block base.
- That the status `0x402` means a byte count. The match with 1026 is a consistency check only.
- The meaning of the id byte (from `[bp-3]` or `es:[49D2+0x18A]`) and which TOC block it names.
- That the fill or either caller executes, or is reachable from entry.
- The buffer's contents at any instant. No dump holds decoded GEO plane bytes.
- That plane 2 is the byte the callee returns, or any consumer of it.
- Any segment-base model for the `0x0AF8` or `0x0802` selectors.

## Next discriminating observations

The probe reports these as `next_discriminating_observations` in its JSON.

1. **At the copy call** (`0x2FA70`, `0x2FA92`, `0x2FAB4`, `0x2FAD6`), in a live run, record the five
   pushed words and 256 bytes at each side, before and after. The helper ABI now says the first far
   pointer is source and the second is destination; the live observation would confirm the fill
   reaches the identified helper and check the resulting bytes.
2. **At the loader return** (`0x2FA17`), record the status at `[bp-2]` and the pointer at `[bp-6]`.
   Status `0x402` with a pointer whose 1026 bytes decode to a pinned GEO block (by `tools/por_map.py`)
   supports `block+2`. Any other pointer falsifies it.
3. **The id byte** pushed by each stub 7 caller (`0x1A27` and `0x1FBC4`), and the TOC block id it
   names.
4. **The unresolved loader** `0x0802:0x0716`, once its segment mapping is established (see
   `docs/por-ecl-target-probe.md`). The copy helper's identity and ABI have a separate dump-backed
   result in [`por-geo-copy-helper-probe.md`](por-geo-copy-helper-probe.md).
5. **A dump of `DGROUP:0x6A5C`** and the 1 KiB it names, taken after an area is entered, compared with
   the four planes of the decoded blocks. The two pinned dumps are of unknown instant.

These need a live run or a further static decode. The probe does not run one.

## Discrepancies and notes

- The callee doc's "next discriminating observation 1" (find the code that fills the buffer, and
  check whether its source is `block + 2`) is answered conditionally: the fill's copy geometry is
  decoded, and the helper ABI identifies the first pushed pointer as source. The loader's returned
  pointer is still not tied to a GEO block, and runtime execution is unobserved.
- The callee doc's `ptr + 0x200` plane-2 link is still not established. This probe adds conditions,
  not evidence.
- Stub 7's trailer is malformed (`0x27`), and its literal `03D5:0043` is a candidate. The fill is
  therefore reached through a malformed stub. That is a weaker identity than the well-formed stub 4.

## Commands

```sh
python tools/por_geo_buffer_fill_probe.py \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-geo-buffer-fill-probe
python -m pytest tests/test_por_geo_buffer_fill_probe.py -q
OPENUA_POR_INSTALL='data/work/por-geo-run/POOLRAD' python -m pytest tests/test_por_geo_callee_identity_probe.py -q
```

Results on this run: `tests/test_por_geo_buffer_fill_probe.py` **18 passed**; the callee probe's
tests with the install variable set **22 passed** (its anchor is unchanged).

## Not claimed

- No plane-2 consumer, no transform, no descriptor-to-event mapping, no area mapping.
- The copy helper identity and ABI are conditionally resolved from pinned dumps, but the fill's
  runtime execution, loader source pointer, and id are open.
- No segment-base model. The `03D5:0043` stub literal is a candidate on a stated stride.
- No reachability from entry for the fill or either caller.
