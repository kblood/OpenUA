# Pool of Radiance: the fifth byte of each VROOMM stub slot

**Status: STATIC-PROBE-ONLY. `playable: false`. The tail byte's meaning is not decided. The zero-only
acceptance rule is neither shown to be wrong nor shown to be right.**

Tool: [`tools/por_stub_tail_probe.py`](../tools/por_stub_tail_probe.py). Tests:
[`tests/test_por_stub_tail_probe.py`](../tests/test_por_stub_tail_probe.py) (35 tests: 21 synthetic, with
falsifiers, plus refusals; 14 retail-pinned; 35 pass, none skipped). Output (git-ignored):
`data/work/por-stub-tail-byte/`. Companion to [por-proc-entry-anomalies.md](por-proc-entry-anomalies.md).
It does not edit `tools/por_farcall_resolve.py` or any other existing file.

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both are checked before use. Read-only on the install. The MZ image base is `0x200`, and the header has
`nreloc = 0`.

## Question and answer

A stub slot is `CD 3F <proc lo> <proc hi> <tail>`. The resolver (`por_farcall_resolve.py`) accepts a group only
when every tail is zero. Otherwise the group is partial, and its nonzero slots are never stubs.

**Answer: the static bytes do not say what the tail does.** Here is what they do establish, with each
evidence class kept apart.

- **Raw pattern.** There are 404 slots. Ten tails are nonzero (`0x13 0x18 0x22 0x27 0x27 0x27 0x40 0x48 0x63
  0x72`). **All ten are the last slot of a partial group**. No non-last slot has a nonzero tail, and all 24
  accepted groups have a zero last tail. So the "partial" label rests on one byte per group.
- **Structural.** A nonzero tail sits in the same layout as a zero tail. The same 5-byte pre-stub block
  (`b2 00 11 00 b0`, or `b2 00 10 00 b0` for the `+0x17` family) precedes every run, in 34 of 34 groups. Each
  partial group then has a 5-byte `b2 00 XX 00 b0` trailer one byte after its stub end, and the gap byte
  is `00` (or `02` in the 117-slot group). The tail is never at a next header's offset. All ten targets
  (`fileofs + proc`) are prologues, against 186 of 191 for accepted slots. The proc word is therefore not
  what sets these ten apart.
- **Relations tested** (proc lo/hi, stub count, slot index, codesz/fixupsz/fileofs bytes, the target's fourth
  byte, the trailer XX): **none matches** on any of the ten. Each is a one-in-256 coincidence, so this is weak
  evidence either way.
- **Decoded reference** (zero-skew model, `phys = 0x200 + seg*16 + off`, from complete `lh.walk` walks at
  each prologue target: 399 of 399 complete, 2,077 unique `call_far` sites):
  - 41 sites land on stub starts. Five of them are well-formed slots of the partial group `0x3E68`, in slots
    0, 1, 2, 4, and 14. **None lands on a nonzero-tail slot.**
  - 11 sites land on the tail byte of accepted group `0xA62` (slots 21, 53, 54, 57, 58, 59). Every one of those
    tails is zero. Under the zero-skew model these are calls to a tail byte, which is not a valid stub entry.
    Shifted by four bytes (`phys - 4`), all eleven land on stub starts of `0xA62`, but the 41 stub-start hits
    fit zero skew, so the two readings conflict. This is **unresolved**: either the model is wrong for these
    segments (`0x8C`, `0x96`), or these walks are misdecoded.
- **Runtime unknown.** The INT 3Fh vector is set at START `0xA7E9` (`mov dx,0x2E6`, with `DS=CS`), `0xA7EE`
  (`mov ax,0x253F`), and `0xA7F1` (`int 21h`). The handler is therefore at `CS:0x2E6`, but the code segment
  of that setup is **not recovered**: the MZ has no relocations and no far call targets the setup routine. A
  search for byte loads at `+2` or `+4` from a pointer register, and for `[bp+2]` IP reads, found no
  attributable read of a stub. The handler is not located, so whether INT 3Fh reads or advances past the tail
  is unknown.

## Verdict on the zero-only rule

- The resolver's partial class is **entirely** the tail byte. Every other slot of each partial group is
  well-formed, and the group's only defect is its one nonzero last tail. So "malformed" here means "tail is
  nonzero", and nothing else in the group is wrong.
- Nothing static shows that a nonzero tail is corrupt. Its placement, its trailer, and its prologue target all
  look like the accepted slots.
- Nothing static shows that it is a real field either. No byte load at `+2` or `+4` from a pointer register is
  attributable to a stub, and no tested relation explains the value.

So the zero-only rule is **not decided** by these bytes. **Do not change `por_farcall_resolve.py` yet.** If
the rule were relaxed, the ten partial groups would become accepted, and their ten last slots would count
as stub candidates, which would change the partial-stub diagnostics.

## Exact open requirement

Either of these would settle it:

1. **The handler.** A decoded disassembly of the INT 3Fh handler at the segment of `CS:0x2E6` (the setup's
   code segment is the open point). It settles the question if it shows whether the handler reads `[IP+4]`
   and what it does with that byte. Or a live CS:IP capture of an INT 3Fh call whose slot is one of the ten
   (blocked per [por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md)).
2. **The segment question.** Whether decoded `9A` sites with segments `0x8C` and `0x96` really target
   `0xAE5` and `0xB99` (tails of `0xA62`), or whether those segments carry a four-byte base. This needs the
   resident code's segment map, which the static bytes do not give.

## Not established

- The meaning of the tail byte, whether a validity bit, an opcode, a terminator, or data. The probe tests
  only the relations listed above, and the byte's effect is not shown.
- The instruction boundaries of the stub runs. The runs were not walked as resident code in this slice.
- Whether the zero-skew model holds for every far-call segment. Eleven decoded sites depend on it.
- Which byte values the copy-protected loader may rewrite at run time. The static bytes cannot show it.

## Commands

```sh
tools/.venv/Scripts/python.exe -I tools/por_stub_tail_probe.py \
    --install data/work/por-geo-run/POOLRAD -o data/work/por-stub-tail-byte       # exit 0
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_stub_tail_probe.py -q -p no:cacheprovider  # 35 passed
```

## Handoff

Static slice, 2026-11-18. Created, not committed or pushed:

- `tools/por_stub_tail_probe.py` (new): the probe.
- `tests/test_por_stub_tail_probe.py` (new): 21 synthetic and refusal tests, 14 retail-pinned. 35 pass.
- `docs/por-stub-tail-byte.md` (new): this document.

Outputs (git-ignored): `data/work/por-stub-tail-byte/por_stub_tail_byte.json` and
`por_stub_tail_byte_report.md`. Scratch survey scripts: `data/work/por-stub-tail-scratch/` (not part of the
deliverable).

Not edited: `tools/por_farcall_resolve.py`, `tools/por_proc_entry_anomalies.py`, the anomaly and
route-census docs, and every other tracked or untracked file. No emulator, DOSBox, GameLink, or codewheel
was run, and no retail file was written.
