# PoR far-call sites in the 0x19BA handler vs START stub 6 in RAM dumps

**Status: memory-byte target cross-check only. `playable: false`; execution is not established.**
This probe re-checks four far-call sites in the shared 0x19BA handler (reached on the `0x37`
side of the `0x21`/`0x37` dispatch) against START stub 6 in two existing RAM dumps. It adds a
byte-level route that the earlier paragraph-aligned image analysis could not model.

**Correction (2026-11-18).** Earlier revisions of this document, and the tool's labels, called
stub 6's procedure a "GEO loader" and the route an "ECL 0x21" route to the GEO loader. Both were
wrong. Stub 6 enters the **WALLDEF wrapper** at `GAME.OVR:0x2F6FF`, which builds `WALLDEF<d>.dax`.
The GEO fill is the separate procedure at `GAME.OVR:0x2F9BE`, and this probe does not test it.
See [`por-ecl-stub6-key-arg-probe.md`](por-ecl-stub6-key-arg-probe.md) for the byte evidence.

## Finding

The pinned `GAME.OVR` has four `9A 3E 00 D5 03` calls at offsets `0x1A77`, `0x1A9E`, `0x1AAA`,
and `0x1AD6`. Each segment word is in the handler group's fixup list. The group at `START:0x3C3`
maps uniquely at linear `0x45C40` in both dumps. At all four mapped sites, both dumps contain
`9A 3E 00 3B 1C`: the live operand is `1C3B:003E`, linear `0x1C3EE`.

The first five bytes at that target are exactly `CD 3F 08 0E 00`, matching START stub 6 at
`0x3E0C`. The stub's procedure word is `0x0E08`. In the partial VROOMM group at START `0x3DD7`,
stub 6 is the entry for code offset `0x0E08`; the owner group's file offset is `0x2E8F7`, so the
candidate procedure is GAME.OVR `0x2F6FF`, whose file bytes begin with `55 89 E5`.

Thus, **if one of those calls executes with the operands present in the dumps**, its immediate
far-call target bytes are stub 6, whose file-side procedure field points to the WALLDEF wrapper at
`0x2F6FF`. This is stronger than the earlier `0x1A27` stub-7 prefix match: stub 6's five-byte entry
matches exactly. It still does not prove execution, INT 3Fh dispatch, or that the wrapper builds
or opens any archive.

## Per-dump result

| Evidence | `pid34644` dump | `wheel-live-capture` dump |
|---|---|---|
| SHA-256 | `f8191750ea6c672ecf649eac86d6dc3efa15766bb50f73ad6f2f68f27dea4895` | `3788787cd795f1f5e433edcfbfa2fb5f05258c57bfbe0d06de400742570516fa` |
| Handler group base | unique at `0x45C40` | unique at `0x45C40` |
| Live operands at four sites | all `1C3B:003E` | all `1C3B:003E` |
| Target linear | `0x1C3EE` | `0x1C3EE` |
| Target bytes | `CD 3F 08 0E 00` | `CD 3F 08 0E 00` |
| Exact match to START stub 6 | yes | yes |

The stub fields and procedure prologue are checked against pinned `START.EXE` and `GAME.OVR`.
The owning VROOMM group is partial, and the probe verifies the descriptor, stub location, proc
word, bounds, and target prologue from bytes rather than treating the group label as proof of
execution.

## Relation to prior results

The zero-skew and paragraph-residue probes remain correct within their stated models: raw
`03D5:003E` does not resolve to stub 6 under the zero-skew or paragraph-aligned segment
arithmetic they tested. The two dumps instead show a concrete live operand and target-byte match
at this site. This is direct evidence for this address in these snapshots; it does not establish
a general sub-paragraph relocation rule or reconcile the full START image placement.

The earlier 32-byte far-call matcher reports the target window as absent because the full window
is not an exact pinned-file window. This probe deliberately checks the exact five-byte stub
entry and its linked procedure field. The adjacent stub 7 remains discrepant: its RAM trailer is
`00`, while START has `27`; see [`por-ecl-21-stub7-dump-probe.md`](por-ecl-21-stub7-dump-probe.md).

## Limits

- The RAM dumps have unknown capture instants. No register or execution trace shows a call at any
  of the four sites.
- The 0x21 handler's reachability from the dispatcher loop is not established.
- The probe identifies the call target bytes and the stub's procedure field. It does not prove
  the INT 3Fh vector/handler was active at capture time or that it entered the procedure.
- The proc at `GAME.OVR:0x2F6FF` is the WALLDEF wrapper, not a GEO routine. Whether any of the four
  calls executes, which archive digit the wrapper selects, and whether it returns a block remain
  open. No GEO load, block, or area association is claimed.
- No gameplay, conversion, or OpenUA mapping is established.

## Reproduction

```sh
python -I tools/por_ecl_21_stub6_dump_probe.py \
  --install data/work/por-geo-run/POOLRAD \
  --out data/work/por-ecl-21-stub6-dump-probe/retail
python -m pytest tests/test_por_ecl_21_stub6_dump_probe.py -q
```

The probe exited 0 with status `ok` for both dumps. The focused suite reports 10 passed,
including the local retail gate. Output is written only under ignored `data/work/`.
