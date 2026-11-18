# PoR save-to-GEO exact payload scan

**Status: exact-byte diagnostic only.** The two pinned saves contain no complete
decoded GEO block and no informative exact plane window. This does not bind a
save to a block or area, and it does not rule out a transformed or partial save
representation.

Tool: `tools/por_save_geo_payload_probe.py`. Tests:
`tests/test_por_save_geo_payload_probe.py`. Retail output is written under
`data/work/por-save-geo-payload-probe/retail/` and is git-ignored.

## Question

Do either of the pinned PoR saves contain a complete decoded GEO block, an
exact 256-byte plane, or a long exact run from a decoded plane that could
provide stronger byte-level evidence for the save-to-GEO join?

## Method

- Reads only the pinned `SAVGAMA.DAT` and `SAVGAMJ.DAT` saves and pinned
  `GEO1.DAX` through `GEO8.DAX`. Sizes and SHA-256 values come from the
  PoR-owned pin tables in `por_save_state_probe.py` and
  `por_area_evidence.py`.
- Decodes the DAX TOCs and RLE payloads with `por_map.py`; all 29 retail
  blocks must decode to 1,026 bytes.
- Searches exact bytes for a whole decoded block and each of its four 256-byte
  planes. A plane match is reported even when its content is low-information.
- Separately scans every window wholly inside each plane at lengths 64, 128,
  192 and 256. The informative-window count requires at least eight distinct
  byte values. This threshold only filters repetitive matches; it is not a
  PoR format rule.
- Re-hashes every input after scanning. A missing, symlinked, size-changed,
  hash-changed, malformed, or mid-run-changed input is refused.
- JSON and Markdown include offsets, hashes and byte statistics, never raw save
  bytes. Output is accepted only in a child directory of `data/`, outside the
  install.

## Retail result

Command:

```powershell
tools/.venv/Scripts/python.exe tools/por_save_geo_payload_probe.py `
  --install "G:/Games/Pool of Radiance/POOLRAD" `
  -o data/work/por-save-geo-payload-probe/retail
```

The pinned inputs matched: two saves, eight GEO archives and 29 decoded blocks.

| Save | Complete block matches | Exact 256-byte plane matches | Informative 64/128/192/256-byte windows |
| --- | ---: | ---: | --- |
| SAVGAMA.DAT | 0 | 2 | 0 / 0 / 0 / 0 |
| SAVGAMJ.DAT | 0 | 2 | 0 / 0 / 0 / 0 |

Both plane matches in each save are all-zero plane 3:

| GEO archive | TOC index | Block id | Save offset | Distinct values | Nonzero bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| GEO6.DAX | 1 | 25 | 1 | 1 | 0 |
| GEO8.DAX | 2 | 27 | 1 | 1 | 0 |

Each all-zero match has SHA-256
`5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1`.
The matches start at save offset 1 in both files. Because a 256-byte zero run
matches at every overlapping offset inside the zero-filled save prefix, the
probe reports 2,615 occurrences in SAVGAMA and 2,597 in SAVGAMJ for each of
these plane records; only the first 16 offsets are printed in JSON. They do not
identify the saved map: they are identical empty planes in two different GEO
blocks.

The scan finds no exact plane window with at least eight distinct values at any
of the four tested lengths. The only 64-byte and longer exact windows are
excluded as low-information repetitive sequences by that explicit threshold.
No decoded block occurs as a complete byte sequence in either save.

## Interpretation and limits

This result rules out only direct byte-for-byte inclusion of a complete decoded
GEO block and the reported exact plane/window forms in these two pinned saves.
It does not test compression, encryption, fieldwise copies, transforms, partial
cell records, sidecar files, other saves, or any runtime loader behavior.

The earlier candidate-cell check found that SAVGAMA's full-cell signature is
unique to GEO2.DAX TOC index 2 / block id 20 among decoded cells, while
SAVGAMJ's signature also occurs in GEO8.DAX. That is still compatibility
evidence only. This payload scan adds no save-to-block or game-area binding.
See `docs/por-save-geo-candidate-check.md`.

No DOSBox, Hatari, GameLink, codewheel, retail-file writes, or GoldBox evidence
is part of this probe.

## Tests

```powershell
tools/.venv/Scripts/python.exe -m pytest tests/test_por_save_geo_payload_probe.py -q
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" `
  tools/.venv/Scripts/python.exe -m pytest tests/test_por_save_geo_payload_probe.py -q
```

The synthetic tests cover full-block and plane matches, informative windows,
zero-plane filtering, one-byte falsification, pins, install mutation,
determinism, output-path refusal, and path-free output. The retail-gated test
checks all 29 blocks and the result table above.
