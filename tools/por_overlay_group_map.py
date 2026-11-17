#!/usr/bin/env python3
"""Pool of Radiance overlay-group memory map: one VROOMM group in a RAM dump, read-only.

Status: MEMORY-MAP-PROBE-ONLY. playable: false. Stdlib-only.

Inputs (all read-only; nothing is written into the install or into any running process):
  * the pinned retail GAME.OVR and START.EXE (exact size + SHA-256, no override);
  * one raw linear memory dump, named ram-LO-HI.bin (or given --dump-base);
  * the START.EXE descriptor offset of one VROOMM group (default 0x39E).

What it does:
  1. Parses the group descriptor in START.EXE (CD 3F 00 00, fileofs dword, codesz, fixupsz, jmpcnt)
     and reads the group's fixup table from GAME.OVR at fileofs+codesz (fixupsz/2 sorted words).
  2. Maps the group's code into the dump by matching only STABLE bytes: every byte except the two
     bytes of each fixup word, because the loader rewrites those segment words. The base must be
     the unique linear address where every stable byte matches. Zero hits is "absent", more than
     one is "ambiguous"; both are refusals.
  3. Finds each far-call site: a fixup word whose preceding opcode is 9A (CALL FAR seg:off), so the
     segment word is at w and the offset word at w-2. The live operand is read from the dump at the
     mapped site, the offset is checked against the file, and the live segment is taken from RAM.
  4. Computes the real-mode target linear address seg_live*10h + off, and matches the 32 bytes at
     that address in the pinned GAME.OVR and START.EXE. A target is unique only if the window occurs
     exactly once across both pinned files.

What it does NOT establish, and the report says so in "not_established":
  * that any target was executed or called (a match means the BYTES are present in memory, nothing
    about control flow);
  * that the dump is an atomic snapshot (caller-declared non-atomic captures are recorded as
    metadata only);
  * what the routine at any target does, or any PoR meaning.

Caller metadata (for example pid=34644, status=program START) is recorded verbatim under
"caller_metadata" and is labelled unverified. It never changes a status.

Exit codes: 0 every far-call target resolves to one pinned file offset; 1 the group maps uniquely
but at least one target is absent, ambiguous, or out of the dump (diagnostic); 2 named refusal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

SCHEMA = "openua.por-overlay-group-map"
SCHEMA_VERSION = 1
STATUS_SCOPE = "memory-map-probe-only"
TOOL = "tools/por_overlay_group_map.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-overlay-group-map"
INSTALL_ENV = "OPENUA_POR_INSTALL"

PINS = {
    "GAME.OVR": {"size": 206105,
                 "sha256": "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"},
    "START.EXE": {"size": 65231,
                  "sha256": "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"},
}
DESC_MAGIC = b"\xCD\x3F\x00\x00"
DESC_MIN = 14                    # magic + fileofs dword + codesz, fixupsz, jmpcnt words
DEFAULT_DESCRIPTOR = 0x39E       # START.EXE offset of the accepted group header (caller may override)
FAR_CALL = 0x9A
WINDOW = 32                      # bytes compared for each far-call target
MIN_ANCHOR = 8                   # the longest stable run must be at least this long
PARA = 16
DUMP_NAME_RE = re.compile(r"ram-([0-9a-fA-F]+)-([0-9a-fA-F]+)\.bin$")
CLAIMS = {
    "memory_present": "a far-call target's 32 bytes match a pinned file offset; memory bytes only",
    "executed": "not_established",
    "called": "not_established",
}
NOT_ESTABLISHED = [
    "that any far-call site or target was executed, or was reached by control flow",
    "that the dump is an atomic snapshot (any caller-declared capture mode is metadata only)",
    "that the loader's segment rewrite equals the live segment at any instant after the dump",
    "what any target routine does, and any PoR meaning of the group or its callees",
    "which pinned file a target routine was loaded from, beyond the byte match itself",
    "the answer table, the input comparison, or the prompt state of any screen",
]


class Refusal(Exception):
    """A named refusal: input missing, unpinned, malformed, ambiguous group, or out of bounds."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def check_pin(name: str, data: bytes, pins: dict) -> None:
    pin = pins[name]
    if len(data) != pin["size"] or sha256(data) != pin["sha256"]:
        raise Refusal("%s does not match its pin (size %d); refusing unpinned input" % (name, len(data)))


def parse_descriptor(exe: bytes, ovr: bytes, off: int) -> dict:
    """Read one VROOMM group header from START.EXE and bound-check it against GAME.OVR."""
    if off < 0 or off + DESC_MIN > len(exe):
        raise Refusal("descriptor offset 0x%X is outside START.EXE" % off)
    if exe[off:off + 4] != DESC_MAGIC:
        raise Refusal("no CD 3F 00 00 descriptor header at START.EXE 0x%X" % off)
    fileofs = struct.unpack_from("<I", exe, off + 4)[0]
    codesz, fixupsz, jmpcnt = struct.unpack_from("<HHH", exe, off + 8)
    if codesz == 0:
        raise Refusal("descriptor at 0x%X has codesz 0" % off)
    if fixupsz % 2:
        raise Refusal("descriptor at 0x%X has an odd fixupsz (%d)" % (off, fixupsz))
    if fileofs + codesz + fixupsz > len(ovr):
        raise Refusal("group at GAME.OVR 0x%X runs past the end of GAME.OVR" % fileofs)
    return {"descriptor_offset": off, "fileofs": fileofs, "codesz": codesz,
            "fixupsz": fixupsz, "jmpcnt": jmpcnt}


def read_fixups(ovr: bytes, group: dict) -> list[int]:
    """Body offsets of the segment-valued words. Each must sit inside the code, and the list
    must be strictly increasing (the retail table is sorted)."""
    base = group["fileofs"] + group["codesz"]
    n = group["fixupsz"] // 2
    words = list(struct.unpack_from("<%dH" % n, ovr, base)) if n else []
    for w in words:
        if w + 2 > group["codesz"]:
            raise Refusal("fixup word 0x%X lies outside the group code (codesz 0x%X)"
                          % (w, group["codesz"]))
    if any(b <= a for a, b in zip(words, words[1:])):
        raise Refusal("fixup table is not strictly increasing")
    return words


class Dump:
    """A raw linear memory dump covering [base, base+len)."""

    def __init__(self, data: bytes, base: int):
        self.data, self.base = data, base

    @property
    def end(self) -> int:
        return self.base + len(self.data)

    def covers(self, lin: int, n: int) -> bool:
        return lin >= self.base and lin + n <= self.end

    def read(self, lin: int, n: int) -> bytes:
        if not self.covers(lin, n):
            raise Refusal("dump does not cover linear 0x%X+%d" % (lin, n))
        off = lin - self.base
        return self.data[off:off + n]

    def find_all(self, needle: bytes) -> list[int]:
        hits, pos = [], self.data.find(needle)
        while pos != -1:
            hits.append(self.base + pos)
            pos = self.data.find(needle, pos + 1)
        return hits


def resolve_dump_base(name: str, data_len: int, base_arg: Optional[int]) -> int:
    """Base from the caller or from the ram-LO-HI.bin name. Refuse when they disagree."""
    name_base = None
    m = DUMP_NAME_RE.search(name)
    if m:
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        if hi - lo != data_len:
            raise Refusal("dump is %d bytes but its name says %d" % (data_len, hi - lo))
        name_base = lo
    if base_arg is not None and name_base is not None and base_arg != name_base:
        raise Refusal("--dump-base %X disagrees with the file name base %X" % (base_arg, name_base))
    base = base_arg if base_arg is not None else name_base
    if base is None:
        raise Refusal("dump base unknown: name the file ram-LO-HI.bin or pass --dump-base")
    return base


def map_group(group: dict, code: bytes, fixups: list[int], dump: Dump) -> dict:
    """Unique linear base where every stable (non-fixup) code byte matches the dump."""
    n = len(code)
    fix_bytes = set()
    for w in fixups:
        fix_bytes.update((w, w + 1))
    stable = [i for i in range(n) if i not in fix_bytes]
    # Anchor on the longest contiguous run of stable bytes; verify the rest per candidate.
    best_s, best_l, s = 0, 0, None
    for i in range(n + 1):
        ok = i < n and i not in fix_bytes
        if ok and s is None:
            s = i
        if (not ok) and s is not None:
            if i - s > best_l:
                best_s, best_l = s, i - s
            s = None
    if best_l < MIN_ANCHOR:
        raise Refusal("too few contiguous stable bytes (%d) to anchor the group" % best_l)
    needle = code[best_s:best_s + best_l]
    hits, truncated, rejected = [], 0, 0
    for pos in dump.find_all(needle):
        base = pos - best_s
        if not dump.covers(base, n):
            truncated += 1          # the group would run past the dump; not a usable base
            continue
        off = base - dump.base
        view = dump.data[off:off + n]
        if all(view[i] == code[i] for i in stable):
            hits.append(base)
        else:
            rejected += 1
    status = "unique" if len(hits) == 1 else ("absent" if not hits else "ambiguous")
    return {"status": status, "hits": hits, "anchor_offset": best_s, "anchor_length": best_l,
            "anchor_candidates": len(hits) + rejected + truncated, "rejected_candidates": rejected,
            "truncated_candidates": truncated, "stable_bytes": len(stable),
            "fixup_bytes_excluded": len(fix_bytes), "base_linear": hits[0] if len(hits) == 1 else None}


def far_call_sites(code: bytes, fixups: list[int]) -> tuple[list[dict], list[dict]]:
    """Fixup words preceded by 9A are far-call segment operands; the rest are reported apart."""
    fix_bytes = set()
    for w in fixups:
        fix_bytes.update((w, w + 1))
    sites, others = [], []
    for w in fixups:
        if w >= 3 and code[w - 3] == FAR_CALL and (w - 3) not in fix_bytes and (w - 2) not in fix_bytes:
            sites.append({"site": w - 3, "seg_word": w})
        else:
            others.append({"seg_word": "0x%X" % w, "raw_seg": "0x%04X" % _u16(code, w),
                           "byte_before_seg": ("0x%02X" % code[w - 1]) if w >= 1 else None})
    return sites, others


def _find_in_file(data: bytes, window: bytes) -> list[int]:
    hits, pos = [], data.find(window)
    while pos != -1:
        hits.append(pos)
        pos = data.find(window, pos + 1)
    return hits


def classify_target(window: bytes, files: dict[str, bytes]) -> dict:
    """Pinned-file offsets holding the 32-byte window. Unique only if exactly one hit overall."""
    hits = {name: _find_in_file(data, window) for name, data in files.items()}
    total = sum(len(v) for v in hits.values())
    if total == 0:
        status = "absent"
    elif total > 1:
        status = "ambiguous"
    else:
        status = "unique-" + next(k for k, v in hits.items() if v)
    return {"status": status, "hits": {k: ["0x%X" % h for h in v] for k, v in hits.items()},
            "hit_count": total}


def analyze(ovr: bytes, exe: bytes, dump_data: bytes, dump_base: int, descriptor_off: int, *,
            dump_name: str = "", pins: dict = PINS, meta: Optional[dict] = None) -> dict:
    check_pin("GAME.OVR", ovr, pins)
    check_pin("START.EXE", exe, pins)
    dump = Dump(dump_data, dump_base)
    group = parse_descriptor(exe, ovr, descriptor_off)
    code = ovr[group["fileofs"]:group["fileofs"] + group["codesz"]]
    fixups = read_fixups(ovr, group)
    mapping = map_group(group, code, fixups, dump)
    if mapping["status"] != "unique":
        raise Refusal("group %s in the dump (%d candidate base(s))"
                      % (mapping["status"], len(mapping["hits"])))
    base = mapping["base_linear"]
    sites, others = far_call_sites(code, fixups)
    files = {"GAME.OVR": ovr, "START.EXE": exe}
    rows, deltas = [], set()
    for s in sites:
        site = s["site"]
        site_lin = base + site
        op = dump.read(site_lin, 5)                     # 9A off16 seg16
        off_raw = _u16(code, site + 1)
        seg_raw = _u16(code, site + 3)
        row = {"site_file_offset": "0x%X" % (group["fileofs"] + site),
               "site_group_offset": "0x%X" % site, "site_linear": "0x%X" % site_lin,
               "opcode_0x9a": op[0] == FAR_CALL, "offset_raw": "0x%04X" % off_raw,
               "offset_live": "0x%04X" % _u16(op, 1), "offset_matches_file": _u16(op, 1) == off_raw,
               "seg_raw": "0x%04X" % seg_raw, "seg_live": "0x%04X" % _u16(op, 3)}
        seg_live = _u16(op, 3)
        deltas.add((seg_live - seg_raw) & 0xFFFF)
        target = seg_live * PARA + off_raw
        row["target"] = "%04X:%04X" % (seg_live, off_raw)
        row["target_linear"] = "0x%X" % target
        if not dump.covers(target, WINDOW):
            row["window"] = {"status": "bounds", "hit_count": 0, "hits": {}}
        else:
            live = dump.read(target, WINDOW)
            row["window"] = classify_target(live, files)
            row["window"]["live_bytes_hex"] = live.hex(" ")   # the bytes compared, for inspection
        row["memory_present"] = row["window"]["status"].startswith("unique-")
        rows.append(row)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["window"]["status"]] = counts.get(r["window"]["status"], 0) + 1
    displacements = segment_displacements(rows)
    all_resolved = bool(rows) and all(r["window"]["status"].startswith("unique-")
                                      and r["opcode_0x9a"] and r["offset_matches_file"] for r in rows)
    status = "ok" if all_resolved else "diagnostic"
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL,
        "status_scope": STATUS_SCOPE, "playable": False, "status": status,
        "inputs": {
            "GAME.OVR": {"size": len(ovr), "sha256": sha256(ovr), "pinned": True},
            "START.EXE": {"size": len(exe), "sha256": sha256(exe), "pinned": True},
            "dump": {"name": dump_name, "size": len(dump_data), "sha256": sha256(dump_data),
                     "base": "0x%X" % dump_base, "end": "0x%X" % dump.end},
        },
        "caller_metadata": {"unverified": True, "values": dict(meta or {})},
        "descriptor": {"descriptor_offset": "0x%X" % group["descriptor_offset"],
                       "fileofs": "0x%X" % group["fileofs"], "codesz": "0x%X" % group["codesz"],
                       "fixupsz": "0x%X" % group["fixupsz"], "jmpcnt": group["jmpcnt"],
                       "fixup_count": len(fixups)},
        "group": {"base_linear": "0x%X" % base,
                  "base_paragraph_aligned": base % PARA == 0,
                  "mapping": {k: v for k, v in mapping.items() if k not in ("hits", "base_linear")},
                  "method": "stable bytes only: every byte except the two bytes of each fixup word"},
        "far_call_sites": rows,
        "non_far_fixups": others,
        "relocation": {"seg_deltas": ["0x%04X" % d for d in sorted(deltas)],
                       "uniform_delta": len(deltas) == 1},
        "counts": counts,
        "segment_displacements": displacements,
        "checks": {
            "group_unique": True,
            "far_call_sites_found": bool(rows),
            "all_opcodes_9a": all(r["opcode_0x9a"] for r in rows),
            "all_offsets_match_file": all(r["offset_matches_file"] for r in rows),
            "all_targets_unique_in_pinned_file": all(r["window"]["status"].startswith("unique-")
                                                     for r in rows),
        },
        "runtime_claims": dict(CLAIMS),
        "not_established": list(NOT_ESTABLISHED),
    }


def segment_displacements(rows: list[dict]) -> dict:
    """Per live target segment: file_offset - segment_offset for each uniquely matched target.

    A consistency observation, not a proof. If one segment's unique targets all share one
    displacement, they are one contiguous block of the pinned file. A shifted window that matched
    by accident would normally break that. It is reported, not used to change any status."""
    per: dict[str, dict] = {}
    for r in rows:
        if r["window"]["status"] not in ("unique-START.EXE", "unique-GAME.OVR"):
            continue
        seg, off = r["target"].split(":")
        fname = next(k for k, v in r["window"]["hits"].items() if v)
        fo = int(r["window"]["hits"][fname][0], 16)
        entry = per.setdefault(seg, {"displacements": set(), "targets": 0, "files": set()})
        entry["displacements"].add(fo - int(off, 16))
        entry["targets"] += 1
        entry["files"].add(fname)
    out = {}
    for seg, e in sorted(per.items()):
        disp = sorted(e["displacements"])
        out[seg] = {"targets": e["targets"], "files": sorted(e["files"]),
                    "displacements": [("0x%X" % d) if d >= 0 else ("-0x%X" % -d) for d in disp],
                    "uniform": len(disp) == 1}
    return out


def find_install(install: Optional[Path]) -> Path:
    """The install folder, or its POOLRAD subfolder, holding GAME.OVR and START.EXE."""
    raw = install if install is not None else os.environ.get(INSTALL_ENV)
    if not raw:
        raise Refusal("install folder not given: pass --install or set %s" % INSTALL_ENV)
    p = Path(raw)
    for cand in (p, p / "POOLRAD"):
        if (cand / "GAME.OVR").is_file() and (cand / "START.EXE").is_file():
            return cand
    raise Refusal("GAME.OVR and START.EXE not found under %s" % p)


def probe(install: Optional[Path], dump_path: Path, *, descriptor_off: int, out: Path,
          dump_base: Optional[int], meta: dict) -> tuple[dict, int]:
    folder = find_install(install)
    try:
        out_dir = validate_output_dir(folder, out)
    except PorSourceError as exc:
        raise Refusal(str(exc))
    if DATA_WORK.resolve() not in out_dir.parents:
        raise Refusal("output must be a folder under data/work; got %s" % out_dir)
    if not dump_path.is_file():
        raise Refusal("dump not found: %s" % dump_path)
    ovr = (folder / "GAME.OVR").read_bytes()
    exe = (folder / "START.EXE").read_bytes()
    dump_bytes = dump_path.read_bytes()
    base = resolve_dump_base(dump_path.name, len(dump_bytes), dump_base)
    doc = analyze(ovr, exe, dump_bytes, base, descriptor_off, dump_name=dump_path.name, meta=meta)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "por_overlay_group_map.json").write_text(json.dumps(doc, indent=2) + "\n",
                                                        encoding="utf-8")
    return doc, (0 if doc["status"] == "ok" else 1)


def _int(text: str) -> int:
    return int(text, 16)          # accepts an optional 0x prefix


def _meta(items: list[str]) -> dict:
    out = {}
    for item in items:
        if "=" not in item:
            raise Refusal("--meta expects KEY=VALUE, got %r" % item)
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Map one VROOMM group in a RAM dump (read-only).")
    ap.add_argument("--install", type=Path, default=None,
                    help="PoR install folder (or POOLRAD inside it); default $%s" % INSTALL_ENV)
    ap.add_argument("--dump", type=Path, required=True, help="raw dump, named ram-LO-HI.bin")
    ap.add_argument("--dump-base", type=_int, default=None, help="hex base if not in the name")
    ap.add_argument("--descriptor", type=_int, default=DEFAULT_DESCRIPTOR,
                    help="START.EXE offset of the group header (hex; default 0x39E)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output folder under data/work")
    ap.add_argument("--meta", action="append", default=[], metavar="KEY=VALUE",
                    help="caller provenance, e.g. pid=34644; recorded, unverified")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.dump, descriptor_off=args.descriptor, out=args.out,
                          dump_base=args.dump_base, meta=_meta(args.meta))
    except Refusal as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2
    print("status=%s group=%s sites=%d counts=%s" % (
        doc["status"], doc["group"]["base_linear"], len(doc["far_call_sites"]), doc["counts"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
