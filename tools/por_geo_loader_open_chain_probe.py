#!/usr/bin/env python3
"""Static, observe-only census of the Pool of Radiance DAX open / filename chain (GEO open path).

Pins START.EXE and GAME.OVR, then re-derives from the bytes:

1. The Pascal length-prefixed pieces that end in a `.dax` suffix piece, in both pinned binaries.
   Each suffix is reported with every chain of printable pieces that ends just before it.
2. Whether any single-character digit piece sits beside the GEO stem. The archive number cannot
   come from a literal unless one does.
3. The byte chains the handoff relies on: the open routine at START 0x8624, its single E8 byte-pattern
   candidate (0x87CC, within the caller body span at 0x876D), the DS-table selector chain at 0x8671, the
   DOS open wrapper (module base 0xAC76 is conditional), and the GAME.OVR selector writer.
4. Whether those byte windows, and the GAME.OVR name-building bytes, are present in the pinned
   RAM dumps, and at what linear address. Presence is memory-present at an unknown instant; it
   is not execution.
5. The install file names, matched against each stem chain with a digit slot. Consistency only.

It does not run DOSBox or any emulator, does not decode DS or read the DS table, and does not
name a GEO archive or GEO block. Every runtime value is reported as "not_established".
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

SCHEMA = "openua.por-geo-loader-open-chain-probe"
VERSION = 1
TOOL = "tools/por_geo_loader_open_chain_probe.py"
ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-geo-loader-open-chain-probe"
DEFAULT_DUMPS = [
    DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
    DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin",
]
START_NAME = "START.EXE"
OVR_NAME = "GAME.OVR"
START_PIN = {"size": 65231,
             "sha256": "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"}
OVR_PIN = {"size": 206105,
           "sha256": "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"}

# START offsets use the same file-offset convention as tools/por_geo_loader_open_probe.py.
OPEN_ROUTINE = 0x8624
BODY = 0x876D
OPEN_PROLOGUE = bytes.fromhex("55 89 e5 81 ec 56 04 c4 7e 16")   # push bp; mov bp,sp; sub sp,0x456; ...
BODY_PROLOGUE = bytes.fromhex("55 89 e5 81 ec 3e 02 c4 7e 14")   # push bp; mov bp,sp; sub sp,0x23E; ...
OPEN_CALL_SITE = 0x87CC            # the E8 that the body uses to call OPEN_ROUTINE (expected)
SELECTOR_AT = 0x8671
MODULE_BASE = 0xAC76               # 0x0AF8 -> START file 0xAC76, from the copy-helper probe (conditional)
OPEN_WRAPPER = MODULE_BASE + 0x1410  # 0xC086 (conditional)
OPEN_INT_AT = OPEN_WRAPPER + 0x3E  # 0xC0C4
PATH_GUARD_AT = 0xC0BD
OPEN_SETUP = bytes.fromhex("a0 2c 44 b4 3d 33 d2 eb 06")
PATH_GUARD = bytes.fromhex("26 80 7d 30 00 74 12")
OPEN_INT = bytes.fromhex("1e 8d 55 30 06 1f 33 c9 cd 21 1f")
SELECTOR_CHAIN = bytes.fromhex("a0 76 53 30 e4 ba 1e 00 f7 e2 8b f8 81 c7 14 26 1e 57 9a 0b 0b f8 0a")
SELECTOR_WRITER_AT = 0x1FBA7       # GAME.OVR
SELECTOR_WRITER = bytes.fromhex("c4 3e d6 49 26 8a 85 24 06 a2 76 53")

# Name-building bytes in GAME.OVR (the GEO fill procedure and its literal) and other resident checks.
GEO_FILL_PROC = 0x2F9BE
GEO_LITERAL_AT = 0x2F994           # length byte of the "\x03GEO" piece (file offset in GAME.OVR)
WALLDEF_WRAPPER_BODY = 0x2F6FF        # stub 6's proc: the WALLDEF wrapper, not the GEO fill
ECL_LITERAL_AT = 0x190E            # "\x03ECL" piece, GAME.OVR
START_8X8_LITERAL_AT = 0x723A      # "\x058X8d1" piece, START.EXE

PRINTABLE = range(0x20, 0x7F)
SUFFIX_RE = re.compile(rb"\x04\.dax", re.IGNORECASE)
DIGIT_PIECE_RE = re.compile(rb"\x01[0-9]")
DUMP_NAME_RE = re.compile(r"ram-([0-9A-Fa-f]+)-([0-9A-Fa-f]+)\.bin$")


class Refusal(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def at(data: bytes, pos: int, expected: bytes) -> bool:
    return pos >= 0 and data[pos:pos + len(expected)] == expected


def _printable(text: bytes) -> bool:
    return len(text) > 0 and all(c in PRINTABLE for c in text)


def pieces_ending_at(data: bytes, last: int, depth: int = 3) -> list:
    """Every chain of length-prefixed printable pieces whose text ends at data[last].

    A piece is [n][n text bytes] with 1 <= n <= 29. A chain is returned as a tuple of
    (length_byte_offset, text) in reading order. Shorter chains are returned as well, so the
    caller sees the ambiguity rather than a chosen parse.
    """
    if depth <= 0 or last < 0:
        return []
    out = []
    for n in range(1, 30):
        a = last - n
        if a < 0:
            break
        if data[a] != n:
            continue
        text = data[a + 1:last + 1]
        if not _printable(text):
            continue
        piece = ((a, text.decode("ascii")),)
        out.append(piece)
        for prev in pieces_ending_at(data, a - 1, depth - 1):
            out.append(prev + piece)
    return out


NAME_PIECE_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")   # a DOS 8.3 stem piece; message text is rejected


def suffix_census(data: bytes, name: str) -> list:
    """One row per `\\x04.dax` suffix piece, with every DOS-name-like stem chain that ends before it.

    Chains that include non-name text (for example a UI message piece) are rejected and counted,
    not used. When more than one name-like chain ends at the suffix, the census flags ambiguity and
    reports the longest as the install-consistent reading; the bytes alone do not choose it.
    """
    rows = []
    for m in SUFFIX_RE.finditer(data):
        q = m.start()
        parses = pieces_ending_at(data, q - 1)
        names = [p for p in parses if all(NAME_PIECE_RE.match(t) for _, t in p)]
        longest = max(names, key=len) if names else ()
        rows.append({
            "file": name,
            "suffix_len_at": "0x%05X" % q,
            "suffix_text": data[q + 1:q + 5].decode("ascii"),
            "stem_parses": ["+".join(t for _, t in p) for p in names],
            "rejected_non_name_parses": len(parses) - len(names),
            "stem": "+".join(t for _, t in longest) if longest else None,
            "stem_len_at": ("0x%05X" % longest[0][0]) if longest else None,
            "stem_pieces": [t for _, t in longest],
            "bare": not names,
            "ambiguous": len({len(p) for p in names}) > 1,
            "stem_contains_digit": any(c.isdigit() for _, t in longest for c in t),
        })
    return rows


def digit_pieces_near(data: bytes, row: dict) -> list:
    """Single-character digit pieces inside the window that holds the stem and suffix."""
    lo = int(row["stem_len_at"], 16) if row["stem_len_at"] else int(row["suffix_len_at"], 16)
    hi = int(row["suffix_len_at"], 16) + 6
    return ["0x%05X" % m.start() for m in DIGIT_PIECE_RE.finditer(data) if lo - 2 <= m.start() <= hi]


def install_matches(install_names: list, pieces: list) -> dict:
    """Count install names matching the stem chain with one digit slot between pieces, or after."""
    if not pieces:
        return {"between_pieces": None, "after_last": None}
    between = r"\d".join(re.escape(p) for p in pieces)
    after = between + r"\d"
    pat_b = re.compile(r"^%s\.DAX$" % between, re.IGNORECASE)
    pat_a = re.compile(r"^%s\.DAX$" % after, re.IGNORECASE)
    exact = re.compile(r"^%s\.DAX$" % "".join(re.escape(p) for p in pieces), re.IGNORECASE)
    return {
        "between_pieces": sorted(n for n in install_names if pat_b.match(n)) if len(pieces) > 1 else None,
        "after_last": sorted(n for n in install_names if pat_a.match(n)),
        "exact_name": sorted(n for n in install_names if exact.match(n)),
    }


def open_call_scan(start: bytes) -> dict:
    """Byte-pattern scan of START for E8 (near) and 9A (far) operands that name OPEN_ROUTINE."""
    near = []
    for i in range(len(start) - 2):
        if start[i] == 0xE8:
            rel = int.from_bytes(start[i + 1:i + 3], "little", signed=True)
            if i + 3 + rel == OPEN_ROUTINE:
                near.append(i)
    far = []
    for i in range(len(start) - 4):
        if start[i] == 0x9A and int.from_bytes(start[i + 1:i + 3], "little") == OPEN_ROUTINE:
            far.append(i)
    return {
        "near_pattern_candidates": ["0x%05X" % i for i in near],
        "far_pattern_candidates": ["0x%05X" % i for i in far],
        "single_near_pattern_candidate_expected": near == [OPEN_CALL_SITE] and not far,
        "method": "byte-pattern scan of START.EXE (not a decode)",
    }


def dump_base(path: Path, length: int) -> int:
    m = DUMP_NAME_RE.search(path.name)
    if not m:
        raise Refusal("dump name must be ram-LO-HI.bin: %s" % path.name)
    lo, hi = int(m.group(1), 16), int(m.group(2), 16)
    if hi - lo != length:
        raise Refusal("dump %s is %d bytes but its name says %d" % (path.name, length, hi - lo))
    return lo


def masked_window(pat: bytes) -> re.Pattern:
    """Regex for a window whose far-call segment words (the two bytes after each 9Ah) are wildcards.

    Those words are relocated by the loader, so the file and the live dump disagree there.
    """
    wild = set()
    for i, b in enumerate(pat):
        if b == 0x9A and i + 4 < len(pat):
            wild.update((i + 3, i + 4))
    body = b"".join(b"." if i in wild else re.escape(bytes([b])) for i, b in enumerate(pat))
    return re.compile(b"(?=" + body + b")", re.DOTALL)


def find_window(dump: bytes, pat: bytes) -> dict:
    hits = [m.start() for m in masked_window(pat).finditer(dump)][:3]
    status = "absent" if not hits else ("unique" if len(hits) == 1 else "ambiguous")
    return {"status": status, "linear": ["0x%X" % h for h in hits]}


MEMORY_WINDOWS = [
    # (image, label, file offset, length, expected-bytes source)
    ("START.EXE", "open_routine_8624", OPEN_ROUTINE, 21),
    ("START.EXE", "caller_body_876D", BODY, 21),
    ("START.EXE", "selector_chain_8671", SELECTOR_AT, len(SELECTOR_CHAIN)),
    ("START.EXE", "open_wrapper_C086_conditional", OPEN_WRAPPER, len(OPEN_SETUP)),
    ("START.EXE", "open_int_C0C4_conditional", OPEN_INT_AT, len(OPEN_INT)),
    ("START.EXE", "piece_8X8d1_723A", START_8X8_LITERAL_AT, 11),
    ("GAME.OVR", "geo_literal_2F994", GEO_LITERAL_AT, 9),
    ("GAME.OVR", "geo_fill_proc_2F9BE", GEO_FILL_PROC, 16),
    ("GAME.OVR", "walldef_wrapper_2F6FF", WALLDEF_WRAPPER_BODY, 16),
    ("GAME.OVR", "ecl_literal_190E", ECL_LITERAL_AT, 8),
    ("GAME.OVR", "selector_writer_1FBA7", SELECTOR_WRITER_AT, len(SELECTOR_WRITER)),
]


def memory_presence(images: dict, dumps: list) -> dict:
    """Presence of each named window in each dump. START code windows are compared by displacement."""
    rows = []
    for image, label, off, n in MEMORY_WINDOWS:
        data = images[image]
        pat = data[off:off + n]
        row = {"image": image, "label": label, "file_offset": "0x%05X" % off, "bytes": pat.hex(" "),
               "dumps": []}
        for dlabel, base, dbytes in dumps:
            res = find_window(dbytes, pat)
            entry = {"dump": dlabel, "status": res["status"], "linear": res["linear"]}
            if res["status"] == "unique":
                entry["displacement"] = "0x%X" % (int(res["linear"][0], 16) - off)
            row["dumps"].append(entry)
        rows.append(row)
    return {"windows": rows}


ANCHORS = ("open_routine_8624", "caller_body_876D")
CODE_WINDOWS = ANCHORS + ("selector_chain_8671",)


def displacement_consistency(memory: dict) -> dict:
    """Linear displacement (dump address minus file offset) of the START code windows, per dump.

    The shared displacement is taken from the two anchors only, and only when both are unique and
    agree in that dump. A window that is ambiguous is then checked against that displacement; it
    is not assigned one.
    """
    rows = {r["label"]: r for r in memory["windows"]}
    per_dump = {}
    for d_idx, d in enumerate(memory["dumps"]):
        label = d["label"]
        anchors = [rows[a]["dumps"][d_idx] for a in ANCHORS]
        anchor_disp = {x.get("displacement") for x in anchors}
        shared = anchor_disp.pop() if len(anchor_disp) == 1 and None not in anchor_disp and \
            all(x["status"] == "unique" for x in anchors) else None
        windows = {}
        for lbl in CODE_WINDOWS:
            entry = rows[lbl]["dumps"][d_idx]
            off = int(rows[lbl]["file_offset"], 16)
            at_shared = None
            if shared is not None and entry["status"] != "absent":
                at_shared = any(int(x, 16) - off == int(shared, 16) for x in entry["linear"])
            windows[lbl] = {"status": entry["status"], "unique_displacement": entry.get("displacement"),
                            "hit_at_shared_displacement": at_shared}
        per_dump[label] = {"shared_displacement": shared, "windows": windows}
    return per_dump


def inspect(start: bytes, ovr: bytes, install_names: list) -> dict:
    """Byte-level census and chain checks, with no runtime claims. Refuses unpinned binaries."""
    if len(start) != START_PIN["size"] or sha(start) != START_PIN["sha256"]:
        raise Refusal("START.EXE does not match the pinned PoR file")
    if len(ovr) != OVR_PIN["size"] or sha(ovr) != OVR_PIN["sha256"]:
        raise Refusal("GAME.OVR does not match the pinned PoR file")

    rows = suffix_census(ovr, OVR_NAME) + suffix_census(start, START_NAME)
    for row in rows:
        data = ovr if row["file"] == OVR_NAME else start
        row["digit_pieces_near"] = digit_pieces_near(data, row) if row["stem"] else []
        row["install_matches"] = install_matches(install_names, row["stem_pieces"]) if row["stem"] else None

    geo_rows = [r for r in rows if r["stem"] == "GEO" and r["file"] == OVR_NAME]
    geo = geo_rows[0] if len(geo_rows) == 1 else None
    geo_digit_candidates = geo["digit_pieces_near"] if geo else None

    chains = {
        "open_routine_prologue": at(start, OPEN_ROUTINE, OPEN_PROLOGUE),
        "body_prologue": at(start, BODY, BODY_PROLOGUE),
        "selector_chain": at(start, SELECTOR_AT, SELECTOR_CHAIN),
        "open_setup": at(start, OPEN_WRAPPER, OPEN_SETUP),
        "path_guard": at(start, PATH_GUARD_AT, PATH_GUARD),
        "open_int": at(start, OPEN_INT_AT, OPEN_INT),
        "selector_writer": at(ovr, SELECTOR_WRITER_AT, SELECTOR_WRITER),
    }
    calls = open_call_scan(start)
    byte_checks_ok = all(chains.values()) and calls["single_near_pattern_candidate_expected"]

    return {
        "chains": chains,
        "open_call_scan": calls,
        "suffix_census": rows,
        "geo": {
            "unique_geo_row": geo is not None,
            "stem_len_at": geo["stem_len_at"] if geo else None,
            "suffix_len_at": geo["suffix_len_at"] if geo else None,
            "digit_piece_candidates_near_stem": geo_digit_candidates,
            "install_matches": geo["install_matches"] if geo else None,
        },
        "byte_checks_ok": byte_checks_ok,
    }


def digit_slot_status(candidates: Optional[list]) -> str:
    """Status of the archive-digit claim. A digit literal beside GEO is never 'established' here."""
    if not candidates:
        return "not_established_no_digit_literal"
    return "candidate_digit_literal_unverified"


def verdict(doc: dict) -> dict:
    """Claim-by-claim status. Each status is computed from the checks above, never assumed."""
    ch = doc["inspect"]["chains"]
    calls = doc["inspect"]["open_call_scan"]
    geo = doc["inspect"]["geo"]
    mem = doc["memory"]
    fill_rows = {r["label"]: r for r in mem.get("windows", [])}
    fill_dumps = fill_rows["geo_fill_proc_2F9BE"]["dumps"] if mem.get("checked") else []
    fill_absent = (all(d["status"] == "absent" for d in fill_dumps) if fill_dumps else None)
    fill_present = any(d["status"] != "absent" for d in fill_dumps)
    digit_status = digit_slot_status(geo.get("digit_piece_candidates_near_stem"))

    claims = [
        {"id": "C1", "claim": "Open is DOS AH=3Dh, path at ES:DI+0x30 (wrapper 0xC086, module base conditional)",
         "status": "bytes_established_conditional" if (ch["open_setup"] and ch["path_guard"] and ch["open_int"])
         else "not_validated"},
        {"id": "C2", "claim": "Path row selected at DS:[0x2614 + low(DS:[0x5376])*0x1E]",
         "status": "bytes_established_runtime_unproven" if ch["selector_chain"] else "not_validated"},
        {"id": "C3", "claim": "GEO stem and .dax suffix exist as Pascal pieces in GAME.OVR",
         "status": "established_file_bytes" if (geo["unique_geo_row"] and geo["stem_len_at"] == "0x%05X" % GEO_LITERAL_AT)
         else "not_validated"},
        {"id": "C4", "claim": "The archive number is a literal digit piece beside GEO",
         "status": digit_status},
        {"id": "C5", "claim": "DS:[0x5376] is fed from ES:[DI+0x624] via DS:[0x49D6] (one static chain)",
         "status": "bytes_established_single_chain_runtime_unproven" if ch["selector_writer"] else "not_validated"},
        {"id": "C6", "claim": "One raw E8 byte pattern to 0x8624 occurs at 0x87CC, inside the 0x876D body span",
         "status": "byte_pattern_candidate" if calls["single_near_pattern_candidate_expected"] else "not_validated"},
        {"id": "C7", "claim": "The GEO fill procedure (GAME.OVR 0x2F9BE) runs and pushes the pieces",
         "status": ("not_established_overlay_not_resident" if fill_absent
                    else ("memory_present_not_executed" if fill_present else "not_checked"))},
        {"id": "C8", "claim": "The opened file is GEO<n>.DAX for n in 1..8",
         "status": "not_established"},
    ]
    ok_bytes = all(c["status"] not in ("not_validated",) for c in claims)
    return {
        "claims": claims,
        "handoff_status": ("bytes_consistent_runtime_open_unresolved" if ok_bytes and doc["inspect"]["byte_checks_ok"]
                           else "not_validated"),
        "archive": "not_established",
        "requested_block": "not_established",
        "playable": False,
    }


def probe(install: Path, dump_paths: list) -> dict:
    exe_file = install / START_NAME
    ovr_file = install / OVR_NAME
    if not exe_file.is_file() or not ovr_file.is_file():
        raise Refusal("missing pinned START.EXE or GAME.OVR")
    start = exe_file.read_bytes()
    ovr = ovr_file.read_bytes()
    names = sorted(p.name for p in install.iterdir() if p.is_file())
    result = inspect(start, ovr, names)

    dumps = []
    for dp in dump_paths:
        if not dp.is_file():
            continue
        raw = dp.read_bytes()
        dumps.append(("%s/%s" % (dp.parent.name, dp.name), dump_base(dp, len(raw)), raw))
    memory = {"checked": bool(dumps), "dumps": [{"label": d[0], "base": "0x%X" % d[1], "size": len(d[2])}
                                              for d in dumps]}
    if dumps:
        memory.update(memory_presence({START_NAME: start, OVR_NAME: ovr},
                                      [(d[0], d[1], d[2]) for d in dumps]))
        memory["displacement"] = displacement_consistency(memory)
    doc = {"schema": SCHEMA, "schema_version": VERSION, "tool": TOOL, "playable": False,
           "pins": {START_NAME: {"size": len(start), "sha256": sha(start), "match": True},
                    OVR_NAME: {"size": len(ovr), "sha256": sha(ovr), "match": True}},
           "inspect": result, "memory": memory}
    doc["verdict"] = verdict(doc)
    if sha(exe_file.read_bytes()) != sha(start) or sha(ovr_file.read_bytes()) != sha(ovr):
        raise Refusal("a pinned input changed during the probe")
    doc["input_unchanged"] = True
    doc["all_byte_checks_match"] = result["byte_checks_ok"]
    return doc


def render_report(doc: dict) -> str:
    ins = doc["inspect"]
    v = doc["verdict"]
    lines = [
        "# Pool of Radiance DAX open chain (static, observe-only)", "",
        "**Status: `playable: false`. Archive, requested block and the GEO digit remain unresolved.**", "",
        "## Byte census (file bytes)", "",
        "| Image | Suffix at | Stem chain | Stem at | Bare | Ambiguous | Digit pieces near |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in ins["suffix_census"]:
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            r["file"], r["suffix_len_at"], r["stem"] or "(none)", r["stem_len_at"] or "-", r["bare"],
            r["ambiguous"], ", ".join(r["digit_pieces_near"]) or "-"))
    lines += ["", "## Install slot check (file names, consistency only)", "",
              "| Stem chain | Names: one digit between pieces | Names: one digit after | Names: exact stem.DAX |",
              "| --- | --- | --- | --- |"]
    for r in ins["suffix_census"]:
        if r["install_matches"] is None:
            continue
        im = r["install_matches"]
        between = len(im["between_pieces"]) if im["between_pieces"] is not None else "n/a"
        lines.append("| %s | %s | %s | %s |" % (r["stem"], between, len(im["after_last"]), len(im["exact_name"])))
    lines += ["", "## Chain checks (file bytes)", ""]
    for k, val in ins["chains"].items():
        lines.append("- `%s`: %s" % (k, val))
    lines.append("- Open-call byte-pattern scan (START E8/9A to 0x8624): near candidates %s, far candidates %s." %
                 (ins["open_call_scan"]["near_pattern_candidates"],
                  ins["open_call_scan"]["far_pattern_candidates"]))
    lines += ["", "## Memory presence (unknown instant; not execution)", ""]
    if doc["memory"]["checked"]:
        for row in doc["memory"]["windows"]:
            cells = ", ".join("%s=%s%s" % (d["dump"].split("/")[0], d["status"],
                                           (" @" + d["linear"][0]) if d["status"] == "unique" else "")
                              for d in row["dumps"])
            lines.append("- `%s` (%s at %s): %s" % (row["label"], row["image"], row["file_offset"], cells))
        for dlabel, info in doc["memory"]["displacement"].items():
            lines.append("- %s: anchor displacement %s; START code windows at that displacement: %s." % (
                dlabel, info["shared_displacement"],
                {k: v["hit_at_shared_displacement"] for k, v in info["windows"].items()}))
    else:
        lines.append("- No pinned RAM dump was present; memory presence was not checked.")
    lines += ["", "## Claims", ""]
    for c in v["claims"]:
        lines.append("- %s %s — `%s`" % (c["id"], c["claim"], c["status"]))
    lines += ["", "## Verdict", "",
              "- Handoff status: `%s`." % v["handoff_status"],
              "- Archive: `%s`; requested block: `%s`; playable: %s." % (v["archive"], v["requested_block"],
                                                                         str(v["playable"]).lower()), ""]
    return "\n".join(lines)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Static PoR DAX open-chain census (observe-only)")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    ap.add_argument("--dump", type=Path, action="append", default=None,
                    help="RAM dump ram-LO-HI.bin (repeatable); defaults to the two pinned dumps if present")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK) or _inside(args.out, args.install):
        print("refused: output must be under data/work and outside the install", file=sys.stderr)
        return 2
    dumps = args.dump if args.dump else DEFAULT_DUMPS
    if args.dump:
        for dp in args.dump:
            if not dp.is_file():
                print("refused: dump not found: %s" % dp, file=sys.stderr)
                return 2
    try:
        doc = probe(args.install, dumps)
    except (Refusal, OSError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "por_geo_loader_open_chain_probe.json").write_text(json.dumps(doc, indent=2) + "\n",
                                                                   encoding="utf-8")
    (args.out / "por_geo_loader_open_chain_probe.md").write_text(render_report(doc), encoding="utf-8")
    print("wrote %s (handoff_status=%s, archive=%s, playable=false)" %
          (args.out, doc["verdict"]["handoff_status"], doc["verdict"]["archive"]))
    return 0 if doc["all_byte_checks_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
