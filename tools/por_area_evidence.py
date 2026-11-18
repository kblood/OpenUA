#!/usr/bin/env python3
"""Pool of Radiance: targeted evidence probe for the GEO map-load path.

Status: STATIC-EVIDENCE-ONLY. Read-only, stdlib-only, playable: false.

Question this probe narrows (it does not answer it): can a GEO archive TOC block
be tied to an in-game area number, and can the authentic start area or start
entry be recovered from the retail binaries or from existing run artifacts?

What it measures, from the retail bytes only:

  * the pinned hashes of START.EXE, GAME.OVR, the eight GEO*.DAX archives, and
    the hashes (not parsed) of the two shipped saved-game files;
  * the TOC of each GEO archive, via tools/por_map.parse_dax (29 blocks on the
    retail install; ids and their TOC positions are recorded);
  * every ".dax" / ".dat" file-name literal in GAME.OVR and START.EXE, as a
    Turbo Pascal length-prefixed string piece, with its file offset;
  * for each literal, whether the bytes immediately before its block are the
    ``ret``/``retf`` of exactly one procedure whose prologue lies a short way
    back (a layout candidate for the owning procedure, not a proof);
  * the decoded argument checks, return width and call sites of that procedure;
  * whether the procedure's CS-relative string operands (``mov r,imm`` then
    ``push cs``) resolve to Pascal strings under any single overlay base;
  * whether each literal lies in an overlay group the START.EXE stub scan
    recognises (``por_farcall_resolve.scan_groups``); a literal outside every
    recognised group is reported as ``uncovered``, not as unrecognised code;
  * optional ``*.log`` files from a run directory: GEO*.DAX file-operation lines.

It emits ``mappings: []``. A block-to-area, file-to-area, or start-entry mapping
is written only when a retail fact determines it and a control shows the
alternatives fail. No such fact exists in the bytes probed here, so the probe
names the candidates and lists the unknown fields with their reasons.

Usage
  python tools/por_area_evidence.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-area-evidence/retail [--run-artifacts DIR]

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_area_evidence.json          schema openua.por-area-evidence, playable: false
  por_area_evidence_report.md     the readable summary

Exit codes
  0  every pin matched and every GEO archive parsed (evidence structure is
     complete; this does not mean a mapping was found)
  1  output written, but a pin did not match (only with --allow-unpinned) or a
     GEO archive was refused
  2  named refusal: missing or ambiguous install files, an unsafe output
     location, or a file not matching its pin without --allow-unpinned
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_map as pm  # noqa: E402
import por_farcall_resolve as farcall  # noqa: E402
import por_loadpieces_handler as handler  # noqa: E402

SCHEMA = "openua.por-area-evidence"
SCHEMA_VERSION = 0
STATUS = "static-evidence-only"
TOOL = "tools/por_area_evidence.py"

OVR_NAME = farcall.OVR_NAME
EXE_NAME = farcall.EXE_NAME
SAVE_NAMES = ("SAVGAMA.DAT", "SAVGAMJ.DAT")
GEO_NAMES = tuple("GEO%d.DAX" % n for n in range(1, 9))

# (size, sha256) of the retail GEO archives, as recorded in
# data/work/por-geo-manifest/retail (GOG DOS install, 2026-11-17).
GEO_PINS = {
    "GEO1.DAX": (2619, "e6bcc8c5ea4b101497353ec75386b96ad6368447a6669f4f82ca7dac3c1e204a"),
    "GEO2.DAX": (2572, "2035246014efdb26de3114f4737d52a935ad8834f79b4a8e4880da2922b6d595"),
    "GEO3.DAX": (1761, "ce4b4ecb74b03ca18bda5d00e9050ec4e18284ef89edf816480800070ed0c6ee"),
    "GEO4.DAX": (2861, "167017243737cfacb996433632d3c70a55ce506d794a44e31c02d34e9e3c55d5"),
    "GEO5.DAX": (3612, "24c5b6f1bbf18b6f9a34600d99043e002848b9d2165189e4000c000a01f5c527"),
    "GEO6.DAX": (2324, "8bf4bbf5b1845c9d3181a7d47382d75f5337e27e1263690abb8820f9b722ecdb"),
    "GEO7.DAX": (3118, "5f30b6e76ca42b563253fc9b4cee5be7db6ccbe0eb38eefe37866197e5be2127"),
    "GEO8.DAX": (4690, "050cd0316ebf339f6b36233156eb99129c8eaa689df89e05fbfa13d72e89c045"),
}

PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
PROLOGUE_WINDOW = 0x2000     # bytes searched backward from a literal block
# Instructions decoded per candidate walk. A walk from a prologue p that ends at a
# block start spans at most PROLOGUE_WINDOW bytes, and each instruction is at least
# one byte, so a matching walk never needs more instructions than the window has
# bytes. The bound therefore cannot hide a layout owner. (It was 800 until the
# WALLDEF owner at GAME.OVR 0x2EEF4 was found to be 827 instructions long.)
MAX_WALK = PROLOGUE_WINDOW
RET_FLOWS = ("ret", "retf")
DAX_SUFFIX = re.compile(rb"\x04\.da[xt]", re.IGNORECASE)
PIECE_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
MAX_PIECE = 12
GEO_LINE = re.compile(rb"GEO\d\.DAX", re.IGNORECASE)
MOV_REG_IMM = re.compile(r"^mov (ax|bx|cx|dx|si|di|sp|bp)$")   # decoder name for mov r16,imm

UNKNOWN = [
    {"field": "block_to_area",
     "status": "unknown",
     "reason": "No retail fact ties a TOC block id to an area number. The procedure that "
               "loads GEO data is located only by layout (see load_routine); this probe does "
               "not establish how its arguments select a TOC block."},
    {"field": "geo_file_to_area_group",
     "status": "unknown",
     "reason": "The file name is assembled at run time from pieces, not from one literal. "
               "The argument that selects the GEO number is not traced to a caller, so no "
               "file-to-area relation is proven."},
    {"field": "start_area",
     "status": "unknown",
     "reason": "No start-area value is recorded in the retail binaries that this probe reads. "
               "GAME001.DAT byte 48 is an OpenUA design field, not a retail value. The only "
               "area numbers on record are a Mac-module observation (see external_leads)."},
    {"field": "start_entry",
     "status": "unknown",
     "reason": "The GoldBox CoK entry-pointer invariant does not hold for PoR "
               "(docs/por-ecl-decoder.md section 1), so an ECL header pointer is not a "
               "start entry. GAME001.DAT byte 49 is a test value, not a recovered one."},
    {"field": "start_facing",
     "status": "unknown",
     "reason": "No facing value is recovered from the install or from a run artifact."},
]

EXTERNAL_LEADS = [
    {"source": "docs/fan-module-hacks.md, section 'POR: no combat in the start area'",
     "claim": "The Mac-module start area is GEO016 (civilized Phlan); the slums are GEO015, "
              "reached through a transfer cell.",
     "class": "runtime observation of a Mac-release module, written in a fan-module note",
     "reproduced_here": False,
     "note": "Not a DOS-install fact. The DOS TOC block ids 15 and 16 are shown below only "
             "as a presence check; a shared number between two releases is not a mapping."},
]


class ProbeError(PorSourceError):
    """A named refusal (exit 2)."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve_folder(install: Path) -> Path:
    """The folder that holds GAME.OVR: the given folder, or its POOLRAD child."""
    for cand in (install, install / "POOLRAD"):
        if (cand / OVR_NAME).is_file():
            if (cand / EXE_NAME).is_file():
                return cand
    raise ProbeError("no %s and %s pair found in %s or its POOLRAD folder"
                     % (OVR_NAME, EXE_NAME, install))


# --------------------------------------------------------------------------
# GEO TOC
# --------------------------------------------------------------------------

def geo_toc(folder: Path, allow_unpinned: bool) -> tuple[list[dict], list[dict], list[str]]:
    rows: list[dict] = []
    archives: list[dict] = []
    problems: list[str] = []
    for name in GEO_NAMES:
        path = folder / name
        if not path.is_file():
            raise ProbeError("%s not found in the install folder" % name)
        data = path.read_bytes()
        size, sha = GEO_PINS[name]
        pin_ok = len(data) == size and _sha(data) == sha
        if not pin_ok and not allow_unpinned:
            raise ProbeError("%s does not match its pinned size and SHA-256 "
                             "(use --allow-unpinned to probe it anyway)" % name)
        rec = {"file": name, "bytes": len(data), "sha256": _sha(data),
               "pin_match": pin_ok, "status": "parsed", "reason": None}
        try:
            entries, _base = pm.parse_dax(data)
        except pm.PorMapError as exc:
            rec["status"] = "refused"
            rec["reason"] = str(exc)
            problems.append("%s refused: %s" % (name, exc))
            archives.append(rec)
            continue
        archives.append(rec)
        for e in entries:
            rows.append({"geo": int(name[3]), "toc_index": e.index, "block_id": e.block_id,
                         "data_offset": e.data_offset, "raw_size": e.raw_size,
                         "comp_size": e.comp_size})
    return rows, archives, problems


def block_ids_by_location(rows: list[dict]) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {}
    for r in rows:
        out.setdefault(r["block_id"], []).append({"geo": r["geo"], "toc_index": r["toc_index"]})
    return out


# --------------------------------------------------------------------------
# Name literals, owner layout, procedure facts
# --------------------------------------------------------------------------

def dax_literals(data: bytes) -> list[dict]:
    """Each '.dax'/'.dat' suffix (Pascal length 4 then the extension), with the
    maximal run of alphanumerics before it as the name piece. Turbo Pascal stores
    names in pieces ("MON" "CHA" ".dax"), so the piece is a fragment, not a file."""
    rows = []
    for m in DAX_SUFFIX.finditer(data):
        p = m.start()
        q = p
        while q > 0 and data[q - 1] in PIECE_CHARS and p - q < MAX_PIECE:
            q -= 1
        piece = data[q:p].decode("ascii") if q < p else None
        block_start = q - 1 if piece and q > 0 and data[q - 1] == len(piece) else None
        rows.append({
            "suffix_offset": p,
            "extension": data[p + 1:p + 5].decode("ascii").lower(),
            "piece": piece,
            "piece_offset": q if piece else None,
            "block_start": block_start,
        })
    return rows


def owner_for(data: bytes, block_start: Optional[int]) -> dict:
    """The procedure whose final ret/retf ends exactly at ``block_start``.

    Layout candidate only: it uses how the code is laid out next to the literal
    block, not a reference to the block from inside the procedure."""
    if block_start is None:
        return {"status": "no-block-start", "owner": None, "matches": [], "truncated_walks": 0}
    matches = []
    truncated = 0   # walks that reached MAX_WALK without a return (cannot match)
    for p in range(max(0, block_start - PROLOGUE_WINDOW), block_start):
        if data[p:p + 3] not in PROLOGUES:
            continue
        insns, err = handler.linear(data, p, MAX_WALK)
        if err or not insns:
            continue
        last = insns[-1]
        if last.flow not in RET_FLOWS and len(insns) >= MAX_WALK:
            truncated += 1
            continue
        if last.flow in RET_FLOWS and last.end == block_start:
            matches.append(p)
    if len(matches) == 1:
        return {"status": "layout-unique", "owner": matches[0], "matches": matches,
                "truncated_walks": truncated}
    if not matches:
        return {"status": "no-layout-match", "owner": None, "matches": [],
                "truncated_walks": truncated}
    return {"status": "ambiguous", "owner": None, "matches": matches,
            "truncated_walks": truncated}


def proc_facts(data: bytes, entry: int) -> dict:
    insns, err = handler.linear(data, entry, MAX_WALK)
    if err or not insns:
        return {"entry": entry, "status": "decode-failed", "reason": err}
    last = insns[-1]
    arg_cmps = []
    far = near = 0
    for ins in insns:
        if ins.name == "cmp" and ins.bp_disp is not None and ins.imm is not None:
            arg_cmps.append({"offset": ins.off, "bp_disp": ins.bp_disp,
                             "imm": ins.imm, "text": ins.text()})
        if ins.flow == "call_far":
            far += 1
        elif ins.flow == "call":
            near += 1
    return {
        "entry": entry,
        "status": "decoded",
        "instructions": len(insns),
        "ret_offset": last.off,
        "ret_flow": last.flow,
        "ret_imm": last.imm,
        "arg_compares": arg_cmps,
        "far_calls_out": far,
        "near_calls_out": near,
        "cs_operands": cs_string_operands(insns),
    }


def cs_string_operands(insns: list) -> list[dict]:
    """``mov r16,imm`` immediately followed by ``push cs``: a CS-relative pointer
    operand candidate (not yet a string reference)."""
    out = []
    for a, b in zip(insns, insns[1:]):
        if MOV_REG_IMM.match(a.name) and a.imm is not None and b.name == "push cs":
            out.append({"offset": a.off, "imm": a.imm})
    return out


def _pascal_at(data: bytes, p: int) -> Optional[str]:
    if p < 0 or p >= len(data):
        return None
    n = data[p]
    if not (1 <= n <= 40) or p + 1 + n > len(data):
        return None
    s = data[p + 1:p + 1 + n]
    if all(0x20 <= c < 0x7F for c in s):
        return s.decode("ascii")
    return None


def string_base_test(data: bytes, operands: list[int]) -> dict:
    """Count overlay bases B for which every operand, read as B+imm, is a
    Pascal string. Zero means no single base explains the operands as strings."""
    if not operands:
        return {"operands": [], "bases_tested": 0, "bases_all_strings": 0}
    hits = []
    tested = 0
    for base in range(0, len(data)):
        tested += 1
        if all(_pascal_at(data, base + x) is not None for x in operands):
            hits.append(base)
            if len(hits) >= 16:
                break
    return {"operands": [hex(x) for x in operands], "bases_tested": tested,
            "bases_all_strings": len(hits), "first_bases": [hex(b) for b in hits[:16]]}


def near_calls_to(data: bytes, target: int) -> list[dict]:
    """Byte-pattern candidates: an E8 rel16 whose decoded target is ``target``.
    Same-overlay only in meaning; reachability is not checked."""
    out = []
    for i in range(len(data) - 2):
        if data[i] != 0xE8:
            continue
        rel = struct.unpack_from("<h", data, i + 1)[0]
        if i + 3 + rel != target:
            continue
        ins = handler.decode(data, i)
        out.append({"offset": i, "decoded_flow": ins.flow, "target": ins.target})
    return out


# --------------------------------------------------------------------------
# Run artifacts
# --------------------------------------------------------------------------

def scan_artifacts(root: Optional[Path]) -> dict:
    if root is None:
        return {"status": "not-requested"}
    if not root.is_dir():
        raise ProbeError("--run-artifacts is not a folder")
    files = sorted(p for p in root.rglob("*.log") if p.is_file())
    per_file = []
    total = 0
    for p in files:
        n = sum(1 for line in p.read_bytes().splitlines() if GEO_LINE.search(line))
        total += n
        per_file.append({"name": p.relative_to(root).as_posix(), "geo_dax_lines": n})
    return {"status": "scanned", "pattern": "GEO<n>.DAX (case-insensitive), *.log only",
            "files_scanned": len(files), "geo_dax_lines": total, "per_file": per_file,
            "root_recorded_as": "run-artifacts folder (path not recorded)"}


# --------------------------------------------------------------------------
# Probe
# --------------------------------------------------------------------------

def _tree_snapshot(paths: list[Path]) -> dict:
    return {p.name: (p.stat().st_size, _sha(p.read_bytes())) for p in paths}


def probe(install: Path, out: Path, allow_unpinned: bool = False,
          artifacts: Optional[Path] = None) -> tuple[dict, int]:
    folder = resolve_folder(install)
    out = validate_output_dir(folder, out)

    watched = [folder / OVR_NAME, folder / EXE_NAME] + [folder / n for n in GEO_NAMES] \
        + [folder / n for n in SAVE_NAMES]
    for p in watched:
        if not p.is_file():
            raise ProbeError("%s not found in the install folder" % p.name)
    before = _tree_snapshot(watched)

    ovr = (folder / OVR_NAME).read_bytes()
    start = (folder / EXE_NAME).read_bytes()
    pins = {}
    for name, data in ((OVR_NAME, ovr), (EXE_NAME, start)):
        size, sha = farcall.PINNED[name]
        ok = len(data) == size and _sha(data) == sha
        pins[name] = {"bytes": len(data), "sha256": _sha(data), "pin_match": ok}
        if not ok and not allow_unpinned:
            raise ProbeError("%s does not match its pinned size and SHA-256 "
                             "(use --allow-unpinned to probe it anyway; the output "
                             "will not be retail evidence)" % name)

    rows, archives, problems = geo_toc(folder, allow_unpinned)

    groups = farcall.scan_groups(start, ovr)
    literal_rows = []
    load_candidate = None
    for name, data in ((OVR_NAME, ovr), (EXE_NAME, start)):
        for lit in dax_literals(data):
            lit["file"] = name
            own = owner_for(data, lit["block_start"])
            lit["owner"] = own
            if name == OVR_NAME:
                g = farcall.group_containing_code(groups, lit["suffix_offset"])
                lit["overlay_group"] = ("0x%x" % g["fileofs"]) if g else "uncovered"
            else:
                lit["overlay_group"] = "not-applicable"
            if own["owner"] is not None:
                lit["owner"]["facts"] = proc_facts(data, own["owner"])
                lit["owner"]["near_callers"] = near_calls_to(data, own["owner"])
            literal_rows.append(lit)
            if (name == OVR_NAME and lit["piece"] == "GEO" and lit["extension"] == ".dax"
                    and own["owner"] is not None):
                load_candidate = {"literal_block": lit["block_start"],
                                  "owner": own["owner"]}

    if load_candidate is not None:
        facts = next(r for r in literal_rows if r["file"] == OVR_NAME
                     and r["block_start"] == load_candidate["literal_block"])["owner"]["facts"]
        operands = [c["imm"] for c in facts["cs_operands"]]
        load_candidate["facts"] = facts
        load_candidate["string_operand_base_test"] = string_base_test(ovr, operands)
        load_candidate["near_callers"] = near_calls_to(ovr, load_candidate["owner"])
        load_candidate["stub_export_matches"] = [
            {"group_fileofs": "0x%x" % g["fileofs"], "stub_proc_offset": "0x%x" % (load_candidate["owner"] - g["fileofs"])}
            for g in groups if (load_candidate["owner"] - g["fileofs"]) in g["procs"]
        ]
        load_candidate["claim_level"] = "layout candidate; not a mapping"

    after = _tree_snapshot(watched)
    unchanged = before == after
    if not unchanged:
        raise ProbeError("the install changed during the run (no output written)")

    all_pins = all(v["pin_match"] for v in pins.values()) and all(a["pin_match"] for a in archives)
    ids = block_ids_by_location(rows)
    dup_ids = sorted(k for k, v in ids.items() if len(v) > 1)

    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "question": ("Can a GEO TOC block be tied to an in-game area, and can the authentic "
                     "start area or entry be recovered from retail bytes or run artifacts?"),
        "answer": "not established: no mapping meets the proof bar (see mappings and unknown)",
        "source": {
            "pins": pins,
            "geo_archives": archives,
            "save_files": {n: {"bytes": (folder / n).stat().st_size,
                               "sha256": _sha((folder / n).read_bytes()),
                               "parsed": False,
                               "reason": "no PoR save-format evidence in the repo"}
                           for n in SAVE_NAMES},
            "all_pins_match": all_pins,
            "install_unchanged": unchanged,
        },
        "geo_toc": {"rows": rows, "block_count": len(rows),
                    "duplicate_block_ids_within_install": dup_ids,
                    "block_ids_present": sorted(ids),
                    "block_ids_absent_in_0_to_32": sorted(set(range(33)) - set(ids))},
        "literals": literal_rows,
        "load_routine": load_candidate,
        "external_leads": [
            {**lead, "dos_toc_presence": {str(k): ids.get(k, []) for k in (15, 16)}}
            for lead in EXTERNAL_LEADS
        ],
        "mappings": [],
        "unknown": UNKNOWN,
        "run_artifacts": scan_artifacts(artifacts),
        "diagnostics": problems,
    }
    write_outputs(doc, out)
    if problems or not all_pins:
        return doc, 1
    return doc, 0


def render_report(doc: dict) -> str:
    L = []
    L.append("# Pool of Radiance: GEO map-load evidence probe")
    L.append("")
    L.append("**Status: %s. `playable: false`. `mappings: %d`.**" %
             (doc["status"], len(doc["mappings"])))
    L.append("")
    L.append("Question: " + doc["question"])
    L.append("")
    L.append("Answer: " + doc["answer"])
    L.append("")
    L.append("## Pins and archives")
    L.append("")
    L.append("| File | Bytes | SHA-256 | Pin match | Status |")
    L.append("| --- | ---: | --- | --- | --- |")
    for name, p in sorted(doc["source"]["pins"].items()):
        L.append("| %s | %d | `%s` | %s | pinned |" % (name, p["bytes"], p["sha256"], p["pin_match"]))
    for a in doc["source"]["geo_archives"]:
        L.append("| %s | %d | `%s` | %s | %s |" % (a["file"], a["bytes"], a["sha256"],
                                                   a["pin_match"], a["status"]))
    L.append("")
    for n, s in sorted(doc["source"]["save_files"].items()):
        L.append("- %s: %d bytes, SHA-256 `%s`, not parsed (%s)." %
                 (n, s["bytes"], s["sha256"], s["reason"]))
    L.append("- install unchanged across the run: %s" % doc["source"]["install_unchanged"])
    L.append("")
    toc = doc["geo_toc"]
    L.append("## GEO TOC")
    L.append("")
    L.append("%d blocks. Duplicate ids within the install: %s. Absent from 0..32: %s." %
             (toc["block_count"], toc["duplicate_block_ids_within_install"] or "none",
              toc["block_ids_absent_in_0_to_32"]))
    L.append("")
    L.append("| GEO | TOC index | Block id | Data offset | Raw | Comp |")
    L.append("| ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in toc["rows"]:
        L.append("| %d | %d | %d | %d | %d | %d |" % (r["geo"], r["toc_index"], r["block_id"],
                                                    r["data_offset"], r["raw_size"], r["comp_size"]))
    L.append("")
    L.append("## Name literals")
    L.append("")
    L.append("| File | Suffix offset | Piece | Block start | Owner status | Owner | Overlay group |")
    L.append("| --- | ---: | --- | ---: | --- | ---: | --- |")
    for r in doc["literals"]:
        L.append("| %s | 0x%x | %s | %s | %s | %s | %s |" % (
            r["file"], r["suffix_offset"], r["piece"] or "-",
            ("0x%x" % r["block_start"]) if r["block_start"] is not None else "-",
            r["owner"]["status"],
            ("0x%x" % r["owner"]["owner"]) if r["owner"]["owner"] is not None else "-",
            r["overlay_group"]))
    L.append("")
    lr = doc["load_routine"]
    L.append("## Load routine candidate (layout only)")
    L.append("")
    if lr is None:
        L.append("No GEO literal with a layout owner was found.")
    else:
        f = lr["facts"]
        L.append("- Owner: `GAME.OVR` 0x%x, %d instructions, return `%s %s` at 0x%x." %
                 (lr["owner"], f["instructions"], f["ret_flow"],
                  ("0x%x" % f["ret_imm"]) if f["ret_imm"] is not None else "-", f["ret_offset"]))
        L.append("- bp-relative compares with an immediate (bp+N = argument, bp-N = local):")
        for c in f["arg_compares"]:
            L.append("  - 0x%x `%s` (bp%+d, imm %d)" % (c["offset"], c["text"], c["bp_disp"], c["imm"]))
        L.append("- CS-relative operand candidates: %s" %
                 ", ".join("0x%x" % c["imm"] for c in f["cs_operands"]))
        sb = lr["string_operand_base_test"]
        L.append("- Single overlay base that makes all operands Pascal strings: %d of %d bases "
                 "tested." % (sb["bases_all_strings"], sb["bases_tested"]))
        L.append("- Near-call byte candidates for this owner: %d." % len(lr["near_callers"]))
        L.append("- Recognised VROOMM stub groups exporting this procedure: %d%s" % (
            len(lr["stub_export_matches"]),
            "" if not lr["stub_export_matches"] else " (%s)" % ", ".join(
                m["group_fileofs"] for m in lr["stub_export_matches"])))
        L.append("- Claim level: %s" % lr["claim_level"])
    L.append("")
    L.append("## Unknown fields")
    L.append("")
    for u in doc["unknown"]:
        L.append("- **%s** (%s): %s" % (u["field"], u["status"], u["reason"]))
    L.append("")
    L.append("## External leads (not retail evidence)")
    L.append("")
    for e in doc["external_leads"]:
        L.append("- %s. %s Class: %s. Reproduced here: %s." %
                 (e["source"], e["claim"], e["class"], e["reproduced_here"]))
        L.append("  - %s" % e["note"])
        for k in sorted(e["dos_toc_presence"]):
            hits = e["dos_toc_presence"][k]
            L.append("  - DOS TOC block %s: %s" % (k, ", ".join("GEO%d #%d" % (h["geo"], h["toc_index"])
                                                              for h in hits) or "absent"))
    L.append("")
    ra = doc["run_artifacts"]
    L.append("## Run artifacts")
    L.append("")
    if ra["status"] == "not-requested":
        L.append("Not requested (`--run-artifacts` absent).")
    else:
        L.append("%d `*.log` files scanned; %d GEO*.DAX lines." % (ra["files_scanned"], ra["geo_dax_lines"]))
    L.append("")
    L.append("## Diagnostics")
    L.append("")
    if doc["diagnostics"]:
        L.extend("- " + d for d in doc["diagnostics"])
    else:
        L.append("None.")
    L.append("")
    return "\n".join(L)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_area_evidence.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_area_evidence_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Pool of Radiance GEO map-load evidence probe.")
    ap.add_argument("--install", required=True, type=Path,
                    help="the DOS install folder or its POOLRAD folder (read-only)")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="probe files that do not match their pins (output is not retail evidence)")
    ap.add_argument("--run-artifacts", type=Path, default=None,
                    help="folder whose *.log files are scanned for GEO*.DAX lines")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out, args.allow_unpinned, args.run_artifacts)
    except PorSourceError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s and %s (static-evidence-only, playable=false, mappings=%d)" % (
        args.out / "por_area_evidence.json", args.out / "por_area_evidence_report.md",
        len(doc["mappings"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
