#!/usr/bin/env python3
"""Pool of Radiance GAME.OVR far-call resolver: VROOMM stub probe.

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only, playable: false.

This tool asks one narrow question of the retail bytes: do the literal far-call
operands (``9A seg:off``) in the 0x37 handler at GAME.OVR:0x19ba land on the
Borland VROOMM ``CD 3F`` stubs in the resident START.EXE, and if so, which
overlay procedure does each stub name? It reports:

  * the MZ image base, and each stub group's header (descriptor) and stub run;
  * two kinds of stub group, kept apart: ACCEPTED groups, whose every stub is
    well-formed at one alignment (header+0x16 or header+0x17, recorded per group
    as ``stub_delta``), and PARTIAL candidates, where a strict majority of the
    stubs is well-formed at one alignment and the other alignment is worse. A
    partial group is never a success verdict, and its malformed slots are never
    stubs;
  * for each stub group, a prologue check: every stub's proc_off, added to the
    group's overlay ``fileofs``, must land on a Borland prologue
    (``55 89 E5`` / ``55 8B EC``);
  * for each far call, the zero-skew image address ``hdr + seg*16 + off``, the
    stub it hits (if any), the stub's proc_off and GAME.OVR target, and whether
    the call's segment word is listed in the containing overlay's fixup table;
  * the operand-parser stub (proc 0 of the 0x74d3 group) and whether any far
    call hits it.

It does NOT decide which resolution is the true one. The image-address model
(seg = paragraph in the resident image, no skew) is an assumption recorded in
the output; the GoldBox CoK resolver's -1 skew is tested and reported, not
adopted. Opcode 0x37 is not given a meaning, no WALLDEF binding is made, and no
module is emitted.

Usage
  python3 tools/por_farcall_resolve.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-farcall-resolve/retail

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_farcall_resolve.json        schema openua.por-farcall-resolve, playable: false
  por_farcall_resolve_report.md   the table of call sites and stub evidence

Exit codes
  0  every structural check passed and every far call was classified
  1  output written with a diagnostic (a stub group failed its prologue check,
     a far call sits outside every overlay, or a far call lands on a partial
     group's stub, well-formed or malformed)
  2  named refusal: bad install, a file not matching its pin (without
     --allow-unpinned), or unsafe output location
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_loadpieces_handler as handler  # noqa: E402

SCHEMA = "openua.por-farcall-resolve"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_farcall_resolve.py"
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"

PINNED = {
    OVR_NAME: (206105, "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"),
    EXE_NAME: (65231, "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"),
}

STUB_OPCODE = b"\xcd\x3f"           # int 3Fh, the VROOMM stub opcode
DESC_MAGIC = b"\xcd\x3f\x00\x00"     # descriptor header start
DESC_STUB_DELTA = 0x16               # header start -> first stub for the original groups
STUB_DELTAS = (0x16, 0x17)           # both header-to-stub distances are scored for every header
PARTIAL_MIN_VALID = 2                # a partial run needs at least this many well-formed stubs
STUB_LEN = 5
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
PARSER_FILEOFS = 0x74D3              # GoldBox runtime-anchored operand parser entry
MIN_FILEOFS = 8                      # FBOV body begins after the 8-byte header


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mz_image_base(start: bytes) -> int:
    """Return the file offset of the resident image (MZ header size).

    Raises ValueError for a file that is not an MZ executable.
    """
    if len(start) < 0x1C or start[:2] != b"MZ":
        raise ValueError("START.EXE is not an MZ executable")
    cparhdr = struct.unpack_from("<H", start, 0x08)[0]
    return cparhdr * 16


def _stub_well_formed(start: bytes, st: int, k: int) -> bool:
    """Slot k of the run at st is ``CD 3F <word> 00``. The caller checks the bounds."""
    base = st + STUB_LEN * k
    return start[base:base + 2] == STUB_OPCODE and start[base + 4] == 0


def _header_fields(start: bytes, ovr: bytes, p: int, min_fo: int) -> Optional[tuple[int, int, int, int]]:
    """(fileofs, codesz, fixupsz, jmpcnt) for a descriptor header in range at p, else None."""
    if start[p:p + 4] != DESC_MAGIC:
        return None
    fo, codesz, fixupsz, jmpcnt = struct.unpack_from("<IHHH", start, p + 4)
    if not (min_fo <= fo < len(ovr)) or codesz == 0 or not (1 <= jmpcnt <= 200):
        return None
    if fo + codesz > len(ovr):
        return None
    return fo, codesz, fixupsz, jmpcnt


def _alignment_candidate(start: bytes, ovr: bytes, p: int, delta: int,
                         header: tuple[int, int, int, int]) -> Optional[dict]:
    """The stub run at header+delta, scored slot by slot. None if it runs past START.EXE."""
    fo, codesz, fixupsz, jmpcnt = header
    st = p + delta
    if st + STUB_LEN * jmpcnt > len(start):
        return None
    valid = [_stub_well_formed(start, st, k) for k in range(jmpcnt)]
    procs = [struct.unpack_from("<H", start, st + STUB_LEN * k + 2)[0] for k in range(jmpcnt)]
    hits = [ovr[fo + pr:fo + pr + 3] in PROLOGUES if fo + pr + 3 <= len(ovr) else False
            for pr in procs]
    return {
        "header_offset": p,
        "stub_delta": delta,
        "stub_start": st,
        "stub_count": jmpcnt,
        "stub_end": st + STUB_LEN * jmpcnt,
        "fileofs": fo,
        "codesz": codesz,
        "fixupsz": fixupsz,
        "procs": procs,
        "stub_valid": valid,
        "valid_stub_count": sum(valid),
        # Counted over well-formed slots only: a malformed slot's proc word is not a
        # stub and says nothing about its group.
        "prologue_hits": sum(1 for h, v in zip(hits, valid) if h and v),
        "prologue_total": sum(valid),
    }


def scan_all(start: bytes, ovr: bytes) -> dict:
    """Score both header-to-stub alignments for every descriptor header.

    Returns three kept-apart lists:
      groups          ACCEPTED: every stub well-formed at one alignment; status "well-formed".
      partial_groups  PARTIAL: at least PARTIAL_MIN_VALID stubs and a strict majority well-formed
                      at one alignment, which beats the other alignment; status "partial".
                      Not a success verdict; its malformed slots are never stubs.
      notes           strings explaining suppressed rows (for the report, not diagnostics).

    At most one row per header: a header whose best alignment fails the rules above is
    not reported. At most one row per fileofs across both lists: the first accepted header
    wins, then the first partial header. The two alignments cannot both be fully
    well-formed at one header (slot 0 at +0x16 needs 0x3F at header+0x17, and slot 0 at
    +0x17 needs 0xCD there), so a header never has two accepted rows.
    """
    min_fo = MIN_FILEOFS if ovr[:4] == b"FBOV" else 4
    accepted: list[dict] = []
    partial: list[dict] = []
    for p in range(0, len(start) - 0x16):
        header = _header_fields(start, ovr, p, min_fo)
        if header is None:
            continue
        cands = {d: _alignment_candidate(start, ovr, p, d, header) for d in STUB_DELTAS}
        full = [d for d, c in cands.items() if c is not None and c["valid_stub_count"] == c["stub_count"]]
        if full:
            c = cands[full[0]]
            c["status"] = "well-formed"
            accepted.append(c)
            continue
        # No alignment is fully well-formed. The best alignment must clearly beat the other.
        n = {d: (c["valid_stub_count"] if c is not None else 0) for d, c in cands.items()}
        best, other = sorted(STUB_DELTAS, key=lambda d: n[d], reverse=True)
        c = cands[best]
        if c is None or n[best] < PARTIAL_MIN_VALID or n[best] <= n[other] or 2 * n[best] <= c["stub_count"]:
            continue
        c["status"] = "partial"
        partial.append(c)

    notes: list[str] = []
    seen: set[int] = set()
    groups: list[dict] = []
    for g in accepted:
        if g["fileofs"] in seen:
            notes.append("accepted header 0x%x suppressed: fileofs 0x%x is already accepted at an earlier header"
                         % (g["header_offset"], g["fileofs"]))
            continue
        seen.add(g["fileofs"])
        groups.append(g)
    partials: list[dict] = []
    for g in partial:
        if g["fileofs"] in seen:
            notes.append("partial header 0x%x suppressed: fileofs 0x%x is already held by another group"
                         % (g["header_offset"], g["fileofs"]))
            continue
        seen.add(g["fileofs"])
        partials.append(g)
    return {"groups": groups, "partial_groups": partials, "notes": notes}


def scan_groups(start: bytes, ovr: bytes) -> list[dict]:
    """ACCEPTED stub groups only (every stub well-formed at one alignment). See scan_all.

    The scan is not a complete census of the overlay descriptors; the groups that
    matter for the call sites are looked up by address, not by census.
    """
    return scan_all(start, ovr)["groups"]


def scan_partial_groups(start: bytes, ovr: bytes) -> list[dict]:
    """PARTIAL stub candidates only. Never a basis for a success verdict. See scan_all."""
    return scan_all(start, ovr)["partial_groups"]


def stub_slot(groups: list[dict], image_f: int) -> Optional[tuple[dict, int]]:
    """The (group, index) whose slot starts exactly at image_f, whether or not it is well-formed."""
    for g in groups:
        if g["stub_start"] <= image_f < g["stub_end"] and (image_f - g["stub_start"]) % STUB_LEN == 0:
            return g, (image_f - g["stub_start"]) // STUB_LEN
    return None


def group_for_stub(groups: list[dict], image_f: int) -> Optional[tuple[dict, int]]:
    """A WELL-FORMED stub starting exactly at image_f, or None. A malformed slot is never returned."""
    for g in groups:
        if g["stub_start"] <= image_f < g["stub_end"] and (image_f - g["stub_start"]) % STUB_LEN == 0:
            k = (image_f - g["stub_start"]) // STUB_LEN
            if g["stub_valid"][k]:
                return g, k
    return None


def _stub_row(g: dict, k: int, ovr: bytes) -> dict:
    proc = g["procs"][k]
    target = g["fileofs"] + proc
    return {
        "group_header_offset": g["header_offset"],
        "group_fileofs": g["fileofs"],
        "group_stub_count": g["stub_count"],
        "group_stub_delta": g["stub_delta"],
        "group_status": g["status"],
        "index": k,
        "stub_valid": g["stub_valid"][k],
        "proc_off": proc,
        "gameovr_target": target,
        "target_prologue": ovr[target:target + 3] in PROLOGUES if target + 3 <= len(ovr) else False,
        "group_prologue_hits": g["prologue_hits"],
        "group_prologue_total": g["prologue_total"],
    }


def group_containing_code(groups: list[dict], at: int) -> Optional[dict]:
    for g in groups:
        if g["fileofs"] <= at < g["fileofs"] + g["codesz"]:
            return g
    return None


def fixup_table(ovr: bytes, group: dict) -> set[int]:
    """Overlay-relative offsets listed in the overlay's fixup table.

    The table starts at fileofs+codesz and holds fixupsz/2 sorted 16-bit words,
    each naming a code word that holds a segment value. Offset words are not
    listed (checked for the retail 0x19ba call sites).
    """
    base = group["fileofs"] + group["codesz"]
    n = group["fixupsz"] // 2
    if base + 2 * n > len(ovr):
        return set()
    return set(struct.unpack_from("<%dH" % n, ovr, base)) if n else set()


def resolve(start: bytes, ovr: bytes, far_calls: list[dict]) -> dict:
    """Classify each far call against the stub groups. Pure function over bytes."""
    hdr = mz_image_base(start)
    scan = scan_all(start, ovr)
    groups = scan["groups"]
    partials = scan["partial_groups"]
    diagnostics: list[str] = []
    rows: list[dict] = []
    image_fs: set[int] = set()

    for c in far_calls:
        at, seg, off = c["at"], c["seg"], c["off"]
        image_f = hdr + seg * 16 + off
        image_fs.add(image_f)
        row: dict = {
            "at": at,
            "seg": seg,
            "off": off,
            "image_f": image_f,
            "skew_minus_1_is_stub": False,
            "stub": None,
            "classification": None,
        }
        # CoK's skew (-1) for comparison; PoR call sites are checked against it.
        m1 = group_for_stub(groups, image_f - 1)
        row["skew_minus_1_is_stub"] = m1 is not None

        ovl = group_containing_code(groups, at)
        if ovl is None:
            row["overlay"] = None
            diagnostics.append("far call at 0x%x is outside every stub-carrying overlay" % at)
            row["seg_word_in_fixup_table"] = None
        else:
            row["overlay"] = {"fileofs": ovl["fileofs"], "codesz": ovl["codesz"]}
            rel = at + 3 - ovl["fileofs"]
            row["seg_word_in_fixup_table"] = rel in fixup_table(ovr, ovl)
            row["off_word_in_fixup_table"] = (at + 1 - ovl["fileofs"]) in fixup_table(ovr, ovl)

        hit = group_for_stub(groups, image_f)
        if hit is not None:
            g, k = hit
            row["stub"] = _stub_row(g, k, ovr)
            row["classification"] = "stub-candidate"
            if g["prologue_hits"] != g["prologue_total"]:
                diagnostics.append("stub group 0x%x fails its prologue check (%d/%d)"
                                   % (g["fileofs"], g["prologue_hits"], g["prologue_total"]))
            rows.append(row)
            continue

        # Not an accepted stub. A partial group is a candidate only: a well-formed slot
        # names a candidate target, a malformed slot names nothing.
        slot = stub_slot(partials, image_f)
        if slot is not None:
            g, k = slot
            valid = g["stub_valid"][k]
            row["partial_group"] = {"fileofs": g["fileofs"], "stub_delta": g["stub_delta"],
                                    "index": k, "stub_valid": valid}
            if valid:
                row["stub"] = _stub_row(g, k, ovr)
                row["classification"] = "partial-stub-candidate"
                diagnostics.append("far call at 0x%x lands on well-formed stub %d of partial group 0x%x "
                                   "(+0x%x, %d of %d stubs well-formed); a candidate, not a resolved target"
                                   % (at, k, g["fileofs"], g["stub_delta"],
                                      g["valid_stub_count"], g["stub_count"]))
            else:
                row["classification"] = "malformed-stub"
                diagnostics.append("far call at 0x%x lands on malformed stub %d of partial group 0x%x "
                                   "(+0x%x); no target"
                                   % (at, k, g["fileofs"], g["stub_delta"]))
            rows.append(row)
            continue

        row["classification"] = "not-a-stub"
        row["bytes_at_image_f"] = start[image_f:image_f + 10].hex(" ") if image_f < len(start) else None
        rows.append(row)

    parser_group = next((g for g in groups if g["fileofs"] == PARSER_FILEOFS), None)
    if parser_group is None:
        parser = {"found": False}
    else:
        k = parser_group["procs"].index(0) if 0 in parser_group["procs"] else None
        if k is None:
            parser = {"found": False}
        else:
            pf = parser_group["stub_start"] + STUB_LEN * k
            parser = {
                "found": True,
                "fileofs": PARSER_FILEOFS,
                "stub_index": k,
                "stub_image_f": pf,
                "called_by_far_call": pf in image_fs,
                "group_prologue_hits": parser_group["prologue_hits"],
                "group_prologue_total": parser_group["prologue_total"],
            }

    return {
        "image_base": hdr,
        "groups": groups,
        "partial_groups": partials,
        "scan_notes": scan["notes"],
        "far_calls": rows,
        "parser": parser,
        "diagnostics": diagnostics,
    }


def _far_calls_from_handler(ovr: bytes) -> list[dict]:
    doc = handler.analyze(ovr)
    return [{"at": c["at"], "seg": c["seg"], "off": c["off"]}
            for c in doc["handler_0x37"]["far_calls"]]


def find_file(install: Path, name: str) -> Path:
    p = install / name
    if not p.is_file():
        raise PorSourceError("%s not found in the install folder" % name)
    return p


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    ovr_path = find_file(install, OVR_NAME)
    exe_path = find_file(install, EXE_NAME)
    ovr = ovr_path.read_bytes()
    start = exe_path.read_bytes()
    pin_status = {}
    for name, data in ((OVR_NAME, ovr), (EXE_NAME, start)):
        size, sha = PINNED[name]
        ok = len(data) == size and _sha(data) == sha
        pin_status[name] = {"size": len(data), "sha256": _sha(data), "pin_match": ok}
        if not ok and not allow_unpinned:
            raise PorSourceError("%s does not match its pinned size and SHA-256 "
                                 "(use --allow-unpinned to probe it anyway; the output "
                                 "will not be retail evidence)" % name)
    far_calls = _far_calls_from_handler(ovr)
    result = resolve(start, ovr, far_calls)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "source": {"pins": pin_status, "all_pins_match": all(v["pin_match"] for v in pin_status.values())},
        "assumptions": [
            "Far-call seg:off resolves to the resident image address hdr + seg*16 + off (zero skew).",
            "A stub's proc_off is relative to its group's overlay fileofs (VROOMM convention, prologue-checked).",
            "The far-call segment word is a loader-fixed-up selector; its listing in the fixup table is recorded, not interpreted.",
        ],
        "established_by_bytes": [
            "Each accepted stub group's CD 3F stub run is at header+0x16 or header+0x17 (its stub_delta); every slot is CD 3F <word> 00, and the run's length is the header's jmpcnt.",
            "The 0x74d3 group's every stub proc_off lands on a Borland prologue under its fileofs.",
            "Partial groups (partial_groups) have a strict majority of well-formed stubs at one alignment. Their malformed slots are not stubs.",
        ],
        "not_established": [
            "Which resolution model is the true one. The zero-skew image model is an assumption, not a proof.",
            "That a partial group (for example fileofs 0x2e8f7, +0x17, slot 7 malformed) is one overlay, or that anything calls it.",
            "The meaning of opcode 0x37, or of the three operand bytes the handler loop reads.",
            "Whether the handler runs at runtime for opcode 0x37. Only a CS:IP breakpoint would show that.",
        ],
        **result,
    }
    write_outputs(doc, out)
    if doc["diagnostics"] or not doc["source"]["all_pins_match"]:
        return doc, 1
    return doc, 0


def render_report(doc: dict) -> str:
    lines = [
        "# PoR GAME.OVR far-call resolution (VROOMM stub probe)",
        "",
        "Status: %s, playable: %s." % (doc["status"], str(doc["playable"]).lower()),
        "",
        "## Pins",
        "",
    ]
    for name, v in sorted(doc["source"]["pins"].items()):
        lines.append("- `%s`: %d bytes, sha256 `%s`, pin match %s"
                     % (name, v["size"], v["sha256"], str(v["pin_match"]).lower()))
    lines += ["", "## Stub groups (accepted: every stub well-formed)", "",
              "| header | fileofs | stubs | stub delta | prologue hits | status |",
              "| --- | --- | --- | --- | --- | --- |"]
    for g in doc["groups"]:
        lines.append("| 0x%x | 0x%x | %d | +0x%x | %d/%d | %s |" % (
            g["header_offset"], g["fileofs"], g["stub_count"], g["stub_delta"],
            g["prologue_hits"], g["prologue_total"], g["status"]))
    lines += ["", "## Partial stub candidates (not accepted; a candidate, never a verdict)", "",
              "| header | fileofs | stubs | stub delta | well-formed | malformed slots | prologue hits (well-formed) | status |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for g in doc["partial_groups"]:
        bad = [str(k) for k, v in enumerate(g["stub_valid"]) if not v]
        lines.append("| 0x%x | 0x%x | %d | +0x%x | %d/%d | %s | %d/%d | %s |" % (
            g["header_offset"], g["fileofs"], g["stub_count"], g["stub_delta"],
            g["valid_stub_count"], g["stub_count"], ", ".join(bad) or "-",
            g["prologue_hits"], g["prologue_total"], g["status"]))
    if not doc["partial_groups"]:
        lines.append("")
        lines.append("None.")
    lines += ["", "## Handler far calls", "",
              "| site | seg:off | image addr | classification | stub -> target | seg word in fixup table | skew -1 is stub |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in doc["far_calls"]:
        st = r["stub"]
        tgt = ("group 0x%x idx %d proc 0x%x -> 0x%x (prologue %s)"
               % (st["group_fileofs"], st["index"], st["proc_off"], st["gameovr_target"],
                  str(st["target_prologue"]).lower())) if st else "-"
        lines.append("| 0x%x | %x:%x | 0x%x | %s | %s | %s | %s |" % (
            r["at"], r["seg"], r["off"], r["image_f"], r["classification"], tgt,
            str(r.get("seg_word_in_fixup_table")).lower(), str(r["skew_minus_1_is_stub"]).lower()))
    p = doc["parser"]
    lines += ["", "## Parser stub", ""]
    if p.get("found"):
        lines.append("- parser fileofs 0x%x, stub index %d, image address 0x%x, called by a handler far call: %s"
                     % (p["fileofs"], p["stub_index"], p["stub_image_f"],
                        str(p["called_by_far_call"]).lower()))
    else:
        lines.append("- parser stub not found")
    lines += ["", "## Scan notes", ""]
    lines += ["- %s" % n for n in doc["scan_notes"]] or ["- none"]
    lines += ["", "## Diagnostics", ""]
    lines += ["- %s" % d for d in doc["diagnostics"]] or ["- none"]
    lines += ["", "## Not established", ""] + ["- %s" % x for x in doc["not_established"]]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_farcall_resolve.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_farcall_resolve_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="user-supplied PoR install folder (read-only)")
    ap.add_argument("-o", "--out", required=True, help="output folder (outside the install)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="probe files that do not match the pinned size/SHA-256 (not retail evidence)")
    args = ap.parse_args(argv)
    try:
        out = validate_output_dir(Path(args.install), Path(args.out))
        doc, code = probe(Path(args.install), out, allow_unpinned=args.allow_unpinned)
    except PorSourceError as exc:
        print("por_farcall_resolve: error: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s and %s (static-probe-only, playable=false; stub candidates %d of %d far calls; diagnostics %d)"
          % (out / "por_farcall_resolve.json", out / "por_farcall_resolve_report.md",
             sum(1 for r in doc["far_calls"] if r["classification"] == "stub-candidate"),
             len(doc["far_calls"]), len(doc["diagnostics"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
