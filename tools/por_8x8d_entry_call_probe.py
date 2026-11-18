#!/usr/bin/env python3
"""Pool of Radiance: static caller census over the edges the earlier 8X8D probes did not count.

Status: STATIC-PROBE-ONLY. Read-only. playable: false, mappings: [], binding_established: false.

Targets (file offsets): START.EXE 0x7245 (block-201 request routine), START.EXE 0x42DE (the
VROOMM stub of GAME.OVR 0x32270), GAME.OVR 0x32270, and the START.EXE DOS open/read chain
(0x0A89E open helper, 0x0A728 overlay-open, 0x0A86A path copy, reads at 0x0A97E, 0x0B306,
0x0B360).

Earlier probes (por_8x8d_archive_chain_probe, por_8x8d_dos_sites_probe) counted decode-verified
E8 near calls and 9A far calls under an unvalidated image model. Neither counted:

  * direct jump-based transfers: E9 and EB (jmp), 70-7F and E0-E3 (jcc, loop, jcxz). Their targets
    are relative, so file offsets are exact with no image model;
  * indirect transfers through memory or a register: FF /2 call near, FF /3 call far, FF /4 jmp
    near, FF /5 jmp far. The direct displacement is recorded where one exists (mod 00 rm 110, or
    a [base+disp] form);
  * word-value hits of each target's offset in the image, under the two near-offset bases used by
    the earlier probes (0 and the MZ header 0x200). A hit is a candidate table slot only. It is not
    linked to any indirect site, because the DS (or CS) base that the displacement is relative to is
    not established.

Tier of a source instruction (decode only, no image model). A body is the set of instruction starts
reached from an entry by fall-through and direct jmp/jcc edges whose target lies within 0x400 bytes
after the entry (a heuristic: a farther jump is treated as a tail jump into another routine). Calls
are not entered, and ret/unconditional jumps/indirect transfers end a path:
  A  in the body of an E8-verified entry (an E8 target);
  B  in a body entered only from a prologue (push bp; mov bp,sp form), not from an E8 target;
  C  in neither.
A direct edge is a caller edge only when its source is tier A AND no E8 body contains both the
source and the target (a branch inside one routine is reported as same-body, not as a caller).
Only those cross-body A-tier edges are counted as established callers. B and C edges are reported, not counted.
9A far edges are model-conditional and are reported separately.

Not established here: which base an indirect table uses; any caller of a far target that is not a
9A literal under the image model; any near Jcc encoded as 0F 8x (the shared decoder rejects 0F).

Usage
  python tools/por_8x8d_entry_call_probe.py --install "PATH/TO/POOLRAD" \
      -o data/work/por-8x8d-entry-call-probe/retail [--allow-unpinned]

Outputs (deterministic: sorted keys, no timestamps, no absolute paths):
  por_8x8d_entry_call_probe.json          schema openua.por-8x8d-entry-call-probe
  por_8x8d_entry_call_probe_report.md     the readable summary

Exit codes
  0  every pin matched and the scan completed
  1  output written, but a pin did not match (only with --allow-unpinned; not retail evidence)
  2  named refusal: missing install files, an output folder outside data/ or inside the install,
     a file not matching its pin without --allow-unpinned, or a source that changed during the run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

import por_loadpieces_handler as h
import por_farcall_resolve as fr
from por_convert import PorSourceError, validate_output_dir

SCHEMA = "openua.por-8x8d-entry-call-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_8x8d_entry_call_probe.py"
EXE_NAME = "START.EXE"
OVR_NAME = "GAME.OVR"
IMAGE_BASE = 0x200
NEAR_BASES = (0x0000, 0x0200)     # near-offset bases the earlier probes used; a hit is a candidate only
MAX_WALK = 300
BODY_SPAN = 0x400                 # a direct jmp/jcc is followed inside a body only this far after entry
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
DIRECT_LEAD = frozenset((0xE8, 0xE9, 0xEB, 0xE0, 0xE1, 0xE2, 0xE3) + tuple(range(0x70, 0x80)))
DIRECT_FLOWS = ("call", "jmp", "jcc")
FLOW_INDIRECT = {"indirect_call": "call_near", "indirect_callf": "call_far",
                 "indirect_jmp": "jmp_near", "indirect_jmpf": "jmp_far"}

# Targets: (id, image, file offset, label). The offsets are the earlier probes' own anchors.
TARGETS = (
    ("L", EXE_NAME, 0x7245, "START 0x7245: block-201 request routine (name pieces at CS:0x171/0x177)"),
    ("STUB", EXE_NAME, 0x42DE, "START 0x42DE: VROOMM stub (cd 3f 3b 00 00) of GAME.OVR 0x32270"),
    ("R", OVR_NAME, 0x32270, "GAME.OVR 0x32270: '8x8d' loader shape, body 0x32235 relative entry 0x3B"),
    ("OPEN", EXE_NAME, 0x0A89E, "START 0x0A89E: open helper (INT 21h AH=3Dh at 0x0A8B6)"),
    ("OVR_OPEN", EXE_NAME, 0x0A728, "START 0x0A728: overlay-open routine (header read at 0x0A77A)"),
    ("PATH", EXE_NAME, 0x0A86A, "START 0x0A86A: path copy loop (tier B; calls OPEN at 0x0A895)"),
    ("READ_A", EXE_NAME, 0x0A97E, "START 0x0A97E: read routine (AH=3Fh at 0x0A9B5, 0x0A9D6)"),
    ("READ_B", EXE_NAME, 0x0B306, "START 0x0B306: read routine (AH=3Fh at 0x0B333)"),
    ("READ_C", EXE_NAME, 0x0B360, "START 0x0B360: read routine (AH=3Fh at 0x0B374)"),
)

_DECODE_FAILURES = (h.DecodeError, IndexError, ValueError, struct.error)


class ProbeError(PorSourceError):
    """A named refusal, or a source that cannot be read as pinned."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dec(data: bytes, p: int):
    if p < 0 or p >= len(data):
        return None
    try:
        return h.decode(data, p)
    except _DECODE_FAILURES:
        return None


# --------------------------------------------------------------------------
# Tiers: ret-stopped linear sweeps, decode only
# --------------------------------------------------------------------------

NO_FALLTHROUGH = frozenset(("ret", "retf", "jmp", "jmp_far", "indirect_jmp", "indirect_jmpf"))


def body(data: bytes, entry: int, cap: int = MAX_WALK, span: int = BODY_SPAN) -> frozenset:
    """Instruction starts of the routine body from entry: fall-through plus direct jmp/jcc targets.

    Calls fall through (the callee is not entered). Returns, unconditional jumps and indirect
    transfers end a path. Decode failures end a path. A direct jmp/jcc is followed only when its
    target lies in [entry, entry + span): a jump outside that window is treated as a tail jump into
    another routine (a caller edge), not a branch inside this one. The set is capped at ``cap``.
    """
    seen: set[int] = set()
    out: set[int] = set()
    todo = [entry]
    while todo and len(out) < cap:
        p = todo.pop()
        if p in seen:
            continue
        seen.add(p)
        ins = _dec(data, p)
        if ins is None:
            continue
        out.add(p)
        if (ins.flow in ("jmp", "jcc") and ins.target is not None
                and entry <= ins.target < entry + span and ins.target < len(data)):
            todo.append(ins.target)
        if ins.flow not in NO_FALLTHROUGH:
            todo.append(ins.end)
    return frozenset(out)


def prologue_offsets(data: bytes) -> list[int]:
    return [i for i in range(len(data) - 2) if data[i:i + 3] in PROLOGUES]


def e8_entries(data: bytes) -> set[int]:
    out: set[int] = set()
    for i in range(len(data) - 2):
        if data[i] != 0xE8:
            continue
        ins = _dec(data, i)
        if ins is not None and ins.flow == "call" and ins.target is not None and 0 <= ins.target < len(data):
            out.add(ins.target)
    return out


def e8_bodies(data: bytes) -> list[frozenset]:
    """One body per E8-verified entry (see body())."""
    return [body(data, e) for e in sorted(e8_entries(data))]


def build_reach(data: bytes, bodies: Optional[list] = None) -> tuple[set[int], set[int]]:
    """reach_a: starts in a body of an E8-verified entry. reach_b: reach_a plus prologue-entered bodies."""
    if bodies is None:
        bodies = e8_bodies(data)
    reach_a: set[int] = set()
    for b in bodies:
        reach_a.update(b)
    reach_b = set(reach_a)
    for p in prologue_offsets(data):
        reach_b.update(body(data, p))
    return reach_a, reach_b


def same_body(bodies: list, src: int, dst: int) -> bool:
    """True if one E8-verified sweep reaches both: a branch within a routine body, not a caller edge."""
    return any(src in b and dst in b for b in bodies)


def make_tier(reach_a: set[int], reach_b: set[int]):
    def tier(off: int) -> str:
        if off in reach_a:
            return "A"
        if off in reach_b:
            return "B"
        return "C"
    return tier


# --------------------------------------------------------------------------
# Edge indexes
# --------------------------------------------------------------------------

def direct_index(data: bytes) -> dict[int, list]:
    """Decode-verified direct transfers (call, jmp, jcc) keyed by file-offset target."""
    idx: dict[int, list] = {}
    for i in range(len(data)):
        if data[i] not in DIRECT_LEAD:
            continue
        ins = _dec(data, i)
        if ins is None or ins.flow not in DIRECT_FLOWS or ins.target is None:
            continue
        idx.setdefault(ins.target, []).append(ins)
    return idx


def far_model_index(data: bytes) -> dict[int, list]:
    """Decode-verified 9A literal sites keyed by the image model 0x200 + seg*16 + off. Model-conditional."""
    idx: dict[int, list] = {}
    for i in range(len(data) - 4):
        if data[i] != 0x9A:
            continue
        ins = _dec(data, i)
        if ins is not None and ins.flow == "call_far" and ins.far:
            seg, off = ins.far
            idx.setdefault(IMAGE_BASE + seg * 16 + off, []).append(ins)
    return idx


def _disp(ins) -> Optional[int]:
    """Displacement of an FF memory operand (the FF forms carry no immediate, so it is the last bytes)."""
    mod, _reg, rm = ins.modrm
    if mod == 3:
        return None
    if mod == 0:
        return int.from_bytes(ins.raw[-2:], "little") if rm == 6 else None
    if mod == 1:
        return struct.unpack("<b", ins.raw[-1:])[0]
    return struct.unpack("<h", ins.raw[-2:])[0]


def _disp_form(mod: int, rm: int) -> str:
    if mod == 3:
        return "register"
    if mod == 0:
        return "direct" if rm == 6 else "base-no-disp"
    return "bp" if rm == 6 else "base-disp"


def indirect_sites(data: bytes, tier) -> list[dict]:
    rows: list[dict] = []
    for i in range(len(data) - 1):
        if data[i] != 0xFF:
            continue
        ins = _dec(data, i)
        if ins is None or ins.flow not in FLOW_INDIRECT or ins.modrm is None:
            continue
        mod, reg, rm = ins.modrm
        rows.append({
            "at": i,
            "kind": FLOW_INDIRECT[ins.flow],
            "reg": reg,
            "disp_form": _disp_form(mod, rm),
            "disp": _disp(ins),
            "tier": tier(i),
        })
    return rows


def word_hits(data: bytes, value: int) -> list[int]:
    vb = (value & 0xFFFF).to_bytes(2, "little")
    out: list[int] = []
    i = data.find(vb)
    while i != -1:
        out.append(i)
        i = data.find(vb, i + 1)
    return out


# --------------------------------------------------------------------------
# Per-image analysis
# --------------------------------------------------------------------------

def _count(rows: list, **want) -> int:
    return sum(1 for r in rows if all(r.get(k) == v for k, v in want.items()))


def analyse_image(data: bytes, targets: list[tuple]) -> dict:
    bodies = e8_bodies(data)
    reach_a, reach_b = build_reach(data, bodies)
    tier = make_tier(reach_a, reach_b)
    didx = direct_index(data)
    fidx = far_model_index(data)
    indirect = indirect_sites(data, tier)

    target_rows = []
    for tid, off, label in targets:
        direct = [{"at": x.off, "kind": x.flow, "opcode": "%02x" % x.op, "tier": tier(x.off),
                   "same_body": same_body(bodies, x.off, off)}
                  for x in didx.get(off, [])]
        far = [{"at": x.off, "seg": x.far[0], "off": x.far[1], "tier": tier(x.off)}
               for x in fidx.get(off, [])]
        hits = []
        zero_skipped = []
        for base in NEAR_BASES:
            value = (off - base) & 0xFFFF
            if value == 0:
                # Every zero word would match: the hit set would be padding, not evidence.
                zero_skipped.append(base)
                continue
            for at in word_hits(data, value):
                hits.append({"at": at, "base": base, "value": value, "loc_tier": tier(at)})
        target_rows.append({
            "id": tid,
            "file_offset": off,
            "label": label,
            "direct": sorted(direct, key=lambda r: r["at"]),
            "far_model": sorted(far, key=lambda r: r["at"]),
            "table_word_hits": sorted(hits, key=lambda r: (r["base"], r["at"])),
            "table_bases_skipped_zero_value": zero_skipped,
            "chance_hits_per_value": round(len(data) / 65536.0, 4),
            "summary": {
                "e8_all_tiers": _count(direct, kind="call"),
                "e8_tier_a": _count(direct, kind="call", tier="A"),
                "jump_tier_a": _count(direct, tier="A") - _count(direct, kind="call", tier="A"),
                "jump_tier_b": _count(direct, tier="B") - _count(direct, kind="call", tier="B"),
                "jump_tier_c": _count(direct, tier="C") - _count(direct, kind="call", tier="C"),
                "far_model_tier_a": _count(far, tier="A"),
                "far_model_total": len(far),
                "table_hits_base0": _count(hits, base=0),
                "table_hits_base200": _count(hits, base=0x200),
                "direct_a_tier_same_body": _count(direct, tier="A", same_body=True),
                "direct_a_tier_callers": _count(direct, tier="A", same_body=False),
            },
        })

    by_kind: dict[str, dict] = {}
    for r in indirect:
        slot = by_kind.setdefault(r["kind"], {"total": 0, "tier_a": 0, "tier_b": 0, "tier_c": 0,
                                              "with_direct": 0})
        slot["total"] += 1
        slot["tier_" + r["tier"].lower()] += 1
        if r["disp_form"] == "direct":
            slot["with_direct"] += 1

    return {
        "bytes": len(data),
        "sha256": _sha(data),
        "reach_a_starts": len(reach_a),
        "reach_b_starts": len(reach_b),
        "e8_entries": len(e8_entries(data)),
        "prologue_entries": len(prologue_offsets(data)),
        "direct_transfer_sites": sum(len(v) for v in didx.values()),
        "indirect_inventory": {k: by_kind[k] for k in sorted(by_kind)},
        "indirect_sites": indirect,
        "targets": target_rows,
    }


UNRESOLVED = [
    {"id": "U1", "edge": "DS (or CS) base of each indirect displacement",
     "why": "table slots cannot be linked to an indirect site until the base is fixed; the word hits are unlinked"},
    {"id": "U2", "edge": "indirect table slots that hold a target offset",
     "why": "word-value hits are candidates only; the chance rate per value is recorded for comparison"},
    {"id": "U3", "edge": "far (9A) callers of the VROOMM stub and of GAME.OVR 0x32270",
     "why": "the image model file = 0x200 + seg*16 + off is not validated (see por-8x8d-dos-sites-probe)"},
    {"id": "U4", "edge": "near Jcc encoded as 0F 8x",
     "why": "the shared decoder rejects 0F two-byte opcodes, so these are not counted"},
    {"id": "U5", "edge": "callers of A-tier routines above depth 1",
     "why": "this probe takes a single census level; it does not walk upward"},
]

NEXT_DISCRIMINATOR = (
    "Fix the DS base first. The START.EXE startup code and the MZ load image give the data segment "
    "literal; the discriminator is then whether a word equal to the target's offset sits at "
    "DSbase + displacement for an indirect site whose own tier is A. A link is established only if "
    "that word is the one the indirect site reads. Until then, every table-word hit stays unlinked."
)


def analyse(start: bytes, ovr: bytes) -> dict:
    images = {EXE_NAME: start, OVR_NAME: ovr}
    per_image = {}
    for name, data in images.items():
        tlist = [(tid, off, label) for tid, img, off, label in TARGETS if img == name]
        per_image[name] = analyse_image(data, tlist)
    return per_image


# --------------------------------------------------------------------------
# Probe entry: pins, refusal, outputs
# --------------------------------------------------------------------------

def resolve_folder(install: Path) -> Path:
    for cand in (install, install / "POOLRAD"):
        if (cand / OVR_NAME).is_file() and (cand / EXE_NAME).is_file():
            return cand
    raise ProbeError("no %s and %s pair found in %s or its POOLRAD folder" % (OVR_NAME, EXE_NAME, install))


def _pinned_row(name: str, data: bytes, allow_unpinned: bool) -> dict:
    size, sha = fr.PINNED[name]
    ok = len(data) == size and _sha(data) == sha
    if not ok and not allow_unpinned:
        raise ProbeError("%s does not match its pinned size and SHA-256" % name)
    return {"bytes": len(data), "sha256": _sha(data), "pin_match": ok}


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    folder = resolve_folder(install)
    validate_output_dir(folder, out)
    paths = {EXE_NAME: folder / EXE_NAME, OVR_NAME: folder / OVR_NAME}
    before = {name: p.read_bytes() for name, p in paths.items()}
    pins = {name: _pinned_row(name, before[name], allow_unpinned) for name in paths}

    per_image = analyse(before[EXE_NAME], before[OVR_NAME])

    after = {name: p.read_bytes() for name, p in paths.items()}
    if any(before[n] != after[n] for n in paths):
        raise ProbeError("a source changed during the run")

    all_pinned = all(v["pin_match"] for v in pins.values())
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "mappings": [],
        "binding_established": False,
        "tool": TOOL,
        "retail_evidence": all_pinned,
        "pins": {k: pins[k] for k in sorted(pins)},
        "source_unchanged_during_run": True,
        "per_image": per_image,
        "unresolved_edges": UNRESOLVED,
        "next_discriminator": NEXT_DISCRIMINATOR,
        "not_claimed": [
            "no caller of any target beyond the A-tier direct edges shown",
            "no 8X8D archive binding, block-to-tile mapping, or PoR screen binding",
            "no emulator, DOSBox, GameLink, codewheel, or retail write",
            "GoldBox and CoK material is not used as evidence for PoR bytes",
        ],
    }
    return doc, (0 if all_pinned else 1)


def _hx(v) -> str:
    if v is None:
        return "-"
    return ("-0x%X" % -v) if v < 0 else ("0x%X" % v)


def render_report(doc: dict) -> str:
    a: list[str] = []
    a.append("# Pool of Radiance entry-call probe (static, observe-only)")
    a.append("")
    a.append("Status: `%s`, `playable: %s`, `binding_established: %s`, `retail_evidence: %s`"
             % (doc["status"], str(doc["playable"]).lower(), str(doc["binding_established"]).lower(),
                str(doc["retail_evidence"]).lower()))
    a.append("")
    a.append("## Pins")
    a.append("")
    a.append("| file | bytes | sha256 | pin |")
    a.append("| --- | ---: | --- | --- |")
    for name, row in doc["pins"].items():
        a.append("| %s | %d | `%s` | %s |" % (name, row["bytes"], row["sha256"],
                                               "match" if row["pin_match"] else "MISMATCH"))
    a.append("")
    a.append("## Targets (direct transfers by tier; word hits are candidates)")
    a.append("")
    a.append("| id | target | E8 A | E8 all | jump A/B/C | far-model A/total | table hits b0 / b0x200 | chance per value |")
    a.append("| --- | --- | ---: | ---: | --- | --- | --- | ---: |")
    for img in (EXE_NAME, OVR_NAME):
        for t in doc["per_image"][img]["targets"]:
            s = t["summary"]
            a.append("| %s | %s `0x%05X` | %d | %d | %d / %d / %d | %d / %d | %d / %d | %s |" % (
                t["id"], img, t["file_offset"], s["e8_tier_a"], s["e8_all_tiers"],
                s["jump_tier_a"], s["jump_tier_b"], s["jump_tier_c"],
                s["far_model_tier_a"], s["far_model_total"],
                s["table_hits_base0"], s["table_hits_base200"], t["chance_hits_per_value"]))
    a.append("")
    a.append("## Indirect transfers by kind (FF /2 to /5)")
    a.append("")
    a.append("| image | kind | total | tier A | tier B | tier C | with direct disp |")
    a.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for img in (EXE_NAME, OVR_NAME):
        for kind, row in doc["per_image"][img]["indirect_inventory"].items():
            a.append("| %s | %s | %d | %d | %d | %d | %d |" % (
                img, kind, row["total"], row["tier_a"], row["tier_b"], row["tier_c"], row["with_direct"]))
    a.append("")
    a.append("## A-tier direct edges (callers = cross-body only; same-body branches listed apart)")
    a.append("")
    any_a = False
    for img in (EXE_NAME, OVR_NAME):
        for t in doc["per_image"][img]["targets"]:
            for r in t["direct"]:
                if r["tier"] != "A":
                    continue
                any_a = True
                role = "same-body branch (not a caller)" if r["same_body"] else "cross-body caller"
                a.append("- %s `%s` at `0x%05X` (opcode `%s`, %s, source tier A, %s) -> `0x%05X`"
                         % (img, t["id"], r["at"], r["opcode"], r["kind"], role, t["file_offset"]))
    if not any_a:
        a.append("None. No A-tier direct edge reaches any target.")
    a.append("")
    a.append("## Tier-A indirect sites (candidate dispatch; displacements not yet linked)")
    a.append("")
    a.append("| image | at | kind | disp form | disp |")
    a.append("| --- | --- | --- | --- | --- |")
    for img in (EXE_NAME, OVR_NAME):
        for r in doc["per_image"][img]["indirect_sites"]:
            if r["tier"] == "A":
                a.append("| %s | `0x%05X` | %s | %s | %s |" % (img, r["at"], r["kind"], r["disp_form"],
                                                           _hx(r["disp"])))
    a.append("")
    a.append("## Unresolved edges")
    a.append("")
    for u in doc["unresolved_edges"]:
        a.append("- **%s** %s: %s" % (u["id"], u["edge"], u["why"]))
    a.append("")
    a.append("## Next discriminator")
    a.append("")
    a.append(doc["next_discriminator"])
    a.append("")
    a.append("## Not claimed")
    a.append("")
    for n in doc["not_claimed"]:
        a.append("- %s" % n)
    a.append("")
    return "\n".join(a)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_8x8d_entry_call_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_8x8d_entry_call_probe_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--install", required=True, type=Path, help="folder holding START.EXE and GAME.OVR")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder (under data/)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="run on a file not matching its pin; output is marked not retail evidence")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out, args.allow_unpinned)
    except PorSourceError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s" % (args.out / "por_8x8d_entry_call_probe.json"))
    print("retail_evidence=%s exit=%d" % (str(doc["retail_evidence"]).lower(), code))
    return code


if __name__ == "__main__":
    sys.exit(main())
