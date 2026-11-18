#!/usr/bin/env python3
"""Pool of Radiance: read-only saved-state byte probe (SAVGAMA.DAT / SAVGAMJ.DAT).

Status: SAVE-BYTE-OBSERVATION-ONLY. Read-only, stdlib-only, playable: false.

Reads the two pinned retail saves and reports the candidate byte fields named by the
GoldBox reference inspector (tools/inspect_pool_save.py in that repo): the wrapper
game-area byte at 0, the ECL member byte at 485, the Area2 game-area byte at 3621, and
pose x / y / facing at 12801..12803. Each value is a byte observation of a file whose
SHA-256 is pinned. None is a runtime fact.

Also lists the CHRDAT[A-J][1-6] sidecar names that a byte scan finds in each save, and
which of those files exist in the install folder. Sidecars are listed by filename only:
they are never opened, parsed, or copied.

Not claimed: a full save schema, a new-game start state, live DOS state, or any mapping
from these values to a GEO TOC block or ECL archive member. Facing names are a candidate
mapping, not a proof. No save-file contents appear in the outputs.

Usage
  python tools/por_save_state_probe.py --install "PATH/TO/POOLRAD" -o data/por-save-state-probe/retail

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_save_state_probe.json          schema openua.por-save-state-probe, playable: false
  por_save_state_probe_report.md     the readable summary

Exit codes
  0  both saves matched their pins; outputs written
  2  named refusal, no output written: install folder or save missing, save size not
     the pinned size, save hash not pinned, or an output path outside data/ (or inside
     the install, or containing it)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATA_DIR = REPO / "data"
SCHEMA = "openua.por-save-state-probe"
SCHEMA_VERSION = 0
STATUS = "save-byte-observation-only"
TOOL = "tools/por_save_state_probe.py"
INSTALL_ENV = "OPENUA_POR_INSTALL"
DEFAULT_INSTALL = "G:/Games/Pool of Radiance/POOLRAD"

# (size, sha256) of the two retail saves; hashes as recorded in docs/por-save-loader-trace.md.
SAVE_PINS = {
    "SAVGAMA.DAT": (13137, "abca248371287c43c99e1b34e03394819fca3cf406bed184e7e4fbfe4f0c08f1"),
    "SAVGAMJ.DAT": (13137, "4b64213a9d19d082af6a075b7aa54407c5cfe3883f6ade1f3862283c130d6ca9"),
}

AREA1_FILE_OFFSET = 1
AREA2_FILE_OFFSET = AREA1_FILE_OFFSET + 0x800

# (field id, file offset, role note). Offsets are the GoldBox reference inspector's
# candidate offsets; the role notes say what is and is not established.
FIELDS = (
    ("wrapper_game_area", 0, "candidate game-area byte of the save wrapper"),
    ("ecl_member", AREA1_FILE_OFFSET + 0x1E4, "candidate ECL member byte"),
    ("area2_game_area", AREA2_FILE_OFFSET + 0x624, "candidate Area2 game-area byte"),
    ("pose_x", 12801, "candidate pose x byte"),
    ("pose_y", 12802, "candidate pose y byte"),
    ("facing_raw", 12803, "candidate facing byte"),
)
MAX_OFFSET = max(off for _, off, _ in FIELDS)

# Candidate facing names copied from the GoldBox reference inspector. The raw byte is the
# observation; the name is a labelled candidate, not a verified mapping.
FACING_CANDIDATE_NAMES = {0: "north", 2: "east", 4: "south", 6: "west"}
FACING_NAME_STATUS = "candidate-mapping-unverified (0/2/4/6 from the GoldBox reference inspector)"

# Values recorded by the read-only GoldBox inspection (2026-11-17). Used only to report
# whether today's bytes still match that record; they are not an oracle for the save format.
RECORDED_OBSERVATIONS = {
    "SAVGAMA.DAT": {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
                    "pose_x": 15, "pose_y": 4, "facing_raw": 6},
    "SAVGAMJ.DAT": {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
                    "pose_x": 14, "pose_y": 5, "facing_raw": 4},
}

SIDECAR_REF = re.compile(rb"CHRDAT[A-J][1-6]")
SIDECAR_SUFFIXES = (".SAV", ".ITM", ".SPC")

LIMITATIONS = (
    "Save bytes only. Six candidate bytes at fixed offsets in each pinned 13,137-byte file. "
    "No full save schema is decoded; every other byte is unexamined.",
    "No new-game start is modelled. These bytes are not a start state.",
    "No live DOS state is observed. Nothing was run, no emulator or codewheel was started, "
    "and no input was sent.",
    "No GEO TOC mapping. Game-area and member values are not tied to any GEO*.DAX block or "
    "ECL archive member here.",
    "Wrapper, ECL-member and Area2 readings are candidates from the reference inspector. "
    "This repo's PoR code does not establish them.",
    "Facing names are a candidate mapping. facing_raw is the observed fact.",
    "Sidecar names are the CHRDAT[A-J][1-6] strings a byte scan finds in each save. They are "
    "listed by filename only. No sidecar was opened, parsed or copied, and a file's presence "
    "says nothing about its content.",
    "Pins cover the two retail saves only. Any other save is refused, not inspected.",
    "No CoK or DoK save rules were transferred. Every field here is a PoR byte observation.",
)
CLAIM_BOUNDARY = (
    "Candidate save-byte observations for two pinned retail saves. Not runtime-established, "
    "not a save schema, not a start state, and not a GEO TOC mapping."
)


class ProbeRefusal(Exception):
    """A named refusal. The CLI prints it and exits with 2, writing no output."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def observe_save(data: bytes, name: str, sha: str,
                 recorded: Optional[dict] = None) -> dict:
    """Pure: candidate fields for one save's bytes. Raises ProbeRefusal if too short."""
    if len(data) <= MAX_OFFSET:
        raise ProbeRefusal("%s is too short for offset %d" % (name, MAX_OFFSET))
    fields = {}
    for fid, off, role in FIELDS:
        value = data[off]
        entry = {
            "offset": off,
            "offset_hex": "0x%X" % off,
            "value": value,
            "role": role,
            "status": "candidate-byte-observed",
        }
        if fid == "facing_raw":
            entry["candidate_name"] = FACING_CANDIDATE_NAMES.get(value, "unmapped")
            entry["candidate_name_status"] = FACING_NAME_STATUS
        if recorded is not None:
            entry["matches_recorded_observation"] = value == recorded[fid]
        fields[fid] = entry
    return {
        "name": name,
        "size": len(data),
        "sha256": sha,
        "pin": "matched",
        "fields": fields,
    }


def sidecar_inventory(install: Path, save_bytes: bytes) -> dict:
    """Names only. Uses a directory listing and never opens a sidecar."""
    refs = sorted({m.decode("ascii") for m in SIDECAR_REF.findall(save_bytes)})
    present = []
    with os.scandir(install) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                continue
            p = Path(entry.name)
            if p.stem.upper() in refs and p.suffix.upper() in SIDECAR_SUFFIXES:
                present.append(entry.name)
    present = sorted(present)
    present_stems = {Path(n).stem.upper() for n in present}
    return {
        "referenced_by_name": refs,
        "present_files": present,
        "missing": [r for r in refs if r not in present_stems],
        "content_examined": False,
    }


def check_output(out: Path, install: Path, data_root: Path) -> None:
    o = out.resolve()
    inst = install.resolve()
    dr = data_root.resolve()
    if o == inst or inst in o.parents or o in inst.parents:
        raise ProbeRefusal("output must not be inside or contain the install")
    if o == dr or dr not in o.parents:
        raise ProbeRefusal("output must be under data/ (git-ignored)")


def probe(install: Path, out: Path, pins: dict = SAVE_PINS,
          data_root: Path = DATA_DIR, recorded: Optional[dict] = RECORDED_OBSERVATIONS) -> dict:
    if not install.is_dir():
        raise ProbeRefusal("install folder not found")
    check_output(out, install, data_root)

    saves = []
    sidecars = {}
    before = {}
    for name, (size, sha) in pins.items():
        path = install / name
        if not path.is_file():
            raise ProbeRefusal("missing save file %s" % name)
        data = path.read_bytes()
        if len(data) != size:
            raise ProbeRefusal("%s size is %d, expected the pinned %d" % (name, len(data), size))
        digest = _sha(data)
        if digest != sha:
            raise ProbeRefusal("%s sha256 does not match its pin; not inspected" % name)
        before[name] = digest
        rec = recorded.get(name) if recorded is not None else None
        saves.append(observe_save(data, name, digest, rec))
        sidecars[name] = sidecar_inventory(install, data)

    unchanged = all(_sha((install / name).read_bytes()) == before[name] for name in pins)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool": TOOL,
        "playable": False,
        "runtime_established": False,
        "saves": saves,
        "sidecars": sidecars,
        "recorded_comparison": recorded is not None,
        "install_unchanged": unchanged,
        "limitations": list(LIMITATIONS),
        "claim_boundary": CLAIM_BOUNDARY,
    }


def render_report(doc: dict) -> str:
    lines = [
        "# Pool of Radiance: saved-state byte probe",
        "",
        "Status: `%s`. `playable: false`. `runtime_established: false`." % doc["status"],
        "Install unchanged during run: `%s`." % doc["install_unchanged"],
        "",
    ]
    for save in doc["saves"]:
        lines += [
            "## %s" % save["name"],
            "",
            "- Size: %d bytes (pinned). SHA-256: `%s`. Pin: %s." % (save["size"], save["sha256"], save["pin"]),
            "",
            "| Field | Offset | Value | Note |",
            "| --- | ---: | ---: | --- |",
        ]
        for fid, f in save["fields"].items():
            note = f["role"]
            if fid == "facing_raw":
                note += "; candidate name `%s` (%s)" % (f["candidate_name"], f["candidate_name_status"])
            if "matches_recorded_observation" in f:
                note += "; matches recorded: %s" % f["matches_recorded_observation"]
            lines.append("| %s | %d (%s) | %d | %s |" % (fid, f["offset"], f["offset_hex"], f["value"], note))
        sc = doc["sidecars"][save["name"]]
        lines += [
            "",
            "Sidecars named by the save (filename only; content not examined):",
            "",
            "- Referenced: %s" % (", ".join(sc["referenced_by_name"]) or "none"),
            "- Present in install: %s" % (", ".join(sc["present_files"]) or "none"),
            "- Missing: %s" % (", ".join(sc["missing"]) or "none"),
            "",
        ]
    lines += ["## Limitations", ""] + ["- %s" % item for item in doc["limitations"]]
    lines += ["", "## Claim boundary", "", doc["claim_boundary"], ""]
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_save_state_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / "por_save_state_probe_report.md").write_text(
        render_report(doc), encoding="utf-8", newline="\n")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--install", help="PoR install folder (default: $%s or %s)"
                    % (INSTALL_ENV, DEFAULT_INSTALL))
    ap.add_argument("-o", "--output", required=True,
                    help="output folder, explicitly under data/ (relative paths are from the repo root)")
    args = ap.parse_args(argv)
    install = Path(args.install or os.environ.get(INSTALL_ENV) or DEFAULT_INSTALL)
    out = Path(args.output)
    if not out.is_absolute():
        out = (REPO / out).resolve()
    try:
        doc = probe(install, out)
    except ProbeRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, out)
    print("saves inspected: %d; sidecars listed by name only; install unchanged %s"
          % (len(doc["saves"]), doc["install_unchanged"]))
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
