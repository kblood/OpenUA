#!/usr/bin/env python3
"""Pool of Radiance runtime-capture readiness and CS:IP breakpoint plan.

Status: RUNTIME-PLAN-ONLY. Read-only, stdlib-only, playable: false.

This tool does NOT launch DOSBox-X and does NOT capture a runtime hit. It does
three things, all static:

  1. Checks the retail inputs against their pins (GAME.OVR, START.EXE), read-only.
  2. Checks the emulator binary you name (``--dosbox`` or ``POR_DOSBOX_X_EXE``):
     present or absent, and its SHA-256.
  3. Derives the breakpoint targets for the three PoR questions and writes them
     as a plan: the 0x37 handler at GAME.OVR:0x19ba, the two literal far-call
     sites that resolve to VROOMM stubs, the two stub target procedures, and the
     operand parser at GAME.OVR:0x74d3. For each it gives the overlay descriptor
     that covers the file offset, the offset inside that descriptor, and the
     route-specific destination segments that GoldBox runtime notes recorded.
     Those destination segments are candidates. They are not observations here.

The file offsets are checked against the retail bytes (opcode ``9A`` at each
call site with the literal seg:off; ``CD 3F`` stub bytes in START.EXE; Borland
prologues at the procedure targets). Those checks are static. They are reported
as ``static_bytes`` and never as ``runtime``.

Runtime capture status is always reported as ``performed: false`` by this tool.
A runtime result needs a separate, logged DOSBox-X run that follows the recipe
in ``docs/por-runtime-capture-assessment.md``.

Usage
  python3 tools/por_runtime_capture_plan.py --install "PATH/TO/POOLRAD" \
      --dosbox "PATH/TO/dosbox-x.exe" -o data/work/por-runtime-capture-plan

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths
other than the ones you pass):
  por_runtime_capture_plan.json         schema openua.por-runtime-capture-plan, playable: false
  por_runtime_capture_plan_report.md    readiness, blockers, targets, procedure

Exit codes
  0  every input matched its pin, the emulator was found, and every target's
     static bytes matched its expectation
  1  output written with a blocker (emulator missing, a static check failed,
     or a retail file did not match its pin under --allow-unpinned)
  2  named refusal: bad install, a file not matching its pin (without
     --allow-unpinned), or unsafe output location
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_farcall_resolve as fc  # noqa: E402

SCHEMA = "openua.por-runtime-capture-plan"
SCHEMA_VERSION = 1
STATUS = "runtime-plan-only"
TOOL = "tools/por_runtime_capture_plan.py"
EMULATOR_ENV = "POR_DOSBOX_X_EXE"
EMULATOR_PIN_SHA256 = "3f548183dc0e937482b531cf72c024108636af822f2c89e19e757a318cc4d509"
EMULATOR_PIN_NOTE = ("dosbox-x-v2026.07.02, x64 Release SDL2, the build recorded in a GoldBox "
                     "build manifest; the pin is a hash of the binary, not a claim about its runtime")
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")

# Overlay descriptors that cover the handler, the stub targets and the parser.
# seek/size are retail GAME.OVR facts (docs/engine/research/pool-runtime-overlay-map.md).
# route_dest_candidates are destination segments GoldBox recorded on specific
# routes. They differ between routes, so each is labelled with its source.
DESCRIPTORS = {
    3: {
        "seek": 0x0D46, "size": 0x350D,
        "route_dest_candidates": [
            {"segment": 0x3581, "source": "pool-runtime-overlay-map.md, descriptor 3, snapshot 33"},
        ],
    },
    7: {
        "seek": 0x74D3, "size": 0x221A,
        "route_dest_candidates": [
            {"segment": 0x30CF, "source": "pool-runtime-route-overlay-trace.md, snapshot 2 (ECL1#18 route)"},
            {"segment": 0x3089, "source": "pool-runtime-overlay-map.md, descriptor 7, snapshot 29"},
        ],
    },
}

# Stub base in START.EXE: MZ image at file 0x200, stubs of group 0x74d3 run from 0x471.
STUB_GROUP_7_RUN_START = 0x471
STUB_LEN = 5

# The handler's literal far-call sites, from docs/por-farcall-resolution.md.
# Each literal seg:off is the link-time operand; the loader fixes up the seg word
# (the fixup table lists it), so the runtime selector is read from the call at run time.
CALL_SITES = [
    {"id": "far_call_a", "file_off": 0x19C3, "seg": 0x2B, "off": 0x2A,
     "stub_index": 21, "stub_proc_off": 0x1DF0, "target_file_off": 0x92C3},
    {"id": "far_call_b", "file_off": 0x19DA, "seg": 0x2B, "off": 0x25,
     "stub_index": 20, "stub_proc_off": 0x1CC3, "target_file_off": 0x9196},
]
HANDLER_FILE_OFF = 0x19BA
PARSER_FILE_OFF = 0x74D3
# The dispatcher's case-0x37 compare (0x3d9e: 3C 37), its jne, push cs, and the near
# call E8 at 0x3da3 that reaches the handler. Recorded in docs/por-loadpieces-handler.md.
DISPATCH_CASE_37_FILE_OFF = 0x3D9E
DISPATCH_CALL_FILE_OFF = 0x3DA3


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cs_ip(segment: int, offset: int) -> str:
    return "%04X:%04X" % (segment, offset)


def _descriptor_for(file_off: int) -> Optional[tuple[int, dict]]:
    for num, d in sorted(DESCRIPTORS.items()):
        if d["seek"] <= file_off < d["seek"] + d["size"]:
            return num, d
    return None


def _target(target_id: str, label: str, file_off: int) -> dict:
    found = _descriptor_for(file_off)
    if found is None:
        return {"id": target_id, "label": label, "file_off": "0x%X" % file_off,
                "descriptor": None, "rel_off": None, "route_candidates": [],
                "note": "no described descriptor covers this file offset"}
    num, d = found
    rel = file_off - d["seek"]
    cands = []
    for c in d["route_dest_candidates"]:
        cands.append({"cs_ip_candidate": _cs_ip(c["segment"], rel), "source": c["source"],
                      "observed_in_this_run": False})
    return {"id": target_id, "label": label, "file_off": "0x%X" % file_off,
            "descriptor": num, "descriptor_seek": "0x%X" % d["seek"],
            "rel_off": "0x%X" % rel, "route_candidates": cands}


def build_targets() -> list[dict]:
    targets = [_target("dispatch_case_37", "dispatcher compare for case 0x37 (cmp al,0x37)",
                       DISPATCH_CASE_37_FILE_OFF),
               _target("handler_entry", "0x37 handler entry (dispatch case 0x37)", HANDLER_FILE_OFF)]
    for site in CALL_SITES:
        targets.append(_target(site["id"] + "_site",
                               "literal far call %04X:%04X at GAME.OVR:0x%X (stub %d)"
                               % (site["seg"], site["off"], site["file_off"], site["stub_index"]),
                               site["file_off"]))
        targets.append(_target(site["id"] + "_proc",
                               "stub %d target procedure (proc_off 0x%X)"
                               % (site["stub_index"], site["stub_proc_off"]),
                               site["target_file_off"]))
    targets.append(_target("operand_parser", "operand parser entry (descriptor 7 proc 0)", PARSER_FILE_OFF))
    return targets


def check_static_bytes(ovr: bytes, start: bytes) -> list[dict]:
    """Static checks against the retail bytes. Never a runtime claim."""
    checks = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    for site in CALL_SITES:
        f = site["file_off"]
        op = ovr[f:f + 1]
        lit = ovr[f + 1:f + 5]
        seg_lit = int.from_bytes(lit[2:4], "little") if len(lit) == 4 else -1
        off_lit = int.from_bytes(lit[0:2], "little") if len(lit) == 4 else -1
        add("%s_9a_literal" % site["id"],
            op == b"\x9a" and off_lit == site["off"] and seg_lit == site["seg"],
            "GAME.OVR:0x%X bytes %s; literal %04X:%04X" % (f, ovr[f:f + 5].hex(), seg_lit, off_lit))
        # Stub: image address 0x200 + seg*16 + off, expected to start a 5-byte CD 3F stub.
        image = 0x200 + site["seg"] * 16 + site["off"]
        stub_start = STUB_GROUP_7_RUN_START + site["stub_index"] * STUB_LEN
        sb = start[image:image + STUB_LEN]
        expected = b"\xcd\x3f" + site["stub_proc_off"].to_bytes(2, "little") + b"\x00"
        add("%s_stub_bytes" % site["id"],
            image == stub_start and sb == expected,
            "START.EXE image 0x%X (stub run start 0x%X + %d*5); bytes %s"
            % (image, STUB_GROUP_7_RUN_START, site["stub_index"], sb.hex()))
        t = site["target_file_off"]
        add("%s_proc_prologue" % site["id"],
            ovr[t:t + 3] in PROLOGUES,
            "GAME.OVR:0x%X bytes %s" % (t, ovr[t:t + 3].hex()))
    p = PARSER_FILE_OFF
    add("operand_parser_prologue", ovr[p:p + 3] in PROLOGUES,
        "GAME.OVR:0x%X bytes %s" % (p, ovr[p:p + 3].hex()))
    h = HANDLER_FILE_OFF
    add("handler_prologue", ovr[h:h + 3] in PROLOGUES,
        "GAME.OVR:0x%X bytes %s" % (h, ovr[h:h + 3].hex()))
    c = DISPATCH_CASE_37_FILE_OFF
    add("dispatch_case_37_compare", ovr[c:c + 2] == b"\x3c\x37",
        "GAME.OVR:0x%X bytes %s" % (c, ovr[c:c + 2].hex()))
    k = DISPATCH_CALL_FILE_OFF
    rel = int.from_bytes(ovr[k + 1:k + 3], "little") if ovr[k:k + 1] == b"\xe8" else -1
    dest = (k + 3 + rel) & 0xFFFF if rel >= 0 else -1
    add("dispatch_case_37_near_call", ovr[k:k + 1] == b"\xe8" and dest == HANDLER_FILE_OFF,
        "GAME.OVR:0x%X bytes %s; near call resolves to 0x%X (file offset model)"
        % (k, ovr[k:k + 3].hex(), dest))
    return checks


def probe_emulator(path: Optional[Path]) -> dict:
    if path is None:
        return {"path": None, "found": False, "sha256": None, "sha_matches_pin": False,
                "pin": EMULATOR_PIN_SHA256, "pin_note": EMULATOR_PIN_NOTE,
                "reason": "no emulator path given (--dosbox or %s)" % EMULATOR_ENV}
    p = Path(path)
    if not p.is_file():
        return {"path": str(p), "found": False, "sha256": None, "sha_matches_pin": False,
                "pin": EMULATOR_PIN_SHA256, "pin_note": EMULATOR_PIN_NOTE,
                "reason": "emulator file not found"}
    digest = _sha(p.read_bytes())
    return {"path": str(p), "found": True, "sha256": digest,
            "sha_matches_pin": digest == EMULATOR_PIN_SHA256,
            "pin": EMULATOR_PIN_SHA256, "pin_note": EMULATOR_PIN_NOTE, "reason": None}


def plan(install: Path, dosbox: Optional[Path], allow_unpinned: bool) -> tuple[dict, int]:
    ovr_path = fc.find_file(install, fc.OVR_NAME)
    exe_path = fc.find_file(install, fc.EXE_NAME)
    ovr = ovr_path.read_bytes()
    start = exe_path.read_bytes()
    pins = {}
    for name, data in ((fc.OVR_NAME, ovr), (fc.EXE_NAME, start)):
        size, sha = fc.PINNED[name]
        ok = len(data) == size and _sha(data) == sha
        pins[name] = {"size": len(data), "sha256": _sha(data), "pin_match": ok}
        if not ok and not allow_unpinned:
            raise PorSourceError("%s does not match its pinned size and SHA-256 "
                                 "(use --allow-unpinned to plan anyway; the output "
                                 "will not be retail evidence)" % name)
    emulator = probe_emulator(dosbox)
    checks = check_static_bytes(ovr, start)
    targets = build_targets()

    blockers = []
    if not emulator["found"]:
        blockers.append({"id": "emulator-missing", "detail": emulator["reason"]})
    elif not emulator["sha_matches_pin"]:
        blockers.append({"id": "emulator-unpinned",
                         "detail": "emulator found but its SHA-256 is not the pinned build"})
    for c in checks:
        if not c["ok"]:
            blockers.append({"id": "static-check-failed", "detail": c["check"]})
    blockers.append({"id": "route-to-opcode-0x37-unproven",
                     "detail": "the GoldBox PoR notes checked here record no runtime execution of "
                               "ECL opcode 0x37; the handler's runtime hit is not established"})
    blockers.append({"id": "route-destination-unobserved",
                     "detail": "descriptor destination segments are route-specific and must be "
                               "observed on the run that is logged"})
    blockers.append({"id": "parser-route-stage-missing",
                     "detail": "the GoldBox ECL2-20 route stage (build/runtime-pool-ecl2-20-gamelink-20260717) "
                               "is absent from the GoldBox checkout"})

    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "runtime_capture": {
            "performed": False,
            "reason": "this tool never launches the emulator; see the blockers and the recipe",
            "hits": [],
        },
        "source": {"pins": pins, "all_pins_match": all(v["pin_match"] for v in pins.values())},
        "emulator": emulator,
        "static_bytes": checks,
        "descriptors": {str(k): {"seek": "0x%X" % v["seek"], "size": "0x%X" % v["size"]}
                        for k, v in sorted(DESCRIPTORS.items())},
        "targets": targets,
        "blockers": blockers,
        "not_established": [
            "that the handler at GAME.OVR:0x19ba runs for opcode 0x37 at runtime",
            "that either far call reaches a stub at runtime",
            "the runtime CS of any descriptor on the route being recorded",
            "that the operand parser runs on the handler's route",
        ],
    }
    exit_code = 0 if not blockers or all(b["id"] in (
        "route-to-opcode-0x37-unproven", "route-destination-unobserved",
        "parser-route-stage-missing") for b in blockers) else 1
    return doc, exit_code


def render_report(doc: dict) -> str:
    em = doc["emulator"]
    lines = [
        "# PoR runtime-capture plan",
        "",
        "Status: `%s`. `playable: false`. Runtime capture performed: **%s**."
        % (doc["status"], "yes" if doc["runtime_capture"]["performed"] else "no"),
        "",
        "## Inputs",
        "",
        "| File | Size | SHA-256 | Pin |",
        "| --- | ---: | --- | --- |",
    ]
    for name, v in doc["source"]["pins"].items():
        lines.append("| `%s` | %d | `%s` | %s |" % (name, v["size"], v["sha256"],
                                                  "match" if v["pin_match"] else "MISMATCH"))
    lines += ["", "## Emulator", ""]
    if em["found"]:
        lines.append("- Path: `%s`" % em["path"])
        lines.append("- SHA-256: `%s` (%s pin)" % (em["sha256"],
                                                  "matches" if em["sha_matches_pin"] else "does NOT match"))
    else:
        lines.append("- Not available: %s" % em["reason"])
    lines += ["", "## Static byte checks (not runtime)", "", "| Check | OK | Detail |",
              "| --- | --- | --- |"]
    for c in doc["static_bytes"]:
        lines.append("| %s | %s | %s |" % (c["check"], "yes" if c["ok"] else "**no**", c["detail"]))
    lines += ["", "## Breakpoint targets (CS:IP candidates, unobserved)", "",
              "| Target | File offset | Descriptor | Offset in descriptor | Route CS:IP candidates |",
              "| --- | --- | --- | --- | --- |"]
    for t in doc["targets"]:
        cands = "; ".join("`%s` (%s)" % (c["cs_ip_candidate"], c["source"]) for c in t["route_candidates"]) or "none"
        lines.append("| %s | `%s` | %s | `%s` | %s |" % (t["label"], t["file_off"], t["descriptor"],
                                                         t["rel_off"], cands))
    lines += ["", "## Blockers", ""]
    for b in doc["blockers"]:
        lines.append("- `%s`: %s" % (b["id"], b["detail"]))
    lines += ["", "## Not established", ""]
    for n in doc["not_established"]:
        lines.append("- %s" % n)
    lines.append("")
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_runtime_capture_plan.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_runtime_capture_plan_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--install", required=True, help="user-supplied PoR install folder (read-only)")
    ap.add_argument("--dosbox", default=os.environ.get(EMULATOR_ENV),
                    help="path to dosbox-x.exe (default: $%s)" % EMULATOR_ENV)
    ap.add_argument("-o", "--out", required=True, help="output folder (not inside the install)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="plan against files that do not match the pins (marked not retail evidence)")
    args = ap.parse_args(argv)
    try:
        install = Path(args.install)
        if not install.is_dir():
            raise PorSourceError("install folder not found")
        out = validate_output_dir(install, Path(args.out))
        dosbox = Path(args.dosbox) if args.dosbox else None
        doc, code = plan(install, dosbox, args.allow_unpinned)
    except PorSourceError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, out)
    print("wrote %s (runtime performed: %s, blockers: %d)"
          % (out, doc["runtime_capture"]["performed"], len(doc["blockers"])))
    return code


if __name__ == "__main__":
    sys.exit(main())
