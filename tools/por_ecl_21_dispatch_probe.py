#!/usr/bin/env python3
"""Pool of Radiance: ECL opcode 0x21 dispatch probe (STATIC, DIAGNOSTIC ONLY).

STATUS: static-probe-only. ``playable: false``. No events, no mappings, no module output.

Question. The live stream loop at ``GAME.OVR:0x3EB7`` hands each ECL key to the dispatcher at
``0x3C73``. Does the ``0x21`` arm reach stub 6 (START file ``0x3E0C``), whose procedure is the WALLDEF
wrapper at ``GAME.OVR:0x2F6FF`` (directly, or through a VROOMM stub), or does it supply archive/block
arguments to that wrapper? The wrapper builds ``WALLDEF<d>.dax``, not a GEO file; the GEO fill at
``GAME.OVR:0x2F9BE`` is a different procedure and is not tested here. Only PoR bytes are used. The opcode name, the CoK LOAD_FILES semantics and every GoldBox opcode map are NOT read and
supply no meaning here.

Method (read-only, bounded; no emulator, no runtime):

* Dispatch arm. ``por_loadpieces_handler.dispatch_cases`` reads the dispatcher's ``cmp al,imm8``
  chain. The ``0x21`` arm is cross-checked by ``por_ecl_handler_cursor_probe.dispatch_edge``, an
  independent branch recomputation from the raw bytes. The control opcode ``0x37`` is reported for
  comparison; both must name the same handler.
* Loop. ``por_ecl_handler_cursor_probe.loop_report`` checks the ``0x3EB7`` loop's key store and its
  ``push cs; call near 0x3C73`` dispatch. A raw ``E8`` scan lists every near call into ``0x3EB7``,
  labelled ``byte-pattern`` (not decoded, not reachability).
* Handler. ``por_loadpieces_handler.walk`` is a recursive-descent walk of the handler. Its near
  calls, indirect calls and far calls are reported as decoded. Each far call's nearest decoded
  instructions by address are listed for inspection only. They are NOT a push-chain: the decoder's
  text drops some ModRM operands, and the list crosses jumps. No argument conclusion is drawn from them.
* Far calls. ``por_farcall_resolve.resolve`` classifies each ``9A seg:off`` against the VROOMM
  stub groups. This probe also computes its own zero-skew stub image address for stub 6
  (``stub_start + 5*index``) and tests every far call against it.

Evidence labels. ``decoded`` = an instruction from a walk. ``byte-pattern`` = a raw-byte match only.
``model-dependent`` = the far call's seg word is in the fixup table, so its load-time value is not in
the file; under the zero-skew model it is tested, and the result is not a fact about the runtime.

Verdict scope. ``stub6_call_status`` is one of ``not-established`` (the default: the zero-skew model
does not reach stub 6, and the remaining far calls are model-dependent), ``candidate-edge`` (a far call
lands on stub 6 under zero-skew, not yet a runtime fact), or ``arm-absent``. This probe never
returns ``established``.

Falsifiers (checked on synthetic and retail-mutated copies in the test suite): a moved compare value
(arm absent); a dispatch ``E8`` target changed (direct edge check fails); a far call retargeted to
stub 6 (candidate-edge must flip); a stub 6 proc changed (candidate must disappear).

Usage::

    python tools/por_ecl_21_dispatch_probe.py --install "PATH/TO/POOLRAD" \\
        -o data/work/por-ecl-21-dispatch-probe

Stdlib + the read-only modules above. Exit: 0 every self-check passes; 1 a self-check failed;
2 a named refusal (missing or unpinned file, output inside the install, output outside data/work/).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"

sys.path.insert(0, str(TOOLS_DIR))
import por_loadpieces_handler as h  # noqa: E402  (read-only decoder; not edited)
import por_farcall_resolve as fr  # noqa: E402  (read-only stub resolver; not edited)
import por_ecl_handler_cursor_probe as hc  # noqa: E402  (read-only; not edited)

SCHEMA = "openua.por-ecl-21-dispatch-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_ecl_21_dispatch_probe.py"
RESULT_JSON = "por_ecl_21_dispatch_probe.json"
RESULT_MD = "por_ecl_21_dispatch_probe.md"

OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"
PINS = {
    "GAME.OVR": (206105, "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"),
    "START.EXE": (65231, "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"),
}

OPCODE = 0x21                 # the arm under study (cmp al,0x21 at GAME.OVR:0x3D9A)
CONTROL_OPCODE = 0x37         # shares the handler; reported as a control only
LOOP_ENTRY = 0x3EB7           # the stream loop
DISPATCH_ENTRY = 0x3C73       # the dispatcher
WALLDEF_BODY = 0x2F6FF            # proc of stub 6: the WALLDEF wrapper (the file offset the question names)
WALLDEF_BODY_PRO = b"\x55\x89\xe5"
EXPECT_HANDLER = 0x19BA       # both 0x21 and 0x37 reach this near target (checked, not trusted)
EXPECT_FAR_CALLS = 11
EXPECT_LOOP_CALLERS = 9       # the raw E8 scan of 0x3EB7 (byte-pattern; checked, not trusted)
STUB_STEP = 5                 # VROOMM stub length: CD 3F <proc word> 00
PRECEDING = 4                 # decoded instructions kept before each far call


class ProbeRefusal(Exception):
    """A named refusal: the probe stops before it reads or writes anything it should not."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%04X" % v


def _dumps(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n"


# ---------------------------------------------------------------------------------------------
# Inputs (pinned, read-only)
# ---------------------------------------------------------------------------------------------

def load_inputs(install: Path) -> dict:
    """Read the two pinned files. A missing file or a mismatched pin is a refusal."""
    out = {}
    for name, (size, sha) in PINS.items():
        p = install / name
        if not p.is_file():
            raise ProbeRefusal("%s not found in the install folder" % name)
        data = p.read_bytes()
        if len(data) != size or _sha(data) != sha:
            raise ProbeRefusal("%s does not match its pin (size %d, expected %d)" % (name, len(data), size))
        out[name] = data
    return out


def _input_hashes(install: Path) -> dict:
    return {name: _sha((install / name).read_bytes()) for name in PINS}


# ---------------------------------------------------------------------------------------------
# Dispatch arm (decoded) and the loop that feeds it
# ---------------------------------------------------------------------------------------------

def dispatch_arm(ovr: bytes, opcode: int) -> dict:
    """The arm for one opcode: the case table entry, plus the independent branch recomputation."""
    doc = h.dispatch_cases(ovr)
    case = next((c for c in doc["cases"] if c["case"] == opcode), None)
    if case is None:
        return {"opcode": _hex(opcode), "present": False, "evidence": "decoded"}
    edge = hc.dispatch_edge(ovr, opcode)
    rec = {
        "opcode": _hex(opcode),
        "present": True,
        "evidence": "decoded",
        "form": case["form"],
        "compare_at": _hex(edge.get("compare_at")),
        "jump_at": _hex(edge.get("jump_at")),
        "push_cs_at": _hex(edge.get("push_cs_at")),
        "call_at": _hex(edge.get("call_at")),
        "handler": _hex(edge.get("handler")),
        "group_members": edge.get("group_members", []),
        "cross_check_status": edge.get("status"),
        "cross_check_consistent": bool(edge.get("consistent")),
    }
    ca = edge.get("call_at")
    if ca is not None and 0 <= ca < len(ovr):
        rec["call_opcode_byte"] = "%02X" % ovr[ca]
        rec["direct_e8_edge"] = ovr[ca] == 0xE8 and edge.get("call_target_raw") == edge.get("handler")
    else:
        rec["direct_e8_edge"] = False
    return rec


def loop_report(ovr: bytes) -> dict:
    """The 0x3EB7 loop (decoded walk, via the handler-cursor probe) and its raw E8 callers."""
    lr = hc.loop_report(ovr, LOOP_ENTRY, DISPATCH_ENTRY)
    callers = []
    for i in range(len(ovr) - 4):
        if ovr[i] == 0xE8:
            tgt = i + 3 + int.from_bytes(ovr[i + 1:i + 3], "little", signed=True)
            if tgt == LOOP_ENTRY:
                callers.append({"at": _hex(i), "evidence": "byte-pattern"})
    return {
        "entry": _hex(LOOP_ENTRY),
        "walk_complete": lr.get("walk_complete"),
        "sequence_found": lr.get("sequence_found"),
        "key_store_at": _hex(lr.get("key_store_at")),
        "dispatch_call_at": _hex(lr.get("dispatch_call_at")),
        "dispatch_call_target": _hex(lr.get("dispatch_call_target")),
        "dispatch_call_target_matches": lr.get("dispatch_call_target_matches"),
        "key_store_immediately_before_call": lr.get("key_store_immediately_before_call"),
        "loop_advances_cursor": lr.get("loop_advances_cursor"),
        "near_calls": [{"at": _hex(c["at"]), "target": _hex(c["target"])} for c in lr.get("near_calls", [])],
        "far_calls": lr.get("far_calls", []),
        "raw_e8_callers_of_loop": callers,
        "raw_e8_caller_count": len(callers),
        "reachability": "not-established: callers are byte-pattern only; no root traced",
    }


# ---------------------------------------------------------------------------------------------
# Handler walk (decoded) and far-call arguments
# ---------------------------------------------------------------------------------------------

def handler_report(ovr: bytes, entry: int) -> dict:
    w = h.walk(ovr, entry)
    items = sorted(w["listing"], key=lambda i: i["at"])
    far = []
    for c in w["far_calls"]:
        before = [i for i in items if c["at"] - 12 <= i["at"] < c["at"]][-PRECEDING:]
        far.append({
            "at": _hex(c["at"]),
            "seg": c["seg"],
            "off": c["off"],
            "text": next((i["text"] for i in items if i["at"] == c["at"]), None),
            "nearest_decoded_before": [{"at": _hex(i["at"]), "text": i["text"]} for i in before],
            "evidence": "decoded",
        })
    return {
        "entry": _hex(entry),
        "instruction_count": w["instruction_count"],
        "walk_complete": w["complete"],
        "incomplete": w["incomplete"],
        "near_calls": [{"at": _hex(c["at"]), "target": _hex(c.get("target"))} for c in w["near_calls"]],
        "indirect": w["indirect"],
        "returns": [{"at": _hex(r["at"]), "kind": r["kind"]} for r in w["returns"]],
        "far_calls": far,
    }


# ---------------------------------------------------------------------------------------------
# Far-call classification (VROOMM stubs under the zero-skew model) and the stub-6 entry test
# ---------------------------------------------------------------------------------------------

def _all_groups(scan: dict) -> list:
    return list(scan["groups"]) + list(scan["partial_groups"])


def stub6_candidates(start: bytes, ovr: bytes, target: int) -> list:
    """Every stub (well-formed or partial, valid or not) whose proc is ``target``, per group."""
    scan = fr.scan_all(start, ovr)
    rows = []
    for g in _all_groups(scan):
        fo, cs = g["fileofs"], g["codesz"]
        if not (fo <= target < fo + cs):
            continue
        rel = target - fo
        for k, proc in enumerate(g["procs"]):
            if proc == rel:
                rows.append({
                    "group_header": _hex(g["header_offset"]),
                    "group_fileofs": _hex(fo),
                    "group_status": g["status"],
                    "stub_index": k,
                    "stub_valid": bool(g["stub_valid"][k]),
                    "proc_off": proc,
                    "stub_image_f": g["stub_start"] + STUB_STEP * k,
                    "target_prologue": ovr[target:target + 3] == WALLDEF_BODY_PRO,
                })
    return rows


def far_classification(start: bytes, ovr: bytes, far: list) -> dict:
    """Classify each far call (zero-skew) and test it against the stub-6 candidates."""
    hdr = fr.mz_image_base(start)
    res = fr.resolve(start, ovr, [{"at": c["at"], "seg": c["seg"], "off": c["off"]} for c in far])
    rows_by_at = {r["at"]: r for r in res["far_calls"]}
    cands = stub6_candidates(start, ovr, WALLDEF_BODY)
    cand_images = {(c["stub_image_f"]): c for c in cands if c["stub_valid"]}
    rows = []
    for c in far:
        r = rows_by_at[c["at"]]
        stub = r.get("stub")
        image_f = hdr + c["seg"] * 16 + c["off"]
        if stub is not None:
            model = "zero-skew-stub"
        else:
            model = "model-dependent"
        stub6_hit = cand_images.get(image_f)
        rows.append({
            "at": _hex(c["at"]),
            "seg": c["seg"],
            "off": c["off"],
            "zero_skew_image_f": image_f,
            "classification": r["classification"],
            "model": model,
            "seg_word_in_fixup_table": bool(r.get("seg_word_in_fixup_table")),
            "off_word_in_fixup_table": bool(r.get("off_word_in_fixup_table")),
            "stub": None if stub is None else {
                "group_header": _hex(stub["group_header_offset"]),
                "group_fileofs": _hex(stub["group_fileofs"]),
                "group_status": stub["group_status"],
                "index": stub["index"],
                "proc_off": stub["proc_off"],
                "gameovr_target": _hex(stub["gameovr_target"]),
            },
            "stub6_edge_zero_skew": None if stub6_hit is None else {
                "group_header": stub6_hit["group_header"],
                "stub_index": stub6_hit["stub_index"],
            },
        })
    return {"rows": rows, "stub6_candidates": cands}


def stub6_status(far_rows: list, cands: list) -> dict:
    hits = [r for r in far_rows if r["stub6_edge_zero_skew"] is not None]
    model_dep = [r for r in far_rows if r["model"] == "model-dependent"]
    if hits:
        status = "candidate-edge"
    else:
        status = "not-established"
    return {
        "stub6_call_status": status,
        "walldef_body": _hex(WALLDEF_BODY),
        "stub6_candidates": cands,
        "zero_skew_edges_to_stub6": [{"at": r["at"], **r["stub6_edge_zero_skew"]} for r in hits],
        "model_dependent_far_calls": [r["at"] for r in model_dep],
        "reason": (
            "a far call lands on stub 6 (the WALLDEF wrapper entry) under the zero-skew image model; not a runtime fact"
            if hits else
            "no far call lands on stub 6 under the zero-skew image model; %d far call(s) are "
            "model-dependent (seg word in fixup table, load-time segment not in the file)" % len(model_dep)
        ),
    }


# ---------------------------------------------------------------------------------------------
# Pure analysis (bytes in, dict out) and the probe driver
# ---------------------------------------------------------------------------------------------

def analyse(ovr: bytes, start: bytes, opcode: int = OPCODE) -> dict:
    arm = dispatch_arm(ovr, opcode)
    control = dispatch_arm(ovr, CONTROL_OPCODE)
    loop = loop_report(ovr)
    if not arm.get("present"):
        return {"arm": arm, "control": control, "loop": loop, "handler": None,
                "far": None, "stub6": {"stub6_call_status": "arm-absent"}}
    hr = handler_report(ovr, int(arm["handler"], 16))
    far = [{"at": int(c["at"], 16), "seg": c["seg"], "off": c["off"]} for c in hr["far_calls"]]
    far_doc = far_classification(start, ovr, far)
    s6 = stub6_status(far_doc["rows"], far_doc["stub6_candidates"])
    return {"arm": arm, "control": control, "loop": loop, "handler": hr,
            "far": far_doc, "stub6": s6}


def self_checks(doc: dict, hashes_before: dict, hashes_after: dict) -> list:
    arm = doc["arm"]
    ctl = doc["control"]
    loop = doc["loop"]
    hr = doc["handler"] or {}
    far_rows = (doc["far"] or {}).get("rows", [])
    checks = [
        ("inputs_unchanged", hashes_before == hashes_after),
        ("arm_present", bool(arm.get("present"))),
        ("arm_handler_is_expected", arm.get("handler") == _hex(EXPECT_HANDLER)),
        ("arm_cross_check_consistent", arm.get("cross_check_consistent") is True),
        ("arm_direct_e8_edge", arm.get("direct_e8_edge") is True),
        ("control_0x37_same_handler", ctl.get("handler") == arm.get("handler")),
        ("loop_sequence_found", loop.get("sequence_found") is True),
        ("loop_dispatch_target_is_dispatcher", loop.get("dispatch_call_target") == _hex(DISPATCH_ENTRY)),
        ("loop_advances_cursor_false", loop.get("loop_advances_cursor") is False),
        ("loop_raw_callers_expected", loop.get("raw_e8_caller_count") == EXPECT_LOOP_CALLERS),
        ("handler_walk_complete", hr.get("walk_complete") is True),
        ("handler_no_near_calls", hr.get("near_calls") == []),
        ("handler_no_indirect_calls", hr.get("indirect") == []),
        ("handler_far_call_count", len(hr.get("far_calls", [])) == EXPECT_FAR_CALLS),
        ("handler_far_calls_at_stub_group_0x74D3",
         sum(1 for r in far_rows if r["stub"] and r["stub"]["group_fileofs"] == "0x74D3") == 2),
        ("walldef_body_has_valid_stub_with_prologue",
         any(c["stub_valid"] and c["target_prologue"]
             for c in ((doc.get("far") or {}).get("stub6_candidates") or []))),
    ]
    return [{"name": n, "ok": bool(ok)} for n, ok in checks]


def probe(install: Path, out: Path) -> tuple:
    inputs = load_inputs(install)
    ovr = inputs[OVR_NAME]
    start = inputs[EXE_NAME]
    before = _input_hashes(install)
    doc = analyse(ovr, start, OPCODE)
    after = _input_hashes(install)
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS, "tool": TOOL,
        "playable": False, "question": "does the 0x21 arm reach stub 6 (proc 0x2F6FF, the WALLDEF wrapper)?",
        "inputs": {n: {"size": len(inputs[n]), "sha256": _sha(inputs[n])} for n in PINS},
        "opcode": _hex(OPCODE), "control_opcode": _hex(CONTROL_OPCODE), "walldef_body": _hex(WALLDEF_BODY),
        **doc,
    }
    doc["self_checks"] = self_checks(doc, before, after)
    doc["exit_ok"] = all(c["ok"] for c in doc["self_checks"])
    return doc, (0 if doc["exit_ok"] else 1)


def _check_out(out: Path, install: Path) -> None:
    out_r = out.resolve()
    inst_r = install.resolve()
    if out_r == inst_r or inst_r in out_r.parents:
        raise ProbeRefusal("output folder is inside the install folder")
    try:
        out_r.relative_to(DATA_WORK.resolve())
    except ValueError:
        raise ProbeRefusal("output folder must be under data/work/")


def render_md(doc: dict) -> str:
    arm = doc["arm"]
    lines = [
        "# Pool of Radiance: ECL opcode 0x21 dispatch probe (static)",
        "",
        "**Status: STATIC-PROBE-ONLY. `playable: false`.** Question: does the `0x21` arm reach stub 6 "
        "(proc `0x2F6FF`, the WALLDEF wrapper)? Answer: **%s**." % doc["stub6"]["stub6_call_status"],
        "",
        "## Dispatch arm",
        "",
        "- present: %s; form `%s`; compare `%s`; push cs `%s`; call `%s` -> handler `%s`" % (
            arm.get("present"), arm.get("form"), arm.get("compare_at"), arm.get("push_cs_at"),
            arm.get("call_at"), arm.get("handler")),
        "- direct `E8` edge (decoded): %s; cross-check `%s`" % (arm.get("direct_e8_edge"), arm.get("cross_check_status")),
        "- control `0x37` handler: `%s` (same handler: %s)" % (
            doc["control"].get("handler"), doc["control"].get("handler") == arm.get("handler")),
        "",
        "## Loop at 0x3EB7 (decoded walk)",
        "",
        "- sequence found: %s; key store `%s`; dispatch call `%s` -> `%s`" % (
            doc["loop"]["sequence_found"], doc["loop"]["key_store_at"], doc["loop"]["dispatch_call_at"],
            doc["loop"]["dispatch_call_target"]),
        "- raw `E8` callers of `0x3EB7` (byte-pattern): %d. Reachability: %s" % (
            doc["loop"]["raw_e8_caller_count"], doc["loop"]["reachability"]),
        "",
    ]
    if doc["handler"]:
        hr = doc["handler"]
        lines += [
            "## Handler (decoded walk)",
            "",
            "- entry `%s`; %d instructions; complete %s; near calls %d; indirect %d; far calls %d" % (
                hr["entry"], hr["instruction_count"], hr["walk_complete"], len(hr["near_calls"]),
                len(hr["indirect"]), len(hr["far_calls"])),
            "",
            "| Call | seg:off | Zero-skew image | Classification | Model | Stub (group, index, target) |",
            "| --- | --- | ---: | --- | --- | --- |",
        ]
        for r in doc["far"]["rows"]:
            st = r["stub"]
            sdesc = "-" if st is None else "%s, %d, %s" % (st["group_fileofs"], st["index"], st["gameovr_target"])
            lines.append("| %s | %02X:%02X | %d | %s | %s | %s |" % (
                r["at"], r["seg"], r["off"], r["zero_skew_image_f"], r["classification"], r["model"], sdesc))
        lines.append("")
    lines += ["## Stub 6 entry (proc `0x2F6FF`, WALLDEF wrapper)", "", doc["stub6"]["reason"], ""]
    for c in doc["stub6"].get("stub6_candidates", []):
        lines.append("- stub candidate: group `%s` (%s, %s), index %d, valid %s, zero-skew image %d" % (
            c["group_header"], c["group_fileofs"], c["group_status"], c["stub_index"], c["stub_valid"],
            c["stub_image_f"]))
    lines += ["", "## Self-checks", ""]
    for c in doc["self_checks"]:
        lines.append("- %s: %s" % (c["name"], "pass" if c["ok"] else "FAIL"))
    lines += ["", "## Runtime limits", "",
              "- The seg word of each model-dependent far call is in the fixup table; its load-time value is not in the file.",
              "- Only GAME.OVR and START.EXE are read. No overlay other than GAME.OVR is scanned.",
              "- No runtime capture was used. No emulator, GameLink, codewheel or GoldBox input.", ""]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(_dumps(doc), encoding="utf-8")
    (out / RESULT_MD).write_text(render_md(doc), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="PoR ECL opcode 0x21 dispatch probe (static)")
    ap.add_argument("--install", required=True, help="PoR install folder (POOLRAD)")
    ap.add_argument("-o", "--out", required=True, help="output folder (under data/work/)")
    args = ap.parse_args(argv)
    install = Path(args.install)
    out = Path(args.out)
    try:
        _check_out(out, install)
        doc, code = probe(install, out)
    except ProbeRefusal as e:
        print("refused: %s" % e, file=sys.stderr)
        return 2
    write_outputs(doc, out)
    print("stub6_call_status=%s self_checks=%s" % (
        doc["stub6"]["stub6_call_status"], "pass" if code == 0 else "FAIL"))
    return code


if __name__ == "__main__":
    sys.exit(main())
