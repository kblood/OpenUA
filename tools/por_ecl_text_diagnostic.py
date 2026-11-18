#!/usr/bin/env python3
"""Pool of Radiance 0x80 payloads: diagnostic 6-bit decode of the string census.

Status: DIAGNOSTIC-UNACCEPTED. Read-only input, stdlib-only, ``playable: false``.
Every output is marked ``accepted: false``. Nothing here makes a string Pool of
Radiance text on screen; it only shows what the PoR-retail-verified codec
(docs/por-ecl-codec-static-probe.md) yields for each census payload.

Input: the string-census JSON written by tools/por_ecl_strings.py
(schema ``openua.por-ecl-strings``, version 1). The census is read, never written.

Codec (the PoR retail bytes, GAME.OVR:0x8626 and 0x7BA6):
  * the payload is split MSB-first into 6-bit groups; floor(8*n/6) values; the
    leftover 1 to 4 bits at the end are dropped;
  * a value of 0 is SKIPPED, and decoding continues. It is never a terminator
    (GoldBox's stop-at-zero reading is not used on this path);
  * value 1..31 maps to value+0x40, value 32..63 maps to itself.

What this does NOT establish (carried into every output as ``unresolved``):
  * that any decoded text is shown on a PoR screen or bound to a runtime message.
  * for frames labelled by the census as spec-menus framing: the framing itself
    is a census result, not proof.
The byte count is no longer unresolved in this tool: the retail 0x80 arm passes
the census ``declared_length`` (the operand's high byte) to the unpacker, by
static code reading of GAME.OVR:0x07526 and 0x07577 (docs/por-ecl-length-xref.md).
Caller reachability at run time is not shown, and that is listed in NOT_CLAIMED.

Usage
  python3 tools/por_ecl_text_diagnostic.py \\
      --census data/work/por-ecl-strings/retail/por_ecl_strings.json \\
      -o data/work/por-ecl-text-diagnostic

Outputs (deterministic: sorted keys, stable frame order, no timestamps, no
absolute paths; the source census is recorded by file name and SHA-256 only):
  por_ecl_text_diagnostic.json          schema openua.por-ecl-text-diagnostic
  por_ecl_text_diagnostic_report.md     human-readable summary of the same

Exit codes: 0 outputs written; 2 named refusal (bad census, unsafe output).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

SCHEMA = "openua.por-ecl-text-diagnostic"
SCHEMA_VERSION = 1
STATUS = "diagnostic-unaccepted"
TOOL = "tools/por_ecl_text_diagnostic.py"
CENSUS_SCHEMA = "openua.por-ecl-strings"
CENSUS_VERSION = 1
CENSUS_STATUS = "census-only"
CENSUS_FRAMINGS = ("conservative", "spec-menus")
FS_BEFORE_MENU = "before-first-menu"
FS_SPEC_MENU = "spec-menu-frame"
FS_AFTER_SPEC_MENU = "after-spec-menu"
CENSUS_FRAMING_STATUSES = (FS_BEFORE_MENU, FS_SPEC_MENU, FS_AFTER_SPEC_MENU)
SPECULATIVE_STATUSES = (FS_SPEC_MENU, FS_AFTER_SPEC_MENU)
OUT_JSON = "por_ecl_text_diagnostic.json"
OUT_MD = "por_ecl_text_diagnostic_report.md"

CODEC_NAME = "pool-of-radiance-0x80-6bit"
CODEC_CLAIM = {
    "name": CODEC_NAME,
    "layout": "MSB-first 6-bit groups of the packed payload; floor(8*n/6) values; "
              "the leftover 1 to 4 bits at the end are dropped",
    "zero_handling": "value 0 is skipped and decoding continues; it is never a terminator",
    "char_map": "value 1..31 -> value+0x40; value 32..63 -> itself",
    "evidence": "docs/por-ecl-codec-static-probe.md: GAME.OVR:0x8626 and 0x7BA6, "
                "statically checked and executed on synthetic payloads",
}

REQ_FRAME_KEYS = (
    "archive", "block_id", "declared_length", "frame_id", "framing", "framing_status",
    "instruction_offset", "mnemonic", "opcode", "operand_offset", "payload_base64",
    "payload_hex", "payload_length", "payload_sha256", "toc_index",
)

UNRESOLVED = {
    "runtime-text-binding": (
        "no runtime text binding: nothing shows that a decoded string appears on a "
        "PoR screen or maps to a message; no matched on-screen run exists"),
    "census-framing-speculative": (
        "the census spec-menus framing is a census result, not proof; frames at or "
        "after the spec menu are flagged"),
}

NOT_CLAIMED = [
    "no decoded string is accepted, verified, or shown as Pool of Radiance text",
    "no string is mapped to a message, event, or STRG resource",
    "the 0x80 count is read from retail code (GAME.OVR:0x07526, 0x07577); that the ECL "
    "walk reaches that parser at run time (its caller is a far call) is not shown",
    "a zero value is skipped by the retail code; it is not treated as a terminator",
    "no playable module, conversion, or route is produced",
]


class DiagnosticError(PorSourceError):
    """A named refusal: bad census input or unsafe output location."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Pure codec (stdlib only; cross-checked by the tests)
# --------------------------------------------------------------------------

def char_of(value: int) -> int:
    """Retail char map: 1..31 -> value+0x40, 32..63 -> value."""
    if not 1 <= value <= 63:
        raise ValueError("char_of is defined for nonzero 6-bit values only")
    return value + 0x40 if value <= 0x1F else value


def decode_payload(payload: bytes) -> dict:
    """Decode one payload with the PoR codec. Pure and deterministic."""
    acc = 0
    nbits = 0
    values: list[int] = []
    for byte in payload:
        acc = (acc << 8) | byte
        nbits += 8
        while nbits >= 6:
            nbits -= 6
            values.append((acc >> nbits) & 0x3F)
        acc &= (1 << nbits) - 1
    nonzero = [v for v in values if v != 0]
    seen_zero = False
    zero_then_nonzero = False
    for v in values:
        if v == 0:
            seen_zero = True
        elif seen_zero:
            zero_then_nonzero = True
            break
    codes = [char_of(v) for v in nonzero]
    for c in codes:
        if not 0x20 <= c <= 0x5F:
            raise ValueError("internal: char code outside 0x20..0x5F")
    return {
        "values_total": len(values),
        "dropped_tail_bits": nbits,
        "zero_values_skipped": len(values) - len(nonzero),
        "zero_then_nonzero": zero_then_nonzero,
        "values": nonzero,
        "char_codes": codes,
        "text": "".join(chr(c) for c in codes),
    }


# --------------------------------------------------------------------------
# Census input (validated; any mismatch is a refusal)
# --------------------------------------------------------------------------

def _refuse(msg: str) -> None:
    raise DiagnosticError(msg)


def load_census(path: Path) -> tuple[dict, bytes]:
    if not path.is_file():
        _refuse("census file not found")
    raw = path.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _refuse("census is not valid UTF-8 JSON")
    if not isinstance(doc, dict):
        _refuse("census top level is not an object")
    if doc.get("schema") != CENSUS_SCHEMA or doc.get("version") != CENSUS_VERSION:
        _refuse("census schema is not %s version %d" % (CENSUS_SCHEMA, CENSUS_VERSION))
    if doc.get("status") != CENSUS_STATUS or doc.get("playable") is not False:
        _refuse("census is not census-only with playable false")
    if not isinstance(doc.get("string_frames"), list):
        _refuse("census has no string_frames list")
    return doc, raw


def _frame_payload(fr: dict, index: int) -> bytes:
    where = "census string_frames[%d]" % index
    for key in REQ_FRAME_KEYS:
        if key not in fr:
            _refuse("%s is missing %s" % (where, key))
    if fr["framing"] not in CENSUS_FRAMINGS:
        _refuse("%s has an unknown framing" % where)
    if fr["framing_status"] not in CENSUS_FRAMING_STATUSES:
        _refuse("%s has an unknown framing_status" % where)
    try:
        payload = bytes.fromhex(fr["payload_hex"])
        b64 = base64.b64decode(fr["payload_base64"], validate=True)
    except (ValueError, TypeError, binascii.Error):
        _refuse("%s has an undecodable payload" % where)
    n = fr["payload_length"]
    if not (len(payload) == n == fr["declared_length"]):
        _refuse("%s payload length disagrees with its declared length" % where)
    if b64 != payload:
        _refuse("%s payload_base64 disagrees with payload_hex" % where)
    if _sha(payload) != fr["payload_sha256"]:
        _refuse("%s payload_sha256 does not match its payload" % where)
    return payload


# --------------------------------------------------------------------------
# Diagnostic records
# --------------------------------------------------------------------------

def _unresolved_for(fr: dict) -> list[str]:
    codes = ["runtime-text-binding"]
    if fr["framing_status"] in SPECULATIVE_STATUSES:
        codes.append("census-framing-speculative")
    return codes


def build_frame(fr: dict, payload: bytes) -> dict:
    d = decode_payload(payload)
    return {
        "frame_id": fr["frame_id"],
        "archive": fr["archive"],
        "toc_index": fr["toc_index"],
        "block_id": fr["block_id"],
        "framing": fr["framing"],
        "framing_status": fr["framing_status"],
        "operand_offset": fr["operand_offset"],
        "instruction_offset": fr["instruction_offset"],
        "mnemonic": fr["mnemonic"],
        "opcode": fr["opcode"],
        "declared_length": fr["declared_length"],
        "payload_length": len(payload),
        "payload_sha256": fr["payload_sha256"],
        "values_total": d["values_total"],
        "dropped_tail_bits": d["dropped_tail_bits"],
        "zero_values_skipped": d["zero_values_skipped"],
        "zero_then_nonzero": d["zero_then_nonzero"],
        "values": d["values"],
        "char_codes": d["char_codes"],
        "text": d["text"],
        "accepted": False,
        "status": STATUS,
        "unresolved": _unresolved_for(fr),
    }


def _empty_group() -> dict:
    return {"frames": 0, "zero_length_frames": 0, "frames_with_dropped_tail": 0,
            "chars_decoded": 0, "frames_with_zero_skips": 0,
            "frames_zero_then_nonzero": 0}


def summarize(frames: list[dict]) -> dict:
    by_framing: dict[str, dict] = {}
    by_status: dict[str, int] = {}
    for f in frames:
        g = by_framing.setdefault(f["framing"], _empty_group())
        g["frames"] += 1
        g["zero_length_frames"] += int(f["payload_length"] == 0)
        g["frames_with_dropped_tail"] += int(f["dropped_tail_bits"] > 0)
        g["chars_decoded"] += len(f["char_codes"])
        g["frames_with_zero_skips"] += int(f["zero_values_skipped"] > 0)
        g["frames_zero_then_nonzero"] += int(f["zero_then_nonzero"])
        by_status[f["framing_status"]] = by_status.get(f["framing_status"], 0) + 1
    return {
        "frames_total": len(frames),
        "distinct_payload_sha256": len({f["payload_sha256"] for f in frames}),
        "chars_decoded_total": sum(len(f["char_codes"]) for f in frames),
        "zero_values_skipped_total": sum(f["zero_values_skipped"] for f in frames),
        "by_framing": by_framing,
        "by_framing_status": by_status,
    }


def unresolved_summary() -> list[dict]:
    scope = {
        "runtime-text-binding": "every frame",
        "census-framing-speculative": "frames with spec-menu-frame or after-spec-menu status",
    }
    return [{"code": k, "message": v, "scope": scope[k]} for k, v in UNRESOLVED.items()]


def diagnose(census_path: Path) -> dict:
    doc, raw = load_census(census_path)
    seen: set[str] = set()
    frames: list[dict] = []
    for i, fr in enumerate(doc["string_frames"]):
        if not isinstance(fr, dict):
            _refuse("census string_frames[%d] is not an object" % i)
        payload = _frame_payload(fr, i)
        if fr["frame_id"] in seen:
            _refuse("census repeats frame_id %r" % fr["frame_id"])
        seen.add(fr["frame_id"])
        frames.append(build_frame(fr, payload))
    frames.sort(key=lambda f: (f["framing"], f["archive"], f["toc_index"],
                               f["operand_offset"], f["frame_id"]))
    return {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "status": STATUS,
        "playable": False,
        "tool": TOOL,
        "source_census": {
            "file": census_path.name,
            "sha256": _sha(raw),
            "schema": CENSUS_SCHEMA,
            "version": CENSUS_VERSION,
            "status": CENSUS_STATUS,
            "string_frames": len(doc["string_frames"]),
        },
        "codec": CODEC_CLAIM,
        "summary": summarize(frames),
        "unresolved": unresolved_summary(),
        "not_claimed": list(NOT_CLAIMED),
        "frames": frames,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _md_cell(text: str) -> str:
    return text.replace("|", "\\|") if text else "(empty)"


def render_report(doc: dict) -> str:
    s = doc["summary"]
    src = doc["source_census"]
    lines = [
        "# Pool of Radiance 0x80 payloads: diagnostic 6-bit decode",
        "",
        "**Status: diagnostic-unaccepted. `playable: false`.** Read-only. "
        "Every frame is `accepted: false`. Nothing here is verified text.",
        "",
        "## Source",
        "",
        "- census file `%s`, sha256 `%s`" % (src["file"], src["sha256"]),
        "- census schema `%s` v%d, status `%s`, %d string frames"
        % (src["schema"], src["version"], src["status"], src["string_frames"]),
        "",
        "## Codec",
        "",
        "- layout: %s" % doc["codec"]["layout"],
        "- zero handling: %s" % doc["codec"]["zero_handling"],
        "- char map: %s" % doc["codec"]["char_map"],
        "- evidence: %s" % doc["codec"]["evidence"],
        "",
        "## Summary",
        "",
        "- frames: %d, distinct payloads: %d" % (s["frames_total"], s["distinct_payload_sha256"]),
        "- characters decoded: %d, zero values skipped: %d"
        % (s["chars_decoded_total"], s["zero_values_skipped_total"]),
        "",
        "| Framing | Frames | Zero-length | With dropped tail | Chars | Zero-skip frames | Zero-then-nonzero |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in sorted(s["by_framing"]):
        g = s["by_framing"][name]
        lines.append("| %s | %d | %d | %d | %d | %d | %d |" % (
            name, g["frames"], g["zero_length_frames"], g["frames_with_dropped_tail"],
            g["chars_decoded"], g["frames_with_zero_skips"], g["frames_zero_then_nonzero"]))
    lines += ["", "| Framing status | Frames |", "| --- | ---: |"]
    for name in sorted(s["by_framing_status"]):
        lines.append("| %s | %d |" % (name, s["by_framing_status"][name]))
    lines += ["", "## Unresolved", ""]
    for u in doc["unresolved"]:
        lines.append("- `%s` (%s): %s" % (u["code"], u["scope"], u["message"]))
    lines += ["", "## Frames", "",
              "| Frame | Framing | Status | Bytes | Values | Text |",
              "| --- | --- | --- | ---: | ---: | --- |"]
    for f in doc["frames"]:
        lines.append("| %s | %s | %s | %d | %d | `%s` |" % (
            f["frame_id"], f["framing"], f["framing_status"], f["payload_length"],
            len(f["values"]), _md_cell(f["text"])))
    lines += ["", "## Not claimed", ""]
    for item in doc["not_claimed"]:
        lines.append("- " + item)
    lines.append("")
    return "\n".join(lines)


def check_output(census_path: Path, out: Path) -> Path:
    dst = validate_output_dir(census_path.parent, out)
    if dst.exists() and not dst.is_dir():
        _refuse("output path exists and is not a folder")
    if (dst / OUT_JSON).resolve() == census_path.resolve():
        _refuse("output would overwrite the source census")
    return dst


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / OUT_JSON).write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out / OUT_MD).write_text(render_report(doc), encoding="utf-8", newline="\n")


def run(census_path: Path, out: Path) -> dict:
    dst = check_output(census_path, out)
    doc = diagnose(census_path)
    write_outputs(doc, dst)
    return doc


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool of Radiance 0x80 payloads: diagnostic 6-bit decode of the census "
                    "(read-only input; diagnostic, unaccepted output).")
    ap.add_argument("--census", required=True, type=Path,
                    help="por_ecl_strings.json from tools/por_ecl_strings.py (read only)")
    ap.add_argument("-o", "--out", required=True, type=Path,
                    help="output folder (outside the census folder; inside the repo only under data/)")
    args = ap.parse_args(argv)
    try:
        doc = run(args.census, args.out)
    except (DiagnosticError, PorSourceError) as exc:
        print("por_ecl_text_diagnostic: refused: %s" % exc, file=sys.stderr)
        return 2
    print("wrote %s and %s (%s, playable=false; %d frames)"
          % (args.out / OUT_JSON, args.out / OUT_MD, STATUS, doc["summary"]["frames_total"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
