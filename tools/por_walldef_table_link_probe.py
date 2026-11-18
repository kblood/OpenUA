#!/usr/bin/env python3
"""Check the PoR WALLDEF loader-to-table-to-renderer byte path.

Static only: the tool recognizes the partial VROOMM group containing the
WALLDEF Pascal strings, validates the loader and 156-byte consumer instruction
anchors, and reports the unresolved runtime edges. It emits no mapping or art.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as dec  # noqa: E402
from por_convert import PorSourceError, validate_output_dir  # noqa: E402

TOOL = "tools/por_walldef_table_link_probe.py"
SCHEMA = "openua.por-walldef-table-link-probe"
SCHEMA_VERSION = 1
HEADER = 0x3DD7
GROUP_FILE = 0x2E8F7
GROUP_SIZE = 0x120B
GROUP_STUB_DELTA = 0x17
STUB_INDEX = 6
STUB_PROC = 0x0E08
LOADER = GROUP_FILE + STUB_PROC
CONSUMER = 0x2EB08
OWNER = 0x2EEF4
WALLDEF_OFFSET = 0x0DB4
SUFFIX_OFFSET = 0x0DBC
TABLE_SLOT = 0x6A58
RECORD_SIZE = 0x030C
SLICE_SIZE = 0x009C

EXPECTED = {
    "wall_piece": bytes.fromhex("07 57 41 4c 4c 44 45 46"),
    "suffix_piece": bytes.fromhex("04 2e 64 61 78"),
    "wall_ref": bytes.fromhex("bf b4 0d 0e 57 9a 0b 0b f8 0a"),
    "suffix_ref": bytes.fromhex("bf bc 0d 0e 57 9a 0b 0b f8 0a"),
    "selector_read": bytes.fromhex("a0 76 53"),
    "loader_call": bytes.fromhex("9a 16 07 02 08"),
    "record_divisor": bytes.fromhex("b9 0c 03 f7 f1"),
    "copy_destination": bytes.fromhex("c4 3e 58 6a 03 f8 81 c7 f4 fc 06 57 b8 0c 03 50 9a 85 16 f8 0a"),
    "consumer_scale": bytes.fromhex("ba 9c 00 f7 e2 c4 3e 58 6a 03 f8"),
}

LIMITS = [
    "the loader stub's execution and caller are not established",
    "the loader's numeric archive selector and requested block id are not tied to live values",
    "copy direction depends on the separately identified 0x0AF8:0x1685 helper ABI",
    "DS:0x6A58 is not proven at runtime to contain a retail WALLDEF block",
    "the 0x2EEF4 owner has no established caller; its static calls to 0x2EB08 do not prove a render path",
    "no WALLDEF byte is bound to an 8X8D block, tile, OpenUA texture group, or screen",
]


class ProbeError(Exception):
    pass


def _check_bytes(data: bytes, offset: int, expected: bytes, label: str) -> dict:
    actual = data[offset:offset + len(expected)]
    ok = actual == expected
    return {"id": label, "ok": ok, "offset": offset,
            "expected": expected.hex(), "actual": actual.hex()}


def _decode_boundary(data: bytes, offset: int, expected: bytes, label: str) -> dict:
    raw = data[offset:offset + len(expected)]
    if raw != expected:
        return {"id": label, "ok": False, "offset": offset,
                "expected": expected.hex(), "actual": raw.hex(),
                "reason": "bytes-mismatch"}
    try:
        insn = dec.decode(data, offset)
    except dec.DecodeError as exc:
        return {"id": label, "ok": False, "offset": offset,
                "expected": expected.hex(), "actual": raw.hex(),
                "reason": "decode-error:" + exc.reason}
    return {"id": label, "ok": insn.raw == expected[:len(insn.raw)],
            "offset": offset, "first_instruction": insn.raw.hex(),
            "first_instruction_len": len(insn.raw), "expected_prefix": expected.hex()}


def analyze_group(ovr: bytes, group: dict) -> dict:
    """Validate the known group-relative strings and code sites; safe for fixtures."""
    group_ok = (group.get("header_offset") == HEADER
                and group.get("fileofs") == GROUP_FILE
                and group.get("codesz") == GROUP_SIZE
                and group.get("stub_delta") == GROUP_STUB_DELTA
                and group.get("procs", [])[STUB_INDEX] == STUB_PROC
                and group.get("stub_valid", [])[STUB_INDEX] is True)
    if len(ovr) < GROUP_FILE + GROUP_SIZE:
        raise ProbeError("GAME.OVR is too short for the pinned group span")

    checks = []
    for label, offset in (("wall_piece", GROUP_FILE + WALLDEF_OFFSET),
                          ("suffix_piece", GROUP_FILE + SUFFIX_OFFSET)):
        checks.append(_check_bytes(ovr, offset, EXPECTED[label], label))

    sites = {
        "wall_ref": GROUP_FILE + 0x0E3E,
        "suffix_ref": GROUP_FILE + 0x0E58,
        "selector_read": LOADER + 0x16,
        "loader_call": LOADER + 0x68,
        "record_divisor": LOADER + 0x7F,
        "copy_destination": LOADER + 0xEF,
        "consumer_scale": CONSUMER + 0x9E,
    }
    for label, offset in sites.items():
        checks.append(_check_bytes(ovr, offset, EXPECTED[label], label))

    # Verify that each expected multi-instruction site begins on a decoder boundary.
    for label in ("wall_ref", "suffix_ref", "copy_destination", "consumer_scale"):
        checks.append(_decode_boundary(ovr, sites[label], EXPECTED[label], label + "_decode"))

    pointer_sites = {
        "loader": (0x2F7EE, 0x2F8B6, 0x2F8EE),
        "consumer": (0x2EBAB, 0x2EBDC),
    }
    pointer_checks = []
    for role, offsets in pointer_sites.items():
        for index, offset in enumerate(offsets):
            check = _decode_boundary(ovr, offset, bytes.fromhex("c4 3e 58 6a"),
                                     "%s_pointer_read_%d" % (role, index + 1))
            checks.append(check)
            pointer_checks.append((role, check))
    ptr_reads_loader = sum(1 for role, row in pointer_checks if role == "loader" and row["ok"])
    ptr_reads_consumer = sum(1 for role, row in pointer_checks if role == "consumer" and row["ok"])

    # Count the table-pointer loads only on decoded instruction starts in these
    # named procedures; the complete functions are not re-swept here.
    near_calls = []
    walk_error = None
    try:
        import por_wall_callee_probe as cp
        walked = cp.explore(ovr, OWNER, 1200)
        near_calls = [c for c in walked["near_calls"] if c.get("target") == CONSUMER]
    except (ImportError, KeyError, TypeError, dec.DecodeError) as exc:
        walk_error = type(exc).__name__

    checks.extend([
        {"id": "partial_group_and_stub6", "ok": bool(group_ok),
         "header_offset": group.get("header_offset"), "fileofs": group.get("fileofs"),
         "codesz": group.get("codesz"), "status": group.get("status"),
         "stub_index": STUB_INDEX, "proc_offset": group.get("procs", [None] * 7)[STUB_INDEX],
         "stub_valid": group.get("stub_valid", [False] * 7)[STUB_INDEX]},
        {"id": "table_pointer_reads", "ok": ptr_reads_loader == 3 and ptr_reads_consumer == 2,
         "loader_reads": ptr_reads_loader, "consumer_reads": ptr_reads_consumer,
         "slot": TABLE_SLOT},
        {"id": "owner_to_consumer_calls", "ok": len(near_calls) == 18 and walk_error is None,
         "count": len(near_calls), "sites": [c.get("at") for c in near_calls],
         "walk_error": walk_error},
    ])

    all_ok = all(c["ok"] for c in checks)
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL,
        "status": "static-probe-only", "playable": False,
        "mappings": [], "events_emitted": 0,
        "answer": "WALLDEF-name-and-shared-table-path-byte-checked" if all_ok else "diagnostic",
        "group": {"header_offset": HEADER, "fileofs": GROUP_FILE, "codesz": GROUP_SIZE,
                  "status": group.get("status"), "stub_index": STUB_INDEX,
                  "entry_file_offset": LOADER},
        "table_shape": {"far_pointer_slot": TABLE_SLOT,
                        "loaded_record_size": RECORD_SIZE,
                        "consumer_slice_size": SLICE_SIZE,
                        "slices_per_record": RECORD_SIZE // SLICE_SIZE,
                        "division_has_remainder": RECORD_SIZE % SLICE_SIZE != 0,
                        "copy_direction": "conditional-on-helper-0AF8-1685-ABI"},
        "load_path": {"stem_piece": "WALLDEF", "suffix_piece": ".dax",
                      "selector_source_address": 0x5376,
                      "loader_call": {"segment": 0x0802, "offset": 0x0716,
                                      "file_offset": sites["loader_call"]}},
        "consumer": {"entry_file_offset": CONSUMER,
                     "owner_file_offset": OWNER,
                     "owner_near_call_count": len(near_calls),
                     "owner_calls_are_static_not-reachability": True},
        "checks": checks, "checks_passed": sum(bool(c["ok"]) for c in checks),
        "checks_total": len(checks), "limits": list(LIMITS),
    }


def analyze(ovr: bytes, start: bytes) -> dict:
    rows = fr.scan_all(start, ovr)
    matches = [g for g in rows["groups"] + rows["partial_groups"]
               if g.get("header_offset") == HEADER]
    if len(matches) != 1:
        raise ProbeError("expected one parsed group at START descriptor 0x3DD7")
    return analyze_group(ovr, matches[0])


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(install: Path, out: Path) -> tuple[dict, int]:
    members = {}
    for name in (fr.OVR_NAME, fr.EXE_NAME):
        path = install / name
        if not path.is_file():
            raise ProbeError("missing " + name)
        data = path.read_bytes()
        size, digest = fr.PINNED[name]
        if len(data) != size or _sha(data) != digest:
            raise ProbeError("un-pinned " + name)
        members[name] = data
    report = analyze(members[fr.OVR_NAME], members[fr.EXE_NAME])
    report["source_pins"] = {name: {"size": len(data), "sha256": _sha(data), "matched": True}
                             for name, data in sorted(members.items())}
    # Re-read the two files to detect a change during the scan.
    unchanged = all((install / name).read_bytes() == data for name, data in members.items())
    report["source_unchanged"] = unchanged
    report["checks"].append({"id": "source_unchanged", "ok": unchanged})
    report["checks_passed"] = sum(bool(c["ok"]) for c in report["checks"])
    report["checks_total"] = len(report["checks"])
    report["answer"] = "WALLDEF-name-and-shared-table-path-byte-checked" if all(c["ok"] for c in report["checks"]) else "diagnostic"
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_walldef_table_link_probe.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# PoR WALLDEF loader-to-table link probe", "",
             "**STATIC-PROBE-ONLY. `playable: false`. No art mapping emitted.**", "",
             "Answer: `%s`. Checks: %d/%d. Source unchanged: `%s`." %
             (report["answer"], report["checks_passed"], report["checks_total"], unchanged), "",
             "The partial overlay descriptor names a valid stub 6 at GAME.OVR `0x%X`. Its code passes the `WALLDEF` and `.dax` Pascal pieces to the string helper, calls the DAX loader, and copies 780-byte units through far-pointer slot `DS:0x6A58`. The neighboring consumer reads that same slot at 156-byte scale. The ratio is 5 slices per 780-byte unit." % LOADER, "",
             "This is static byte evidence. The loader's caller, runtime file and block selection, execution, table contents, and all WALLDEF-to-8X8D/tile/screen bindings remain unresolved.", "",
             "## Checks", "", "| Check | Result |", "| --- | --- |"]
    for check in report["checks"]:
        lines.append("| %s | %s |" % (check["id"], "PASS" if check["ok"] else "FAIL"))
    lines += ["", "## Limits", ""] + ["- " + item for item in LIMITS] + [""]
    (out / "por_walldef_table_link_probe_report.md").write_text("\n".join(lines), encoding="utf-8")
    return report, 0 if all(c["ok"] for c in report["checks"]) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install", type=Path, required=True, help="user-supplied POOLRAD folder")
    ap.add_argument("-o", "--out", type=Path, required=True, help="output folder under data/work")
    args = ap.parse_args(argv)
    try:
        install = args.install.resolve()
        out = validate_output_dir(install, args.out)
        data_root = (Path(__file__).resolve().parents[1] / "data" / "work").resolve()
        if not out.is_relative_to(data_root):
            raise ProbeError("output must be under data/work")
        report, code = run(install, out)
    except (OSError, ValueError, KeyError, ProbeError, PorSourceError, dec.DecodeError) as exc:
        print("por_walldef_table_link_probe: refusal: %s" % exc, file=sys.stderr)
        return 2
    print("por_walldef_table_link_probe: %s checks=%d/%d" %
          (report["answer"], report["checks_passed"], report["checks_total"]))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
