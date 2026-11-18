#!/usr/bin/env python3
"""Identity, caller ABI and bounded body of the two far module targets 0x0AF8:0x023F and 0x0AF8:0x0254.

Both targets are called from the wall-record helpers that `tools/por_wall_0111_target_probe.py` reached
from the far target 0x0464:0x0111 (START 0x6B07 and 0x6C0E). This probe asks whether the pinned bytes and
the RAM dumps identify these two targets, what their wrappers and near helpers do, and whether the
call-site bytes give an allocate/release shape. Read-only and stdlib-only. It writes only under
data/work/por-wall-0111-module-target-probe/.

Every claim is conditional on the module base (file 0xAC76, from the routine-B handler pattern in START)
and on the live module segment (0x235E = 0x0AF8 + the module load 0x1866 measured from the dump anchor).
Nothing here runs the code, reads the F table at run time, or identifies what DS holds in the overlay.
The output is a fact sheet; it does not decide the allocator question.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_overlay_group_map as om  # noqa: E402
import por_geo_copy_helper_probe as gcp  # noqa: E402
import por_loadpieces_handler as lp  # noqa: E402

Refusal = om.Refusal
SCHEMA = "openua.por-wall-0111-module-target-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "module-target-probe-only"
TOOL = "tools/por_wall_0111_module_target_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-wall-0111-module-target-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMPS = gcp.DEFAULT_DUMPS
OVR_NAME = "GAME.OVR"
EXE_NAME = "START.EXE"

MODULE_SEG = 0x0AF8
EXPECT_LOAD = 0x1866                 # module load segment, as measured from the dump anchor (copy-helper probe)
WINDOW = 32
PARA = 16
TARGETS = (0x023F, 0x0254)
ROLE = {0x023F: "allocate-candidate", 0x0254: "release-candidate"}
RETF_IMM = {0x023F: 2, 0x0254: 6}          # one word argument; word plus far pointer
ERR_CODE = {0x023F: 0x00CB, 0x0254: 0x00CC}
ERR_JOIN = 0x00E2                    # module offset both wrappers jump to on carry set
EXIT_TAIL = {0x023F: bytes.fromhex("58 5a f8 c3"), 0x0254: bytes.fromhex("f8 c3")}
PREFIXES = (0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3)

# Byte templates of the two wrappers (module-relative offsets 0 .. len-1). Each wrapper: push bp; mov bp,sp;
# mov ax,[bp+6] (the size word); a near call with CF from the helper; pop bp; jc over the retf; retf imm;
# mov ax,err; jmp to the shared join. The 0x0254 wrapper also loads ES:CX from [bp+8] and passes BX=ES.
WRAPPER = {
    0x023F: bytes.fromhex("55 8b ec 8b 46 06 e8 c0 00 5d 72 03 ca 02 00 b8 cb 00 e9 8e fe"),
    0x0254: bytes.fromhex("55 8b ec 8b 46 06 c4 4e 08 8c c3 e8 71 01 5d 72 03 ca 06 00 b8 cc 00 e9 74 fe"),
}
WRAP_AT = {   # index of each instruction in the template
    0x023F: {"call": 6, "pop": 9, "jc": 10, "retf": 12, "err": 15, "jmp": 18},
    0x0254: {"call": 11, "pop": 14, "jc": 15, "retf": 17, "err": 20, "jmp": 23},
}

# Call-site byte pattern: 9A, offset word, segment word 0x0AF8.
def call_bytes(off: int) -> bytes:
    return b"\x9a" + off.to_bytes(2, "little") + MODULE_SEG.to_bytes(2, "little")

# Wall-helper bytes checked at fixed START offsets (the helpers are START 0x6B07 and 0x6C0E). Each row is
# (label, offset, expected bytes). The labels describe what the bytes do; the probe checks the bytes only.
WALL_PATTERNS = [
    ("base-size-mul-bp16-bp14-shl1", 0x6B0D, "8b 46 10 f7 66 0e d1 e0 89 46 fe"),
    ("base-shl1-when-flag-nonzero", 0x6B18, "80 3e 1e 4a 00 74 08"),
    ("alloc-base-mul-byte-bp12", 0x6B27, "8a 46 0c 30 e4 f7 66 fe 89 46 fc"),
    ("alloc-element-store-dx-ax", 0x6B3E, "c4 7e 06 26 89 05 26 89 55 02"),
    ("alloc-header-plus17-from-bp-2", 0x6B81, "26 89 45 11"),
    ("alloc-header-plus8-from-bp12", 0x6B8E, "26 88 45 08"),
    ("alloc-flag-one-test", 0x6B9B, "80 3e 1e 4a 01 75 39"),
    ("alloc-main-size-bp-4-plus-17", 0x6B32, "8b 46 fc 05 17 00 50 9a 3f 02 f8 0a"),
    ("alloc-main-fill-zero-count-bp-4-plus-17", 0x6B50, "8b 46 fc 05 17 00 50 b0 00 50 9a a8 16 f8 0a"),
    ("alloc-sub-size-bp-4-shr2", 0x6BA2, "8b 46 fc d1 e8 d1 e8 50 9a 3f 02 f8 0a"),
    ("alloc-sub-size-bp-4-raw", 0x6BDB, "ff 76 fc 9a 3f 02 f8 0a"),
    ("alloc-sub-store-block-plus19", 0x6BAF, "c4 7e 06 26 c4 3d 26 89 45 13 26 89 55 15"),
    ("release-null-guard-element", 0x6C14, "c4 7e 06 26 8b 05 26 0b 45 02 75 03 e9 82 00"),
    ("release-flag-one-test", 0x6C4F, "80 3e 1e 4a 01 75 1a"),
    ("release-base-from-block-byte8-times-17", 0x6C32, "26 8a 45 08 30 e4 c4 7e fa 26 f7 65 11 89 46 fe"),
    ("release-sub-size-bp-2-shr2", 0x6C61, "8b 46 fe d1 e8 d1 e8 50 9a 54 02 f8 0a"),
    ("release-sub-size-bp-2-raw", 0x6C7B, "ff 76 fe 9a 54 02 f8 0a"),
    ("release-main-size-bp-2-plus-17", 0x6C8D, "8b 46 fe 05 17 00 50 9a 54 02 f8 0a"),
    ("release-element-clear", 0x6C99, "c4 7e 06 31 c0 26 89 05 26 89 45 02"),
]
# Wall-helper windows: the two helpers' linear decode runs from the entry to its retf.
WALL_HELPERS = {"0x6B07": 0x6B07, "0x6C0E": 0x6C0E}

NOT_ESTABLISHED = [
    "That either target runs at any real instant, or with which arguments (the caller's DS, the table index and the size are not measured).",
    "That DS:0x440C, DS:0x4400..0x4406 and DS:0x8754 hold the values the near helpers assume; the F table is not shown to be initialised at run time.",
    "That the returned DX:AX is the block the caller keeps: the helper returns the node it chose, and whether the node is a free-list entry or a block is not shown.",
    "That the 0x0254 helper frees the block it is handed; the helper writes size fields and links the block, which fits release but is not proven.",
    "That the alloc and release calls pair up at run time: the size symmetry is a property of the bytes, and it assumes the header fields are unchanged between the two calls.",
    "That DS:0x4A1E is a bit-depth or mode switch: it selects the shifted and unshifted size paths; its meaning is not established.",
    "The body of the zero-fill helper 0x0AF8:0x16A8 and of the common error join at module 0xE2; they are not decoded here.",
    "What the F element's fields at +8, +17, +19 and +21 mean beyond the size and pointer roles shown by the bytes.",
]


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def _s16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little", signed=True)


def _sha(data: bytes) -> str:
    return gcp._sha(data)


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def check_pins(ovr: bytes, exe: bytes) -> dict:
    return gcp.check_pins(ovr, exe)


def _need_pinned(pins: dict) -> None:
    for name, row in pins.items():
        if not row.get("pinned"):
            raise Refusal("%s does not match its pin; refusing to read it" % name)


# ---- identity of each target window ------------------------------------------------------------

def _window_row(exe: bytes, base_file: int, off: int, dump: om.Dump, load: int) -> dict:
    file_off = base_file + off
    live_lin = (MODULE_SEG + load) * PARA + off
    row = {"module_offset": _hex(off), "file_offset": _hex(file_off), "live_linear": _hex(live_lin),
           "live_covered": dump.covers(live_lin, WINDOW), "code_evidence": gcp.code_evidence(exe, file_off)}
    fb = exe[file_off:file_off + WINDOW]
    if not row["live_covered"]:
        row["state"] = "memory-not-covered"
        return row
    db = dump.read(live_lin, WINDOW)
    row["memory_equals_file"] = db == fb
    if db != fb:
        row["state"] = "memory-disagrees"
        row["differing_offsets"] = [i for i in range(WINDOW) if db[i] != fb[i]][:8]
        return row
    if db[:16].count(0) >= gcp.DEGENERATE_ZEROS:
        row["state"] = "degenerate-window"
        return row
    placed = gcp._positions(exe, db)
    row["file_placements"] = [_hex(p) for p in placed[:4]]
    row["state"] = "memory-agrees-unique-placement" if placed == [file_off] else "placement-not-unique"
    return row


def identity(exe: bytes, base_file: int, dumps: list[dict]) -> dict:
    """A target is identified only if every covering dump agrees with the file window at a unique file place."""
    out = {}
    for off in TARGETS:
        per_dump = []
        for d in dumps:
            per_dump.append({"dump": d["label"], "load_seg": _hex(d["load"]),
                             "window": _window_row(exe, base_file, off, d["dump"], d["load"])})
        states = [r["window"]["state"] for r in per_dump]
        good = all(s == "memory-agrees-unique-placement" for s in states) and bool(states)
        out["0x%04X" % off] = {"role_by_bytes": ROLE[off],
                               "verdict": "identified-by-bytes-in-pinned-dumps" if good else "unresolved",
                               "per_dump": per_dump}
    return out


# ---- wrapper ABI (exact template plus derived targets) -----------------------------------------

def wrapper_facts(exe: bytes, base_file: int, off: int) -> dict:
    tmpl = WRAPPER[off]
    body = exe[base_file + off:base_file + off + len(tmpl)]
    at = WRAP_AT[off]
    facts = {"module_offset": _hex(off), "template_matched": body == tmpl, "length": len(tmpl)}
    if body != tmpl:
        facts["matched"] = False
        return facts
    near_target = off + at["call"] + 3 + _s16(tmpl, at["call"] + 1)
    jc_target = off + at["jc"] + 2 + int.from_bytes(tmpl[at["jc"] + 1:at["jc"] + 2], "little", signed=True)
    jmp_target = off + at["jmp"] + 3 + _s16(tmpl, at["jmp"] + 1)
    facts.update({
        "near_call_target_module": _hex(near_target),
        "carry_branch_skips_to_module": _hex(jc_target),
        "carry_branch_skips_retf": jc_target == off + at["err"],
        "retf_imm": _u16(tmpl, at["retf"] + 1),
        "retf_imm_expected": RETF_IMM[off],
        "error_code_loaded": _u16(tmpl, at["err"] + 1),
        "error_code_expected": ERR_CODE[off],
        "jump_target_module": _hex(jmp_target),
        "jump_join_expected": _hex(ERR_JOIN),
        "matched": (jc_target == off + at["err"]
                    and _u16(tmpl, at["retf"] + 1) == RETF_IMM[off]
                    and _u16(tmpl, at["err"] + 1) == ERR_CODE[off]
                    and jmp_target == ERR_JOIN),
    })
    return facts


# ---- near helpers (bounded linear decode to the first ret) ------------------------------------

def helper_summary(exe: bytes, base_file: int, module_off: int, exit_tail: Optional[bytes]) -> dict:
    start = base_file + module_off
    insns, stop = lp.linear(exe, start, 0x200, True)
    ds_direct, imm_mov, calls, store_ops = [], [], [], []
    for i in insns:
        raw = i.raw
        k = 0
        while k < len(raw) and raw[k] in PREFIXES:
            k += 1
        op = raw[k] if k < len(raw) else None
        if i.direct is not None:
            ds_direct.append({"at": _hex(i.off - base_file), "addr": _hex(i.direct),
                              "kind": "store" if op in (0x88, 0x89, 0x8C, 0xA3, 0xC6, 0xC7) else "read-or-other"})
        if op is not None and 0xB8 <= op <= 0xBF and i.imm is not None:
            imm_mov.append({"at": _hex(i.off - base_file), "imm": _hex(i.imm)})
        if i.target is not None and i.flow == "call":
            calls.append({"at": _hex(i.off - base_file), "target_module": _hex(i.target - base_file)})
    tail_ok = None
    if exit_tail is not None and insns:
        # Join instructions from the end until the tail length is covered, then compare the last bytes.
        acc, k = b"", len(insns) - 1
        while k >= 0 and len(acc) < len(exit_tail):
            acc = insns[k].raw + acc
            k -= 1
        tail_ok = acc.endswith(exit_tail)
    addrs = sorted({d["addr"] for d in ds_direct})
    return {"module_offset": _hex(module_off), "instructions": len(insns), "stop": stop,
            "last": insns[-1].raw.hex(" ") if insns else None, "exit_tail_ok": tail_ok,
            "ds_direct": ds_direct, "ds_direct_addresses": addrs, "mov_imm16": imm_mov,
            "near_calls": calls}


# ---- caller sites and the wall-helper patterns -------------------------------------------------

def site_counts(files: dict[str, bytes]) -> dict:
    out = {}
    for off in TARGETS:
        pat = call_bytes(off)
        per_file = {}
        for name, data in files.items():
            hits, pos = [], data.find(pat)
            while pos != -1:
                hits.append(pos)
                pos = data.find(pat, pos + 1)
            per_file[name] = [_hex(h) for h in hits]
        out["0x%04X" % off] = per_file
    return out


def wall_pattern_rows(exe: bytes) -> list[dict]:
    rows = []
    for label, off, hx in WALL_PATTERNS:
        want = bytes.fromhex(hx)
        got = exe[off:off + len(want)]
        rows.append({"label": label, "start_offset": _hex(off), "matched": got == want,
                     "expected": hx, "found": got.hex(" ")})
    return rows


def wall_helper_decode(exe: bytes) -> dict:
    out = {}
    for name, entry in WALL_HELPERS.items():
        insns, stop = lp.linear(exe, entry, 0x400, True)
        calls = [{"at": _hex(i.off), "far": ("0x%04X:0x%04X" % i.far) if i.far else None}
                 for i in insns if i.flow == "call_far"]
        out[name] = {"entry": _hex(entry), "instructions": len(insns), "stop": stop,
                     "last": insns[-1].raw.hex(" ") if insns else None,
                     "far_call_sites": [c for c in calls if c["far"] in ("0x0AF8:0x023F", "0x0AF8:0x0254",
                                                                          "0x0AF8:0x16A8")]}
    return out


def symmetry_rows() -> dict:
    """Read off the size formulas from the matched bytes (static reading; not run)."""
    return {
        "main": {
            "alloc_size": "[bp-4] + 0x17, where [bp-4] = (byte [bp+12]) * [bp-2]",
            "alloc_header": "block+8 <- byte [bp+12]; block+17 <- word [bp-2]",
            "release_size": "[bp-2] + 0x17, where [bp-2] = (byte block+8) * (word block+17)",
            "same_formula_when_header_intact": True,
            "basis": "alloc bytes 0x6B0D/0x6B27/0x6B32/0x6B81/0x6B8E; release bytes 0x6C32/0x6C8D",
        },
        "sub": {
            "alloc_size": "[bp-4] >> 2 when DS:0x4A1E == 1, else [bp-4]",
            "release_size": "[bp-2] >> 2 when DS:0x4A1E == 1, else [bp-2]",
            "same_formula_when_header_intact": True,
            "pointer": "alloc returns DX:AX stored at block+19 (off) and block+21 (seg); release pushes block+21 then block+19",
            "basis": "alloc bytes 0x6B9B/0x6BA2/0x6BDB/0x6BAF; release bytes 0x6C4F/0x6C61/0x6C7B (pushes from 0x6C56 onward)",
        },
        "guards": {
            "alloc_sub_conditional_on": "bit 0 of [bp+10] (and al,1; or al,al; jbe skip)",
            "release_main_conditional_on": "element first dword non-zero (0x6C14 guard)",
            "release_sub_conditional_on": "block+19 or block+21 non-zero (0x6C4D guard)",
            "element_store_before_alloc_check": "0x6B07 stores the new pointer without testing the old one",
        },
    }


# ---- top level --------------------------------------------------------------------------------

def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = check_pins(ovr, exe)
    _need_pinned(pins)
    base = gcp.handler_base(exe)
    base_file = base["base_file"]
    dumps, dump_meta = [], []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        lin_base = om.resolve_dump_base(dp.name, len(raw), None)
        dump = om.Dump(raw, lin_base)
        mod = gcp.dump_module(dump, exe, base_file)
        if mod.get("status") != "unique" or mod.get("load_seg") != EXPECT_LOAD:
            raise Refusal("module anchor in %s is not a unique load 0x%04X: %s" % (dp.parent.name, EXPECT_LOAD, mod))
        label = "%s/%s" % (dp.parent.name, dp.name)
        dumps.append({"label": label, "dump": dump, "load": mod["load_seg"]})
        dump_meta.append({"label": label, "sha256_prefix": _sha(raw)[:16], "dump_base": _hex(lin_base),
                          "module_anchor": mod})
    ident = identity(exe, base_file, dumps)
    wrappers = {"0x%04X" % off: wrapper_facts(exe, base_file, off) for off in TARGETS}
    helpers = {"0x%04X" % off: helper_summary(exe, base_file, _near_target(exe, base_file, off),
                                              EXIT_TAIL[off]) for off in TARGETS}
    counts = site_counts({"START.EXE": exe, OVR_NAME: ovr})
    patterns = wall_pattern_rows(exe)
    helpers_wall = wall_helper_decode(exe)
    all_patterns_ok = all(r["matched"] for r in patterns)
    ident_ok = all(v["verdict"] == "identified-by-bytes-in-pinned-dumps" for v in ident.values())
    wrap_ok = all(w.get("matched") for w in wrappers.values())
    shape_ok = ident_ok and wrap_ok and all_patterns_ok
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL, "status_scope": STATUS_SCOPE,
        "playable": False,
        "inputs": {"pins": pins, "dumps": dump_meta},
        "module": {"file_base": _hex(base_file), "module_segment": _hex(MODULE_SEG),
                   "load_segment_measured": _hex(EXPECT_LOAD),
                   "live_segment": _hex(MODULE_SEG + EXPECT_LOAD),
                   "basis": "routine-B handler pattern (unique in START) and dump anchor (unique per dump)"},
        "identity": ident,
        "wrappers": wrappers,
        "near_helpers": helpers,
        "call_site_byte_counts": counts,
        "wall_helper_patterns": patterns,
        "wall_helper_decode": helpers_wall,
        "symmetry": symmetry_rows(),
        "not_established": NOT_ESTABLISHED,
        "verdict": ("module targets identified by bytes in the pinned dumps; wrappers and wall-helper call "
                    "shapes match the template bytes; the alloc/release size symmetry is a static reading, "
                    "not a run" if shape_ok else "not all checks matched; see identity, wrappers and patterns"),
        "executed": "not_established",
        "playable_claim": False,
    }
    return doc


def _near_target(exe: bytes, base_file: int, off: int) -> int:
    """Module offset of the near helper the wrapper calls (from the template call instruction)."""
    at = WRAP_AT[off]
    tmpl = WRAPPER[off]
    return off + at["call"] + 3 + _s16(tmpl, at["call"] + 1)


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_0111_module_target_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Identity and bounded body of far targets 0x0AF8:0x023F and :0x0254.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    ap.add_argument("--dump", type=Path, action="append", default=None)
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    dumps = args.dump if args.dump else DEFAULT_DUMPS
    try:
        doc = probe(args.install, dumps)
    except (Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    idents = {k: v["verdict"] for k, v in doc["identity"].items()}
    print("wrote %s (identity=%s, wrappers matched=%s, wall patterns matched=%s)" % (
        args.out, idents, all(w.get("matched") for w in doc["wrappers"].values()),
        all(r["matched"] for r in doc["wall_helper_patterns"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
