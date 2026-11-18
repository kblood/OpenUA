#!/usr/bin/env python3
"""Check the recorded PoR flag-2 door runtime observations (stdlib only).

Parses the two captured DBG.LOG files from the flag-2 candidate experiment
(run-ctl: passability 15 / 0xFA default; run-cand: passability 2 / 0x2A opt-in)
and checks the exact values recorded in
docs/por-door-flag2-candidate-runtime-20261118.md, plus the
docs/por-flag2-runtime-repeat-20261118.md summary of this check.

It deliberately does not infer the visible menu label, destination parity,
persistence beyond the captured runtime nibble, or general flag-2 semantics.

Exit codes:
  0  every check passed
  1  a log parsed cleanly but at least one recorded value differs
  2  a log is missing, malformed or ambiguous; nothing is checked or written

Output never contains filesystem paths.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA_WORK = (REPO / "data" / "work").resolve()
DEFAULT_ROOT = DATA_WORK / "por-flag2-candidate-20261118"
LOG_NAME = "DBG.LOG"
RUNS = ("run-ctl", "run-cand")

# Printed by main() before any door diagnostic; a second occurrence means two
# boot sessions were appended into one file.
BOOT_MARKER = "main: display up"
GEO_CELLS = 16  # the GEO-SWEEP line for area 020 reports width 16 height 16

FORWARD_RE = re.compile(r"^DOOR forward (row|col|facing|edge|allowed)=(-?\d+)$")
MENU_RE = re.compile(r"^DOOR menu (pick|allowed)=(-?\d+)$")
STORED_RE = re.compile(r"^DOOR stored edge (-?\d+),(-?\d+) W=(-?\d+)$")

# Key sequences printed per forward decision, in boot.c print order.
SHAPE_MENU = (
    "row", "col", "facing", "edge", "menu.pick", "menu.allowed",
    "forward.allowed", "stored",
)
SHAPE_PLAIN = ("row", "col", "facing", "edge", "forward.allowed", "stored")

STORED_CELL = (14, 10)  # the "14,10" literal in boot.c, row 10 col 14 per its comment

_FIRST_CELL = {
    "row": 10, "col": 14, "facing": 6,
}

# Values recorded in the experiment doc. Block 0 is the selected decision
# (menu runs at the Blocked door); later blocks are the next forward decision.
EXPECTED = {
    "run-ctl": [
        {**_FIRST_CELL,"edge": 15, "menu": {"pick": 0, "allowed": 0},
         "forward_allowed": 0, "stored_cell": STORED_CELL, "stored_w": 15},
        {**_FIRST_CELL,"edge": 15, "menu": {"pick": 0, "allowed": 0},
         "forward_allowed": 0, "stored_cell": STORED_CELL, "stored_w": 15},
    ],
    "run-cand": [
        {**_FIRST_CELL,"edge": 2, "menu": {"pick": 0, "allowed": 1},
         "forward_allowed": 1, "stored_cell": STORED_CELL, "stored_w": 2},
        {"row": 9, "col": 14, "facing": 6, "edge": 14, "menu": None,
         "forward_allowed": 0, "stored_cell": STORED_CELL, "stored_w": 2},
    ],
}


class Refused(Exception):
    """The log is missing, malformed or ambiguous; no result is produced."""


def _int_in(value, lo, hi, what):
    n = int(value)
    if not lo <= n <= hi:
        raise Refused(f"{what} value {n} outside {lo}..{hi}")
    return n


def parse_log(text):
    """Return a list of decision blocks parsed from one DBG.LOG text.

    Raises Refused for any structure that is not exactly one known shape.
    """
    lines = text.splitlines()
    if sum(1 for ln in lines if ln == BOOT_MARKER) != 1:
        raise Refused("ambiguous: boot marker count is not exactly 1")

    door_lines = [ln for ln in lines if ln.startswith("DOOR ")]
    if not door_lines:
        raise Refused("no DOOR observations in log")

    blocks = []
    current = None  # list of (key, raw_fields)
    for ln in door_lines:
        m_f = FORWARD_RE.match(ln)
        m_m = MENU_RE.match(ln)
        m_s = STORED_RE.match(ln)
        if m_f:
            key = m_f.group(1)
            if key == "row":
                if current is not None:
                    blocks.append(current)
                current = []
            if current is None:
                raise Refused("DOOR line before first forward row")
            key = "forward.allowed" if key == "allowed" else key
            current.append((key, int(m_f.group(2))))
        elif m_m:
            if current is None:
                raise Refused("DOOR menu line before first forward row")
            current.append(("menu." + m_m.group(1), int(m_m.group(2))))
        elif m_s:
            if current is None:
                raise Refused("DOOR stored line before first forward row")
            current.append(("stored", (int(m_s.group(1)), int(m_s.group(2)),
                                       int(m_s.group(3)))))
        else:
            raise Refused("unrecognised DOOR line")
    if current is not None:
        blocks.append(current)

    parsed = []
    for raw in blocks:
        keys = tuple(k for k, _ in raw)
        vals = dict(raw)  # a duplicate key is caught by the shape check below
        if keys == SHAPE_MENU:
            menu = {"pick": vals["menu.pick"], "allowed": vals["menu.allowed"]}
        elif keys == SHAPE_PLAIN:
            menu = None
        else:
            raise Refused("ambiguous: decision block does not match a known shape")
        cell = vals["stored"]
        block = {
            "row": _int_in(vals["row"], 0, GEO_CELLS - 1, "row"),
            "col": _int_in(vals["col"], 0, GEO_CELLS - 1, "col"),
            "facing": _int_in(vals["facing"], 0, 255, "facing"),
            "edge": _int_in(vals["edge"], 0, 255, "edge"),
            "menu": None,
            "forward_allowed": _int_in(vals["forward.allowed"], 0, 1,
                                       "forward allowed"),
            "stored_cell": (cell[0], cell[1]),
            "stored_w": _int_in(cell[2], 0, 255, "stored edge"),
        }
        if menu is not None:
            block["menu"] = {
                "pick": _int_in(menu["pick"], 0, 255, "menu pick"),
                "allowed": _int_in(menu["allowed"], 0, 1, "menu allowed"),
            }
        parsed.append(block)
    return parsed


def _check(results, cid, ok, detail):
    results.append({"id": cid, "pass": bool(ok), "detail": detail})


def check_run(name, blocks):
    """Compare parsed blocks with the recorded EXPECTED values for one run."""
    expected = EXPECTED[name]
    results = []
    _check(results, "decision-count", len(blocks) == len(expected),
           f"parsed {len(blocks)}, recorded {len(expected)}")
    first_edge = blocks[0]["edge"] if blocks else None
    for i, exp in enumerate(expected):
        if i >= len(blocks):
            break
        got = blocks[i]
        tag = f"block{i}"
        _check(results, f"{tag}.cell", (got["row"], got["col"]) ==
               (exp["row"], exp["col"]),
               f"row {got['row']} col {got['col']}")
        _check(results, f"{tag}.facing", got["facing"] == exp["facing"],
               f"facing {got['facing']}")
        _check(results, f"{tag}.edge", got["edge"] == exp["edge"],
               f"edge {got['edge']} (recorded {exp['edge']})")
        if exp["menu"] is None:
            _check(results, f"{tag}.menu-absent", got["menu"] is None,
                   "no menu lines" if got["menu"] is None else "menu present")
        else:
            _check(results, f"{tag}.menu-pick",
                   got["menu"] is not None and got["menu"]["pick"] == exp["menu"]["pick"],
                   f"menu pick {got['menu'] and got['menu']['pick']}")
            _check(results, f"{tag}.action-allowed",
                   got["menu"] is not None and got["menu"]["allowed"] == exp["menu"]["allowed"],
                   f"action allowed {got['menu'] and got['menu']['allowed']}"
                   f" (recorded {exp['menu']['allowed']})")
        _check(results, f"{tag}.forward-allowed",
               got["forward_allowed"] == exp["forward_allowed"],
               f"forward allowed {got['forward_allowed']} (recorded {exp['forward_allowed']})")
        _check(results, f"{tag}.stored-edge-unchanged",
               got["stored_cell"] == exp["stored_cell"] and got["stored_w"] == first_edge,
               f"stored cell {got['stored_cell'][0]},{got['stored_cell'][1]} "
               f"W={got['stored_w']} (selected edge {first_edge})")
    return results


def compare_runs(parsed):
    """Cross-run values the doc's table compares directly (selected decision)."""
    ctl, cand = parsed["run-ctl"][0], parsed["run-cand"][0]
    if ctl["menu"] is None or cand["menu"] is None:
        raise Refused("selected decision has no menu lines in one run")
    pairs = [
        ("selected-edge", ctl["edge"], cand["edge"], 15, 2),
        ("menu-pick", ctl["menu"]["pick"], cand["menu"]["pick"], 0, 0),
        ("action-allowed", ctl["menu"]["allowed"], cand["menu"]["allowed"], 0, 1),
        ("forward-allowed", ctl["forward_allowed"], cand["forward_allowed"], 0, 1),
    ]
    results = []
    for cid, a, b, want_a, want_b in pairs:
        _check(results, f"compare.{cid}", a == want_a and b == want_b,
               f"run-ctl {a} vs run-cand {b}")
    return results


def run_checks(root):
    """Parse both logs under root; return (parsed, results) or raise Refused."""
    parsed = {}
    for name in RUNS:
        log = root / name / LOG_NAME
        if not log.is_file():
            raise Refused(f"{name}: {LOG_NAME} not found")
        try:
            text = log.read_bytes().decode("ascii")
        except UnicodeDecodeError as exc:
            raise Refused(f"{name}: log is not ASCII") from exc
        try:
            parsed[name] = parse_log(text)
        except Refused as exc:
            raise Refused(f"{name}: {exc}") from exc
    results = {name: check_run(name, parsed[name]) for name in RUNS}
    results["compare"] = compare_runs(parsed)
    return parsed, results


def _all_results(results):
    for group in results.values():
        yield from group


def write_report(path, parsed, results):
    target = Path(path).resolve()
    try:
        target.relative_to(DATA_WORK)
    except ValueError:
        raise Refused("report path must be under data/work")
    report = {
        "schema": 1,
        "scope": "PoR flag-2 door runtime observations; not general flag-2 semantics",
        "result": "pass" if all(r["pass"] for r in _all_results(results)) else "fail",
        "runs": {
            name: {
                "blocks": [
                    {**b, "stored_cell": list(b["stored_cell"])} for b in parsed[name]
                ],
                "checks": results[name],
            }
            for name in RUNS
        },
        "compare": results["compare"],
    }
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT,
                    help="folder holding run-ctl/ and run-cand/ (default: the "
                         "ignored data/work capture folder)")
    ap.add_argument("--report", type=Path, default=None,
                    help="optional JSON report; must resolve under data/work")
    args = ap.parse_args(argv)

    try:
        parsed, results = run_checks(args.root.resolve())
        if args.report is not None:
            write_report(args.report, parsed, results)
    except Refused as exc:
        print(f"REFUSED: {exc}")
        return 2

    failed = 0
    total = 0
    for name in RUNS:
        print(f"{name}: parsed {len(parsed[name])} decision block(s)")
    for group in ("run-ctl", "run-cand", "compare"):
        for r in results[group]:
            total += 1
            if not r["pass"]:
                failed += 1
            print(f"{'PASS' if r['pass'] else 'FAIL'} {group} {r['id']}: {r['detail']}")
    print(f"RESULT: {total - failed} pass, {failed} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
