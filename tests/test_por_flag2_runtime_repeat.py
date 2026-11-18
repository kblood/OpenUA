"""Focused tests for tools/por_flag2_runtime_repeat.py.

Synthetic DBG.LOG fixtures cover the pass, mismatch and refusal paths. The
real captured logs under data/work are checked only when present (data/ is
git-ignored), so CI without the capture skips that one test.
"""
import ast
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import por_flag2_runtime_repeat as rr  # noqa: E402


HEADER = [
    "ste: blitter = 1",
    "main: display up",
    "GEO-SWEEP end: continuing into jt948",
    "ste: viewport composite = COPY (B5)",
]


def block(row, col, facing, edge, menu=None, fwd=0, stored_w=None):
    """One forward decision as boot.c prints it under FRUA_DOOR_DIAG."""
    if stored_w is None:
        stored_w = edge
    lines = [
        f"DOOR forward row={row}",
        f"DOOR forward col={col}",
        f"DOOR forward facing={facing}",
        f"DOOR forward edge={edge}",
    ]
    if menu is not None:
        lines += [f"DOOR menu pick={menu[0]}", f"DOOR menu allowed={menu[1]}"]
    lines += [
        f"DOOR forward allowed={fwd}",
        f"DOOR stored edge 14,10 W={stored_w}",
    ]
    return lines


def ctl_log():
    b = block(10, 14, 6, 15, menu=(0, 0), fwd=0)
    return HEADER + b + b


def cand_log():
    return (HEADER
            + block(10, 14, 6, 2, menu=(0, 1), fwd=1)
            + block(9, 14, 6, 14, fwd=0, stored_w=2))


def make_root(tmp_path, ctl_lines, cand_lines):
    root = tmp_path / "capture"
    for name, lines in (("run-ctl", ctl_lines), ("run-cand", cand_lines)):
        d = root / name
        d.mkdir(parents=True)
        (d / "DBG.LOG").write_text("\n".join(lines) + "\n", encoding="ascii")
    return root


def run(root, *extra):
    return rr.main(["--root", str(root), *extra])


def test_recorded_values_pass(tmp_path, capsys):
    root = make_root(tmp_path, ctl_log(), cand_log())
    assert run(root) == 0
    out = capsys.readouterr().out
    assert "RESULT: 33 pass, 0 fail" in out
    assert "PASS compare compare.selected-edge: run-ctl 15 vs run-cand 2" in out
    assert "PASS compare compare.action-allowed: run-ctl 0 vs run-cand 1" in out
    assert "PASS compare compare.forward-allowed: run-ctl 0 vs run-cand 1" in out


def test_output_is_path_free(tmp_path, capsys):
    root = make_root(tmp_path, ctl_log(), cand_log())
    assert run(root) == 0
    out = capsys.readouterr().out
    assert str(tmp_path) not in out
    assert "DBG.LOG" not in out


def test_candidate_selected_edge_must_be_two(tmp_path, capsys):
    cand = cand_log()
    cand[cand.index("DOOR forward edge=2")] = "DOOR forward edge=15"
    root = make_root(tmp_path, ctl_log(), cand)
    assert run(root) == 1
    assert "FAIL run-cand block0.edge: edge 15 (recorded 2)" in capsys.readouterr().out


def test_action_allowed_mismatch_fails(tmp_path, capsys):
    cand = cand_log()
    cand[cand.index("DOOR menu allowed=1")] = "DOOR menu allowed=0"
    root = make_root(tmp_path, ctl_log(), cand)
    assert run(root) == 1
    out = capsys.readouterr().out
    assert "FAIL run-cand block0.action-allowed" in out
    assert "FAIL compare compare.action-allowed" in out


def test_menu_pick_mismatch_fails(tmp_path, capsys):
    ctl = ctl_log()
    ctl[ctl.index("DOOR menu pick=0")] = "DOOR menu pick=1"
    root = make_root(tmp_path, ctl, cand_log())
    assert run(root) == 1
    assert "FAIL run-ctl block0.menu-pick: menu pick 1" in capsys.readouterr().out


def test_changed_stored_edge_fails(tmp_path, capsys):
    cand = cand_log()
    last = max(i for i, x in enumerate(cand) if x.startswith("DOOR stored edge"))
    cand[last] = "DOOR stored edge 14,10 W=15"
    root = make_root(tmp_path, ctl_log(), cand)
    assert run(root) == 1
    out = capsys.readouterr().out
    assert "FAIL run-cand block1.stored-edge-unchanged" in out
    assert "PASS run-cand block0.stored-edge-unchanged" in out


def test_decision_count_mismatch_fails(tmp_path, capsys):
    root = make_root(tmp_path, ctl_log()[:-len(block(10, 14, 6, 15, menu=(0, 0)))],
                     cand_log())
    assert run(root) == 1
    assert "FAIL run-ctl decision-count: parsed 1, recorded 2" in capsys.readouterr().out


def _drop_first_stored(ls):
    i = next(i for i, x in enumerate(ls) if x.startswith("DOOR stored edge"))
    return ls[:i] + ls[i + 1:]


@pytest.mark.parametrize("mutate", [
    # the first block loses its stored-edge line: no known shape matches
    _drop_first_stored,
    # a duplicated key inside one block
    lambda ls: ls[:ls.index("DOOR forward allowed=0")] + ["DOOR forward allowed=0"]
    + ls[ls.index("DOOR forward allowed=0"):],
    # an unrecognised DOOR line
    lambda ls: ls + ["DOOR something else=1"],
    # a value outside its range
    lambda ls: [x.replace("DOOR forward allowed=1", "DOOR forward allowed=2")
                for x in ls],
    # two boot sessions appended into one file
    lambda ls: ls + ls,
    # no door observations at all
    lambda ls: [x for x in ls if not x.startswith("DOOR ")],
])
def test_malformed_or_ambiguous_cand_log_is_refused(tmp_path, mutate, capsys):
    root = make_root(tmp_path, ctl_log(), mutate(cand_log()))
    assert run(root) == 2
    out = capsys.readouterr().out
    assert out.startswith("REFUSED: run-cand: ")
    assert str(tmp_path) not in out


def test_missing_log_is_refused(tmp_path, capsys):
    root = make_root(tmp_path, ctl_log(), cand_log())
    (root / "run-ctl" / "DBG.LOG").unlink()
    assert run(root) == 2
    assert capsys.readouterr().out == "REFUSED: run-ctl: DBG.LOG not found\n"


def test_non_ascii_log_is_refused(tmp_path, capsys):
    root = make_root(tmp_path, ctl_log(), cand_log())
    (root / "run-ctl" / "DBG.LOG").write_bytes("café\n".encode("utf-8"))
    assert run(root) == 2
    assert "REFUSED: run-ctl: log is not ASCII" in capsys.readouterr().out


def test_report_outside_data_work_is_refused(tmp_path, capsys):
    root = make_root(tmp_path, ctl_log(), cand_log())
    target = tmp_path / "report.json"
    assert run(root, "--report", str(target)) == 2
    assert not target.exists()
    assert "report path must be under data/work" in capsys.readouterr().out


def test_report_written_under_data_work(tmp_path, monkeypatch):
    work = tmp_path / "data-work"
    work.mkdir()
    monkeypatch.setattr(rr, "DATA_WORK", work.resolve())
    root = make_root(tmp_path, ctl_log(), cand_log())
    target = work / "repeat.json"
    assert run(root, "--report", str(target)) == 0
    text = target.read_text(encoding="ascii")
    assert str(tmp_path) not in text
    report = json.loads(text)
    assert report["result"] == "pass"
    assert report["runs"]["run-cand"]["blocks"][0]["stored_cell"] == [14, 10]
    assert [c["id"] for c in report["compare"]] == [
        "compare.selected-edge", "compare.menu-pick",
        "compare.action-allowed", "compare.forward-allowed"]


def test_tool_is_stdlib_only():
    src = (TOOLS / "por_flag2_runtime_repeat.py").read_text(encoding="utf-8")
    names = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module.split(".")[0])
    assert names <= set(sys.stdlib_module_names)


def test_real_captured_logs_pass_when_present(capsys):
    root = rr.DEFAULT_ROOT
    if not (root / "run-ctl" / "DBG.LOG").is_file():
        pytest.skip("captured run logs are git-ignored and absent")
    assert rr.main([]) == 0
    assert "RESULT: 33 pass, 0 fail" in capsys.readouterr().out
