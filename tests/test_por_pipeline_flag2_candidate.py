"""Opt-in flag-2 candidate through tools/por_pipeline.py (``--candidate-flag2-passable``).

The candidate encodes Gen1 door flag 2 as OpenUA passability N instead of 15, in
every normalized map and design a run writes. These tests pin four things:

- the default run (candidate absent) is byte-identical to a pinned golden, and its
  manifest has no candidate key anywhere;
- an opted-in run propagates N to block rows, flat design rows, grouped design
  rows, the normalized maps and the GEO bytes, and changes ONLY flag-2 walls;
- out-of-range N is refused before anything is staged or published;
- candidate metadata is deterministic and path-free, and the install is untouched.

Synthetic fixtures only (test_por_pipeline.py helpers); no retail data.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(TESTS, "..", "tools"))
sys.path.insert(0, TESTS)
import por_pipeline as pp  # noqa: E402
import por_map as pm  # noqa: E402
from geo import Geo  # noqa: E402
from test_por_pipeline import (  # noqa: E402
    make_full_install, _plan, _good_design, _group, _tree,
)

FLAG2_WALL = (10, 10, "S", 0xF6, 0x26)  # the one flag-2 wall in the synthetic fixture


def _norm_tree(root: Path) -> dict:
    """SHA-256 per file with CRLF folded to LF. The manifest and report are written
    in text mode, so Windows and Linux bytes differ only in line endings."""
    out = {}
    for dirpath, _d, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            data = p.read_bytes().replace(b"\r\n", b"\n")
            out[p.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    return out


def _digest(tree: dict) -> str:
    return hashlib.sha256("".join("%s %s\n" % kv for kv in sorted(tree.items())).encode()).hexdigest()


def _default_plan(tmp: Path) -> Path:
    return _plan(tmp, [_good_design(), _group()])


def _run(tmp: Path, flag2=None, name="out"):
    """One synthetic install and one run, under ``tmp / name`` (a fresh root per run)."""
    root = tmp / name
    root.mkdir()
    install = make_full_install(root)
    out = root / "out"
    manifest, code = pp.run(install, out, _default_plan(root), flag2_passability=flag2)
    return install, out, manifest, code


def _changed_walls(a: Geo, b: Geo):
    changed = []
    for y in range(16):
        for x in range(16):
            wa, wb = tuple(a.cell(x, y)[:4]), tuple(b.cell(x, y)[:4])
            for k, (va, vb) in enumerate(zip(wa, wb)):
                if va != vb:
                    changed.append((x, y, "NESW"[k], va, vb))
    return changed


# ---- default: byte-identical golden, no candidate key anywhere ------------------

# Pinned on the pipeline with the one-route-fit row=x/col=y candidate,
# candidate absent; CRLF-normalized. The earlier baseline marked correct
# transposed entries failed because _round_trip expected (y,x).
GOLDEN_DEFAULT_TREE = "84738bdc7411340276e405558b2c879758fc6087e7419cc3a460a3c2a88d47d5"
GOLDEN_DEFAULT_MANIFEST = "86a52670abe322901b798430e79fc29e575d6801a74df840c83ec0ccf4ebd5e5"


def test_default_run_matches_pinned_golden(tmp_path):
    _install, out, manifest, code = _run(tmp_path)
    assert code == 0
    assert manifest["designs"][0]["checks"]["entry_point"] is True
    tree = _norm_tree(out)
    assert _digest(tree) == GOLDEN_DEFAULT_TREE
    assert tree["por_pipeline.json"] == GOLDEN_DEFAULT_MANIFEST


def test_default_manifest_and_designs_have_no_candidate_fields(tmp_path):
    _install, out, manifest, _code = _run(tmp_path)
    assert "candidate" not in manifest
    assert all("flag2_candidate" not in b for b in manifest["blocks"])
    assert all("flag2_candidate" not in d for d in manifest["designs"])
    assert manifest["unsupported"] == pp.UNSUPPORTED
    text = (out / "por_pipeline.json").read_text(encoding="utf-8")
    assert "flag2_candidate" not in text and '"candidate"' not in text
    assert "OPT-IN CANDIDATE" not in (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "passability 15" in pp.UNSUPPORTED[1]


def test_candidate_absent_equals_explicit_none(tmp_path):
    _i, a, _m, _c = _run(tmp_path, None, "a")
    _i2, b, _m2, _c2 = _run(tmp_path, None, "b")
    assert _norm_tree(a) == _norm_tree(b)


# ---- propagation: flat design, grouped design, blocks and normalized maps ---------

def test_candidate_is_recorded_on_manifest_and_every_row(tmp_path):
    _install, out, manifest, code = _run(tmp_path, 2)
    assert code in (0, 1)                  # 1 = the pre-existing entry-point check; see handoff
    cand = manifest["candidate"]
    assert cand == {"opt_in": True, "default": False, "playable": False,
                    "rule": "locked", "door": 2, "flag2_passability": 2,
                    "default_flag2_passability": 15, "door3_passability": 15,
                    "door3_status": "unresolved",
                    "evidence_doc": "docs/por-door-flag2-candidate-runtime-20261118.md",
                    "status": ("one OpenUA test run logged crossing allowed=1 with passability 2; "
                               "input action label and PoR parity are unverified; the tested edge "
                               "remained passability 2 after crossing; general flag-2 mapping and "
                               "GEO-reader binding remain unproven; not default or a general rule")}
    assert manifest["playable"] is False
    assert all(b["flag2_candidate"] == 2 for b in manifest["blocks"] if b["status"] == "decoded")
    flat, grouped = manifest["designs"]
    assert flat["flag2_candidate"] == 2 and "areas" not in flat
    assert grouped["flag2_candidate"] == 2 and grouped["playable"] is False


def test_candidate_reaches_every_normalized_map_and_design_json(tmp_path):
    _install, out, _manifest, _code = _run(tmp_path, 2)
    jsons = sorted(out.rglob("por_map.json"))
    # 8 block maps and the flat design map. A grouped design writes no por_map.json
    # (it never did); its candidate is on the manifest row and in its GEO bytes.
    assert len(jsons) == 8 + 1
    for p in jsons:
        norm = json.loads(p.read_text(encoding="utf-8"))
        assert norm["candidate"]["flag2_passability"] == 2, p
        assert norm["candidate"]["default"] is False, p
        assert norm["playable"] is False, p


def test_flat_design_changes_only_flag2_wall_bytes(tmp_path):
    _i, d_out, _m, _c = _run(tmp_path, None, "d")
    _j, c_out, _m2, _c2 = _run(tmp_path, 2, "c")
    gd = Geo.parse((d_out / "designs" / "PORMAP" / "PORMAP.DSN" / "GEO005.DAT").read_bytes())
    gc = Geo.parse((c_out / "designs" / "PORMAP" / "PORMAP.DSN" / "GEO005.DAT").read_bytes())
    assert _changed_walls(gd, gc) == [FLAG2_WALL]
    game_d = (d_out / "designs" / "PORMAP" / "PORMAP.DSN" / "GAME001.DAT").read_bytes()
    game_c = (c_out / "designs" / "PORMAP" / "PORMAP.DSN" / "GAME001.DAT").read_bytes()
    assert game_d == game_c                   # the candidate touches walls, not GAME001


def test_grouped_design_changes_only_flag2_wall_bytes_per_area(tmp_path):
    _i, d_out, _m, _c = _run(tmp_path, None, "d")
    _j, c_out, _m2, _c2 = _run(tmp_path, 2, "c")
    for fname in ("GEO005.DAT", "GEO006.DAT"):
        path = Path("designs") / "TWOAREA" / "TWOAREA.DSN" / fname
        gd = Geo.parse((d_out / path).read_bytes())
        gc = Geo.parse((c_out / path).read_bytes())
        assert _changed_walls(gd, gc) == [FLAG2_WALL], fname


def test_grouped_candidate_bytes_equal_the_flat_candidate_bytes(tmp_path):
    _i, out, _m, _c = _run(tmp_path, 2)
    flat = (out / "designs" / "PORMAP" / "PORMAP.DSN" / "GEO005.DAT").read_bytes()
    grouped = (out / "designs" / "TWOAREA" / "TWOAREA.DSN" / "GEO005.DAT").read_bytes()
    assert flat == grouped


def test_candidate_maps_differ_from_default_only_at_flag2_walls(tmp_path):
    _i, d_out, _m, _c = _run(tmp_path, None, "d")
    _j, c_out, _m2, _c2 = _run(tmp_path, 2, "c")
    d_norm = json.loads((d_out / "designs" / "PORMAP" / "por_map.json").read_text(encoding="utf-8"))
    c_norm = json.loads((c_out / "designs" / "PORMAP" / "por_map.json").read_text(encoding="utf-8"))
    c_norm.pop("candidate")
    assert c_norm == d_norm                   # edge rule names and diagnostics unchanged


def test_candidate_report_and_unsupported_say_candidate_not_both_15(tmp_path):
    _i, out, manifest, _c = _run(tmp_path, 2)
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "OPT-IN CANDIDATE" in report and "passability 2" in report
    assert "UNRESOLVED" in report
    door = [u for u in manifest["unsupported"] if u.startswith("Door mapping")]
    assert len(door) == 1
    assert "flags 2 and 3 currently map to OpenUA passability 15" not in door[0]
    assert "written as passability 2" in door[0]
    assert "Flag 3" in door[0] and "UNRESOLVED" in door[0]


def test_default_unsupported_line_is_unchanged_wording(tmp_path):
    assert pp.unsupported_list(None) == pp.UNSUPPORTED
    assert pp.DOOR_LINE_DEFAULT in pp.UNSUPPORTED


# ---- out-of-range refusal writes nothing -----------------------------------------

@pytest.mark.parametrize("bad", [16, -1, 99, True, "2", 2.0])
def test_out_of_range_or_non_int_is_refused_before_staging(tmp_path, bad):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="0..15"):
        pp.run(install, out, _default_plan(tmp_path), flag2_passability=bad)
    assert not out.exists()
    assert not any(p.name.startswith(pp.STAGE_PREFIX) for p in tmp_path.iterdir())


@pytest.mark.parametrize("ok", [0, 2, 15])
def test_bounds_are_accepted(tmp_path, ok):
    _i, out, manifest, code = _run(tmp_path, ok, "o%d" % ok)
    assert manifest["candidate"]["flag2_passability"] == ok


def test_cli_out_of_range_exits_2_and_writes_nothing(tmp_path, capsys):
    install = make_full_install(tmp_path)
    plan = _default_plan(tmp_path)
    for bad in ("16", "-1"):
        out = tmp_path / ("cli" + bad.replace("-", "m"))
        rc = pp.main(["--install", str(install), "-o", str(out), "--plan", str(plan),
                      "--candidate-flag2-passable", bad])
        assert rc == 2
        assert not out.exists()
    assert "0..15" in capsys.readouterr().err


def test_cli_flag_absent_is_the_default_and_present_is_announced(tmp_path, capsys):
    install = make_full_install(tmp_path)
    plan = _default_plan(tmp_path)
    assert pp.main(["--install", str(install), "-o", str(tmp_path / "d"),
                    "--plan", str(plan)]) in (0, 1)
    assert "OPT-IN" not in capsys.readouterr().out
    assert pp.main(["--install", str(install), "-o", str(tmp_path / "c"),
                    "--plan", str(plan), "--candidate-flag2-passable", "2"]) in (0, 1)
    assert "OPT-IN CANDIDATE: flag 2 as passability 2" in capsys.readouterr().out


# ---- deterministic, path-free, install untouched ----------------------------------

def test_candidate_outputs_are_deterministic_and_path_free(tmp_path):
    _i, a, _m, _c = _run(tmp_path, 2, "a")
    _j, b, _m2, _c2 = _run(tmp_path, 2, "b")
    assert _norm_tree(a) == _norm_tree(b)
    for name in ("por_pipeline.json", "por_pipeline_report.md"):
        text = (a / name).read_text(encoding="utf-8")
        assert str(tmp_path) not in text
        assert str(tmp_path).replace("\\", "/") not in text
        assert ":/" not in text and ":\\" not in text


def test_candidate_run_never_writes_the_install(tmp_path):
    install, _out, _m, _c = _run(tmp_path, 2)
    before = _tree(install)
    pp.run(install, tmp_path / "again", _default_plan(tmp_path), flag2_passability=2)
    assert _tree(install) == before
