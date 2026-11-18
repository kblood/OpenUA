"""Opt-in flag-2 passability candidate for tools/por_map.py.

The default conversion encodes Gen1 door flag 2 as passability 15 (the
Blocked-menu edge). The candidate encodes it as passability 2 and is reachable
ONLY through an explicit argument / ``--candidate-flag2-passable``. These tests
pin three things: the corrected default output has a deterministic golden, the
candidate changes only flag-2 wall bytes, and the candidate is never on by
default.

Synthetic fixtures only (tests/test_por_map.py helpers); no retail data.
"""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_por_map as T  # noqa: E402  (synthetic DAX/install writers)
from geo import Geo  # noqa: E402

import por_map as pm  # noqa: E402

GEO_NAME = "GEO005.DAT"  # design PORMAP, area 5 (the synthetic fixture's area)


def _default_byte(slot, door):
    if slot == 0:
        return 0x00
    if door == 0:
        return (14 << 4) | slot
    if door == 1:
        return (1 << 4) | slot
    return (15 << 4) | slot  # door 2 and door 3 (default)


# ---- map_edge: default table and opt-in candidate ---------------------------

@pytest.mark.parametrize("slot", range(16))
@pytest.mark.parametrize("door", range(4))
def test_default_map_edge_unchanged(slot, door):
    assert pm.map_edge(slot, door)[0] == _default_byte(slot, door)
    assert pm.map_edge(slot, door, flag2_passability=None) == pm.map_edge(slot, door)


@pytest.mark.parametrize("slot", range(1, 16))
def test_candidate_encodes_only_flag2_walls(slot):
    byte, rule = pm.map_edge(slot, 2, flag2_passability=pm.CANDIDATE_FLAG2_PASSABILITY)
    assert byte == (pm.CANDIDATE_FLAG2_PASSABILITY << 4) | slot == (0x20 | slot)
    assert rule == "locked"  # rule name and evidence labels do not change


@pytest.mark.parametrize("door", [0, 1, 3])
def test_candidate_leaves_other_doors_alone(door):
    for slot in range(16):
        assert (pm.map_edge(slot, door, flag2_passability=2)
                == pm.map_edge(slot, door))


def test_candidate_leaves_open_edges_alone():
    assert pm.map_edge(0, 2, flag2_passability=2) == (0x00, "open")


def test_candidate_constant_is_two_and_not_default():
    assert pm.CANDIDATE_FLAG2_PASSABILITY == 2
    assert pm.map_edge(10, 2)[0] == 0xFA  # default flag-2 encoding is still 15


# ---- golden: default output after the one-route axis correction ------------

# Recorded after the runtime-supported PoR x/y -> OpenUA row/column transform.
GOLDEN_DEFAULT = {
    "por_map.json": "ac35defe6ee1ee3f75eea3d72a3ab8ee8d55fe935e813666289ec9640fae3efc",
    "por_map_report.md": "1cc39b34c7299f346ae1056e06c2a592cf63301de18aa4266f532670a487b186",
    "PORMAP.DSN/GAME001.DAT": "918e07b80465a8cdf4d572dab356dce6f2f373a0faea14a862f50e867757c506",
    "PORMAP.DSN/" + GEO_NAME: "1b9aed39096b77cb4f471c3facaedbb12fa4802883c9ce0e19a8a36ffc50e900",
}


def _convert_args(install, out, extra=()):
    return ["--install", str(install), "--geo", "1", "--index", "0",
            "-o", str(out), "--entry", "3,5", "--facing", "north",
            "--area", "5", "--name", "PORMAP", *extra]


def _hashes(out: Path) -> dict:
    res = {}
    for key in GOLDEN_DEFAULT:
        res[key] = hashlib.sha256((out / key).read_bytes()).hexdigest()
    return res


def test_default_output_matches_transposed_axis_golden(tmp_path):
    install = T.make_install(tmp_path)
    out = tmp_path / "out"
    assert pm.main(_convert_args(install, out)) == 0
    assert _hashes(out) == GOLDEN_DEFAULT


def test_default_json_has_no_candidate_key(tmp_path):
    install = T.make_install(tmp_path)
    out = tmp_path / "out"
    assert pm.main(_convert_args(install, out)) == 0
    assert "candidate" not in (out / "por_map.json").read_text(encoding="utf-8")
    assert "OPT-IN CANDIDATE" not in (out / "por_map_report.md").read_text(encoding="utf-8")


# ---- end to end: candidate is opt-in and changes only flag-2 bytes ----------

def test_candidate_is_opt_in_via_cli(tmp_path, capsys):
    install = T.make_install(tmp_path)
    out = tmp_path / "cand"
    rc = pm.main(_convert_args(install, out,
                               ("--candidate-flag2-passable", "2")))
    assert rc == 0
    assert "OPT-IN CANDIDATE" in capsys.readouterr().err
    import json
    norm = json.loads((out / "por_map.json").read_text(encoding="utf-8"))
    assert norm["candidate"]["opt_in"] is True
    assert norm["candidate"]["default"] is False
    assert norm["candidate"]["flag2_passability"] == 2
    assert norm["candidate"]["evidence_doc"] == "docs/por-door-flag2-candidate-runtime-20261118.md"
    report = (out / "por_map_report.md").read_text(encoding="utf-8")
    assert "OPT-IN FLAG-2 ENCODING" in report
    assert "single-route runtime-tested" in report
    assert "general flag-2 mapping" in report
    assert "persistent opening remain unproven" in report
    assert "single-route runtime-tested" in norm["candidate"]["status"]


def test_non_two_candidate_value_is_not_called_runtime_tested(tmp_path):
    install = T.make_install(tmp_path)
    out = tmp_path / "cand3"
    assert pm.main(_convert_args(install, out,
                                 ("--candidate-flag2-passable", "3"))) == 0
    import json
    norm = json.loads((out / "por_map.json").read_text(encoding="utf-8"))
    assert norm["candidate"]["status"].startswith("not runtime-tested")


def test_candidate_geo_differs_only_at_flag2_walls(tmp_path):
    install = T.make_install(tmp_path)
    dflt, cand = tmp_path / "d", tmp_path / "c"
    assert pm.main(_convert_args(install, dflt)) == 0
    assert pm.main(_convert_args(install, cand,
                                 ("--candidate-flag2-passable", "2"))) == 0
    gd = Geo.parse((dflt / "PORMAP.DSN" / GEO_NAME).read_bytes())
    gc = Geo.parse((cand / "PORMAP.DSN" / GEO_NAME).read_bytes())
    changed = []
    for y in range(16):
        for x in range(16):
            # Geo.cell() returns the raw cell bytes; the first four are N,E,S,W.
            wd = tuple(gd.cell(x, y)[:4])
            wc = tuple(gc.cell(x, y)[:4])
            for k, (a, b) in enumerate(zip(wd, wc)):
                if a != b:
                    changed.append((x, y, "NESW"[k], hex(a), hex(b)))
    # The fixture has exactly one flag-2 wall: (10,10) south, slot 6.
    assert changed == [(10, 10, "S", "0xf6", "0x26")]


def test_candidate_out_of_range_is_refused(tmp_path, capsys):
    install = T.make_install(tmp_path)
    for bad in ("16", "-1"):
        out = tmp_path / ("bad" + bad.replace("-", "m"))
        rc = pm.main(_convert_args(install, out,
                                   ("--candidate-flag2-passable", bad)))
        assert rc == 2
        assert not (out / "por_map.json").exists()
    assert "0..15" in capsys.readouterr().err
