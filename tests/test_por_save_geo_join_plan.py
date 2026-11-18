"""Tests for tools/por_save_geo_join_plan.py (candidate save/GEO join as a one-area plan).

Synthetic cases build stand-in saves and small DAX archives in a temp folder, pin their own
hashes, and write only under that temp data root, so they run without the retail install.
The retail class runs only when OPENUA_POR_INSTALL names a folder holding the pinned saves
and archives. Its assertions are the recorded 2026-11-17 outcomes, not claims about the game.
"""
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_save_geo_join_plan as jp  # noqa: E402
import por_save_state_probe as sp  # noqa: E402
import por_pipeline as pp  # noqa: E402

RETAIL_ENV = os.environ.get(jp.INSTALL_ENV)
SAVE_SIZE = 13137
SENTINEL = b"SENTINEL-JOIN-TAIL-DO-NOT-LEAK"

SIG_A = {"N": (14, 0), "E": (11, 1), "S": (14, 0), "W": (0, 0), "desc": 0}
SIG_J = {"N": (10, 1), "E": (0, 0), "S": (0, 0), "W": (9, 0), "desc": 0}
BASE = {"N": (1, 1), "E": (1, 1), "S": (1, 1), "W": (1, 1), "desc": 0x55}
SAVE_A = {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
          "pose_x": 15, "pose_y": 4, "facing_raw": 6}
SAVE_J = {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
          "pose_x": 14, "pose_y": 5, "facing_raw": 4}


def geo_block(overrides=None) -> bytes:
    overrides = overrides or {}
    planes = [bytearray(256) for _ in range(4)]
    for y in range(16):
        for x in range(16):
            i = y * 16 + x
            s = overrides.get((x, y), BASE)
            planes[0][i] = (s["N"][0] << 4) | s["E"][0]
            planes[1][i] = (s["S"][0] << 4) | s["W"][0]
            planes[2][i] = s["desc"]
            planes[3][i] = s["N"][1] | (s["E"][1] << 2) | (s["S"][1] << 4) | (s["W"][1] << 6)
    return struct.pack("<H", 1024) + b"".join(bytes(p) for p in planes)


def rle_literal(raw: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(raw), 128):
        chunk = raw[i:i + 128]
        out.append(len(chunk) - 1)
        out += chunk
    return bytes(out)


def build_dax(blocks: list) -> bytes:
    comps = [rle_literal(raw) for _, raw in blocks]
    toc = bytearray()
    off = 0
    for (bid, raw), comp in zip(blocks, comps):
        toc += struct.pack("<BIHH", bid, off, len(raw), len(comp))
        off += len(comp)
    return struct.pack("<H", len(toc)) + bytes(toc) + b"".join(comps)


def make_save(values: dict) -> bytes:
    buf = bytearray(SAVE_SIZE)
    for fid, off, _ in sp.FIELDS:
        if fid in values:
            buf[off] = values[fid]
    buf[13000:13000 + len(SENTINEL)] = SENTINEL
    return bytes(buf)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_geo() -> dict:
    """Synthetic GEO1..8. GEO2 TOC 2 is id 20 with SIG_A at (15,4) and SIG_J at (14,5).
    GEO8 TOC 1 is id 16 with SIG_J at (4,8): the second compatible block for SAVGAMJ, as
    in the retail census. SIG_A appears nowhere else."""
    return {
        "GEO1.DAX": [(18, geo_block()), (24, geo_block())],
        "GEO2.DAX": [(9, geo_block()), (15, geo_block()),
                     (20, geo_block({(15, 4): SIG_A, (14, 5): SIG_J}))],
        "GEO3.DAX": [(0, geo_block())],
        "GEO4.DAX": [(2, geo_block())],
        "GEO5.DAX": [(3, geo_block())],
        "GEO6.DAX": [(1, geo_block())],
        "GEO7.DAX": [(17, geo_block())],
        "GEO8.DAX": [(29, geo_block()), (16, geo_block({(4, 8): SIG_J}))],
    }


def make_install(root: Path, geo: dict = None, saves: dict = None) -> Path:
    install = root / "install"
    install.mkdir(parents=True)
    saves = saves or {"SAVGAMA.DAT": make_save(SAVE_A), "SAVGAMJ.DAT": make_save(SAVE_J)}
    for name, data in saves.items():
        (install / name).write_bytes(data)
    for name, blocks in (default_geo() if geo is None else geo).items():
        (install / name).write_bytes(build_dax(blocks))
    return install


def pins(install: Path) -> tuple[dict, dict]:
    save_pins, geo_pins = {}, {}
    for name in sorted(p.name for p in install.iterdir() if p.name.startswith("SAVGAM")):
        data = (install / name).read_bytes()
        save_pins[name] = (len(data), _sha(data))
    for n in range(1, 9):
        name = "GEO%d.DAX" % n
        data = (install / name).read_bytes()
        geo_pins[name] = (len(data), _sha(data))
    return save_pins, geo_pins


def run(install: Path, root: Path, sub: str = "out", **kw) -> tuple[dict, object]:
    save_pins, geo_pins = pins(install)
    data_root = root / "data"
    kw.setdefault("save", "SAVGAMA.DAT")
    kw.setdefault("ordering", "pose_xy")
    kw.setdefault("area", 2)
    kw.setdefault("facing_from_mapping", True)
    return jp.build(install, data_root / sub, save_pins=save_pins, geo_pins=geo_pins,
                    data_root=data_root, recorded=None, **kw)


@pytest.fixture
def synth(tmp_path):
    return make_install(tmp_path), tmp_path


def _read_all(out: Path) -> dict:
    return {p.name: p.read_bytes() for p in sorted(out.iterdir())}


# ---- emitted plan ------------------------------------------------------------------------

def test_unique_signature_emits_validated_one_area_plan(synth):
    install, root = synth
    rep, plan = run(install, root, sub="emit")
    assert rep["plan_emitted"] is True and rep["refusal"] is None
    assert [b["archive"] + ":" + str(b["toc_index"]) + ":" + str(b["block_id"])
            for b in rep["compatible_blocks"]] == ["GEO2.DAX:2:20"]
    assert plan["designs"] == [{"name": "PSAVGAMA", "geo": 2, "index": 2, "area": 2,
                                "entry": [15, 4], "facing": "west",
                                "title": plan["designs"][0]["title"]}]
    assert len(plan["designs"]) == 1
    out = root / "data" / "emit"
    assert (out / jp.PLAN_FILE).is_file()
    rows, _sha_plan = pp.load_plan(out / jp.PLAN_FILE)
    assert len(rows) == 1 and rows[0]["geo"] == 2 and rows[0]["index"] == 2


def test_provenance_forces_playable_false_and_no_binding(synth):
    install, root = synth
    rep, plan = run(install, root, sub="prov")
    for doc in (rep, plan["provenance"]):
        assert doc["playable"] is False
    assert rep["runtime_binding_claimed"] is False
    assert plan["provenance"]["runtime_binding_claimed"] is False
    assert plan["provenance"]["status"] == "hypothesis"
    assert plan["provenance"]["runtime_loaded"] is False and plan["provenance"]["engine_executed"] is False
    assert rep["join"]["status"] == "hypothesis"


def test_facing_from_candidate_mapping_is_marked_unverified(synth):
    install, root = synth
    rep, plan = run(install, root, sub="facmap")
    assert rep["facing"]["name"] == "west"
    assert rep["facing"]["status"] == sp.FACING_NAME_STATUS
    assert plan["provenance"]["facing_status"] == sp.FACING_NAME_STATUS


def test_caller_supplied_facing_is_used_and_marked(synth):
    install, root = synth
    rep, plan = run(install, root, sub="facname", facing_name="north", facing_from_mapping=False)
    assert plan["designs"][0]["facing"] == "north"
    assert rep["facing"]["status"] == jp.FACING_STATUS_CALLER


def test_requested_block_matching_the_unique_block_emits(synth):
    install, root = synth
    rep, plan = run(install, root, sub="reqok", requested_block="GEO2.DAX:2:20")
    assert rep["plan_emitted"] is True


# ---- refusals: ambiguity, mismatch, absence, repeat --------------------------------------

def test_save_j_reports_both_compatible_blocks_and_refuses(synth):
    install, root = synth
    rep, plan = run(install, root, sub="jref", save="SAVGAMJ.DAT", ordering="pose_xy")
    assert plan is None and rep["plan_emitted"] is False
    ids = [(b["archive"], b["toc_index"], b["block_id"]) for b in rep["compatible_blocks"]]
    assert ids == [("GEO2.DAX", 2, 20), ("GEO8.DAX", 1, 16)]
    assert "2 blocks" in rep["refusal"]
    out = root / "data" / "jref"
    assert (out / jp.REPORT_JSON).is_file() and (out / jp.REPORT_MD).is_file()
    assert not (out / jp.PLAN_FILE).exists()


def test_requested_block_that_is_not_the_unique_block_is_refused(synth):
    install, root = synth
    rep, plan = run(install, root, sub="reqbad", requested_block="GEO3.DAX:0:0")
    assert plan is None
    assert "requested block" in rep["refusal"]


def test_absent_hypothesised_block_is_not_evaluable(synth, tmp_path):
    geo = default_geo()
    geo["GEO2.DAX"] = [(9, geo_block()), (15, geo_block())]   # id 20 removed
    install = make_install(tmp_path / "x", geo=geo)
    rep, plan = run(install, tmp_path, sub="absent")
    assert plan is None
    assert "not evaluable" in rep["refusal"]


def test_repeat_within_the_block_is_refused(synth, tmp_path):
    geo = default_geo()
    geo["GEO2.DAX"][2] = (20, geo_block({(15, 4): SIG_A, (14, 5): SIG_J, (0, 0): SIG_A}))
    install = make_install(tmp_path / "x", geo=geo)
    rep, plan = run(install, tmp_path, sub="repeat")
    assert plan is None
    assert "occurs 2 time" in rep["refusal"]


def test_second_compatible_block_for_save_a_is_refused(synth, tmp_path):
    geo = default_geo()
    geo["GEO8.DAX"] = [(29, geo_block()), (16, geo_block({(4, 8): SIG_A}))]
    install = make_install(tmp_path / "x", geo=geo)
    rep, plan = run(install, tmp_path, sub="twoA")
    assert plan is None
    assert len(rep["compatible_blocks"]) == 2


def test_out_of_grid_pose_is_not_evaluable(synth, tmp_path):
    saves = {"SAVGAMA.DAT": make_save(dict(SAVE_A, pose_x=16)),
             "SAVGAMJ.DAT": make_save(SAVE_J)}
    install = make_install(tmp_path / "x", saves=saves)
    rep, plan = run(install, tmp_path, sub="oog")
    assert plan is None
    assert "not evaluable" in rep["refusal"]


def test_unmapped_raw_facing_refuses_without_inferring(synth, tmp_path):
    saves = {"SAVGAMA.DAT": make_save(dict(SAVE_A, facing_raw=1)),
             "SAVGAMJ.DAT": make_save(SAVE_J)}
    install = make_install(tmp_path / "x", saves=saves)
    rep, plan = run(install, tmp_path, sub="unmapped")
    assert plan is None
    assert "no candidate name" in rep["refusal"]
    assert rep["facing"] is None


# ---- usage and input refusals (nothing written) ----------------------------------------

def test_facing_must_be_named_exactly_once(synth, tmp_path):
    install, root = synth
    with pytest.raises(jp.JoinRefusal):
        run(install, root, sub="nofacing", facing_from_mapping=False)
    with pytest.raises(jp.JoinRefusal):
        run(install, root, sub="both", facing_name="north", facing_from_mapping=True)
    assert not (root / "data" / "nofacing").exists()


def test_unknown_facing_name_and_unknown_save_are_refused(synth):
    install, root = synth
    with pytest.raises(jp.JoinRefusal):
        run(install, root, sub="badf", facing_name="up", facing_from_mapping=False)
    with pytest.raises(jp.JoinRefusal):
        run(install, root, sub="bads", save="SAVGAMX.DAT")
    with pytest.raises(jp.JoinRefusal):
        run(install, root, sub="badord", ordering="pose_zz")


def test_bad_area_and_block_format_refused(synth):
    install, root = synth
    with pytest.raises(jp.JoinRefusal):
        run(install, root, sub="area0", area=0)
    with pytest.raises(jp.JoinRefusal):
        jp.parse_block("GEO2:2:20")
    assert jp.parse_block("GEO2.DAX:2:20") == ("GEO2.DAX", 2, 20)


def test_output_outside_data_or_inside_install_is_refused(synth, tmp_path):
    install, root = synth
    save_pins, geo_pins = pins(install)
    with pytest.raises(jp.JoinRefusal):
        jp.build(install, root / "not-data" / "out", save="SAVGAMA.DAT", ordering="pose_xy",
                 area=2, facing_from_mapping=True, save_pins=save_pins, geo_pins=geo_pins,
                 data_root=root / "data")
    with pytest.raises(jp.JoinRefusal):
        jp.build(install, install / "inside", save="SAVGAMA.DAT", ordering="pose_xy",
                 area=2, facing_from_mapping=True, save_pins=save_pins, geo_pins=geo_pins,
                 data_root=install)


def test_pin_mismatch_is_refused_before_any_output(synth):
    install, root = synth
    save_pins, geo_pins = pins(install)
    save_pins["SAVGAMA.DAT"] = (SAVE_SIZE, "0" * 64)
    with pytest.raises(jp.JoinRefusal):
        jp.build(install, root / "data" / "pin", save="SAVGAMA.DAT", ordering="pose_xy",
                 area=2, facing_from_mapping=True, save_pins=save_pins, geo_pins=geo_pins,
                 data_root=root / "data")
    assert not (root / "data" / "pin").exists()


def test_cli_refuses_output_outside_data_and_writes_nothing(synth, tmp_path):
    install, root = synth
    out = root / "outside"
    rc = jp.main(["--install", str(install), "--save", "SAVGAMA.DAT", "--ordering", "pose_xy",
                  "--area", "2", "--facing", "north", "-o", str(out)])
    assert rc == 2
    assert not out.exists()


# ---- loader validation -------------------------------------------------------------------

def test_plan_the_pipeline_loader_refuses_is_not_written(synth, tmp_path):
    install, root = synth
    rep, plan = run(install, root, sub="ok")
    bad = json.loads(json.dumps(plan))
    bad["designs"][0]["geo"] = 9
    out = root / "data" / "badplan"
    with pytest.raises(jp.JoinRefusal):
        jp.write_outputs(rep, bad, out)
    assert not (out / jp.PLAN_FILE).exists()


def test_plan_name_is_bounded_and_distinct_per_save():
    assert jp.plan_name("SAVGAMA.DAT") == "PSAVGAMA"
    assert jp.plan_name("SAVGAMJ.DAT") == "PSAVGAMJ"
    assert len(jp.plan_name("SAVGAMJ.DAT")) <= 8


# ---- determinism, path hygiene, sentinel ----------------------------------------------

def test_outputs_are_deterministic_and_path_free(synth):
    install, root = synth
    run(install, root, sub="det1")
    run(install, root, sub="det2")
    a = _read_all(root / "data" / "det1")
    b = _read_all(root / "data" / "det2")
    assert a == b and set(a) == {jp.REPORT_JSON, jp.REPORT_MD, jp.PLAN_FILE}
    for name, raw in a.items():
        text = raw.decode("utf-8")
        assert str(root) not in text and str(install) not in text
        assert not re.search(r"[A-Za-z]:[\\/]", text), name
        assert "/tmp" not in text and "\\Users\\" not in text
        assert SENTINEL.decode() not in text


def test_report_labels_join_as_hypothesis_and_is_json_stable(synth):
    install, root = synth
    run(install, root, sub="lab")
    doc = json.loads((root / "data" / "lab" / jp.REPORT_JSON).read_text(encoding="utf-8"))
    assert doc["schema"] == jp.SCHEMA and doc["playable"] is False
    classes = {f["class"] for f in doc["facts"]}
    assert {"observed", "computed", "hypothesis", "candidate"} <= classes
    md = (root / "data" / "lab" / jp.REPORT_MD).read_text(encoding="utf-8")
    assert "playable: false" in md and "hypothesis" in md


# ---- retail-gated anchor -----------------------------------------------------------------

@pytest.mark.skipif(not RETAIL_ENV, reason="%s not set; retail anchor skipped" % jp.INSTALL_ENV)
class TestRetailAnchor:
    @pytest.fixture
    def install(self):
        p = Path(RETAIL_ENV)
        if not (p / "SAVGAMA.DAT").is_file():
            pytest.skip("retail install not present at %s" % RETAIL_ENV)
        return p

    def test_savgama_emits_unique_geo2_block_20_plan(self, install, tmp_path):
        rep, plan = jp.build(install, tmp_path / "data" / "r1", save="SAVGAMA.DAT",
                             ordering="pose_xy", area=2, facing_from_mapping=True,
                             requested_block="GEO2.DAX:2:20", data_root=tmp_path / "data",
                             recorded=None)
        assert plan is not None
        assert plan["designs"][0]["entry"] == [15, 4]
        assert plan["designs"][0]["facing"] == "west"
        assert (plan["designs"][0]["geo"], plan["designs"][0]["index"]) == (2, 2)
        assert plan["provenance"]["playable"] is False
        assert rep["install_unchanged"] is True

    def test_savgamj_reports_both_blocks_and_refuses(self, install, tmp_path):
        rep, plan = jp.build(install, tmp_path / "data" / "r2", save="SAVGAMJ.DAT",
                             ordering="pose_xy", area=2, facing_from_mapping=True,
                             data_root=tmp_path / "data", recorded=None)
        assert plan is None
        ids = [(b["archive"], b["toc_index"], b["block_id"]) for b in rep["compatible_blocks"]]
        assert ids == [("GEO2.DAX", 2, 20), ("GEO8.DAX", 1, 16)]
