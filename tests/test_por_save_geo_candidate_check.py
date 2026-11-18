"""Tests for tools/por_save_geo_candidate_check.py (save position vs GEO cell signatures).

Synthetic cases build stand-in saves and small DAX archives in a temp install and pin
their own hashes, so they run without the retail install. Filler cells use a value that
cannot collide with the candidate signature unless a test puts it there on purpose.

The retail class runs only when OPENUA_POR_INSTALL names a folder holding both pinned saves
and all eight pinned GEO archives. Its assertions are the recorded outcomes of the 2026-11-17
run, not claims about the game.
"""
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_save_geo_candidate_check as tool  # noqa: E402
import por_save_state_probe as sp  # noqa: E402

REPO = Path(TESTS).resolve().parent
RETAIL_ENV = os.environ.get(tool.INSTALL_ENV)
SAVE_SIZE = 13137
SENTINEL = b"SENTINEL-SAVE-TAIL-DO-NOT-LEAK"

# Signature cells. SIG_A is the SAVGAMA (15,4) cell and SIG_J the SAVGAMJ (14,5) cell,
# as recorded in docs/por-save-state-probe.md (descriptor 0, facing edge slot 0 door 0).
SIG_A = {"N": (14, 0), "E": (11, 1), "S": (14, 0), "W": (0, 0), "desc": 0}
SIG_J = {"N": (10, 1), "E": (0, 0), "S": (0, 0), "W": (9, 0), "desc": 0}
BASE = {"N": (1, 1), "E": (1, 1), "S": (1, 1), "W": (1, 1), "desc": 0x55}


def geo_block(overrides=None) -> bytes:
    """A 1026-byte Gen1 GEO block: size field 1024, four 256-byte planes."""
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
    """Signed-byte RLE using only literal runs (control c < 0x80 copies c+1 bytes)."""
    out = bytearray()
    for i in range(0, len(raw), 128):
        chunk = raw[i:i + 128]
        out.append(len(chunk) - 1)
        out += chunk
    return bytes(out)


def build_dax(blocks: list) -> bytes:
    """A DAX container: u16 TOC size, 9-byte TOC entries, contiguous data chain."""
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


SAVE_A_VALUES = {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
                 "pose_x": 15, "pose_y": 4, "facing_raw": 6}
SAVE_J_VALUES = {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
                 "pose_x": 14, "pose_y": 5, "facing_raw": 4}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_geo() -> dict:
    """Filler archives GEO1..8 with one hypothesised block (GEO2 TOC 2, id 20)."""
    geo = {
        "GEO1.DAX": [(18, geo_block()), (24, geo_block())],
        "GEO2.DAX": [(9, geo_block()), (15, geo_block()),
                     (20, geo_block({(15, 4): SIG_A, (14, 5): SIG_J}))],
        "GEO3.DAX": [(0, geo_block())],
        "GEO4.DAX": [(2, geo_block())],
        "GEO5.DAX": [(3, geo_block())],
        "GEO6.DAX": [(1, geo_block())],
        "GEO7.DAX": [(17, geo_block())],
        "GEO8.DAX": [(16, geo_block()), (29, geo_block())],
    }
    return geo


def make_install(root: Path, geo: dict = None, saves: dict = None) -> Path:
    install = root / "install"
    install.mkdir(parents=True)
    saves = saves or {"SAVGAMA.DAT": make_save(SAVE_A_VALUES),
                      "SAVGAMJ.DAT": make_save(SAVE_J_VALUES)}
    for name, data in saves.items():
        (install / name).write_bytes(data)
    geo = default_geo() if geo is None else geo
    for name, blocks in geo.items():
        (install / name).write_bytes(build_dax(blocks))
    return install


def pins(install: Path) -> tuple[dict, dict]:
    save_pins = {}
    for name in ("SAVGAMA.DAT", "SAVGAMJ.DAT"):
        data = (install / name).read_bytes()
        save_pins[name] = (len(data), _sha(data))
    geo_pins = {}
    for n in range(1, 9):
        name = "GEO%d.DAX" % n
        data = (install / name).read_bytes()
        geo_pins[name] = (len(data), _sha(data))
    return save_pins, geo_pins


def run(install: Path, root: Path, **kw) -> dict:
    save_pins, geo_pins = pins(install)
    data_root = root / "data"
    out = data_root / "out"
    return tool.check(install, out, save_pins=save_pins, geo_pins=geo_pins,
                      data_root=data_root, recorded=kw.pop("recorded", None), **kw)


def cand(doc: dict, save: str, ordering: str) -> dict:
    for c in doc["candidates"]:
        if c["save"] == save and c["ordering"] == ordering:
            return c
    raise KeyError((save, ordering))


@pytest.fixture
def synth(tmp_path):
    return make_install(tmp_path), tmp_path


# ---- signature search -------------------------------------------------------------

def test_candidate_signature_unique_to_hypothesised_block(synth):
    install, root = synth
    doc = run(install, root)
    a = cand(doc, "SAVGAMA.DAT", "pose_xy")
    assert (a["x"], a["y"], a["in_bounds"]) == (15, 4, True)
    assert a["facing_edge_candidate"] == "W"
    full = a["signatures"]["full_cell"]
    assert full["verdict"] == "unique-to-hypothesised-block"
    assert full["match_count"] == 1
    assert full["same_position_match_count"] == 1
    assert full["matches"][0] == {"archive": "GEO2.DAX", "toc_index": 2, "block_id": 20,
                                  "x": 15, "y": 4, "same_position": True,
                                  "hypothesised_block": True}
    assert a["signatures"]["facing_edge"]["verdict"] == "unique-to-hypothesised-block"


def test_signature_repeated_in_other_block_is_non_unique(synth):
    install, root = synth
    geo = default_geo()
    geo["GEO8.DAX"] = [(16, geo_block({(4, 8): SIG_J})), (29, geo_block())]
    install = make_install(root / "b", geo=geo)
    doc = run(install, root / "b")
    j = cand(doc, "SAVGAMJ.DAT", "pose_xy")
    full = j["signatures"]["full_cell"]
    assert full["verdict"] == "non-unique-across-blocks"
    assert full["match_count"] == 2
    assert {"archive": "GEO8.DAX", "toc_index": 0, "block_id": 16, "cell_matches": 1} in full["distinct_blocks"]
    other = [m for m in full["matches"] if not m["hypothesised_block"]]
    assert other == [{"archive": "GEO8.DAX", "toc_index": 0, "block_id": 16, "x": 4, "y": 8,
                      "same_position": False, "hypothesised_block": False}]


def test_repeat_inside_hypothesised_block_only(synth):
    install, root = synth
    geo = default_geo()
    geo["GEO2.DAX"][2] = (20, geo_block({(15, 4): SIG_A, (0, 0): SIG_A, (14, 5): SIG_J}))
    install = make_install(root / "c", geo=geo)
    doc = run(install, root / "c")
    full = cand(doc, "SAVGAMA.DAT", "pose_xy")["signatures"]["full_cell"]
    assert full["verdict"] == "repeats-only-within-hypothesised-block"
    assert full["match_count"] == 2
    assert full["same_position_match_count"] == 1
    assert full["candidate_block_match_count"] == 2


def test_ordering_swap_uses_swapped_cell(tmp_path):
    values = dict(SAVE_A_VALUES, pose_x=3, pose_y=9)
    install = make_install(tmp_path, saves={"SAVGAMA.DAT": make_save(values),
                                             "SAVGAMJ.DAT": make_save(SAVE_J_VALUES)})
    doc = run(install, tmp_path)
    xy = cand(doc, "SAVGAMA.DAT", "pose_xy")
    yx = cand(doc, "SAVGAMA.DAT", "pose_yx")
    assert (xy["x"], xy["y"]) == (3, 9)
    assert (yx["x"], yx["y"]) == (9, 3)
    assert xy["candidate_cell"]["x"] == 3 and xy["candidate_cell"]["y"] == 9
    assert yx["candidate_cell"]["x"] == 9 and yx["candidate_cell"]["y"] == 3


def test_out_of_grid_position_is_not_evaluable(tmp_path):
    values = dict(SAVE_A_VALUES, pose_x=16)
    install = make_install(tmp_path, saves={"SAVGAMA.DAT": make_save(values),
                                             "SAVGAMJ.DAT": make_save(SAVE_J_VALUES)})
    doc = run(install, tmp_path)
    for ordering in ("pose_xy", "pose_yx"):
        c = cand(doc, "SAVGAMA.DAT", ordering)
        assert c["in_bounds"] is False
        assert c["candidate_cell"] is None
        for sid in ("full_cell", "facing_edge"):
            assert c["signatures"][sid]["verdict"] == "not-evaluable"
            assert c["signatures"][sid]["evaluable"] is False
            assert "outside the 16 x 16 grid" in c["signatures"][sid]["reason"]


def test_unmapped_facing_leaves_full_cell_evaluable(tmp_path):
    values = dict(SAVE_A_VALUES, facing_raw=5)
    install = make_install(tmp_path, saves={"SAVGAMA.DAT": make_save(values),
                                             "SAVGAMJ.DAT": make_save(SAVE_J_VALUES)})
    doc = run(install, tmp_path)
    a = cand(doc, "SAVGAMA.DAT", "pose_xy")
    assert a["facing_candidate"] == "unmapped"
    assert a["facing_edge_candidate"] is None
    assert a["signatures"]["full_cell"]["verdict"] == "unique-to-hypothesised-block"
    assert a["signatures"]["facing_edge"]["verdict"] == "not-evaluable"


def test_hypothesised_block_absent_is_not_evaluable(tmp_path):
    geo = default_geo()
    geo["GEO2.DAX"][2] = (21, geo_block({(15, 4): SIG_A, (14, 5): SIG_J}))
    install = make_install(tmp_path, geo=geo)
    doc = run(install, tmp_path)
    a = cand(doc, "SAVGAMA.DAT", "pose_xy")
    assert a["candidate_cell"] is None
    assert "not decoded" in a["signatures"]["full_cell"]["reason"]
    assert doc["block_id_20_occurrences"] == []


def test_block_id_20_census_lists_every_occurrence(tmp_path):
    geo = default_geo()
    geo["GEO5.DAX"] = [(3, geo_block()), (20, geo_block())]
    install = make_install(tmp_path, geo=geo)
    doc = run(install, tmp_path)
    assert doc["block_id_20_occurrences"] == [
        {"archive": "GEO2.DAX", "toc_index": 2}, {"archive": "GEO5.DAX", "toc_index": 1}]


# ---- undecodable blocks, scope -----------------------------------------------------

def test_undecodable_block_is_skipped_and_listed(tmp_path):
    bad = struct.pack("<H", 1000) + b"\x00" * 1024
    geo = default_geo()
    geo["GEO5.DAX"] = [(3, geo_block()), (7, bad)]
    install = make_install(tmp_path, geo=geo)
    doc = run(install, tmp_path)
    g5 = [a for a in doc["inputs"]["archives"] if a["name"] == "GEO5.DAX"][0]
    assert g5["toc_entries"] == 2 and g5["decoded_blocks"] == 1
    assert g5["skipped_blocks"][0]["toc_index"] == 1
    assert g5["skipped_blocks"][0]["block_id"] == 7
    assert "size field" in g5["skipped_blocks"][0]["reason"]
    assert doc["search_scope"]["search_complete"] is False
    assert doc["search_scope"]["skipped_blocks"] == 1
    assert doc["search_scope"]["decoded_blocks"] == 12


def test_scope_counts_all_eight_archives(synth):
    install, root = synth
    doc = run(install, root)
    assert [a["name"] for a in doc["inputs"]["archives"]] == ["GEO%d.DAX" % n for n in range(1, 9)]
    assert doc["search_scope"]["archives"] == 8
    assert doc["search_scope"]["toc_entries"] == doc["search_scope"]["decoded_blocks"] == 12
    assert doc["search_scope"]["search_complete"] is True


# ---- refusals --------------------------------------------------------------------

def test_malformed_dax_is_refused_without_output(tmp_path):
    install = make_install(tmp_path)
    # TOC size 8 is not a multiple of 9. Pin the bad bytes so the parser is reached.
    (install / "GEO3.DAX").write_bytes(b"\x08\x00" + b"\x00" * 40)
    save_pins, geo_pins = pins(install)
    out = tmp_path / "data" / "out"
    with pytest.raises(tool.CheckRefusal, match="GEO3.DAX"):
        tool.check(install, out, save_pins=save_pins, geo_pins=geo_pins,
                   data_root=tmp_path / "data")
    assert not out.exists()


def test_missing_archive_is_refused(tmp_path):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    (install / "GEO4.DAX").unlink()
    with pytest.raises(tool.CheckRefusal, match="missing input GEO4.DAX"):
        tool.check(install, tmp_path / "data" / "out", save_pins=save_pins,
                   geo_pins=geo_pins, data_root=tmp_path / "data")


def test_archive_hash_mismatch_is_refused(tmp_path):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    path = install / "GEO2.DAX"
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(tool.CheckRefusal, match="GEO2.DAX sha256 does not match"):
        tool.check(install, tmp_path / "data" / "out", save_pins=save_pins,
                   geo_pins=geo_pins, data_root=tmp_path / "data")


def test_save_size_mismatch_is_refused(tmp_path):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    (install / "SAVGAMA.DAT").write_bytes(make_save(SAVE_A_VALUES)[:-1])
    with pytest.raises(tool.CheckRefusal, match="SAVGAMA.DAT size is 13136"):
        tool.check(install, tmp_path / "data" / "out", save_pins=save_pins,
                   geo_pins=geo_pins, data_root=tmp_path / "data")


def test_save_hash_mismatch_is_refused(tmp_path):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    changed = bytearray(make_save(SAVE_A_VALUES))
    changed[12801] ^= 1
    (install / "SAVGAMJ.DAT").write_bytes(bytes(changed))
    with pytest.raises(tool.CheckRefusal, match="SAVGAMJ.DAT sha256 does not match"):
        tool.check(install, tmp_path / "data" / "out", save_pins=save_pins,
                   geo_pins=geo_pins, data_root=tmp_path / "data")


def test_input_changed_during_run_is_refused(tmp_path, monkeypatch):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    original = tool.decode_archive

    def tamper(name, data):
        result = original(name, data)
        if name == "GEO1.DAX":
            p = install / "GEO3.DAX"
            b = bytearray(p.read_bytes())
            b[-1] ^= 0x01
            p.write_bytes(bytes(b))
        return result

    monkeypatch.setattr(tool, "decode_archive", tamper)
    with pytest.raises(tool.CheckRefusal, match="GEO3.DAX changed during the run"):
        tool.check(install, tmp_path / "data" / "out", save_pins=save_pins,
                   geo_pins=geo_pins, data_root=tmp_path / "data")
    assert not (tmp_path / "data" / "out").exists()


@pytest.mark.parametrize("where", ["outside", "inside_install"])
def test_output_location_is_refused(tmp_path, where):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    if where == "outside":
        out, data_root = tmp_path / "elsewhere" / "out", tmp_path / "data"
    else:
        out, data_root = install / "data" / "out", install / "data"
    with pytest.raises(tool.CheckRefusal):
        tool.check(install, out, save_pins=save_pins, geo_pins=geo_pins, data_root=data_root)
    assert not out.exists()


def test_symlinked_archive_is_refused(tmp_path):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    real = install / "GEO6.DAX"
    target = tmp_path / "elsewhere" / "GEO6.DAX"
    target.parent.mkdir()
    target.write_bytes(real.read_bytes())
    real.unlink()
    try:
        os.symlink(target, real)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this host")
    with pytest.raises(tool.CheckRefusal, match="GEO6.DAX is a symbolic link"):
        tool.check(install, tmp_path / "data" / "out", save_pins=save_pins,
                   geo_pins=geo_pins, data_root=tmp_path / "data")


def test_missing_install_is_refused(tmp_path):
    with pytest.raises(tool.CheckRefusal, match="install folder not found"):
        tool.check(tmp_path / "nope", tmp_path / "data" / "out", data_root=tmp_path / "data")


def test_cli_refuses_output_outside_data_with_exit_2(tmp_path, capsys):
    install = make_install(tmp_path)
    code = tool.main(["--install", str(install), "-o", str(tmp_path / "elsewhere")])
    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "elsewhere").exists()


# ---- recorded comparison, flags, determinism and hygiene ---------------------------

def test_flags_and_recorded_comparison(tmp_path):
    install = make_install(tmp_path)
    doc = run(install, tmp_path, recorded=sp.RECORDED_OBSERVATIONS)
    assert doc["schema"] == tool.SCHEMA
    assert doc["playable"] is False
    assert doc["runtime_established"] is False
    assert doc["runtime_binding_claimed"] is False
    assert doc["install_unchanged"] is True
    saves = {s["name"]: s for s in doc["inputs"]["saves"]}
    assert saves["SAVGAMA.DAT"]["fields"]["pose_x"]["matches_recorded_observation"] is True
    assert saves["SAVGAMJ.DAT"]["fields"]["facing_raw"]["matches_recorded_observation"] is True
    assert saves["SAVGAMA.DAT"]["fields"]["facing_raw"]["candidate_name"] == "west"


def test_outputs_are_deterministic_and_leak_nothing(tmp_path):
    install = make_install(tmp_path)
    save_pins, geo_pins = pins(install)
    texts = []
    for i in range(2):
        data_root = tmp_path / ("data%d" % i)
        out = data_root / "out"
        doc = tool.check(install, out, save_pins=save_pins, geo_pins=geo_pins, data_root=data_root)
        tool.write_outputs(doc, out)
        texts.append((out / "por_save_geo_candidate_check.json").read_bytes()
                     + b"\n----\n" + (out / "por_save_geo_candidate_check_report.md").read_bytes())
    assert texts[0] == texts[1]
    blob = texts[0].decode("utf-8")
    assert str(tmp_path) not in blob
    assert str(install) not in blob
    assert "SENTINEL" not in blob
    assert "install/" not in blob and "install\\" not in blob
    assert "C:\\" not in blob and "G:/" not in blob
    d = json.loads(texts[0].split(b"\n----\n")[0])
    assert d["schema"] == tool.SCHEMA
    assert "candidate-compatibility-only" in blob
    for s in d["inputs"]["saves"]:
        for f in s["fields"].values():
            assert set(f) <= {"offset", "offset_hex", "value", "role", "candidate_name",
                              "matches_recorded_observation"}


def test_report_states_compatibility_not_binding(tmp_path):
    install = make_install(tmp_path)
    doc = run(install, tmp_path)
    report = tool.render_report(doc)
    for heading in ("## 1. Directly observed saved bytes", "## 2. Decoded GEO cell bytes",
                    "## 3. Candidate join", "## 4. Search results",
                    "## 6. Hypothesis and claim limits"):
        assert heading in report
    assert "not a runtime binding" in report
    assert "compatibility evidence only" in report


# ---- retail-gated ------------------------------------------------------------------

def _retail_ready() -> bool:
    if not RETAIL_ENV:
        return False
    root = Path(RETAIL_ENV)
    if not root.is_dir():
        return False
    names = ["SAVGAMA.DAT", "SAVGAMJ.DAT"] + ["GEO%d.DAX" % n for n in range(1, 9)]
    return all((root / n).is_file() for n in names)


@pytest.fixture(scope="module")
def retail_doc(tmp_path_factory):
    """Runs only when a retail test requests it (the skipif gates the class)."""
    root = tmp_path_factory.mktemp("retail")
    install = Path(RETAIL_ENV)
    data_root = root / "data"
    out = data_root / "out"
    doc = tool.check(install, out, data_root=data_root, recorded=sp.RECORDED_OBSERVATIONS)
    tool.write_outputs(doc, out)
    return doc, out


@pytest.mark.skipif(not _retail_ready(),
                    reason="OPENUA_POR_INSTALL not set or install lacks the pinned inputs")
class TestRetail:
    """Recorded outcomes of the 2026-11-17 run. Regression checks, not game claims."""

    @pytest.fixture
    def doc(self, retail_doc):
        return retail_doc

    def test_all_pins_matched_and_search_complete(self, doc):
        d, _ = doc
        assert [s["pin"] for s in d["inputs"]["saves"]] == ["matched", "matched"]
        assert [a["pin"] for a in d["inputs"]["archives"]] == ["matched"] * 8
        sc = d["search_scope"]
        assert (sc["archives"], sc["toc_entries"], sc["decoded_blocks"], sc["skipped_blocks"]) == (8, 29, 29, 0)
        assert sc["search_complete"] is True

    def test_block_id_20_only_in_geo2_toc2(self, doc):
        d, _ = doc
        assert d["block_id_20_occurrences"] == [{"archive": "GEO2.DAX", "toc_index": 2}]

    def test_candidate_cells_match_recorded_readings(self, doc):
        d, _ = doc
        a = cand(d, "SAVGAMA.DAT", "pose_xy")["candidate_cell"]
        j = cand(d, "SAVGAMJ.DAT", "pose_xy")["candidate_cell"]
        assert a["edges"]["W"] == [0, 0] and a["descriptor"] == 0
        assert j["edges"]["S"] == [0, 0] and j["descriptor"] == 0

    def test_savgama_full_cell_unique_to_hypothesised_block(self, doc):
        d, _ = doc
        full = cand(d, "SAVGAMA.DAT", "pose_xy")["signatures"]["full_cell"]
        assert full["verdict"] == "unique-to-hypothesised-block"
        assert full["match_count"] == 1

    def test_savgamj_full_cell_also_in_geo8_toc1(self, doc):
        d, _ = doc
        full = cand(d, "SAVGAMJ.DAT", "pose_xy")["signatures"]["full_cell"]
        assert full["verdict"] == "non-unique-across-blocks"
        assert full["match_count"] == 2
        others = [m for m in full["matches"] if not m["hypothesised_block"]]
        assert [(m["archive"], m["toc_index"], m["block_id"], m["x"], m["y"]) for m in others] == \
            [("GEO8.DAX", 1, 16, 4, 8)]

    def test_retail_outputs_are_path_clean(self, doc):
        d, out = doc
        blob = (out / "por_save_geo_candidate_check.json").read_text(encoding="utf-8") \
            + (out / "por_save_geo_candidate_check_report.md").read_text(encoding="utf-8")
        assert RETAIL_ENV not in blob
        assert "Caldor" not in blob
        assert "G:/" not in blob and "G:\\" not in blob
