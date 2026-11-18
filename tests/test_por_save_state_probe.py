"""Tests for tools/por_save_state_probe.py (PoR read-only saved-state byte probe).

Synthetic cases build 13,137-byte stand-in saves in a temp install and pin their own
hashes, so the probe runs without the retail install. Sidecars in the temp install hold
a sentinel that must never be read. The retail class runs only when the local install and
both pinned saves are present, and is skipped otherwise. Retail assertions are the byte
observations recorded in docs/por-save-state-probe.md, not claims about the save format.
"""
import builtins
import hashlib
import json
import os
import sys
from functools import lru_cache
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_save_state_probe as probe_tool  # noqa: E402

REPO = Path(TESTS).resolve().parent
RETAIL = Path(os.environ.get(probe_tool.INSTALL_ENV) or probe_tool.DEFAULT_INSTALL)
SIZE = 13137
SENTINEL = b"SENTINEL-SIDECAR-CONTENT-DO-NOT-READ"


def _make_save(values: dict, refs: bytes = b"") -> bytes:
    """A stand-in save: zero-filled, with the candidate bytes and optional sidecar names."""
    buf = bytearray(SIZE)
    for fid, off, _ in probe_tool.FIELDS:
        if fid in values:
            buf[off] = values[fid]
    assert 13000 + len(refs) <= SIZE
    buf[13000:13000 + len(refs)] = refs
    return bytes(buf)


SYNTH_VALUES = {"wrapper_game_area": 2, "ecl_member": 20, "area2_game_area": 2,
                "pose_x": 15, "pose_y": 4, "facing_raw": 6}
SYNTH_REFS = b"..CHRDATA1..CHRDATJ2..CHRDATA1.."


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def synth(tmp_path):
    """A temp install with a pinned synthetic SAVGAMA.DAT and sentinel sidecars."""
    install = tmp_path / "install"
    install.mkdir()
    save = _make_save(SYNTH_VALUES, SYNTH_REFS)
    (install / "SAVGAMA.DAT").write_bytes(save)
    (install / "CHRDATA1.SAV").write_bytes(SENTINEL)
    (install / "CHRDATJ2.ITM").write_bytes(SENTINEL)
    pins = {"SAVGAMA.DAT": (SIZE, _sha(save))}
    data_root = tmp_path / "data"
    data_root.mkdir()
    return {"install": install, "pins": pins, "data_root": data_root, "save": save,
            "tmp": tmp_path}


# ---- pure observation -------------------------------------------------------------

def test_candidate_offsets_are_the_reference_offsets():
    offs = {fid: off for fid, off, _ in probe_tool.FIELDS}
    assert offs == {
        "wrapper_game_area": 0,
        "ecl_member": 485,
        "area2_game_area": 3621,
        "pose_x": 12801,
        "pose_y": 12802,
        "facing_raw": 12803,
    }


def test_observe_reads_values_at_candidate_offsets():
    save = _make_save(SYNTH_VALUES)
    obs = probe_tool.observe_save(save, "SAVGAMA.DAT", _sha(save))
    got = {fid: f["value"] for fid, f in obs["fields"].items()}
    assert got == SYNTH_VALUES
    assert obs["fields"]["ecl_member"]["offset_hex"] == "0x1E5"
    assert obs["fields"]["pose_x"]["offset"] == 12801
    assert all(f["status"] == "candidate-byte-observed" for f in obs["fields"].values())


def test_facing_candidate_name_and_unmapped_keep_raw_byte():
    west = probe_tool.observe_save(_make_save({"facing_raw": 6}), "a", "x")
    assert west["fields"]["facing_raw"]["candidate_name"] == "west"
    assert west["fields"]["facing_raw"]["value"] == 6
    odd = probe_tool.observe_save(_make_save({"facing_raw": 7}), "a", "x")
    assert odd["fields"]["facing_raw"]["candidate_name"] == "unmapped"
    assert odd["fields"]["facing_raw"]["value"] == 7
    assert "unverified" in west["fields"]["facing_raw"]["candidate_name_status"]


def test_recorded_comparison_flags_each_field():
    save = _make_save({**SYNTH_VALUES, "pose_x": 99})
    obs = probe_tool.observe_save(save, "a", "x", recorded=SYNTH_VALUES)
    assert obs["fields"]["pose_x"]["matches_recorded_observation"] is False
    assert obs["fields"]["ecl_member"]["matches_recorded_observation"] is True


def test_short_data_is_refused():
    with pytest.raises(probe_tool.ProbeRefusal, match="too short"):
        probe_tool.observe_save(b"\x00" * 100, "a", "x")


# ---- sidecars: names only ---------------------------------------------------------

def test_sidecar_inventory_lists_names_and_never_opens(synth, monkeypatch):
    opened = []
    real_open = builtins.open
    real_read_bytes = Path.read_bytes

    def spy_open(file, *a, **k):
        opened.append(str(file))
        return real_open(file, *a, **k)

    def spy_read_bytes(self):
        opened.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)
    inv = probe_tool.sidecar_inventory(synth["install"], synth["save"])
    assert inv["referenced_by_name"] == ["CHRDATA1", "CHRDATJ2"]
    assert inv["present_files"] == ["CHRDATA1.SAV", "CHRDATJ2.ITM"]
    assert inv["missing"] == []
    assert inv["content_examined"] is False
    assert not any("CHRDAT" in p for p in opened)


def test_sidecar_missing_and_suffix_rules(tmp_path):
    install = tmp_path / "inst"
    install.mkdir()
    (install / "CHRDATA2.TXT").write_bytes(b"x")  # wrong suffix: not a sidecar
    (install / "CHRDATA3.SPC").mkdir()            # a directory: not a sidecar
    save = _make_save({}, b"CHRDATA2 CHRDATA3")
    inv = probe_tool.sidecar_inventory(install, save)
    assert inv["referenced_by_name"] == ["CHRDATA2", "CHRDATA3"]
    assert inv["present_files"] == []
    assert inv["missing"] == ["CHRDATA2", "CHRDATA3"]


# ---- probe() and refusals ---------------------------------------------------------

def test_probe_writes_deterministic_outputs_without_paths_or_content(synth):
    out = synth["data_root"] / "out"
    doc = probe_tool.probe(synth["install"], out, pins=synth["pins"],
                           data_root=synth["data_root"], recorded=None)
    probe_tool.write_outputs(doc, out)
    first = (out / "por_save_state_probe.json").read_bytes()
    report = (out / "por_save_state_probe_report.md").read_text(encoding="utf-8")
    doc2 = probe_tool.probe(synth["install"], out, pins=synth["pins"],
                            data_root=synth["data_root"], recorded=None)
    probe_tool.write_outputs(doc2, out)
    assert (out / "por_save_state_probe.json").read_bytes() == first

    text = first.decode("utf-8") + report
    assert str(synth["install"]) not in text
    assert str(synth["tmp"]) not in text
    assert SENTINEL.decode() not in text
    assert doc["playable"] is False and doc["runtime_established"] is False
    assert doc["install_unchanged"] is True
    assert doc["recorded_comparison"] is False
    parsed = json.loads(first)
    assert parsed["schema"] == "openua.por-save-state-probe"
    assert parsed["saves"][0]["size"] == SIZE


def test_limitations_name_each_boundary(synth):
    doc = probe_tool.probe(synth["install"], synth["data_root"] / "o", pins=synth["pins"],
                           data_root=synth["data_root"], recorded=None)
    text = " ".join(doc["limitations"])
    for phrase in ("No full save schema", "No new-game start", "No live DOS state",
                   "No GEO TOC mapping", "No CoK or DoK"):
        assert phrase in text


def test_size_mismatch_is_refused(synth):
    (synth["install"] / "SAVGAMA.DAT").write_bytes(synth["save"][:-1])
    with pytest.raises(probe_tool.ProbeRefusal, match="expected the pinned"):
        probe_tool.probe(synth["install"], synth["data_root"] / "o", pins=synth["pins"],
                         data_root=synth["data_root"], recorded=None)


def test_unpinned_hash_is_refused(synth):
    changed = bytearray(synth["save"])
    changed[12803] ^= 0x01
    (synth["install"] / "SAVGAMA.DAT").write_bytes(bytes(changed))
    with pytest.raises(probe_tool.ProbeRefusal, match="does not match its pin"):
        probe_tool.probe(synth["install"], synth["data_root"] / "o", pins=synth["pins"],
                         data_root=synth["data_root"], recorded=None)


def test_missing_save_and_install_are_refused(synth):
    (synth["install"] / "SAVGAMA.DAT").unlink()
    with pytest.raises(probe_tool.ProbeRefusal, match="missing save file"):
        probe_tool.probe(synth["install"], synth["data_root"] / "o", pins=synth["pins"],
                         data_root=synth["data_root"], recorded=None)
    with pytest.raises(probe_tool.ProbeRefusal, match="install folder not found"):
        probe_tool.probe(synth["tmp"] / "nope", synth["data_root"] / "o", pins=synth["pins"],
                         data_root=synth["data_root"], recorded=None)


@pytest.mark.parametrize("which", ["outside", "root", "inside_install", "contains_install"])
def test_output_location_refusals(synth, which):
    install = synth["install"]
    targets = {
        "outside": synth["tmp"] / "elsewhere",
        "root": synth["data_root"],
        "inside_install": install / "sub",
        "contains_install": synth["tmp"],
    }
    with pytest.raises(probe_tool.ProbeRefusal):
        probe_tool.probe(install, targets[which], pins=synth["pins"],
                         data_root=synth["data_root"], recorded=None)


def test_repo_tree_outside_data_is_refused(synth):
    with pytest.raises(probe_tool.ProbeRefusal, match="under data/"):
        probe_tool.check_output(REPO / "docs" / "x", synth["install"], REPO / "data")


def test_cli_refusal_writes_nothing(synth, capsys):
    out = synth["data_root"] / "never"
    rc = probe_tool.main(["--install", str(synth["tmp"] / "missing"), "-o", str(out)])
    assert rc == 2
    assert not out.exists()
    assert "refused" in capsys.readouterr().err


def test_cli_requires_explicit_output(synth):
    with pytest.raises(SystemExit):
        probe_tool.main(["--install", str(synth["install"])])


# ---- retail-gated -----------------------------------------------------------------

def _retail_ready() -> bool:
    return all((RETAIL / name).is_file() for name in probe_tool.SAVE_PINS)


RETAIL_OUT = REPO / "data" / "work" / "por-save-state-probe" / "retail-test"


@lru_cache(maxsize=1)
def _retail_doc():
    return probe_tool.probe(RETAIL, RETAIL_OUT)


@pytest.mark.skipif(not _retail_ready(), reason="retail install with both saves not present")
class TestRetailSaves:
    OUT = RETAIL_OUT

    @pytest.fixture
    def doc(self):
        return _retail_doc()

    def test_pins_matched_and_install_unchanged(self, doc):
        assert [s["name"] for s in doc["saves"]] == ["SAVGAMA.DAT", "SAVGAMJ.DAT"]
        assert all(s["pin"] == "matched" and s["size"] == SIZE for s in doc["saves"])
        assert doc["install_unchanged"] is True

    def test_recorded_observations_still_match(self, doc):
        for save in doc["saves"]:
            for fid, f in save["fields"].items():
                assert f["matches_recorded_observation"] is True, (save["name"], fid)

    def test_expected_values(self, doc):
        by_name = {s["name"]: {k: v["value"] for k, v in s["fields"].items()} for s in doc["saves"]}
        assert by_name["SAVGAMA.DAT"] == {"wrapper_game_area": 2, "ecl_member": 20,
                                          "area2_game_area": 2, "pose_x": 15, "pose_y": 4,
                                          "facing_raw": 6}
        assert by_name["SAVGAMJ.DAT"] == {"wrapper_game_area": 2, "ecl_member": 20,
                                          "area2_game_area": 2, "pose_x": 14, "pose_y": 5,
                                          "facing_raw": 4}

    def test_sidecars_are_names_only(self, doc):
        for name, inv in doc["sidecars"].items():
            assert inv["content_examined"] is False
            assert inv["referenced_by_name"], name
            for present in inv["present_files"]:
                assert present.upper().endswith((".SAV", ".ITM", ".SPC"))

    def test_cli_writes_outputs_without_install_path(self):
        rc = probe_tool.main(["--install", str(RETAIL), "-o",
                              str(self.OUT.relative_to(REPO))])
        assert rc == 0
        text = (self.OUT / "por_save_state_probe_report.md").read_text(encoding="utf-8")
        text += (self.OUT / "por_save_state_probe.json").read_text(encoding="utf-8")
        assert str(RETAIL) not in text
        assert "G:/Games" not in text and "G:\\Games" not in text
