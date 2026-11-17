"""Tests for tools/por_convert.py (Pool of Radiance source inventory, slice 1).

All fixtures are synthetic and generated under tmp_path. No retail or derived
game data is needed, and nothing is committed.
"""
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import por_convert as pc
from por_convert import PorSourceError


def _bmp(width=4, height=3, bpp=24):
    """Build a minimal, valid BMP header plus zeroed pixels (synthetic)."""
    row = ((width * bpp + 31) // 32) * 4
    pix = bytes(row * height)
    pix_off = 54
    size = pix_off + len(pix)
    hdr = bytearray(54)
    hdr[0:2] = b"BM"
    struct.pack_into("<I", hdr, 2, size)
    struct.pack_into("<I", hdr, 10, pix_off)
    struct.pack_into("<I", hdr, 14, 40)
    struct.pack_into("<ii", hdr, 18, width, height)
    struct.pack_into("<H", hdr, 26, 1)
    struct.pack_into("<H", hdr, 28, bpp)
    struct.pack_into("<I", hdr, 30, 0)
    return bytes(hdr) + pix


def _game_dat(title=b"Synthetic Module"):
    return b"\x01\x10" + title + b"\x00" + bytes(40)


def make_source(root: Path) -> Path:
    src = root / "source"
    (src / "Items").mkdir(parents=True)
    (src / "Game.dat").write_bytes(_game_dat())
    (src / "Levels.txt").write_bytes(b"@ max levels\r\nline two\r\n")
    (src / "World.bmp").write_bytes(_bmp(4, 3))
    (src / "Items" / "Sample Item.itm").write_bytes(b"synthetic item\n")
    (src / "misc.bin").write_bytes(b"\xff\xfe\x00")
    return src


def _tree_hashes(root: Path) -> dict:
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_inventory_classifies_members(tmp_path):
    src = make_source(tmp_path)
    recs = {r.path: r for r in pc.inventory_source(src)}
    assert recs["World.bmp"].kind == "bmp"
    assert recs["World.bmp"].details["width"] == 4
    assert recs["World.bmp"].details["height"] == 3
    assert recs["World.bmp"].details["bits_per_pixel"] == 24
    assert recs["World.bmp"].details["decoded"] is False
    assert recs["Game.dat"].kind == "game-dat"
    assert recs["Game.dat"].details["title"] == "Synthetic Module"
    assert recs["Game.dat"].details["prefix_hex"] == "0110"
    assert recs["Levels.txt"].kind == "text"
    assert recs["Levels.txt"].details["lines"] == 2
    assert recs["Levels.txt"].details["line_ending"] == "crlf"
    assert recs["Levels.txt"].details["content_kept"] is False
    assert recs["Items/Sample Item.itm"].kind == "item"
    assert recs["misc.bin"].kind == "unknown"
    assert recs["misc.bin"].status == "unrecognised"


def test_inventory_records_sha256(tmp_path):
    src = make_source(tmp_path)
    recs = {r.path: r for r in pc.inventory_source(src)}
    expected = hashlib.sha256((src / "misc.bin").read_bytes()).hexdigest()
    assert recs["misc.bin"].sha256 == expected


def test_convert_writes_labelled_ir_and_report(tmp_path):
    src = make_source(tmp_path)
    out = tmp_path / "out"
    ir = pc.convert(src, out)
    data = json.loads((out / "por_ir.json").read_text(encoding="utf-8"))
    assert data == ir
    assert data["schema"] == "openua.por-source-ir"
    assert data["status"] == "source-inventory-only"
    assert data["playable"] is False
    assert data["areas"] == []
    codes = {u["code"] for u in data["unsupported"]}
    assert {"no-design-output", "world-map-raster", "ecl-scripts"} <= codes
    report = (out / "por_report.md").read_text(encoding="utf-8")
    assert "NOT a playable FRUA module" in report
    assert "## Not converted (unsupported)" in report
    assert "Next blockers" in report


def test_output_does_not_leak_absolute_source_path(tmp_path):
    src = make_source(tmp_path)
    out = tmp_path / "out"
    pc.convert(src, out)
    text = (out / "por_ir.json").read_text(encoding="utf-8")
    text += (out / "por_report.md").read_text(encoding="utf-8")
    assert str(src) not in text
    assert str(tmp_path) not in text
    assert json.loads((out / "por_ir.json").read_text())["source"]["label"] == "source"


def test_outputs_are_deterministic(tmp_path):
    src = make_source(tmp_path)
    a = tmp_path / "a"
    b = tmp_path / "b"
    pc.convert(src, a)
    pc.convert(src, b)
    assert (a / "por_ir.json").read_bytes() == (b / "por_ir.json").read_bytes()
    assert (a / "por_report.md").read_bytes() == (b / "por_report.md").read_bytes()


def test_source_is_never_modified(tmp_path):
    src = make_source(tmp_path)
    before = _tree_hashes(src)
    pc.convert(src, tmp_path / "out")
    assert _tree_hashes(src) == before


def test_missing_required_member_is_refused(tmp_path):
    src = make_source(tmp_path)
    (src / "World.bmp").unlink()
    with pytest.raises(PorSourceError, match="World.bmp"):
        pc.convert(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_required_member_failing_probe_is_refused(tmp_path):
    src = make_source(tmp_path)
    (src / "World.bmp").write_bytes(b"not a bitmap at all, padded out to fifty-four bytes!!!!!")
    with pytest.raises(PorSourceError, match="failed validation"):
        pc.convert(src, tmp_path / "out")


def test_bmp_declared_size_mismatch_is_a_warning(tmp_path):
    src = make_source(tmp_path)
    raw = bytearray((src / "World.bmp").read_bytes())
    struct.pack_into("<I", raw, 2, len(raw) + 100)
    (src / "World.bmp").write_bytes(bytes(raw))
    rec = {r.path: r for r in pc.inventory_source(src)}["World.bmp"]
    assert rec.status == "header-read"
    assert any("declares" in w for w in rec.warnings)


def test_game_dat_nonprintable_title_warns(tmp_path):
    details, warnings = pc.probe_game_dat(b"\x01\x10\xff\xfe\x00rest")
    assert any("non-printable" in w for w in warnings)
    assert details["body_decoded"] is False


def test_game_dat_unterminated_title_warns():
    details, warnings = pc.probe_game_dat(b"\x01\x10" + b"A" * 80)
    assert any("NUL-terminated" in w for w in warnings)
    assert len(details["title"]) <= 64


def test_output_inside_source_is_refused(tmp_path):
    src = make_source(tmp_path)
    with pytest.raises(PorSourceError, match="inside the source"):
        pc.convert(src, src / "out")
    with pytest.raises(PorSourceError, match="inside the source"):
        pc.validate_output_dir(src, src)


def test_output_inside_repo_outside_data_is_refused(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "data").mkdir(parents=True)
    monkeypatch.setattr(pc, "REPO_ROOT", repo)
    monkeypatch.setattr(pc, "DATA_DIR", repo / "data")
    with pytest.raises(PorSourceError, match="under data/"):
        pc.validate_output_dir(tmp_path / "src", repo / "tools" / "out")


def test_output_under_repo_data_is_allowed(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "data").mkdir(parents=True)
    monkeypatch.setattr(pc, "REPO_ROOT", repo)
    monkeypatch.setattr(pc, "DATA_DIR", repo / "data")
    got = pc.validate_output_dir(tmp_path / "src", repo / "data" / "work" / "por")
    assert got == (repo / "data" / "work" / "por").resolve()


def test_symlink_is_recorded_not_followed(tmp_path):
    src = make_source(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    link = src / "link.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    recs = {r.path: r for r in pc.inventory_source(src)}
    assert recs["link.txt"].kind == "symlink"
    assert recs["link.txt"].sha256 is None


def test_cli_exit_codes(tmp_path, capsys):
    src = make_source(tmp_path)
    assert pc.main([str(src), "-o", str(tmp_path / "ok")]) == 0
    assert pc.main([str(tmp_path / "nope"), "-o", str(tmp_path / "x")]) == 2
    err = capsys.readouterr().err
    assert "not a directory" in err


def test_pipe_in_source_name_is_escaped_in_report():
    # Windows forbids '|' in file names, so exercise the renderer directly.
    ir = {
        "status": "source-inventory-only",
        "source": {"label": "x", "file_count": 1, "missing_members": [],
                   "files": [pc.FileRecord(path="a|b.txt", kind="text", size=2,
                                           status="inventoried").as_json()]},
        "unsupported": [], "loss": [],
    }
    report = pc.render_report(ir)
    assert "`a\\|b.txt`" in report


def test_no_design_files_are_written(tmp_path):
    src = make_source(tmp_path)
    out = tmp_path / "out"
    pc.convert(src, out)
    names = sorted(p.name for p in out.iterdir())
    assert names == ["por_ir.json", "por_report.md"]
