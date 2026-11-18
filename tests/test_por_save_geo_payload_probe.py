from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

from tools import por_save_geo_payload_probe as probe


def _raw(tag: int = 0) -> bytes:
    planes = []
    for plane in range(4):
        planes.append(bytes((i + tag + plane * 17) & 0xFF for i in range(256)))
    return b"\x88\x13" + b"".join(planes)


def _rle_literal(data: bytes) -> bytes:
    out = bytearray()
    for start in range(0, len(data), 128):
        chunk = data[start:start + 128]
        out.append(len(chunk) - 1)
        out.extend(chunk)
    return bytes(out)


def _dax(raw: bytes, block_id: int = 7) -> bytes:
    compressed = _rle_literal(raw)
    entry = struct.pack("<BIHH", block_id, 0, len(raw), len(compressed))
    return struct.pack("<H", len(entry)) + entry + compressed


def _synthetic_install(tmp_path: Path) -> tuple[Path, dict, dict, bytes, bytes]:
    install = tmp_path / "install"
    install.mkdir()
    raw = _raw()
    save = b"prefix:" + raw + b":suffix"
    archive = _dax(raw)
    (install / "SAVGAMA.DAT").write_bytes(save)
    (install / "GEO1.DAX").write_bytes(archive)
    saves = {"SAVGAMA.DAT": (len(save), hashlib.sha256(save).hexdigest())}
    geos = {"GEO1.DAX": (len(archive), hashlib.sha256(archive).hexdigest())}
    return install, saves, geos, save, raw


def test_exact_full_block_planes_and_informative_windows():
    raw = _raw()
    block = {"archive": "GEO1.DAX", "toc_index": 0, "block_id": 7, "raw": raw}
    result = probe.scan_save(b"prefix:" + raw + b":suffix", [block])
    assert result["full_block_match_count"] == 1
    assert result["full_block_matches"][0]["save_offsets"] == [7]
    assert result["exact_plane_match_count"] == 4
    assert all(row["distinct_byte_count"] == 256 for row in result["exact_plane_matches"])
    assert all(result["informative_windows"][str(n)]["matching_window_count"] > 0
               for n in probe.WINDOW_LENGTHS)


def test_zero_plane_exact_match_is_separate_from_informative_windows():
    raw = b"\x88\x13" + bytes(256) + _raw(9)[258:]
    block = {"archive": "GEO1.DAX", "toc_index": 0, "block_id": 25, "raw": raw}
    result = probe.scan_save(b"Z" + bytes(256), [block])
    assert result["full_block_match_count"] == 0
    assert result["exact_plane_match_count"] == 1
    match = result["exact_plane_matches"][0]
    assert match["plane_index"] == 0
    assert match["save_offsets"] == [1]
    assert match["distinct_byte_count"] == 1
    assert match["nonzero_byte_count"] == 0
    assert all(result["informative_windows"][str(n)]["matching_window_count"] == 0
               for n in probe.WINDOW_LENGTHS)


def test_repetitive_plane_offsets_are_counted_without_unbounded_output():
    raw = b"\x88\x13" + bytes(256) + _raw(9)[258:]
    block = {"archive": "GEO1.DAX", "toc_index": 0, "block_id": 25, "raw": raw}
    result = probe.scan_save(bytes(3000), [block])
    match = result["exact_plane_matches"][0]
    assert match["save_offset_count"] == 3000 - 256 + 1
    assert match["save_offsets"] == list(range(16))
    assert match["save_offsets_truncated"] is True


def test_one_byte_mutation_falsifies_full_block_match():
    raw = _raw()
    block = {"archive": "GEO1.DAX", "toc_index": 0, "block_id": 7, "raw": raw}
    save = bytearray(b"prefix:" + raw + b":suffix")
    save[7 + 2 + 8] ^= 0x80
    result = probe.scan_save(bytes(save), [block])
    assert result["full_block_match_count"] == 0


def test_build_report_decodes_synthetic_dax_and_is_deterministic(tmp_path):
    install, saves, geos, save, raw = _synthetic_install(tmp_path)
    a = probe.build_report(install, save_pins=saves, geo_pins=geos)
    b = probe.build_report(install, save_pins=saves, geo_pins=geos)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["search_scope"]["decoded_block_count"] == 1
    assert a["status"] == "exact-payload-match-found-unbound"
    assert a["save_findings"][0]["full_block_match_count"] == 1
    assert raw.hex() not in json.dumps(a, sort_keys=True)


def test_wrong_pin_is_refused_before_report(tmp_path):
    install, saves, geos, _, _ = _synthetic_install(tmp_path)
    bad = dict(saves)
    bad["SAVGAMA.DAT"] = (saves["SAVGAMA.DAT"][0], "0" * 64)
    with pytest.raises(probe.ProbeRefusal, match="SHA-256 mismatch"):
        probe.build_report(install, save_pins=bad, geo_pins=geos)


def test_output_outside_data_is_refused(tmp_path):
    install, saves, geos, _, _ = _synthetic_install(tmp_path)
    with pytest.raises(probe.ProbeRefusal, match="child of data"):
        probe.build_report(install, tmp_path / "outside", saves, geos)


def test_input_change_during_scan_is_refused(tmp_path, monkeypatch):
    install, saves, geos, _, _ = _synthetic_install(tmp_path)
    original = probe.scan_save

    def mutate_after_scan(save, blocks):
        result = original(save, blocks)
        (install / "SAVGAMA.DAT").write_bytes(b"changed")
        return result

    monkeypatch.setattr(probe, "scan_save", mutate_after_scan)
    with pytest.raises(probe.ProbeRefusal, match="changed during the run"):
        probe.build_report(install, save_pins=saves, geo_pins=geos)


def test_outputs_are_path_free_and_do_not_contain_save_bytes(tmp_path):
    install, saves, geos, save, _ = _synthetic_install(tmp_path)
    doc = probe.build_report(install, save_pins=saves, geo_pins=geos)
    out = tmp_path / "report"
    probe.write_outputs(doc, out)
    encoded = (out / "por_save_geo_payload_probe.json").read_text()
    report = (out / "por_save_geo_payload_probe_report.md").read_text()
    assert str(install) not in encoded + report
    assert save.hex() not in encoded
    assert doc["playable"] is False
    assert doc["runtime_binding_claimed"] is False


@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"),
                    reason="set OPENUA_POR_INSTALL for the pinned retail test")
def test_pinned_retail_save_geo_payload_result():
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    doc = probe.build_report(install)
    assert doc["search_scope"]["decoded_block_count"] == 29
    assert doc["install_unchanged"] is True
    assert all(row["full_block_match_count"] == 0 for row in doc["save_findings"])
    assert all(row["exact_plane_match_count"] == 2 for row in doc["save_findings"])
    for row in doc["save_findings"]:
        for match in row["exact_plane_matches"]:
            assert match["plane_index"] == 3
            assert match["distinct_byte_count"] == 1
            assert match["nonzero_byte_count"] == 0
        assert all(row["informative_windows"][str(n)]["matching_window_count"] == 0
                   for n in probe.WINDOW_LENGTHS)
