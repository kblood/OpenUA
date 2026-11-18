"""Tests for the capture-scoped PoR far-call cross-check toward START stub 6."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_farcall_dump_crosscheck as cross  # noqa: E402


def _candidate():
    return {
        "at": "0x0100", "seg": "0x1000", "off": "0x000C", "strong": True,
        "owners": [{"owner_fileofs": "0x0020", "status": "candidate-given-di-not-established",
                    "di_constraint_mod64k": 0x1866, "group_status": "well-formed"}],
    }


def _mapped(seg_live="0x2866", stub6_hit=True):
    return {"far_call_sites": [{
        "site_file_offset": "0x0100", "opcode_0x9a": True,
        "offset_matches_file": True, "seg_raw": "0x1000", "seg_live": seg_live,
        "target_linear": "0x2866C", "window": {
            "status": "unique-START.EXE",
            "hits": {"START.EXE": ["0x3E0C"] if stub6_hit else ["0x4200"]},
        },
    }]}


def test_candidate_observation_matches_live_delta_and_stub6_window():
    row = cross.candidate_observation(_candidate(), _candidate()["owners"][0], _mapped())
    assert row["observation"] == "mapped-live-callsite"
    assert row["observed_delta_mod64k"] == 0x1866
    assert row["delta_matches_candidate_constraint"] is True
    assert row["target_window_matches_stub6"] is True


def test_candidate_observation_rejects_wrong_live_delta_and_other_start_window():
    row = cross.candidate_observation(_candidate(), _candidate()["owners"][0],
                                      _mapped(seg_live="0x2000", stub6_hit=False))
    assert row["delta_matches_candidate_constraint"] is False
    assert row["target_window_matches_stub6"] is False


def test_absent_owner_group_stays_unobserved():
    row = cross.candidate_observation(_candidate(), _candidate()["owners"][0], None)
    assert row["observation"] == "owner-group-absent-or-unmapped"
    assert "seg_live" not in row


def test_output_guard_rejects_outside_install_and_data_work_root(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(cross.CrosscheckRefusal, match="under data/work"):
        cross.check_out(tmp_path / "outside", install)
    with pytest.raises(cross.CrosscheckRefusal, match="data/work"):
        cross.check_out(cross.DATA_WORK, install)
    with pytest.raises(cross.CrosscheckRefusal, match="inside the install"):
        cross.check_out(install / "out", install)


@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"), reason="retail install not configured")
def test_pinned_dumps_eliminate_mapped_candidates_only(tmp_path):
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    dump_dir = Path(__file__).resolve().parents[1] / "data" / "work"
    dumps = [dump_dir / "por-live-memory-pid34644" / "ram-000000-100000.bin",
             dump_dir / "por-wheel-live-capture" / "ram-000000-100000.bin"]
    if not all(p.is_file() for p in dumps):
        pytest.skip("the two local captured RAM dumps are not available")
    before = cross.census._hashes(install)
    doc = cross.build_report(install, dumps)
    after = cross.census._hashes(install)

    assert before == after
    assert doc["source_inputs_unchanged"] == {"GAME.OVR": True, "START.EXE": True}
    assert doc["geo_binding_established"] is False
    assert doc["static_census"]["candidate_count"] == 181
    assert len(doc["captures"]) == 2
    assert doc["captures"][0]["sha256"] != doc["captures"][1]["sha256"]
    for capture in doc["captures"]:
        totals = capture["totals"]
        assert totals["groups_mapped_unique"] == 16
        assert totals["candidate_owner_rows"] == 181
        assert totals["candidate_owner_rows_with_live_callsite"] == 90
        assert totals["candidate_constraints_matching_observed_delta"] == 0
        assert totals["targets_matching_stub6_bytes"] == 0
        assert totals["candidate_rows_unobserved"] == 91
        observed = [r for r in capture["candidate_observations"]
                    if r["observation"] == "mapped-live-callsite"]
        assert {r["observed_delta_mod64k"] for r in observed} == {0x1866}

    report = cross.render_report(doc)
    assert "memory-presence diagnostic only" in report
    assert "candidate rows in absent or unmapped groups: 91" in report
    assert "far call executed" in report
    assert str(install) not in report
