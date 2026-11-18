"""Tests for the bounded PoR far-call-to-GEO census."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_farcall_census as census  # noqa: E402


TARGET = census.GEO_STUB_F
HDR = 0x200


@pytest.mark.parametrize("listed,seg,off,status,skew", [
    ({0x103}, 0x1234, 0x0C, census.SITE_CANDIDATE_RESIDUE, 0),
    ({0x103}, 0x1234, 0x0D, census.SITE_RESIDUE_NO, 15),
    (set(), 0x03C0, 0x0C, census.SITE_CANDIDATE_LITERAL, None),
    ({0x103, 0x101}, 0x1234, 0x0C, census.SITE_UNDECIDED_BOTH, None),
    ({0x101}, 0x1234, 0x0B, census.SITE_UNDECIDED_OFF, None),
])
def test_site_eval_keeps_fixup_cases_separate(listed, seg, off, status, skew):
    row = census.site_eval(0x1000, seg, off, 0x0F00, listed, HDR, TARGET)
    assert row["status"] == status
    assert row["candidate"] is (status in census.CANDIDATE_STATUSES)
    if skew is not None:
        assert row["skew_needed_mod16"] == skew


def test_site_eval_candidate_delta_is_a_constraint_not_an_observation():
    row = census.site_eval(0x1000, 0x1234, 0x0C, 0x0F00, {0x103}, HDR, TARGET)
    assert row["status"] == census.SITE_CANDIDATE_RESIDUE
    assert row["di_constraint_mod64k"] == ((TARGET - HDR - 0x0C) // 16 - 0x1234) % 0x10000


def test_output_guard_requires_data_work_and_rejects_install_child(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(census.p.ProbeRefusal, match="under data/work"):
        census.check_out(tmp_path / "outside", install)
    with pytest.raises(census.p.ProbeRefusal, match="under data/work"):
        census.check_out(census.DATA_WORK, install)
    with pytest.raises(census.p.ProbeRefusal, match="inside the install"):
        census.check_out(install / "output", install)


@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL"), reason="retail install not configured")
def test_retail_census_is_pinned_bounded_and_does_not_claim_mapping():
    install = Path(os.environ["OPENUA_POR_INSTALL"])
    before = census._hashes(install)
    inputs = census.p.load_inputs(install)
    doc = census.analyse(inputs[census.EXE_NAME], inputs[census.OVR_NAME])
    after = census._hashes(install)

    assert before == after
    assert doc["totals"]["parsed_groups"] == 34
    assert doc["totals"]["far_call_sites"] == 3993
    assert doc["totals"]["far_call_sites_strong"] == 3615
    assert doc["totals"]["far_call_sites_weak_only"] == 378
    assert doc["totals"]["near_calls_to_geo_body"] == 0
    assert doc["verdict"]["geo_status"] == census.STATUS_CANDIDATE
    assert doc["verdict"]["candidate_count"] == 181

    wrapped = {"schema": census.SCHEMA, "schema_version": census.SCHEMA_VERSION,
               "tool": census.TOOL, "status": census.STATUS, "playable": False,
               "geo_binding_established": False,
               "inputs": {k: {"size": len(v), "sha256": census._sha(v)} for k, v in inputs.items()},
               **doc}
    wrapped["self_checks"] = census.self_checks(wrapped, before, after)
    assert all(c["ok"] for c in wrapped["self_checks"])

    report = census.render_report(wrapped)
    assert "181" in report
    assert "does not identify a runtime call" in report
    assert "Weak means reached only from a prologue byte pattern" in report
    assert "G:\\Games" not in report
