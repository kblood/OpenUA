"""Tests for tools/por_geo_buffer_fill_probe.py (PoR buffer at DGROUP 0x6A5C, observe-only).

Synthetic tests run on hand-encoded 8086 bytes and small dumps; no install is needed. Each
synthetic test has a falsifier: a single changed byte must change the reported fact, or the
probe must fail closed. The retail tests run only when a pinned PoR install is present
(OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD) and pin the byte facts the probe
reports. They test no PoR semantics beyond those bytes.
"""
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_buffer_fill_probe as p  # noqa: E402
import por_overlay_group_map as om  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
RETAIL_DUMP = REPO / "data" / "work" / "por-live-memory-pid34644" / "ram-000000-100000.bin"


def _hex(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def _copy_window(src_imm: int = 0x0002, dst_imm_base: int = 0x0000, copies: int = 4) -> bytes:
    """The straight-line copy window as encoded in GAME.OVR 0x2FA57..0x2FAD8 (retail bytes)."""
    out = bytearray(_hex("c7 46 f8") + src_imm.to_bytes(2, "little"))      # mov [bp-8], src_imm
    for k in range(copies):
        if k:
            out += _hex("81 46 f8 00 01")                                  # add [bp-8], 0x100
        out += _hex("8b 46 f8")                                            # mov ax, [bp-8]
        out += _hex("c4 7e fa")                                            # les di, [bp-6]
        out += _hex("03 f8")                                               # add di, ax
        out += _hex("06 57")                                               # push es; push di (src)
        out += _hex("c4 3e 5c 6a")                                         # les di, [0x6a5c]
        if k:
            out += _hex("81 c7") + (0x100 * k).to_bytes(2, "little")       # add di, 0x100*k
        out += _hex("06 57")                                               # push es; push di (dst)
        out += _hex("b8 00 01 50")                                         # mov ax, 0x100; push ax
        out += _hex("9a 85 16 f8 0a")                                      # call 0x0AF8:0x1685
    return bytes(out)


# ---- copy simulation (fill) ----------------------------------------------------------

def test_copy_window_decodes_block_plus_two_geometry():
    sim = p.simulate_copies(_copy_window(), 0)
    assert sim["ok"] is True
    rows = p.copy_rows(sim)
    assert [r["src_offset"] for r in rows] == [0x002, 0x102, 0x202, 0x302]
    assert [r["dst_offset"] for r in rows] == [0x000, 0x100, 0x200, 0x300]
    assert all(r["count"] == 0x100 and r["ok"] for r in rows)
    assert rows[2]["plane"] == 2


def test_falsifier_cursor_start_changes_every_source():
    # Falsifier: start the cursor at 0 instead of 2. Every source moves by two bytes.
    rows = p.copy_rows(p.simulate_copies(_copy_window(src_imm=0x0000), 0))
    assert [r["src_offset"] for r in rows] == [0x000, 0x100, 0x200, 0x300]


def test_falsifier_missing_source_push_fails_the_copy_row():
    window = _copy_window()
    broken = window.replace(_hex("c4 7e fa 03 f8 06 57"), _hex("c4 7e fa 03 f8 57"), 1)
    rows = p.copy_rows(p.simulate_copies(broken, 0))
    assert rows[0]["ok"] is False


def test_unmodelled_opcode_fails_closed():
    window = _copy_window()
    padded = window[:5] + b"\x90" + window[5:]          # a nop between the first two instructions
    sim = p.simulate_copies(padded, 0)
    assert sim["ok"] is False
    assert sim["reason"].startswith("unmodelled-opcode")


def test_copy_count_is_required():
    # Three copies then the window ends: the walk must not report success for a four-copy fill.
    sim = p.simulate_copies(_copy_window(copies=3), 0, copies=4)
    assert sim["ok"] is False
    assert sim["reason"].startswith("unmodelled-opcode")


# ---- allocation store and ES operand decoding ------------------------------------------

def test_store_pattern_requires_0x400_push_before_allocator_call():
    good = _hex("b8 00 04 50 9a 3f 02 f8 0a a3 5c 6a 89 16 5e 6a")
    facts = p.allocation_facts(b"\x00" * 3 + good)
    assert facts["store_count"] == 1
    assert facts["store_sites"][0]["pattern_ok"] is True
    bad = _hex("b8 00 03 50 9a 3f 02 f8 0a a3 5c 6a 89 16 5e 6a")      # 0x300 pushed, not 0x400
    assert p.allocation_facts(b"\x00" * 3 + bad)["store_sites"][0]["pattern_ok"] is False


def test_es_operand_decoding_reads_and_writes():
    assert p._es_access(_hex("26 8a 85 00 02"), 0) == {"at": 0, "op": 0x8A, "modrm": 0x85, "disp": 0x200,
                                                       "kind": "read"}
    assert p._es_access(_hex("26 88 9d 00 03"), 0)["disp"] == 0x300
    assert p._es_access(_hex("26 88 9d 00 03"), 0)["kind"] == "write"
    assert p._es_access(_hex("26 8a 05"), 0)["disp"] == 0
    assert p._es_access(_hex("26 8a 8f 00 02"), 0) is None          # [bx+disp], not the [di] base


def test_loader_gate_requires_status_0x402():
    args = _hex("8a 46 06 50 8d 7e fe 16 57 8d 7e fa 16 57")
    gate = _hex("83 7e fe 00 74 07 81 7e fe 02 04 74 2e")
    base = args + _hex("9a 16 07 02 08") + gate
    ovr = b"\x00" * 0x2F000 + base
    site = 0x2F000 + len(args)
    # The fill search checks a call inside the fill's own window; use a window that covers it.
    facts = p.loader_facts(ovr, 0x2F000)
    assert facts["found"] == 1 and facts["args_pattern_ok"] is True and facts["gate_ok"] is True
    assert facts["call_at"] == site
    falsified = ovr.replace(_hex("81 7e fe 02 04"), _hex("81 7e fe 01 04"), 1)
    assert p.loader_facts(falsified, 0x2F000)["gate_ok"] is False


# ---- callers and literal census ---------------------------------------------------------

def test_caller_argument_classes():
    local = _hex("8a 46 fd 50 9a 43 00 d5 03")
    far = _hex("c4 3e d2 49 26 8a 85 8a 01 50 9a 43 00 d5 03")
    assert p.caller_arg(local, 4)["source"] == "local [bp-3]"
    assert p.caller_arg(far, 10)["source"].startswith("es:[49D2")
    assert p.caller_arg(_hex("90 90 50 9a 43 00 d5 03"), 3)["source"] == "unclassified"


def test_stub_literal_census_finds_stub_seven_literal():
    ovr = b"\x00" * 4 + _hex("9a 43 00 d5 03") + b"\x00" * 4 + _hex("9a 34 00 d5 03")
    census = p.stub_literal_census(ovr)
    assert census == {0x34: [13], 0x43: [4]}


# ---- dump search and positive control ---------------------------------------------------

def test_window_search_finds_and_refuses_absent_windows():
    needle = bytes(range(1, 17))
    dump = b"\x00" * 100 + needle + b"\x00" * 50
    assert p.window_search(dump, needle) == [100]
    assert p.window_search(dump, bytes(range(2, 18))) == []


def test_dump_observation_reports_plane_hit_for_a_planted_plane(tmp_path):
    # A planted decoded plane 2 must be found; the same dump without it must not report the plane.
    raw = bytes([0x00, 0x04]) + bytes(((i * 37 + 5) & 0xFF) or 1 for i in range(1024))
    block = {"geo": 1, "index": 0, "raw": raw, "sha256": "x"}
    plane2 = raw[2 + 512: 2 + 768]
    dump = b"\xAA" * 0x1000 + plane2 + b"\xAA" * 0x100
    dump_path = tmp_path / "dump.bin"
    dump_path.write_bytes(dump)
    needle = bytes(range(200, 216))                      # absent from the dump: no positive control
    obs = p.dump_observations(dump_path, needle, [block])
    assert any(h["plane"] == 2 and h["offset"] == 0 for h in obs["geo_plane_window_hits"])
    assert obs["positive_control_hits"] == []
    clean = tmp_path / "clean.bin"
    clean.write_bytes(b"\xAA" * 0x3000)
    assert p.dump_observations(clean, needle, [block])["geo_plane_window_hits"] == []


# ---- refusals ---------------------------------------------------------------------------

def test_output_outside_data_work_is_refused(tmp_path):
    assert p.main(["-o", str(tmp_path / "out")]) == 2


def test_unpinned_install_is_refused(tmp_path):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"not pool")
    (install / "START.EXE").write_bytes(b"not pool")
    out = p.DATA_WORK / "por-geo-buffer-fill-probe-refusal-test"
    assert p.main(["--install", str(install), "-o", str(out)]) == 2
    assert not out.exists()


# ---- retail-gated (pinned PoR bytes present) -------------------------------------------

RETAIL = pytest.mark.skipif(not (RETAIL_INSTALL / "GAME.OVR").exists()
                            or not (RETAIL_INSTALL / "START.EXE").exists(),
                            reason="no pinned PoR install (set OPENUA_POR_INSTALL)")


@RETAIL
def test_retail_fill_geometry_and_store():
    ovr = (RETAIL_INSTALL / "GAME.OVR").read_bytes()
    exe = (RETAIL_INSTALL / "START.EXE").read_bytes()
    assert (len(ovr), len(exe)) == (om.PINS["GAME.OVR"]["size"], om.PINS["START.EXE"]["size"])
    store = p.allocation_facts(ovr)["store_sites"]
    assert [s["store_at"] for s in store] == [0xE670]
    assert store[0]["pattern_ok"] is True and store[0]["enclosing_entry"] == 0xE600
    census = p.pointer_census(ovr)["counts"]
    assert census == {"les": 29, "store-ax": 1, "store-dx": 1}
    fill = p.analyse(ovr, exe, {})["fill"]
    assert fill["entry"] == 0x2F9BE and fill["owner_group_fileofs"] == "0x2E8F7"
    assert fill["copy_simulation_ok"] is True
    rows = fill["copies"]
    assert [r["src_offset"] for r in rows] == [2, 258, 514, 770]
    assert [r["dst_offset"] for r in rows] == [0, 256, 512, 768]
    assert fill["loader"]["gate_ok"] is True and fill["loader"]["args_pattern_ok"] is True


@RETAIL
def test_retail_stub_seven_and_callers():
    ovr = (RETAIL_INSTALL / "GAME.OVR").read_bytes()
    exe = (RETAIL_INSTALL / "START.EXE").read_bytes()
    doc = p.analyse(ovr, exe, {})
    assert doc["stub7"]["bytes"] == "cd 3f c7 10 27"
    assert doc["stub7"]["proc"] == "0x10C7" and doc["stub7"]["trailer_well_formed"] is False
    assert [c["site"] for c in doc["callers"]] == [0x1A27, 0x1FBC4]
    assert doc["callers"][0]["arg"]["source"] == "local [bp-3]"


@RETAIL
def test_retail_dump_positive_control_and_no_geo_planes():
    if not RETAIL_DUMP.exists():
        pytest.skip("pid34644 dump not present")
    exe = (RETAIL_INSTALL / "START.EXE").read_bytes()
    blocks = p.decoded_geo_blocks(RETAIL_INSTALL)
    assert len(blocks) == 29
    obs = p.dump_observations(RETAIL_DUMP, exe[p.STUB4_FILE:p.STUB4_FILE + 16], blocks)
    assert obs["positive_control_hits"] == ["0x1C3E4"]
    # Observed negative: no 16-byte decoded GEO plane window is in this dump (unknown instant).
    assert obs["geo_plane_window_hits"] == []


@RETAIL
def test_retail_probe_never_claims_fill_or_plane_two(tmp_path):
    rc = p.main(["--install", str(RETAIL_INSTALL), "--dump", str(RETAIL_DUMP),
                 "-o", str(p.DATA_WORK / "por-geo-buffer-fill-probe-test")])
    assert rc == 0
    import json
    doc = json.loads((p.DATA_WORK / "por-geo-buffer-fill-probe-test" / "por_geo_buffer_fill_probe.json").read_text())
    assert doc["fill_established"] is False
    assert doc["plane2_binding"] == "not claimed"
    assert doc["playable"] is False
    assert "copy direction unresolved" not in doc["verdict"]
    assert any("helper ABI probe" in s for s in doc["next_discriminating_observations"])
    assert any("prototype conflict" in s for s in doc["next_discriminating_observations"])
