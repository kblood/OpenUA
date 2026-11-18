"""Tests for tools/por_geo_capture_aid.py (PoR GEO-load capture aid).

The default suite uses synthetic GAME.OVR bytes, synthetic DAX containers and temp folders.
It never launches an emulator and never writes to a PoR install. The retail anchor runs only
when OPENUA_POR_INSTALL names a PoR install folder; it reads the install read-only.
"""
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_capture_aid as g  # noqa: E402
import por_map  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUP = g.GROUP
SEEK = GROUP["seek"]  # 0x2E8F7
SIZE = GROUP["code_size"]  # 0x120B
GEO_SEG = 0x23A5


# --------------------------------------------------------------------------
# Synthetic fixtures
# --------------------------------------------------------------------------

def synth_ovr() -> bytes:
    """GAME.OVR-sized bytes with the GEO fill's candidate bytes in place. The fill body is NOPs
    (no stray return bytes), so a linear walk from the entry has exactly one exit."""
    buf = bytearray((i * 7 + 3) & 0xFF for i in range(0x2FB02 + 0x100))
    buf[g.OWNER_OFF:g.RETF_OFF] = b"\x90" * (g.RETF_OFF - g.OWNER_OFF)
    for off, data in (
        (g.OWNER_OFF, bytes.fromhex("5589E5")),
        (g.POST_FRAME_OFF, bytes.fromhex("81EC1001")),
        (g.ARG_BP6_READ_OFF, bytes.fromhex("8A4606")),
        (g.RETF_OFF, bytes.fromhex("CA0200")),
        (g.LITERAL_OFF, b"\x03GEO\x04.dax"),
    ):
        buf[off:off + len(data)] = data
    return bytes(buf)


def synth_start(proc: int = 0x10C7, tail: int = 0x27, fileofs: int = SEEK, codesz: int = SIZE,
                nstubs: int = 8) -> bytes:
    """START.EXE-sized bytes with the owner header at 0x3DD7 and a stub run at 0x3DEE. Slot 7 is
    the GEO-fill candidate (CD 3F <proc> <tail>); slots 0..6 are well-formed (tail 00) stubs with
    proc words that land elsewhere."""
    buf = bytearray(0x3F00)
    buf[g.START_HDR_OFF:g.START_HDR_OFF + 4] = b"\xCD\x3F\x00\x00"
    struct.pack_into("<IHHH", buf, g.START_HDR_OFF + 4, fileofs, codesz, 0x50, nstubs)
    for i in range(nstubs):
        off = g.START_STUB_RUN_OFF + g.START_STUB_SLOT_LEN * i
        p, t = (proc, tail) if i == 7 else (0x057A + i, 0)
        buf[off:off + 5] = b"\xCD\x3F" + struct.pack("<H", p) + bytes([t])
    return bytes(buf)


def make_dax(blocks) -> bytes:
    """blocks: list of (block_id, comp_bytes, raw_size). Builds a contiguous DAX container."""
    toc = b""
    data = b""
    off = 0
    for bid, comp, raw in blocks:
        toc += struct.pack("<BIHH", bid, off, raw, len(comp))
        data += comp
        off += len(comp)
    return struct.pack("<H", len(toc)) + toc + data


def synth_dax():
    return make_dax([(10, b"A" * 5, 16), (11, b"BB" * 4, 32), (12, b"C" * 3, 8)])


def dax_seek(dax: bytes, index: int) -> int:
    entries, base = por_map.parse_dax(dax)
    return base + entries[index].data_offset


def good_obs(ovr: bytes, dax: bytes) -> dict:
    return {
        "schema": g.OBS_SCHEMA,
        "schema_version": g.SCHEMA_VERSION,
        "route": "synthetic route (test only)",
        "load": {"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK, "read_count": "0x%X" % SIZE,
                 "dest": "23A5:0000", "dest_dump_hex": ovr[SEEK:SEEK + 8].hex(" ")},
        "owner_stop": {"at": "post_frame", "cs": "23A5", "ip": "10CA", "code_hex": "81 EC 10 01",
                       "bp": "FFF0", "return_cs": "23A5", "return_ip": "0F00",
                       "arg_bp6_word": "0001"},
        "dax": {"open_name": "GEO8.DAX", "open_handle": "0005", "seek_handle": "0005",
                "seek_al": "0x0", "seek_abs": "0x%X" % dax_seek(dax, 1),
                "read_count": "0x%X" % 8},
    }


# --------------------------------------------------------------------------
# Translation: address arithmetic and refusals
# --------------------------------------------------------------------------

def test_owner_entry_translates_to_expected_offset():
    # The GEO fill: group-relative 0x10C7 (0x2F9BE - 0x2E8F7).
    assert g.file_to_cs_ip(g.OWNER_OFF, GROUP, GEO_SEG, 0) == (0x23A5, 0x10C7)


def test_post_frame_arg_read_and_retf_translate():
    assert g.file_to_cs_ip(g.POST_FRAME_OFF, GROUP, GEO_SEG, 0) == (0x23A5, 0x10CA)
    assert g.file_to_cs_ip(g.ARG_BP6_READ_OFF, GROUP, GEO_SEG, 0) == (0x23A5, 0x1112)
    assert g.file_to_cs_ip(g.RETF_OFF, GROUP, GEO_SEG, 0) == (0x23A5, 0x1203)


def test_owner_target_is_not_the_walldef_wrapper():
    # The WALLDEF wrapper (START stub 6, proc 0x0E08) must not be the owner target any more.
    assert g.OWNER_OFF != g.WALLDEF_OFF
    assert g.file_to_cs_ip(g.WALLDEF_OFF, GROUP, GEO_SEG, 0) == (0x23A5, 0x0E08)
    assert g.OWNER_OFF == g.GROUP["seek"] + 0x10C7


def test_buffer_offset_shifts_the_translation():
    assert g.file_to_cs_ip(g.OWNER_OFF, GROUP, GEO_SEG, 0x0100) == (0x23A5, 0x11C7)


def test_group_bounds_are_inclusive_low_exclusive_high():
    assert g.file_to_cs_ip(SEEK, GROUP, GEO_SEG, 0) == (GEO_SEG, 0)
    assert g.file_to_cs_ip(SEEK + SIZE - 1, GROUP, GEO_SEG, 0) == (GEO_SEG, SIZE - 1)


def test_refuses_offset_below_group():
    with pytest.raises(g.AidRefusal, match="outside group 29"):
        g.file_to_cs_ip(SEEK - 1, GROUP, GEO_SEG, 0)


def test_refuses_offset_at_group_end():
    with pytest.raises(g.AidRefusal, match="outside group 29"):
        g.file_to_cs_ip(SEEK + SIZE, GROUP, GEO_SEG, 0)


def test_refuses_out_of_range_load_segment():
    with pytest.raises(g.AidRefusal, match="not a 16-bit"):
        g.file_to_cs_ip(g.OWNER_OFF, GROUP, 0x10000, 0)
    with pytest.raises(g.AidRefusal, match="not a 16-bit"):
        g.file_to_cs_ip(g.OWNER_OFF, GROUP, -1, 0)


def test_refuses_translation_that_wraps_the_segment():
    # 0xFFF0 + 0x10C7 is past 0xFFFF: the load would not hold the owner in this segment.
    with pytest.raises(g.AidRefusal, match="64 KiB"):
        g.file_to_cs_ip(g.OWNER_OFF, GROUP, GEO_SEG, 0xFFF0)


def test_cs_ip_round_trip_to_file_offset():
    assert g.cs_ip_to_file(0x23A5, 0x10C7, GROUP, GEO_SEG, 0) == g.OWNER_OFF
    assert g.cs_ip_to_file(0x23A5, 0x0100 + 0x10C7, GROUP, GEO_SEG, 0x0100) == g.OWNER_OFF


def test_cs_ip_refuses_other_segment():
    with pytest.raises(g.AidRefusal, match="not the observed load segment"):
        g.cs_ip_to_file(0x3581, 0x10C7, GROUP, GEO_SEG, 0)


def test_cs_ip_refuses_ip_below_buffer():
    with pytest.raises(g.AidRefusal, match="below the buffer start"):
        g.cs_ip_to_file(GEO_SEG, 0x00FF, GROUP, GEO_SEG, 0x0100)


def test_cs_ip_refuses_ip_past_group():
    with pytest.raises(g.AidRefusal, match="past group 29"):
        g.cs_ip_to_file(GEO_SEG, SIZE, GROUP, GEO_SEG, 0)


def test_build_targets_blocked_without_observed_segment():
    targets = g.build_targets(None)
    assert [t["id"] for t in targets] == ["owner_entry", "owner_post_frame", "owner_retf"]
    for t in targets:
        assert t["cs_ip"] is None
        assert "no observed load segment" in t["blocked"]
        assert t["status"] == "UNVERIFIED candidate"


def test_build_targets_with_segment_is_deterministic():
    a = g.build_targets(GEO_SEG, 0)
    b = g.build_targets(GEO_SEG, 0)
    assert a == b
    assert [t["cs_ip"] for t in a] == ["23A5:10C7", "23A5:10CA", "23A5:1203"]
    assert all(t["status"] == "UNVERIFIED candidate" for t in a)


# --------------------------------------------------------------------------
# Strict parsing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,value", [("0x2E8F7", 0x2E8F7), ("2e8f7", 0x2E8F7), (0x2E8F7, 0x2E8F7)])
def test_parse_hex_accepts_hex_text_and_ints(text, value):
    assert g.parse_hex(text, "x", 0xFFFFFFFF) == value


@pytest.mark.parametrize("bad", [True, "", "0xZZ", "10000", None, ["0x1"], "12345678901"])
def test_parse_hex_refuses_bad_values(bad):
    with pytest.raises(g.AidRefusal):
        g.parse_hex(bad, "x", 0xFFFF)


def test_parse_seg_off_requires_two_halves():
    assert g.parse_seg_off("23A5:0000", "d") == (0x23A5, 0)
    for bad in ("23A5", "23A5:0000:1", "G000:0000", 0x23A5, "10000:0000"):
        with pytest.raises(g.AidRefusal):
            g.parse_seg_off(bad, "d")


def test_parse_bytes_hex_rules():
    assert g.parse_bytes_hex("55 89 E5", "c") == b"\x55\x89\xe5"
    for bad, minimum in (("5589E", 1), ("", 1), ("55 89", 4), ("ZZ", 1)):
        with pytest.raises(g.AidRefusal):
            g.parse_bytes_hex(bad, "c", min_len=minimum)


# --------------------------------------------------------------------------
# Static checks
# --------------------------------------------------------------------------

def test_static_checks_pass_on_candidate_bytes():
    checks = g.static_checks(synth_ovr())
    assert all(c["ok"] for c in checks), [c for c in checks if not c["ok"]]
    assert {c["id"] for c in checks} >= {"owner_prologue", "post_frame_is_insn_boundary",
                                         "retf_decodes_as_retf", "fill_exit_is_single",
                                         "arg_bp6_read", "retf_2"}


def test_static_checks_catch_a_wrong_prologue():
    ovr = bytearray(synth_ovr())
    ovr[g.OWNER_OFF] = 0x90  # nop instead of push bp
    checks = {c["id"]: c for c in g.static_checks(bytes(ovr))}
    assert checks["owner_prologue"]["ok"] is False
    assert checks["post_frame_is_insn_boundary"]["ok"] is False


def test_static_checks_refuse_a_retf_4_exit():
    # The WALLDEF wrapper exits with retf 4; the GEO fill exits with retf 2. Bytes must say 2.
    ovr = bytearray(synth_ovr())
    ovr[g.RETF_OFF:g.RETF_OFF + 3] = bytes.fromhex("CA0400")
    checks = {c["id"]: c for c in g.static_checks(bytes(ovr))}
    assert checks["retf_2"]["ok"] is False
    assert checks["retf_decodes_as_retf"]["ok"] is True


def test_static_checks_refuse_a_second_return_in_the_fill():
    # A stray near ret inside the fill body makes the fill's exit ambiguous.
    ovr = bytearray(synth_ovr())
    ovr[g.OWNER_OFF + 0x40] = 0xC3
    checks = {c["id"]: c for c in g.static_checks(bytes(ovr))}
    assert checks["fill_exit_is_single"]["ok"] is False


def test_static_checks_refuse_a_fill_without_its_post_frame():
    # A bare push bp/mov bp,sp with no sub sp,0x110 after it is not the fill: the prologue alone
    # does not pass, the post-frame boundary is checked as well.
    ovr = bytearray(synth_ovr())
    ovr[g.OWNER_OFF:g.OWNER_OFF + 8] = b"\x55\x89\xE5\x90\x90\x90\x90\x90"
    checks = {c["id"]: c for c in g.static_checks(bytes(ovr))}
    assert checks["owner_post_frame_sub_sp"]["ok"] is False


# --------------------------------------------------------------------------
# START.EXE stub-slot evidence for the GEO fill entry (static; never establishes the entry)
# --------------------------------------------------------------------------

def test_geo_entry_candidate_names_slot_7_and_stays_unestablished():
    cand = g.geo_entry_candidate(synth_start())
    assert cand["header"]["is_group_29"] is True
    assert cand["status"] == "candidate"
    assert cand["binding"] == "unestablished"
    (slot,) = cand["slots"]
    assert slot["index"] == 7
    assert slot["file_off"] == "START:0x3E11"
    assert slot["target"] == "GAME.OVR:0x2F9BE"
    assert slot["tail_is_zero"] is False  # recorded, not used to accept or reject


def test_geo_entry_candidate_with_zero_tail_is_still_only_a_candidate():
    cand = g.geo_entry_candidate(synth_start(tail=0x00))
    assert cand["status"] == "candidate"
    assert cand["slots"][0]["tail_is_zero"] is True
    assert cand["binding"] == "unestablished"


def test_geo_entry_candidate_absent_when_proc_lands_elsewhere():
    # Proc 0x0E08 names the WALLDEF wrapper (0x2F6FF), not the fill.
    cand = g.geo_entry_candidate(synth_start(proc=0x0E08))
    assert cand["status"] == "absent"
    assert cand["slots"] == []
    assert cand["binding"] == "unestablished"


def test_geo_entry_candidate_refuses_other_group_header():
    cand = g.geo_entry_candidate(synth_start(fileofs=0x2E8F8))
    assert cand["header"]["is_group_29"] is False
    assert cand["status"] == "not-group-29"


def test_geo_entry_candidate_refuses_short_or_headerless_file():
    with pytest.raises(g.AidRefusal, match="too short"):
        g.geo_entry_candidate(b"\x00" * 0x100)
    bad = bytearray(synth_start())
    bad[g.START_HDR_OFF:g.START_HDR_OFF + 2] = b"\x00\x00"
    with pytest.raises(g.AidRefusal, match="no INT 3F"):
        g.geo_entry_candidate(bytes(bad))


# --------------------------------------------------------------------------
# Load and owner-stop checks
# --------------------------------------------------------------------------

def test_load_refuses_a_different_group_seek():
    load = {"file": "GAME.OVR", "seek_abs": "0x%X" % (SEEK + 1), "read_count": "0x%X" % SIZE,
            "dest": "23A5:0000"}
    with pytest.raises(g.AidRefusal, match="candidate starts"):
        g.load_check(load, None)


def test_load_refuses_a_short_read():
    load = {"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK, "read_count": "0x1000",
            "dest": "23A5:0000"}
    with pytest.raises(g.AidRefusal, match="does not cover"):
        g.load_check(load, None)


def test_load_refuses_a_non_ovr_file():
    with pytest.raises(g.AidRefusal, match="load.file"):
        g.load_check({"file": "START.EXE", "seek_abs": "0x0", "read_count": "0x0",
                      "dest": "0:0"}, None)


def test_load_dump_matches_install_bytes():
    ovr = synth_ovr()
    load = {"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK, "read_count": "0x%X" % SIZE,
            "dest": "23A5:0000", "dest_dump_hex": ovr[SEEK:SEEK + 8].hex(" ")}
    out = g.load_check(load, ovr)
    assert out["dump"]["status"] == "matched"
    assert out["owner_cs_ip"] == "23A5:10C7"


def test_load_dump_mismatch_is_a_refusal():
    ovr = synth_ovr()
    load = {"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK, "read_count": "0x%X" % SIZE,
            "dest": "23A5:0000", "dest_dump_hex": "00 00 00 00"}
    with pytest.raises(g.AidRefusal, match="do not match"):
        g.load_check(load, ovr)


def test_load_dump_not_compared_without_install_bytes():
    load = {"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK, "read_count": "0x%X" % SIZE,
            "dest": "23A5:0000", "dest_dump_hex": "00 01 02 03"}
    out = g.load_check(load, None)
    assert out["dump"]["status"] == "not-compared"


def test_load_without_dump_is_not_confirmed():
    load = {"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK, "read_count": "0x%X" % SIZE,
            "dest": "23A5:0000"}
    assert g.load_check(load, synth_ovr())["dump"]["status"] == "not-dumped"


def test_owner_stop_refuses_wrong_segment():
    ovr = synth_ovr()
    load = g.load_check({"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK,
                         "read_count": "0x%X" % SIZE, "dest": "23A5:0000"}, ovr)
    stop = {"at": "owner_entry", "cs": "3581", "ip": "10C7", "code_hex": "55 89 E5"}
    with pytest.raises(g.AidRefusal, match="not the translated owner_entry"):
        g.owner_stop_check(stop, load, GEO_SEG, 0, ovr)


def test_owner_stop_refuses_wrong_code_bytes():
    ovr = synth_ovr()
    load = g.load_check({"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK,
                         "read_count": "0x%X" % SIZE, "dest": "23A5:0000"}, ovr)
    stop = {"at": "owner_entry", "cs": "23A5", "ip": "10C7", "code_hex": "90 90 90"}
    with pytest.raises(g.AidRefusal, match="wrong code"):
        g.owner_stop_check(stop, load, GEO_SEG, 0, ovr)


def test_walldef_wrapper_stop_is_refused_as_the_geo_fill():
    # FALSIFIER. A stop at the WALLDEF wrapper's translated CS:IP (23A5:0E08, file 0x2F6FF) carries
    # the right prologue bytes, but it is not the GEO fill. It must be refused, not bound.
    ovr = synth_ovr()
    load = g.load_check({"file": "GAME.OVR", "seek_abs": "0x%X" % SEEK,
                         "read_count": "0x%X" % SIZE, "dest": "23A5:0000"}, ovr)
    walldef_cs_ip = g.file_to_cs_ip(g.WALLDEF_OFF, GROUP, GEO_SEG, 0)
    assert walldef_cs_ip == (0x23A5, 0x0E08)
    stop = {"at": "owner_entry", "cs": "23A5", "ip": "0E08", "code_hex": "55 89 E5"}
    with pytest.raises(g.AidRefusal, match="not the translated owner_entry"):
        g.owner_stop_check(stop, load, GEO_SEG, 0, ovr)


def test_walldef_stop_cannot_produce_a_toc_block_binding():
    # FALSIFIER at the observation level: a WALLDEF-wrapper owner stop, with a valid GEO seek,
    # is a refusal. toc_block_bound must not come out True from the wrapper.
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["owner_stop"] = {"at": "owner_entry", "cs": "23A5", "ip": "0E08", "code_hex": "55 89 E5"}
    with pytest.raises(g.AidRefusal, match="not the translated owner_entry"):
        g.check_observation(obs, ovr, _geo(dax))


def test_post_frame_requires_frame_fields():
    stop = {"at": "post_frame", "cs": "23A5", "ip": "10CA", "code_hex": "81 EC 10 01"}
    with pytest.raises(g.AidRefusal, match="required at post_frame"):
        g.owner_stop_check(stop, {"dest": "23A5:0000"}, GEO_SEG, 0, None)


def test_post_frame_needs_only_the_one_byte_argument():
    # The fill reads one byte argument ([bp+6]); there is no [bp+8] field to require.
    stop = {"at": "post_frame", "cs": "23A5", "ip": "10CA", "code_hex": "81 EC 10 01",
            "bp": "FFF0", "return_cs": "23A5", "return_ip": "0F00", "arg_bp6_word": "0001"}
    out = g.owner_stop_check(stop, {"dest": "23A5:0000"}, GEO_SEG, 0, None)
    assert out["frame"] is not None
    assert "arg_bp8" not in out["frame"]


def test_post_frame_caller_inside_group_is_translated():
    stop = {"at": "post_frame", "cs": "23A5", "ip": "10CA", "code_hex": "81 EC 10 01",
            "bp": "FFF0", "return_cs": "23A5", "return_ip": "0F00",
            "arg_bp6_word": "0301"}
    out = g.owner_stop_check(stop, {"dest": "23A5:0000"}, GEO_SEG, 0, None)
    assert out["frame"]["caller"]["in_group"] is True
    assert out["frame"]["caller"]["file_off"] == "0x%X" % (SEEK + 0x0F00)
    assert out["frame"]["arg_bp6"]["low_byte"] == "01"
    assert out["frame"]["args_semantics"] == "unresolved"


def test_post_frame_caller_outside_group_is_reported_not_refused():
    stop = {"at": "post_frame", "cs": "23A5", "ip": "10CA", "code_hex": "81 EC 10 01",
            "bp": "FFF0", "return_cs": "3581", "return_ip": "0F00",
            "arg_bp6_word": "0001"}
    out = g.owner_stop_check(stop, {"dest": "23A5:0000"}, GEO_SEG, 0, None)
    assert out["frame"]["caller"]["in_group"] is False
    assert "not the observed load segment" in out["frame"]["caller"]["reason"]


# --------------------------------------------------------------------------
# TOC binding
# --------------------------------------------------------------------------

def test_bind_toc_block_start():
    dax = synth_dax()
    res = g.bind_toc("GEO8.DAX", dax, dax_seek(dax, 1), 8)
    assert res["toc_index"] == 1
    assert res["block_id"] == 11
    assert res["comp_size"] == 8
    assert res["read_matches_comp_size"] is True
    assert res["mapping"] is None


def test_bind_toc_read_count_mismatch_is_recorded_not_refused():
    dax = synth_dax()
    res = g.bind_toc("GEO8.DAX", dax, dax_seek(dax, 0), 99)
    assert res["toc_index"] == 0
    assert res["read_matches_comp_size"] is False


def test_bind_toc_refuses_offset_inside_a_block():
    dax = synth_dax()
    with pytest.raises(g.AidRefusal, match="not the start of any TOC block"):
        g.bind_toc("GEO8.DAX", dax, dax_seek(dax, 1) + 1, None)


def test_bind_toc_refuses_non_geo_name():
    with pytest.raises(g.AidRefusal, match="not GEO<n>.DAX"):
        g.bind_toc("SAVGAM.DAT", synth_dax(), 0, None)


def test_bind_toc_refuses_malformed_container():
    with pytest.raises(g.AidRefusal, match="not a valid DAX"):
        g.bind_toc("GEO8.DAX", b"\x05\x00" + b"\x00" * 5, 7, None)


# --------------------------------------------------------------------------
# Observation check (end to end, bytes in)
# --------------------------------------------------------------------------

def _geo(dax):
    return lambda n: dax if n == 8 else None


def test_complete_observation_binds_without_mapping():
    ovr, dax = synth_ovr(), synth_dax()
    doc = g.check_observation(good_obs(ovr, dax), ovr, _geo(dax))
    assert doc["blockers"] == []
    assert doc["claims"]["toc_block_bound"] is True
    assert doc["claims"]["toc_seek_is_block_start"] is True
    assert doc["claims"]["geo_fill_entry"] == "observed-in-this-run"
    assert doc["claims"]["load_segment_confirmed"] is True
    assert doc["claims"]["area_mapping"] is None
    assert doc["mappings"] == []
    assert doc["dax"]["toc_binding"]["toc_index"] == 1


def test_seek_without_a_fill_stop_is_not_a_toc_block_binding():
    # The seek IS a block start, but nothing observed the GEO fill in this run: the entry is
    # unestablished and toc_block_bound stays False.
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    del obs["owner_stop"]
    doc = g.check_observation(obs, ovr, _geo(dax))
    assert doc["claims"]["toc_seek_is_block_start"] is True
    assert doc["claims"]["owner_stop_observed"] is False
    assert doc["claims"]["geo_fill_entry"] == "unestablished"
    assert doc["claims"]["toc_block_bound"] is False
    assert doc["geo_entry"]["binding"] == "unestablished"
    assert any(b.startswith("owner stop not observed") for b in doc["blockers"])


def test_observation_without_install_reports_blockers_not_success():
    ovr, dax = synth_ovr(), synth_dax()
    doc = g.check_observation(good_obs(ovr, dax), None, None)
    assert any("install not given" in b for b in doc["blockers"])
    assert any("TOC binding not checked" in b for b in doc["blockers"])
    assert doc["claims"]["toc_block_bound"] is False
    assert doc["claims"]["owner_stop_observed"] is True


def test_missing_owner_stop_and_dax_are_blockers():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    del obs["owner_stop"]
    del obs["dax"]
    doc = g.check_observation(obs, ovr, _geo(dax))
    assert any(b.startswith("owner stop not observed") for b in doc["blockers"])
    assert "GEO DAX seek not observed" in doc["blockers"]
    assert doc["claims"]["toc_block_bound"] is False


def test_static_entry_candidate_is_reported_but_never_establishes_the_entry():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    del obs["owner_stop"]
    doc = g.check_observation(obs, ovr, _geo(dax), start=synth_start())
    assert doc["geo_entry"]["static"]["status"] == "candidate"
    assert doc["geo_entry"]["binding"] == "unestablished"
    assert doc["claims"]["geo_fill_entry"] == "unestablished"
    assert doc["claims"]["toc_block_bound"] is False


def test_blank_template_is_refused():
    with pytest.raises(g.AidRefusal, match="route"):
        g.check_observation(g.observation_template(), None, None)


def test_wrong_schema_is_refused():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["schema"] = "openua.something-else"
    with pytest.raises(g.AidRefusal, match="schema must be"):
        g.check_observation(obs, ovr, _geo(dax))


def test_schema_version_1_is_refused_as_the_walldef_targets():
    # v1 observations were recorded against the WALLDEF wrapper (0x2F6FF). They must not be
    # re-read as GEO-fill evidence.
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["schema_version"] = 1
    with pytest.raises(g.AidRefusal, match="WALLDEF"):
        g.check_observation(obs, ovr, _geo(dax))


def test_handle_mismatch_is_refused():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["dax"]["seek_handle"] = "0006"
    with pytest.raises(g.AidRefusal, match="not the open handle"):
        g.check_observation(obs, ovr, _geo(dax))


def test_relative_seek_is_refused():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["dax"]["seek_al"] = "0x1"
    with pytest.raises(g.AidRefusal, match="absolute"):
        g.check_observation(obs, ovr, _geo(dax))


def test_non_geo_open_name_is_refused():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["dax"]["open_name"] = "SAVGAMA.DAT"
    with pytest.raises(g.AidRefusal, match="GEO<n>.DAX"):
        g.check_observation(obs, ovr, _geo(dax))


def test_geo_file_absent_from_install_is_refused():
    ovr, dax = synth_ovr(), synth_dax()
    with pytest.raises(g.AidRefusal, match="not in the install"):
        g.check_observation(good_obs(ovr, dax), ovr, lambda n: None)


def test_geo_seek_must_be_a_toc_start_for_check_to_pass():
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["dax"]["seek_abs"] = "0x%X" % (dax_seek(dax, 1) + 2)
    with pytest.raises(g.AidRefusal, match="not the start of any TOC block"):
        g.check_observation(obs, ovr, _geo(dax))


# --------------------------------------------------------------------------
# Emulator inspection (static)
# --------------------------------------------------------------------------

def test_emulator_inspection_reports_absent_and_not_given(tmp_path):
    assert g._inspect_file(None, "x")["status"] == "not-given"
    assert g._inspect_file(str(tmp_path / "nope.exe"), "x")["status"] == "absent"


def test_emulator_inspection_reads_strings_and_never_launches(tmp_path):
    fake = tmp_path / "dosbox-x.exe"
    fake.write_bytes(b"MZ....BPINT....BPLIST....BPDEL")
    emu = g._inspect_file(str(fake), "dosbox-x")
    assert emu["status"] == "present"
    assert emu["launched"] is False
    assert emu["matches_pin"] is False
    assert emu["debugger_strings"]["BPINT"] is True
    assert emu["debugger_strings"]["Breakpoint"] is False


# --------------------------------------------------------------------------
# CLI: plan and check, determinism, refusals
# --------------------------------------------------------------------------

def _run(argv):
    return g.main(argv)


def test_plan_without_install_writes_four_files_deterministically(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    a, b = tmp_path / "a", tmp_path / "b"
    assert _run(["plan", "-o", str(a)]) == 0
    assert _run(["plan", "-o", str(b)]) == 0
    names = ["por_geo_capture_aid.json", "por_geo_capture_checklist.md",
             "por_geo_capture_dosbox_commands.txt", "por_geo_capture_observation.template.json"]
    for n in names:
        assert (a / n).read_bytes() == (b / n).read_bytes(), n


def test_plan_without_segment_emits_no_concrete_breakpoint(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    _run(["plan", "-o", str(tmp_path)])
    text = (tmp_path / "por_geo_capture_dosbox_commands.txt").read_text(encoding="utf-8")
    assert "BLOCKED" in text
    import re
    assert not re.search(r"^BP [0-9A-F]{4}:", text, re.MULTILINE)


def test_plan_with_segment_emits_labelled_candidate_breakpoints(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    assert _run(["plan", "--load-seg", "23A5", "--buffer-off", "0", "-o", str(tmp_path)]) == 0
    text = (tmp_path / "por_geo_capture_dosbox_commands.txt").read_text(encoding="utf-8")
    assert "BP 23A5:10C7" in text
    assert "BP 23A5:10CA" in text
    assert "BP 23A5:1203" in text
    assert "BP 23A5:0E08" not in text  # the WALLDEF wrapper is never a breakpoint
    assert text.count("[UNVERIFIED]") == 3
    assert "RUN" in text and "BPINT 21 42" in text


def test_plan_output_has_no_absolute_paths_or_timestamps(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    _run(["plan", "--load-seg", "23A5", "-o", str(tmp_path)])
    for p in tmp_path.iterdir():
        text = p.read_text(encoding="utf-8")
        assert str(tmp_path) not in text
        assert ":\\" not in text and ":/" not in text
    doc = json.loads((tmp_path / "por_geo_capture_aid.json").read_text(encoding="utf-8"))
    assert doc["playable"] is False and doc["performed"] is False
    assert doc["mappings"] == [] and doc["claims"]["area_mapping"] is None


def test_plan_refuses_output_inside_repo_outside_data(monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    target = REPO_ROOT / "tmp_geo_capture_aid_should_not_exist"
    assert _run(["plan", "-o", str(target)]) == 2
    assert not target.exists()


def test_plan_refuses_bad_segment(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    assert _run(["plan", "--load-seg", "ZZZZ", "-o", str(tmp_path / "x")]) == 2


def test_plan_refuses_a_pin_mismatch(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"not the retail file")
    (install / "START.EXE").write_bytes(b"also not retail")
    assert _run(["plan", "--install", str(install), "-o", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out").exists()


def test_check_refuses_non_json(tmp_path):
    obs = tmp_path / "obs.json"
    obs.write_text("{not json", encoding="utf-8")
    assert _run(["check", "--observation", str(obs), "-o", str(tmp_path / "out")]) == 2


def test_check_refuses_a_schema_v1_observation_with_exit_2(tmp_path):
    ovr, dax = synth_ovr(), synth_dax()
    obs = good_obs(ovr, dax)
    obs["schema_version"] = 1
    path = tmp_path / "obs.json"
    path.write_text(json.dumps(obs), encoding="utf-8")
    assert _run(["check", "--observation", str(path), "-o", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out" / "por_geo_capture_check.json").exists()


def test_check_refuses_blank_template(tmp_path):
    obs = tmp_path / "obs.json"
    obs.write_text(json.dumps(g.observation_template()), encoding="utf-8")
    assert _run(["check", "--observation", str(obs), "-o", str(tmp_path / "out")]) == 2


def test_check_without_install_exits_1_with_blockers(tmp_path):
    ovr, dax = synth_ovr(), synth_dax()
    obs = tmp_path / "obs.json"
    obs.write_text(json.dumps(good_obs(ovr, dax)), encoding="utf-8")
    out = tmp_path / "out"
    assert _run(["check", "--observation", str(obs), "-o", str(out)]) == 1
    doc = json.loads((out / "por_geo_capture_check.json").read_text(encoding="utf-8"))
    assert doc["load"]["owner_cs_ip"] == "23A5:10C7"
    assert doc["mappings"] == []
    assert any("install not given" in b for b in doc["blockers"])


def test_check_is_deterministic(tmp_path):
    ovr, dax = synth_ovr(), synth_dax()
    obs = tmp_path / "obs.json"
    obs.write_text(json.dumps(good_obs(ovr, dax)), encoding="utf-8")
    _run(["check", "--observation", str(obs), "-o", str(tmp_path / "a")])
    _run(["check", "--observation", str(obs), "-o", str(tmp_path / "b")])
    for n in ("por_geo_capture_check.json", "por_geo_capture_check_report.md"):
        assert (tmp_path / "a" / n).read_bytes() == (tmp_path / "b" / n).read_bytes()


# --------------------------------------------------------------------------
# Retail anchor (runs only when OPENUA_POR_INSTALL names an install)
# --------------------------------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_INSTALL")


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")
def test_retail_static_checks_and_toc_table(tmp_path, monkeypatch):
    monkeypatch.delenv(g.EMULATOR_ENV, raising=False)
    assert _run(["plan", "--install", RETAIL, "-o", str(tmp_path / "retail")]) == 0
    doc = json.loads((tmp_path / "retail" / "por_geo_capture_aid.json").read_text(encoding="utf-8"))
    assert all(c["ok"] for c in doc["install"]["static_checks"])
    assert len(doc["install"]["toc_blocks"]) == 29
    assert doc["group"]["seek"] == "0x2E8F7"
    # The static stub-7 candidate names the GEO fill; the entry stays unestablished.
    entry = doc["install"]["geo_entry_static"]
    assert entry["status"] == "candidate"
    assert entry["binding"] == "unestablished"
    assert entry["slots"][0]["index"] == 7 and entry["slots"][0]["tail"] == "0x27"
    assert [t["cs_ip"] for t in doc["targets"]] == [None, None, None]  # no load segment given
