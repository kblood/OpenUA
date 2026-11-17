"""Tests for tools/por_overlay_group_map.py (one VROOMM group mapped into a RAM dump, read-only).

Default suite: synthetic bytes only. The GAME.OVR, START.EXE and dump are generated here, and the
pins are computed from the generated blobs and passed into analyze(). Nothing is read from the
install, no process is touched, and nothing is written outside a pytest tmp folder.

The retail test runs only when OPENUA_POR_INSTALL names the install and the local dump
data/work/por-wheel-live-capture/ram-000000-100000.bin exists. It checks the mapping facts the
probe reports for the user-supplied pinned files and the dump; it does not test any meaning.
"""
import os
import random
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_overlay_group_map as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_DUMP = REPO / "data" / "work" / "por-wheel-live-capture" / "ram-000000-100000.bin"

G = 0x100              # group fileofs in GAME.OVR (synthetic)
C = 0x60               # group codesz
D = 0x40               # START.EXE offset of the descriptor header (synthetic)
DELTA = 0x1866         # the uniform fixup delta observed on retail (live = raw + DELTA)
GROUP_LIN = 0x49150    # linear base of the synthetic group in the dump
SITE1_OFF, SITE1_RAW_SEG = 0x1234, 0x0AF8
SITE2_OFF, SITE2_RAW_SEG = 0x0040, 0x0709
W1_EXE = 0x200         # 32-byte target window 1 in START.EXE
W2_EXE = 0x300         # 32-byte target window 2 in START.EXE


def _window(seed: int) -> bytes:
    # 32 bytes, distinct within a blob (no accidental repeats)
    return bytes(((seed + 7 * i) ^ (i << 3)) & 0xFF for i in range(32))


W1 = _window(0x11)
W2 = _window(0xC3)


def make_code() -> bytearray:
    code = bytearray((0x90 + (i % 5)) & 0xFF for i in range(C))
    code[0x10:0x15] = b"\x9a" + struct.pack("<HH", SITE1_OFF, SITE1_RAW_SEG)    # far call 1
    code[0x30:0x35] = b"\x9a" + struct.pack("<HH", SITE2_OFF, SITE2_RAW_SEG)    # far call 2
    code[0x50:0x53] = b"\xb8" + struct.pack("<H", SITE1_RAW_SEG)                # mov ax,seg (no 9A)
    return code


FIXUPS = [0x13, 0x33, 0x51]        # 0x13, 0x33: far-call seg words; 0x51: mov-ax seg word
SITE1_SEG_WORD, SITE2_SEG_WORD = 0x13, 0x33


def make_blobs(*, w1=W1, w2=W2, extra_w1_at=None, fixups=FIXUPS, exe_size=0x800):
    # Non-repeating pseudo-random filler, so no shifted 32-byte window can match by accident.
    ovr = bytearray(random.Random(0x0B).randbytes(0x400))
    code = make_code()
    ovr[G:G + C] = code
    ovr[G + C:G + C + 2 * len(fixups)] = struct.pack("<%dH" % len(fixups), *fixups)
    exe = bytearray(random.Random(0x5EED).randbytes(exe_size))
    exe[D:D + 4] = p.DESC_MAGIC
    struct.pack_into("<I", exe, D + 4, G)
    struct.pack_into("<HHH", exe, D + 8, C, 2 * len(fixups), 0)
    exe[W1_EXE:W1_EXE + 32] = w1
    exe[W2_EXE:W2_EXE + 32] = w2
    if extra_w1_at is not None:
        exe[extra_w1_at:extra_w1_at + 32] = w1
    return bytes(ovr), bytes(exe)


def pins_for(ovr: bytes, exe: bytes) -> dict:
    return {"GAME.OVR": {"size": len(ovr), "sha256": p.sha256(ovr)},
            "START.EXE": {"size": len(exe), "sha256": p.sha256(exe)}}


LIVE1 = (SITE1_RAW_SEG + DELTA) & 0xFFFF      # 0x235E: where the window really lives
LIVE2 = (SITE2_RAW_SEG + DELTA) & 0xFFFF      # 0x1F6F


def make_dump(*, base: int = 0, size: int = 0x100000, patched: bool = True,
              live1: int = None, live2: int = None, ovr: bytes = None, w1=W1, w2=W2):
    """A RAM image. The group's code sits at GROUP_LIN with fixup words patched (live = raw + DELTA,
    or raw when patched=False). live1/live2 override the patched operand words in the dump only.
    The two target windows are always placed at their TRUE live addresses (LIVE1/LIVE2), so an
    operand override moves the call away from its window rather than moving the window."""
    ovr = ovr if ovr is not None else make_blobs()[0]
    mem = bytearray(size)

    def put(lin: int, data: bytes) -> None:
        if base <= lin and lin + len(data) <= base + size:
            mem[lin - base:lin - base + len(data)] = data

    code = bytearray(ovr[G:G + C])
    for w in FIXUPS:
        raw = struct.unpack_from("<H", code, w)[0]
        live = (raw + DELTA) & 0xFFFF if patched else raw
        if w == SITE1_SEG_WORD and live1 is not None:
            live = live1
        if w == SITE2_SEG_WORD and live2 is not None:
            live = live2
        struct.pack_into("<H", code, w, live)
    put(GROUP_LIN, bytes(code))
    put(LIVE1 * p.PARA + SITE1_OFF, w1)
    put(LIVE2 * p.PARA + SITE2_OFF, w2)
    return bytes(mem)


def run(ovr, exe, dump, *, base=0, meta=None):
    return p.analyze(ovr, exe, dump, base, D, dump_name="ram-%06x-%06x.bin" % (base, base + len(dump)),
                     pins=pins_for(ovr, exe), meta=meta)


def _site(doc, offset_hex):
    return [r for r in doc["far_call_sites"] if r["site_group_offset"] == offset_hex][0]


# ---- positive path ------------------------------------------------------------------------

def test_positive_group_and_targets_resolve():
    ovr, exe = make_blobs()
    doc = run(ovr, exe, make_dump())
    assert doc["status"] == "ok"
    assert doc["group"]["base_linear"] == "0x%X" % GROUP_LIN
    assert doc["group"]["mapping"]["status"] == "unique"
    sites = doc["far_call_sites"]
    assert len(sites) == 2                                    # the 0x51 mov-ax word is not a site
    assert [r["window"]["status"] for r in sites] == ["unique-START.EXE", "unique-START.EXE"]
    assert sites[0]["window"]["hits"]["START.EXE"] == ["0x%X" % W1_EXE]
    assert sites[1]["window"]["hits"]["START.EXE"] == ["0x%X" % W2_EXE]
    assert all(r["memory_present"] and r["opcode_0x9a"] and r["offset_matches_file"] for r in sites)
    assert doc["checks"]["all_targets_unique_in_pinned_file"] is True
    assert doc["relocation"]["uniform_delta"] is True
    assert doc["relocation"]["seg_deltas"] == ["0x%04X" % DELTA]


def test_segment_displacement_is_one_block_per_live_segment():
    ovr, exe = make_blobs()
    doc = run(ovr, exe, make_dump())
    disp = doc["segment_displacements"]
    # 235E:1234 -> START 0x200 and 1F6F:0040 -> START 0x300 (one target each, one block each)
    assert disp["235E"]["displacements"] == ["-0x1034"] and disp["235E"]["uniform"] is True
    assert disp["1F6F"]["displacements"] == ["0x2C0"] and disp["1F6F"]["uniform"] is True


def test_non_far_fixup_is_reported_not_counted_as_site():
    ovr, exe = make_blobs()
    doc = run(ovr, exe, make_dump())
    assert [r["seg_word"] for r in doc["non_far_fixups"]] == ["0x51"]
    assert doc["non_far_fixups"][0]["byte_before_seg"] == "0xB8"
    assert len(doc["far_call_sites"]) == 2


def test_fixup_words_are_masked_so_patched_dump_maps_and_unpatched_maps_too():
    ovr, exe = make_blobs()
    assert run(ovr, exe, make_dump(patched=True))["group"]["base_linear"] == "0x%X" % GROUP_LIN
    # Unpatched raw segment words still map (they are masked), but the targets then miss.
    doc = run(ovr, exe, make_dump(patched=False))
    assert doc["group"]["base_linear"] == "0x%X" % GROUP_LIN
    assert doc["status"] == "diagnostic"
    # The raw 0AF8/0709 targets hold no window, so they are not unique (zero padding: ambiguous).
    assert all(not r["window"]["status"].startswith("unique-") for r in doc["far_call_sites"])


def test_caller_metadata_is_recorded_unverified_and_never_changes_status():
    ovr, exe = make_blobs()
    base = run(ovr, exe, make_dump())
    with_meta = run(ovr, exe, make_dump(), meta={"pid": "34644", "dump_capture": "non-atomic"})
    assert with_meta["status"] == base["status"] == "ok"
    assert with_meta["caller_metadata"] == {"unverified": True,
                                            "values": {"pid": "34644", "dump_capture": "non-atomic"}}


def test_runtime_claims_keep_memory_presence_separate_from_execution():
    ovr, exe = make_blobs()
    doc = run(ovr, exe, make_dump())
    assert doc["runtime_claims"]["executed"] == "not_established"
    assert doc["runtime_claims"]["called"] == "not_established"
    assert doc["runtime_claims"]["memory_present"].startswith("a far-call target")
    assert all(r["memory_present"] for r in doc["far_call_sites"])
    assert any("executed" in s for s in doc["not_established"])


# ---- falsification: group mapping ---------------------------------------------------------

def test_group_absent_is_refused():
    ovr, exe = make_blobs()
    dump = bytearray(make_dump())
    dump[GROUP_LIN + 5] ^= 0xFF                          # one stable byte wrong
    with pytest.raises(p.Refusal, match="absent"):
        run(ovr, exe, bytes(dump))


def test_group_missing_entirely_is_refused():
    ovr, exe = make_blobs()
    with pytest.raises(p.Refusal, match="absent"):
        run(ovr, exe, bytes(0x100000))


def test_group_ambiguous_is_refused():
    ovr, exe = make_blobs()
    dump = bytearray(make_dump())
    copy = bytes(dump[GROUP_LIN:GROUP_LIN + C])
    dump[0x60000:0x60000 + C] = copy                     # a second, identical copy
    with pytest.raises(p.Refusal, match="ambiguous"):
        run(ovr, exe, bytes(dump))


def test_wrong_offset_operand_breaks_group_match_and_is_refused():
    ovr, exe = make_blobs()
    dump = bytearray(make_dump())
    dump[GROUP_LIN + 0x11] ^= 0x01                       # offset low byte of far call 1
    with pytest.raises(p.Refusal, match="absent"):
        run(ovr, exe, bytes(dump))


def test_wrong_segment_operand_is_a_diagnostic_not_a_match():
    ovr, exe = make_blobs()
    wrong = (((SITE1_RAW_SEG + DELTA) & 0xFFFF) + 1) & 0xFFFF
    doc = run(ovr, exe, make_dump(live1=wrong))
    assert doc["group"]["base_linear"] == "0x%X" % GROUP_LIN
    assert doc["status"] == "diagnostic"
    assert _site(doc, "0x10")["window"]["status"] == "absent"
    assert _site(doc, "0x30")["window"]["status"] == "unique-START.EXE"


def test_fixup_table_out_of_range_is_refused():
    ovr, exe = make_blobs(fixups=[0x13, 0x33, 0x5F])     # 0x5F + 2 > codesz
    with pytest.raises(p.Refusal, match="outside the group code"):
        run(ovr, exe, make_dump(ovr=ovr))


def test_fixup_table_not_sorted_is_refused():
    ovr, exe = make_blobs(fixups=[0x33, 0x13, 0x51])
    with pytest.raises(p.Refusal, match="not strictly increasing"):
        run(ovr, exe, make_dump(ovr=ovr))


# ---- falsification: targets ---------------------------------------------------------------

def test_nonunique_code_target_is_ambiguous_not_resolved():
    ovr, exe = make_blobs(extra_w1_at=0x500)            # window 1 also at START 0x500
    doc = run(ovr, exe, make_dump())
    site = _site(doc, "0x10")
    assert site["window"]["status"] == "ambiguous"
    assert site["window"]["hit_count"] == 2
    assert site["memory_present"] is False
    assert doc["status"] == "diagnostic"


def test_target_absent_from_both_pinned_files_is_diagnostic():
    ovr, exe = make_blobs()
    alien = bytes(range(0xE0, 0xE0 + 32))               # not in either pinned file
    doc = run(ovr, exe, make_dump(w1=alien))
    assert _site(doc, "0x10")["window"]["status"] == "absent"
    assert _site(doc, "0x10")["window"]["hit_count"] == 0
    assert doc["status"] == "diagnostic"


def test_target_outside_dump_is_bounds_not_a_crash():
    ovr, exe = make_blobs()
    dump = make_dump(base=0x40000, size=0x10000)        # group inside; both windows below base
    doc = run(ovr, exe, dump, base=0x40000)
    assert [r["window"]["status"] for r in doc["far_call_sites"]] == ["bounds", "bounds"]
    assert doc["status"] == "diagnostic"


def test_live_window_bytes_are_recorded_for_inspection():
    ovr, exe = make_blobs()
    doc = run(ovr, exe, make_dump())
    assert _site(doc, "0x10")["window"]["live_bytes_hex"] == W1.hex(" ")


# ---- falsification: sources, pins, bounds -------------------------------------------------

def test_unpinned_start_is_refused():
    ovr, exe = make_blobs()
    pins = pins_for(ovr, exe)
    bad = bytearray(exe)
    bad[0x0F] ^= 0x01                                    # one byte of START.EXE changed
    with pytest.raises(p.Refusal, match="START.EXE does not match its pin"):
        p.analyze(ovr, bytes(bad), make_dump(), 0, D, dump_name="ram-000000-100000.bin", pins=pins)


def test_unpinned_game_ovr_is_refused():
    ovr, exe = make_blobs()
    pins = pins_for(ovr, exe)
    bad = bytearray(ovr)
    bad[0x7] ^= 0x01
    with pytest.raises(p.Refusal, match="GAME.OVR does not match its pin"):
        p.analyze(bytes(bad), exe, make_dump(), 0, D, dump_name="ram-000000-100000.bin", pins=pins)


def test_descriptor_offset_outside_start_is_refused():
    ovr, exe = make_blobs()
    with pytest.raises(p.Refusal, match="outside START.EXE"):
        p.analyze(ovr, exe, make_dump(), 0, len(exe) - 4, dump_name="x.bin", pins=pins_for(ovr, exe))


def test_descriptor_without_magic_is_refused():
    ovr, exe = make_blobs()
    bad = bytearray(exe)
    bad[D] = 0x00
    with pytest.raises(p.Refusal, match="no CD 3F 00 00"):
        p.analyze(ovr, bytes(bad), make_dump(), 0, D, dump_name="x.bin", pins=pins_for(ovr, bytes(bad)))


def test_group_running_past_game_ovr_is_refused():
    ovr, exe = make_blobs()
    short = ovr[:G + C - 4]                              # the group and fixup table no longer fit
    with pytest.raises(p.Refusal, match="runs past the end of GAME.OVR"):
        p.analyze(short, exe, make_dump(), 0, D, dump_name="x.bin", pins=pins_for(short, exe))


def test_group_running_past_dump_end_is_refused():
    ovr, exe = make_blobs()
    dump = make_dump(size=GROUP_LIN + 0x20)              # the group's code is cut off by the dump end
    with pytest.raises(p.Refusal, match="absent"):
        run(ovr, exe, dump)


def test_dump_name_size_mismatch_is_refused():
    with pytest.raises(p.Refusal, match="says"):
        p.resolve_dump_base("ram-000000-000100.bin", 0x80, None)


def test_dump_base_disagreeing_with_name_is_refused():
    with pytest.raises(p.Refusal, match="disagrees"):
        p.resolve_dump_base("ram-000000-100000.bin", 0x100000, 0x40000)


def test_dump_base_must_be_known():
    with pytest.raises(p.Refusal, match="base unknown"):
        p.resolve_dump_base("dump.bin", 0x100, None)


def test_probe_refuses_output_outside_data_work(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"x")
    (install / "START.EXE").write_bytes(b"x")
    dump = tmp_path / "ram-000000-000001.bin"
    dump.write_bytes(b"\x00")
    with pytest.raises(p.Refusal, match="under data/work"):
        p.probe(install, dump, descriptor_off=D, out=tmp_path / "out", dump_base=None, meta={})


def test_probe_refuses_unpinned_install(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"x")
    (install / "START.EXE").write_bytes(b"x")
    dump = tmp_path / "ram-000000-000001.bin"
    dump.write_bytes(b"\x00")
    out = REPO / "data" / "work" / "por-overlay-group-map-test-unused"
    with pytest.raises(p.Refusal, match="does not match its pin"):
        p.probe(install, dump, descriptor_off=D, out=out, dump_base=None, meta={})
    assert not out.exists()


def test_meta_must_be_key_value():
    with pytest.raises(p.Refusal, match="KEY=VALUE"):
        p._meta(["pid"])


# ---- retail (optional) --------------------------------------------------------------------

RETAIL_SITES = {"0x10": "unique-START.EXE"}


@pytest.mark.skipif(not os.environ.get("OPENUA_POR_INSTALL") or not RETAIL_DUMP.is_file(),
                    reason="needs OPENUA_POR_INSTALL and the local retail dump under data/work")
def test_retail_group_map_against_local_dump():
    folder = p.find_install(Path(os.environ["OPENUA_POR_INSTALL"]))
    ovr = (folder / "GAME.OVR").read_bytes()
    exe = (folder / "START.EXE").read_bytes()
    dump = RETAIL_DUMP.read_bytes()
    doc = p.analyze(ovr, exe, dump, 0, p.DEFAULT_DESCRIPTOR, dump_name=RETAIL_DUMP.name)
    assert doc["group"]["base_linear"] == "0x49150"
    assert doc["descriptor"]["fileofs"] == "0x9AC"
    assert len(doc["far_call_sites"]) == 30
    assert doc["counts"].get("unique-START.EXE") == 18
    assert doc["counts"].get("absent") == 12
    by_target = {r["target"]: r["window"] for r in doc["far_call_sites"]}
    for tgt, start_off in (("235E:11C0", "0xBE36"), ("235E:0B0B", "0xB781"),
                           ("235E:0B25", "0xB79B"), ("235E:0B98", "0xB80E"), ("235E:0C10", "0xB886")):
        assert by_target[tgt]["status"] == "unique-START.EXE", tgt
        assert by_target[tgt]["hits"]["START.EXE"] == [start_off], tgt
    assert doc["relocation"]["uniform_delta"] is True
    assert doc["relocation"]["seg_deltas"] == ["0x1866"]
    assert doc["status"] == "diagnostic"                  # 12 absent targets remain
