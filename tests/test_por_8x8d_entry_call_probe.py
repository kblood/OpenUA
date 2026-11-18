"""Tests for tools/por_8x8d_entry_call_probe.py (static caller census, observe-only).

Each rule has a falsifier on a hand-assembled synthetic image: an E8 caller counts only from a tier-A
body; a jump outside the body span is a tail-jump caller; a jump inside the span, or a jcc inside one
routine, is a same-body branch and not a caller; an unreached source is tier C; the FF /2-/5 forms
decode with the displacement the bytes give; a table word is a candidate only; a 9A literal counts
only under the image model; a bad pin or a non-data output folder is refused (exit 2).

The retail anchors run only when OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and
are skipped otherwise. Nothing here writes outside a temporary folder; the refusal tests never write.
"""
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, TESTS)
import por_8x8d_entry_call_probe as P  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402
from por_convert import PorSourceError  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
RETAIL = os.environ.get(ENV)
needs_retail = pytest.mark.skipif(not RETAIL, reason="set %s to the PoR DOS install" % ENV)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def image(places: dict, size: int = 0x1000) -> bytes:
    """A flat image of zeros with the given {offset: bytes} written in."""
    b = bytearray(size)
    for off, blob in places.items():
        b[off:off + len(blob)] = blob
    return bytes(b)


def rel16(src_next: int, target: int) -> bytes:
    return struct.pack("<h", target - src_next)


def root_calls(entry: int) -> dict:
    """A root at 0x050 that calls `entry` by E8, so `entry` is an E8-verified body (tier A)."""
    return {0x050: b"\xE8" + rel16(0x053, entry) + b"\xC3"}


def routine(off: int, body: bytes) -> dict:
    """A prologue-entered routine: push bp; mov bp,sp; body."""
    return {off: b"\x55\x89\xE5" + body}


def analyse_one(data: bytes, off: int, tid: str = "T") -> dict:
    out = P.analyse_image(data, [(tid, off, "synthetic")])
    return out["targets"][0]


# --------------------------------------------------------------------------
# Direct edges and tiers
# --------------------------------------------------------------------------

def test_tail_jump_outside_span_is_cross_body_caller():
    """E9 from a tier-A body to a target 0x800 bytes away is a tail jump, so it counts as a caller."""
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xE9" + rel16(0x106, 0x900)))
    places.update(routine(0x900, b"\xC3"))
    t = analyse_one(image(places), 0x900)
    row = t["direct"][0]
    assert row["at"] == 0x103 and row["kind"] == "jmp" and row["tier"] == "A"
    assert row["same_body"] is False
    assert t["summary"]["direct_a_tier_callers"] == 1


def test_tail_jump_falsifier_unreached_source_is_not_a_caller():
    """The same E9 with no E8 root is tier B (prologue only), so it is reported but not counted."""
    places = {}
    places.update(routine(0x100, b"\xE9" + rel16(0x106, 0x900)))
    places.update(routine(0x900, b"\xC3"))
    t = analyse_one(image(places), 0x900)
    row = t["direct"][0]
    assert row["tier"] == "B"
    assert t["summary"]["direct_a_tier_callers"] == 0


def test_e8_from_tier_a_body_is_cross_body_caller():
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xE8" + rel16(0x106, 0x900) + b"\xC3"))
    places.update(routine(0x900, b"\xC3"))
    t = analyse_one(image(places), 0x900)
    row = t["direct"][0]
    assert row["kind"] == "call" and row["tier"] == "A" and row["same_body"] is False
    assert t["summary"]["e8_tier_a"] == 1 and t["summary"]["direct_a_tier_callers"] == 1


def test_near_jump_inside_span_is_same_body_not_caller():
    """A jmp to 0x180 from routine 0x100 stays inside the 0x400 span: a branch, not a caller."""
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xE9" + rel16(0x106, 0x180)))
    places.update({0x180: b"\xC3"})
    t = analyse_one(image(places), 0x180)
    row = t["direct"][0]
    assert row["tier"] == "A" and row["same_body"] is True
    assert t["summary"]["direct_a_tier_callers"] == 0


def test_jcc_inside_one_routine_is_same_body_like_path_label():
    """A jz that skips into the same routine (the PATH-label shape at 0x0A85B) is same-body."""
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\x74\x02" + b"\x90\x90" + b"\xC3"))
    t = analyse_one(image(places), 0x107)
    row = t["direct"][0]
    assert row["kind"] == "jcc" and row["tier"] == "A" and row["same_body"] is True
    assert t["summary"]["direct_a_tier_callers"] == 0
    assert t["summary"]["jump_tier_a"] == 1


def test_unreached_data_source_is_tier_c_and_not_counted():
    """An E8 at 0x800 that no prologue or E8 body reaches is tier C: reported, not counted."""
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xC3"))
    places.update({0x800: b"\xE8" + rel16(0x803, 0x900)})
    places.update(routine(0x900, b"\xC3"))
    t = analyse_one(image(places), 0x900)
    row = t["direct"][0]
    assert row["at"] == 0x800 and row["tier"] == "C"
    assert t["summary"]["direct_a_tier_callers"] == 0
    assert t["summary"]["e8_all_tiers"] == 1


def test_no_transfer_to_target_gives_no_rows():
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xC3"))
    t = analyse_one(image(places), 0x300)
    assert t["direct"] == [] and t["far_model"] == []
    assert t["summary"]["direct_a_tier_callers"] == 0


# --------------------------------------------------------------------------
# Indirect transfers: decode of the displacement forms
# --------------------------------------------------------------------------

def test_indirect_forms_decode_with_displacement():
    """FF /2 to /5 in each addressing form: direct disp16, [bx+disp16], register, [bx]."""
    data = image({0x10: b"\xFF\x97\x10\x00",     # call [bx+0x10]      (FF /2, mod 10)
                  0x14: b"\xFF\xD0",             # call ax             (FF /2, mod 11)
                  0x16: b"\xFF\x1E\x34\x12",     # call far [0x1234]   (FF /3, mod 00 rm 110)
                  0x1A: b"\xFF\x2F"},            # jmp far [bx]        (FF /5, mod 00 rm 111)
                 size=0x40)
    rows = P.indirect_sites(data, lambda off: "A")
    got = [(r["at"], r["kind"], r["disp_form"], r["disp"]) for r in rows]
    assert got == [(0x10, "call_near", "base-disp", 0x10),
                   (0x14, "call_near", "register", None),
                   (0x16, "call_far", "direct", 0x1234),
                   (0x1A, "jmp_far", "base-no-disp", None)]


def test_indirect_jmp_direct_is_tier_a_inside_body():
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xFF\x26\x00\x04" + b"\xC3"))
    data = image(places)
    rows = P.indirect_sites(data, P.make_tier(*P.build_reach(data)))
    row = [r for r in rows if r["at"] == 0x103][0]
    assert row["kind"] == "jmp_near" and row["disp_form"] == "direct"
    assert row["disp"] == 0x400 and row["tier"] == "A"


# --------------------------------------------------------------------------
# Table words, far model, chance rate
# --------------------------------------------------------------------------

def test_table_word_hit_is_candidate_with_base_zero():
    data = image({0x400: b"\x00\x02"})          # word 0x0200 at 0x400
    t = analyse_one(data, 0x200)
    hits = [h for h in t["table_word_hits"] if h["base"] == 0]
    assert [h["at"] for h in hits] == [0x400] and hits[0]["loc_tier"] == "C"


def test_table_word_falsifier_off_by_one_is_not_a_hit():
    data = image({0x400: b"\x01\x02"})          # word 0x0201, not 0x0200
    t = analyse_one(data, 0x200)
    assert t["table_word_hits"] == []


def test_zero_value_base_is_skipped_not_padded():
    """Base 0x200 with T=0x200 gives value 0, which every zero word would match: skipped, and recorded."""
    t = analyse_one(image({}), 0x200)
    assert t["table_bases_skipped_zero_value"] == [0x200]
    assert [h for h in t["table_word_hits"] if h["base"] == 0x200] == []


def test_table_word_base_0x200_uses_mz_relative_value():
    data = image({0x600: b"\x00\x01"})          # word 0x0100 = 0x300 - 0x200
    t = analyse_one(data, 0x300)
    assert [(h["at"], h["base"]) for h in t["table_word_hits"]] == [(0x600, 0x200)]


def test_chance_rate_is_length_over_64k():
    t = analyse_one(image({}, size=0x1000), 0x300)
    assert t["chance_hits_per_value"] == round(0x1000 / 65536.0, 4)


def test_far_model_literal_counts_only_under_image_model():
    """9A 0100:0000 is model 0x200 + 0*16 + 0x100 = 0x300, so it counts for 0x300, not for 0x301."""
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\x9A\x00\x01\x00\x00" + b"\xC3"))
    data = image(places)
    t300 = analyse_one(data, 0x300)
    assert t300["summary"]["far_model_total"] == 1 and t300["summary"]["far_model_tier_a"] == 1
    t301 = analyse_one(data, 0x301)
    assert t301["summary"]["far_model_total"] == 0


# --------------------------------------------------------------------------
# Refusals, pins, determinism
# --------------------------------------------------------------------------

def _synthetic_install(root: Path, start: bytes, ovr: bytes) -> Path:
    inst = root / "POOLRAD"
    inst.mkdir(parents=True)
    (inst / "START.EXE").write_bytes(start)
    (inst / "GAME.OVR").write_bytes(ovr)
    return inst


def test_unpinned_install_is_refused_without_flag(tmp_path):
    inst = _synthetic_install(tmp_path / "src", b"\x00" * 64, b"\x00" * 64)
    out = tmp_path / "out"
    assert P.main(["--install", str(inst), "-o", str(out)]) == 2
    assert not (out / "por_8x8d_entry_call_probe.json").exists()


def test_unpinned_install_with_flag_is_exit_1_and_not_retail(tmp_path):
    inst = _synthetic_install(tmp_path / "src", b"\x00" * 64, b"\x00" * 64)
    out = tmp_path / "out"
    assert P.main(["--install", str(inst), "-o", str(out), "--allow-unpinned"]) == 1
    doc = json.loads((out / "por_8x8d_entry_call_probe.json").read_text(encoding="utf-8"))
    assert doc["retail_evidence"] is False and doc["playable"] is False and doc["mappings"] == []


def test_output_inside_repo_but_not_data_is_refused(tmp_path):
    inst = _synthetic_install(tmp_path / "src", b"\x00" * 64, b"\x00" * 64)
    bad = Path(TESTS).parent / "tests" / "_no_such_out_dir_entry_call"
    assert P.main(["--install", str(inst), "-o", str(bad), "--allow-unpinned"]) == 2
    assert not bad.exists()


def test_output_inside_install_is_refused(tmp_path):
    inst = _synthetic_install(tmp_path / "src", b"\x00" * 64, b"\x00" * 64)
    assert P.main(["--install", str(inst), "-o", str(inst / "out"), "--allow-unpinned"]) == 2
    assert not (inst / "out").exists()


def test_missing_install_is_refused(tmp_path):
    assert P.main(["--install", str(tmp_path / "nothing"), "-o", str(tmp_path / "o"),
                   "--allow-unpinned"]) == 2


def test_probe_output_is_deterministic(tmp_path):
    places = {}
    places.update(root_calls(0x100))
    places.update(routine(0x100, b"\xE9" + rel16(0x106, 0x900) + b"\xFF\x26\x00\x04\xC3"))
    places.update(routine(0x900, b"\xC3"))
    inst = _synthetic_install(tmp_path / "src", image(places), image({}))
    a, b = tmp_path / "a", tmp_path / "b"
    assert P.main(["--install", str(inst), "-o", str(a), "--allow-unpinned"]) == 1
    assert P.main(["--install", str(inst), "-o", str(b), "--allow-unpinned"]) == 1
    for name in ("por_8x8d_entry_call_probe.json", "por_8x8d_entry_call_probe_report.md"):
        assert (a / name).read_bytes() == (b / name).read_bytes()


# --------------------------------------------------------------------------
# Retail anchors (skipped without OPENUA_POR_INSTALL)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def retail():
    folder = P.resolve_folder(Path(RETAIL))
    start = (folder / "START.EXE").read_bytes()
    ovr = (folder / "GAME.OVR").read_bytes()
    assert (len(start), P._sha(start)) == fr.PINNED["START.EXE"]
    assert (len(ovr), P._sha(ovr)) == fr.PINNED["GAME.OVR"]
    return P.analyse(start, ovr)


def _target(per_image, tid):
    for img in per_image.values():
        for t in img["targets"]:
            if t["id"] == tid:
                return t
    raise KeyError(tid)


@needs_retail
def test_retail_open_helper_has_three_cross_body_e8_callers(retail):
    t = _target(retail, "OPEN")
    callers = sorted(r["at"] for r in t["direct"] if r["kind"] == "call" and r["same_body"] is False)
    assert callers == [0x0A806, 0x0A841, 0x0A895]
    assert t["summary"]["direct_a_tier_callers"] == 3


@needs_retail
def test_retail_path_label_is_same_body_not_a_caller(retail):
    t = _target(retail, "PATH")
    assert t["summary"]["direct_a_tier_callers"] == 0
    assert sorted((r["at"], r["kind"], r["same_body"]) for r in t["direct"]) == [
        (0x0A85B, "jcc", True), (0x0A89A, "jcc", True)]


@needs_retail
def test_retail_l_stub_and_overlay_open_have_no_direct_or_far_model_callers(retail):
    for tid in ("L", "STUB", "OVR_OPEN", "R", "READ_A", "READ_C"):
        t = _target(retail, tid)
        assert t["summary"]["direct_a_tier_callers"] == 0, tid
        assert t["summary"]["e8_all_tiers"] == 0, tid
        assert t["summary"]["far_model_total"] == 0, tid


@needs_retail
def test_retail_overlay_open_and_stub_have_no_table_word_hits(retail):
    assert _target(retail, "OVR_OPEN")["table_word_hits"] == []
    assert _target(retail, "STUB")["table_word_hits"] == []


@needs_retail
def test_retail_r_table_hits_are_all_unwalked_candidates(retail):
    t = _target(retail, "R")
    hits = [h for h in t["table_word_hits"] if h["base"] == 0x200]
    assert len(hits) == 12
    assert all(h["loc_tier"] == "C" for h in hits)


@needs_retail
def test_retail_tier_a_indirect_sites_are_not_linked(retail):
    for img in retail.values():
        for r in img["indirect_sites"]:
            assert set(r) == {"at", "kind", "reg", "disp_form", "disp", "tier"}
