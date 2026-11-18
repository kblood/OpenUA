"""Tests for tools/por_wall_0111_fill_callers_probe.py (fill 0x0AF8:0x16A8 and the START callers of 0x023F/0x0254).

Synthetic fixtures (default) check each claim with a mutated-byte falsifier that must change the result: the fill
body template and its layout, the window identity of the fill, the three wall-helper fill sites (count expression,
zero value, destination pushes, call targets), the two START caller frames (size, pointer source, copy and link
words, straight-line runs, entry guard, retf), the pairing verdict, the static caller search, and the CLI refusals.
The retail test runs only when OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and is skipped
otherwise; it reads the install and the ignored RAM dumps read-only, writes nothing, and checks that two in-memory
runs agree.
"""
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_0111_fill_callers_probe as fp  # noqa: E402
import por_wall_0111_module_target_probe as mp  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
BASE = 0x100                                   # synthetic module base in the fake START.EXE
LIVE_SEG = mp.MODULE_SEG + mp.EXPECT_LOAD      # 0x235E
NOP = 0x90


def _blank(size: int) -> bytearray:
    """A NOP-filled fake START.EXE: every byte is a one-byte instruction, so linear decode lands on any placement."""
    return bytearray([NOP] * size)


def _place(exe: bytearray, at: int, hexstr: str) -> None:
    data = bytes.fromhex(hexstr)
    exe[at:at + len(data)] = data


def _dump_at_live(off: int, window: bytes) -> ogm.Dump:
    return ogm.Dump(bytes(window), LIVE_SEG * mp.PARA + off)


# -- fill body ------------------------------------------------------------------------------------

def _fill_exe() -> bytearray:
    exe = _blank(0x2000)
    _place(exe, BASE + fp.FILL_OFF, fp.FILL_BODY.hex(" "))
    return exe


def test_fill_body_template_matches_and_decodes_to_retf():
    facts = fp.fill_body_facts(bytes(_fill_exe()), BASE)
    assert facts["template_matched"] is True
    assert facts["decode_boundaries_match_template"] is True
    assert facts["retf_imm"] == 8
    assert facts["matched"] is True
    assert facts["layout_from_callee_sp"] == {"value_byte_sp": 4, "count_word_sp": 6,
                                              "dst_off_sp": 8, "dst_seg_sp": 10}


@pytest.mark.parametrize("label,mutate", [
    ("stosb-to-stosw", lambda b: b.__setitem__(fp.FILL_BODY.index(b"\xf3\xaa") + 1, 0xAB)),
    ("retf-8-to-6", lambda b: b.__setitem__(len(fp.FILL_BODY) - 2, 0x06)),
    ("value-read-as-word", lambda b: b.__setitem__(fp.FILL_BODY.index(b"\x36\x8a\x47\x04") + 1, 0x8B)),
    ("dst-offset-slot-moved", lambda b: b.__setitem__(fp.FILL_BODY.index(b"\x36\xc4\x7f\x08") + 3, 0x0A)),
    ("cld-removed", lambda b: b.__setitem__(fp.FILL_BODY.index(b"\xfc"), 0x90)),
])
def test_fill_body_falsified_by_one_byte(label, mutate):
    exe = _blank(0x2000)
    body = bytearray(fp.FILL_BODY)
    mutate(body)
    _place(exe, BASE + fp.FILL_OFF, bytes(body).hex(" "))
    facts = fp.fill_body_facts(bytes(exe), BASE)
    assert facts["template_matched"] is False, label
    assert facts["matched"] is False, label


# -- fill identity --------------------------------------------------------------------------------

def test_fill_identity_identified_when_dumps_agree_at_unique_placement():
    exe = bytes(_fill_exe())
    win = exe[BASE + fp.FILL_OFF:BASE + fp.FILL_OFF + mp.WINDOW]
    dumps = [{"label": "d", "dump": _dump_at_live(fp.FILL_OFF, win), "load": mp.EXPECT_LOAD}]
    res = fp.fill_identity(exe, BASE, dumps)
    assert res["verdict"] == "identified-by-bytes-in-pinned-dumps"


def test_fill_identity_falsified_by_one_byte_in_the_dump():
    exe = bytes(_fill_exe())
    win = bytearray(exe[BASE + fp.FILL_OFF:BASE + fp.FILL_OFF + mp.WINDOW])
    win[7] ^= 0x01
    dumps = [{"label": "d", "dump": _dump_at_live(fp.FILL_OFF, bytes(win)), "load": mp.EXPECT_LOAD}]
    res = fp.fill_identity(exe, BASE, dumps)
    assert res["verdict"] == "unresolved"
    assert res["per_dump"][0]["window"]["state"] == "memory-disagrees"


def test_fill_identity_falsified_when_the_window_repeats_in_the_file():
    exe = _fill_exe()
    win = bytes(exe[BASE + fp.FILL_OFF:BASE + fp.FILL_OFF + mp.WINDOW])
    _place(exe, 0x500, win.hex(" "))
    dumps = [{"label": "d", "dump": _dump_at_live(fp.FILL_OFF, win), "load": mp.EXPECT_LOAD}]
    res = fp.fill_identity(bytes(exe), BASE, dumps)
    assert res["verdict"] == "unresolved"
    assert res["per_dump"][0]["window"]["state"] == "placement-not-unique"


# -- wall-helper fill sites ---------------------------------------------------------------------

def _wall_exe() -> bytearray:
    """The three alloc/fill pairs of the wall helper, at the START offsets the probe names."""
    exe = _blank(0x7000)
    # main: alloc size [bp-4]+0x17 -> 0x023F ; fill count same expression, value 0, dst es:di pushed
    _place(exe, 0x6B32, "8b 46 fc 05 17 00 50")
    _place(exe, 0x6B39, "9a 3f 02 f8 0a")
    _place(exe, 0x6B4E, "06 57")
    _place(exe, 0x6B50, "8b 46 fc 05 17 00 50")
    _place(exe, 0x6B57, "b0 00 50")
    _place(exe, 0x6B5A, "9a a8 16 f8 0a")
    # sub-shr2: alloc [bp-4]>>2 ; fill same expression
    _place(exe, 0x6BA2, "8b 46 fc d1 e8 d1 e8 50")
    _place(exe, 0x6BAA, "9a 3f 02 f8 0a")
    _place(exe, 0x6BC7, "06 57")
    _place(exe, 0x6BC9, "8b 46 fc d1 e8 d1 e8 50")
    _place(exe, 0x6BD1, "b0 00 50")
    _place(exe, 0x6BD4, "9a a8 16 f8 0a")
    # sub-raw: alloc push [bp-4] ; fill push [bp-4]
    _place(exe, 0x6BDB, "ff 76 fc")
    _place(exe, 0x6BDE, "9a 3f 02 f8 0a")
    _place(exe, 0x6BFB, "06 57")
    _place(exe, 0x6BFD, "ff 76 fc")
    _place(exe, 0x6C00, "b0 00 50")
    _place(exe, 0x6C03, "9a a8 16 f8 0a")
    return exe


def test_size_pairs_all_match_on_the_wall_layout():
    res = fp.size_pairs(bytes(_wall_exe()))
    assert res["all_matched"] is True
    assert all(r["count_expression_equal"] for r in res["rows"])


def _pair_row(exe: bytearray, label: str) -> dict:
    return next(r for r in fp.size_pairs(bytes(exe))["rows"] if r["label"] == label)


def test_fill_count_expression_falsified_by_one_byte():
    exe = _wall_exe()
    _place(exe, 0x6B50 + 4, "18")                  # fill main: add 0x17 becomes add 0x18
    row = _pair_row(exe, "main")
    assert row["count_expression_equal"] is False and row["matched"] is False


def test_fill_value_falsified_when_not_zero():
    exe = _wall_exe()
    _place(exe, 0x6BD1 + 1, "01")                  # sub-shr2 fill pushes 1, not 0
    row = _pair_row(exe, "sub-shr2")
    assert row["value_push_zero"] is False and row["matched"] is False


def test_fill_dst_push_falsified_when_missing():
    exe = _wall_exe()
    _place(exe, 0x6BFB, "90 90")                   # no push es / push di before the sub-raw fill count
    row = _pair_row(exe, "sub-raw")
    assert row["dst_pushed_es_di"] is False and row["matched"] is False


def test_fill_call_target_falsified():
    exe = _wall_exe()
    _place(exe, 0x6B5A + 1, "54")                  # 9a a8 16 becomes 9a 54 16 : offset 0x1654, not 0x16A8
    row = _pair_row(exe, "main")
    assert row["fill_call_is_0x16A8"] is False and row["matched"] is False


def test_alloc_call_target_falsified():
    exe = _wall_exe()
    _place(exe, 0x6BDE + 1, "54")                  # alloc becomes a 0x0254 call
    row = _pair_row(exe, "sub-raw")
    assert row["alloc_call_is_0x023F"] is False and row["matched"] is False


# -- START caller frames ------------------------------------------------------------------------

E_ALLOC = 0x2000       # entry of the alloc-copy frame; site = entry + 10 (0x227D in the real file)
E_REL = 0x2100         # entry of the release frame; site = 0x2140
S_ALLOC = E_ALLOC + 10
S_REL = 0x2140
ALLOC_LOOK = "c4 7e 0a"                  # les di,[bp+10] (the second far pointer, as the real frame reads it)


def _alloc_frame(exe: bytearray) -> None:
    _place(exe, E_ALLOC, "55 89 e5 83 ec 08")            # prologue, sub sp,8
    _place(exe, E_ALLOC + 6, "b8 3f 00 50")               # mov ax,0x3F ; push ax
    _place(exe, S_ALLOC, "9a 3f 02 f8 0a")                # call 0x0AF8:0x023F
    _place(exe, S_ALLOC + 5, "89 46 f8 89 56 fa")         # mov [bp-8],ax ; mov [bp-6],dx
    _place(exe, S_ALLOC + 11, fp.ALLOC_COPY.hex(" "))     # copy 0x3F from [bp+6] to [bp-8] via 0x1685
    _place(exe, S_ALLOC + 30, fp.ALLOC_LINK_ZERO.hex(" "))
    _place(exe, S_ALLOC + 43, ALLOC_LOOK)
    _place(exe, S_ALLOC + 46, "89 ec 5d ca 08 00")        # mov sp,bp ; pop bp ; retf 8


def _release_frame(exe: bytearray) -> None:
    _place(exe, E_REL, "55 89 e5 83 ec 2c")
    _place(exe, E_REL + 6, fp.RELEASE_ENTRY_GUARD.hex(" "))
    _place(exe, E_REL + 14, "c4 7e 0a")                  # les di,[bp+10] (second far pointer)
    _place(exe, S_REL - 23, fp.RELEASE_LINK_ZERO.hex(" "))
    _place(exe, S_REL - 10, fp.RELEASE_PRE.hex(" "))     # push [bp+8]; push [bp+6]; mov ax,0x3F; push ax
    _place(exe, S_REL, "9a 54 02 f8 0a")                  # call 0x0AF8:0x0254
    _place(exe, S_REL + 5, "89 ec 5d ca 08 00")


def _frames_exe() -> bytearray:
    exe = _blank(0x2400)
    _alloc_frame(exe)
    _release_frame(exe)
    return exe


def _frame(exe, role: str, site: int, target: int) -> dict:
    return fp.frame_facts(bytes(exe), site, target, role)


def test_both_frames_match_their_layouts():
    exe = _frames_exe()
    a = _frame(exe, "alloc-copy", S_ALLOC, 0x023F)
    r = _frame(exe, "release", S_REL, 0x0254)
    assert a["enclosing_entry"] == hex(E_ALLOC) and a["matched"] is True
    assert r["enclosing_entry"] == hex(E_REL) and r["matched"] is True
    assert a["size_imm"] == fp.SIZE and r["size_imm"] == fp.SIZE
    assert a["result_stored_to"] == "[bp-8]:[bp-6]"
    assert r["pointer_pushed"] == {"seg": "[bp+8]", "off": "[bp+6]"}
    assert r["entry_guard_on_first_pointer"] is True
    assert a["entry_guard_on_first_pointer"] is False


def test_pair_verdict_pairs_when_both_frames_match_at_size_0x3f():
    exe = _frames_exe()
    p = fp.pair_verdict(_frame(exe, "alloc-copy", S_ALLOC, 0x023F), _frame(exe, "release", S_REL, 0x0254))
    assert p["shapes_pair_on_size_and_pointer_role"] is True
    assert p["pointer_identity_between_frames"] == "not-established"


def test_alloc_size_falsified_by_one_byte():
    exe = _frames_exe()
    _place(exe, E_ALLOC + 7, "40")                       # mov ax,0x40
    a = _frame(exe, "alloc-copy", S_ALLOC, 0x023F)
    assert a["pre_call_matched"] is False and a["matched"] is False


def test_release_pointer_order_falsified_by_swap():
    exe = _frames_exe()
    _place(exe, S_REL - 10, "ff 76 06 ff 76 08")         # swap: push [bp+6] first, then [bp+8]
    r = _frame(exe, "release", S_REL, 0x0254)
    assert r["pre_call_matched"] is False and r["pointer_source"] is None and r["matched"] is False


def test_alloc_copy_size_falsified():
    exe = _frames_exe()
    _place(exe, S_ALLOC + 11 + 11, "40")                 # copy count 0x40 instead of 0x3F
    a = _frame(exe, "alloc-copy", S_ALLOC, 0x023F)
    assert a["copy_run_matched"] is False and a["matched"] is False


def test_alloc_result_store_removed():
    exe = _frames_exe()
    _place(exe, S_ALLOC + 5, "90 90 90 90 90 90")
    a = _frame(exe, "alloc-copy", S_ALLOC, 0x023F)
    assert a["result_stored_to"] is None and a["matched"] is False


def test_release_link_zero_removed():
    exe = _frames_exe()
    _place(exe, S_REL - 23, "90" * 13)
    r = _frame(exe, "release", S_REL, 0x0254)
    assert r["link_zero_matched"] is False and r["matched"] is False


def test_release_run_falsified_by_a_branch_target_inside_it():
    exe = _frames_exe()
    jmp_at = S_REL - 40
    target = S_REL - 15                                  # inside the link-zero run, after its start
    _place(exe, jmp_at, "eb %02x" % ((target - (jmp_at + 2)) & 0xFF))
    r = _frame(exe, "release", S_REL, 0x0254)
    assert r["straight_line_release_run"] is False and r["matched"] is False


def test_release_entry_guard_removed():
    exe = _frames_exe()
    _place(exe, E_REL + 6, "90" * 8)
    r = _frame(exe, "release", S_REL, 0x0254)
    assert r["entry_guard_on_first_pointer"] is False and r["matched"] is False


def test_frame_retf_falsified():
    exe = _frames_exe()
    _place(exe, S_REL + 5 + 4, "06")                     # retf 8 becomes retf 6
    r = _frame(exe, "release", S_REL, 0x0254)
    assert r["frame_retf_imm"] == 6 and r["frame_args_are_two_far_pointers"] is False and r["matched"] is False


def test_frame_refused_as_no_entry_when_no_prologue_reaches_the_site():
    exe = _blank(0x400)
    _place(exe, 0x200, "9a 54 02 f8 0a")
    r = _frame(exe, "release", 0x200, 0x0254)
    assert r["enclosing_entry"] is None and r["matched"] is False


def test_pair_falsified_by_size_mismatch():
    exe = _frames_exe()
    p = fp.pair_verdict(_frame(exe, "alloc-copy", S_ALLOC, 0x023F),
                        {"size_imm": 0x40, "matched": True})
    assert p["size_equal_both_frames"] is False and p["shapes_pair_on_size_and_pointer_role"] is False


def test_pair_falsified_when_one_frame_fails():
    exe = _frames_exe()
    _place(exe, S_REL - 10, "ff 76 06 ff 76 08")
    p = fp.pair_verdict(_frame(exe, "alloc-copy", S_ALLOC, 0x023F), _frame(exe, "release", S_REL, 0x0254))
    assert p["release_frame_shape"] is False and p["shapes_pair_on_size_and_pointer_role"] is False


# -- static callers -----------------------------------------------------------------------------

def test_static_near_caller_found_and_falsified_by_displacement():
    exe = _blank(0x3000)
    entry = 0x2000
    site = 0x2800
    rel = entry - (site + 3)
    _place(exe, site, "e8 %02x %02x" % (rel & 0xFF, (rel >> 8) & 0xFF))
    found = fp.static_callers(bytes(exe), bytes(exe), [entry])
    assert found[hex(entry)]["near_call_sites_in_START"] == [hex(site)]
    _place(exe, site + 1, "%02x" % ((rel + 1) & 0xFF))
    none = fp.static_callers(bytes(exe), bytes(exe), [entry])
    assert none[hex(entry)]["near_call_sites_in_START"] == []


# -- CLI refusals --------------------------------------------------------------------------------

def test_cli_refuses_output_outside_data_work(tmp_path):
    rc = fp.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")])
    assert rc == 2


def test_cli_refuses_output_inside_the_install():
    install = fp.DEFAULT_INSTALL
    rc = fp.main(["--install", str(install), "-o", str(install / "out")])
    assert rc == 2
    assert not (install / "out").exists()


def test_cli_refuses_unpinned_install(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"\x00" * 10)
    (tmp_path / "START.EXE").write_bytes(b"\x00" * 10)
    rc = fp.main(["--install", str(tmp_path), "-o", str(fp.DEFAULT_OUT)])
    assert rc == 2


# -- retail (gated) -----------------------------------------------------------------------------

@pytest.mark.skipif(not os.environ.get(ENV), reason=f"set {ENV} to the Pool of Radiance install")
def test_retail_fill_callers_and_repeatable():
    install = Path(os.environ[ENV])
    doc = fp.probe(install, fp.DEFAULT_DUMPS)
    assert doc["inputs"]["pins"]["GAME.OVR"]["pinned"] and doc["inputs"]["pins"]["START.EXE"]["pinned"]
    assert doc["fill_body"]["matched"] is True
    assert doc["fill_identity"]["verdict"] == "identified-by-bytes-in-pinned-dumps"
    assert all(p["window"]["state"] == "memory-agrees-unique-placement"
               for p in doc["fill_identity"]["per_dump"])
    assert doc["fill_size_pairs"]["all_matched"] is True
    assert doc["start_callers"]["0x227D"]["matched"] is True
    assert doc["start_callers"]["0x2268"]["matched"] is True
    assert doc["pair"]["shapes_pair_on_size_and_pointer_role"] is True
    assert doc["playable_claim"] is False and doc["executed"] == "not_established"
    again = fp.probe(install, fp.DEFAULT_DUMPS)
    assert fp.json.dumps(doc, sort_keys=True) == fp.json.dumps(again, sort_keys=True)
