"""Tests for tools/por_ecl_native_framing_probe.py.

Synthetic tests run everywhere: small hand-assembled buffers in the same instruction forms as the
retail classifier and operand body, plus mutations and refusals. Retail tests are gated on
OPENUA_POR_INSTALL (the pinned POOLRAD folder) and skip without it.
"""

import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl_native_framing_probe as p  # noqa: E402


def _put(buf: bytearray, at: int, hexstr: str) -> None:
    raw = bytes.fromhex(hexstr.replace(" ", ""))
    buf[at:at + len(raw)] = raw


def _chain(match_value: int, arm_class: int, parser: int = 0x200, base: int = 0x100) -> bytes:
    """Synthetic classifier: cmp al,match; jz arm; default: inc [0x49ED]; arm: mov al,class; push ax;
    push cs; call parser."""
    buf = bytearray(0x400)
    _put(buf, base, "3c %02x" % match_value)        # cmp al,match
    _put(buf, base + 2, "74 04")                    # jz +4 -> base+8 (the arm)
    _put(buf, base + 4, "ff06ed49")                 # default: inc [0x49ED]
    _put(buf, base + 8, "b0 %02x" % arm_class)      # arm: mov al,class
    _put(buf, base + 10, "50")                      # push ax
    _put(buf, base + 11, "0e")                      # push cs
    rel = parser - (base + 12 + 3)
    _put(buf, base + 12, "e8" + struct.pack("<h", rel).hex())
    return bytes(buf)


def test_classify_matched_value_reaches_parser_with_class_byte():
    data = _chain(0x15, arm_class=3, parser=0x200)
    got = p.classify_value(data, 0x15, entry=0x100, parser=0x200)
    assert got["arm"] == "push-cs-call" and got["class"] == 3 and got["call"] == 0x200


def test_classify_unmatched_value_takes_default_inc_only():
    data = _chain(0x15, arm_class=3, parser=0x200)
    got = p.classify_value(data, 0x2B, entry=0x100, parser=0x200)
    assert got["arm"] == "inc-only" and got["operands_parsed"] == 0 and got["inc"] == 0x49ED


def test_mutating_the_compare_immediate_flips_the_arm():
    base = _chain(0x15, arm_class=3)
    mutant = _chain(0x16, arm_class=3)
    assert p.classify_value(base, 0x15, entry=0x100, parser=0x200)["arm"] == "push-cs-call"
    assert p.classify_value(mutant, 0x15, entry=0x100, parser=0x200)["arm"] == "inc-only"


def test_call_to_other_target_is_not_mistaken_for_the_parser():
    data = _chain(0x15, arm_class=3, parser=0x300)
    got = p.classify_value(data, 0x15, entry=0x100, parser=0x200)
    assert got["arm"] == "other-call" and got["call"] == 0x300


def test_unmodelled_byte_is_a_named_refusal():
    data = bytearray(_chain(0x15, arm_class=3))
    data[0x100] = 0x90  # nop is not in the modelled chain set: refuse, do not guess
    got = p.classify_value(bytes(data), 0x15, entry=0x100, parser=0x200)
    assert got["arm"] == "refusal" and got["reason"] == "unmodelled-byte"


def test_jcc_without_compare_is_refused():
    buf = bytearray(0x200)
    _put(buf, 0x100, "74 02 90 90")
    got = p.classify_value(bytes(buf), 0x15, entry=0x100, parser=0x200)
    assert got["arm"] == "refusal" and got["reason"] == "jcc-without-compare"


def test_jcc_predicates_match_unsigned_flags():
    assert p._jcc_taken("jb", 1, 2) and not p._jcc_taken("jb", 2, 2)
    assert p._jcc_taken("jbe", 2, 2) and not p._jcc_taken("ja", 2, 2)
    assert p._jcc_taken("ja", 3, 2) and p._jcc_taken("jnz", 3, 2)
    assert p._jcc_taken("jz", 2, 2) and not p._jcc_taken("jnb", 1, 2)


def test_ranges_and_overlap_helpers():
    assert p._ranges({1, 2, 3, 7}) == [[1, 3], [7, 7]]
    assert p._size([[0, 0], [4, 127], [130, 255]]) == 1 + 124 + 126
    assert p._rects_overlap(([[1, 3]], [[0, 255]]), ([[3, 4]], [[9, 9]]))
    assert not p._rects_overlap(([[1, 3]], [[0, 255]]), ([[4, 4]], [[0, 255]]))


# --- operand body: a sequentially assembled body in the same forms as the retail body --------
BASE = 0x100


def _assemble(parts: list, base: int = BASE) -> tuple:
    """Lay the instructions out one after another; return (bytes, end address)."""
    blob = bytearray()
    for part in parts:
        blob += bytes.fromhex(part.replace(" ", ""))
    buf = bytearray(base + len(blob) + 0x10)
    buf[base:base + len(blob)] = blob
    return bytes(buf), base + len(blob)


def _body(tag_cmp: str = "3c 01", jump: str = "75", cursor_load: bool = True,
          cursor_write: bool = True) -> tuple:
    """Tag at +1 and value at +2 read through the cursor; cursor += 2 (mov [cur],ax); then
    ``cmp al,imm; jcc +4`` over ``inc [cur]``; then a straight-line tail. Returns (bytes, stop)."""
    parts = [
        "a1ed49",                       # mov ax,[cur]            ax = 0
        "40",                           # inc ax                  ax = 1: tag at +1
        "c43ede49",                     # les di,[far]
        "03f8",                         # add di,ax
        "268a950067",                   # es mov dl,[di+0x6700]   tag <- rel 1
        "8bf8",                         # mov di,ax  (operand-index mode)
        "88950570",                     # mov [di+0x7005],dl
        "a1ed49",                       # mov ax,[cur]            ax = 0
        "40 40",                        # inc ax; inc ax          ax = 2: value at +2
        "c43ede49",                     # les di,[far]
        "03f8",                         # add di,ax
        "268a950067",                   # es mov dl,[di+0x6700]   value <- rel 2
        "8bf8",                         # mov di,ax
        "88958570",                     # mov [di+0x7085],dl
        "a1ed49" if cursor_load else "909090",   # mov ax,[cur]   (or nops: AX stays unknown)
        "40 40",                        # inc ax; inc ax
    ]
    if cursor_write:
        parts.append("a3ed49")          # mov [cur],ax            cursor += 2
    parts += [
        "8a850570",                     # mov al,[di+0x7005]      al = tag
        tag_cmp,                        # cmp al,imm  (or nops)
        jump + " 04",                   # jcc +4 over the increment
        "ff06ed49",                     # inc [cur]               +1 on the fall-through arm
        "8a46ff",                       # mov al,[bp-1]           clobbers AL; end of the body
    ]
    return _assemble(parts)


def _paths(*args, **kwargs):
    data, stop = _body(*args, **kwargs)
    return p.body_paths(data, BASE, stop=stop)


def test_body_two_paths_tile_the_tag_space_and_count_bytes():
    summ = p.body_summary(_paths())
    assert summ["refused_paths"] == []
    assert summ["tiling_complete"] and summ["tiling_disjoint"]
    got = {tuple(map(tuple, k["tag_set"])): k["cursor_delta"] for k in summ["kinds"]}
    # 'jnz' jumps over the increment for every tag except 1, so tag 1 pays +2 (cursor write) +1
    assert got == {((1, 1),): 3, ((0, 0), (2, 255)): 2}


def test_body_tag_compare_mutation_moves_the_tag_set():
    base = p.body_summary(_paths(tag_cmp="3c 01"))
    mutant = p.body_summary(_paths(tag_cmp="3c 02"))
    base_sets = {tuple(map(tuple, k["tag_set"])) for k in base["kinds"]}
    mut_sets = {tuple(map(tuple, k["tag_set"])) for k in mutant["kinds"]}
    assert ((1, 1),) in base_sets and ((2, 2),) in mut_sets and ((1, 1),) not in mut_sets
    assert mutant["tiling_complete"] and mutant["tiling_disjoint"]


def test_body_jump_mutation_flips_which_tag_pays_the_increment():
    d_base = {tuple(map(tuple, k["tag_set"])): k["cursor_delta"]
              for k in p.body_summary(_paths(jump="75"))["kinds"]}
    d_mut = {tuple(map(tuple, k["tag_set"])): k["cursor_delta"]
             for k in p.body_summary(_paths(jump="74"))["kinds"]}
    # jnz: tag 1 falls through the increment (3); jz: tag 1 jumps over it (2)
    assert d_base[((1, 1),)] == 3 and d_mut[((1, 1),)] == 2


def test_body_stores_are_cursor_relative_and_land_in_named_buffers():
    paths = [pp for pp in _paths() if pp["refusal"] is None]
    assert paths
    for path in paths:
        assert [s["buf"] for s in path["stores"]][:2] == ["tag", "value"]
        assert [s["rel"] for s in path["stores"]][:2] == [1, 2]


def test_cursor_write_of_unknown_ax_is_refused_not_guessed():
    paths = _paths(cursor_load=False)
    assert [pp["refusal"] for pp in paths] == ["cursor-write-of-unknown-ax"]


def test_jcc_after_an_unmodelled_compare_is_refused_not_read_stale():
    # the compare is replaced by two nops: the flags are unknown at the jnz, so the path is refused
    paths = _paths(tag_cmp="90 90")
    assert [pp["refusal"] for pp in paths] == ["jcc-on-unbound-flags"]


def test_unknown_near_callee_is_refused():
    buf = bytearray(0x400)
    _put(buf, 0x100, "e8 fd 01")                 # call near 0x300 (not a modelled helper)
    paths = p.body_paths(bytes(buf), 0x100, stop=0x103)
    assert paths and paths[0]["refusal"] == "unknown-near-callee"


def _call_at(site: int, target: int) -> bytes:
    buf = bytearray(0x9000)
    _put(buf, site, "e8" + struct.pack("<h", target - (site + 3)).hex())
    return bytes(buf)


def test_string_helper_call_is_open_and_value_helper_is_pure():
    # the call sits next to its target so the signed 16-bit displacement stays in range
    site = p.HELPER_STRING - 0x10
    paths = p.body_paths(_call_at(site, p.HELPER_STRING), site, stop=site + 3)
    assert paths[0]["calls"][0]["name"] == "string-0x8626" and paths[0]["open"] is True
    site2 = p.HELPER_VALUE - 0x10
    paths2 = p.body_paths(_call_at(site2, p.HELPER_VALUE), site2, stop=site2 + 3)
    assert paths2[0]["calls"][0]["name"] == "value-decode-0x7B82" and paths2[0]["open"] is False


def test_refuses_unpinned_install(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"x" * 10)
    (tmp_path / "START.EXE").write_bytes(b"y" * 10)
    with pytest.raises(p.ProbeRefusal):
        p.probe(tmp_path, tmp_path / "out")


def test_refuses_output_inside_install(tmp_path):
    with pytest.raises(p.ProbeRefusal):
        p.probe(tmp_path, tmp_path)


RETAIL = os.environ.get("OPENUA_POR_INSTALL")


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_INSTALL to the pinned POOLRAD folder")
def test_retail_bytes_settle_the_framing_checks(tmp_path):
    install = Path(RETAIL)
    before = {n: _sha_file(install / n) for n in p.PINS}
    out = tmp_path / "out"
    doc, code = p.probe(install, out)
    assert code == 0, doc["checks"]
    assert all(doc["checks"].values()), doc["checks"]
    assert doc["playable"] is False and doc["mappings"] == []
    assert {n: _sha_file(install / n) for n in p.PINS} == before
    # class sets (PoR bytes): the classes this probe depends on
    cls = doc["classifier"]["class_sets"]
    assert "0x27" in cls["8"] and "0x29" in cls["14"] and "0x2D" in cls["1"] and "0x37" in cls["3"]
    # the menu opcodes take the default arm (one byte) and have a structured dispatcher case
    assert doc["classifier"]["per_opcode"]["0x15"]["arm"] == "default"
    assert doc["classifier"]["per_opcode"]["0x2B"]["arm"] == "default"
    assert "0x15" in doc["classifier"]["default_arm_with_dispatch_case"]
    assert "0x00" in doc["classifier"]["default_arm_with_dispatch_case"]
    # the operand body: seven tail paths, exact tiling, and the expected deltas by tag kind
    body = doc["parser"]["body"]
    assert body["tail_paths"] == 7 and body["tiling_complete"] and body["tiling_disjoint"]
    kinds = {}
    for k in doc["parser"]["operand_kinds"]:
        key = (tuple(map(tuple, k["tag_set"])),
               None if k["value_set"] is None else tuple(map(tuple, k["value_set"])))
        kinds[key] = (k["cursor_delta"], k["open"])
    assert kinds == {
        (((1, 1),), None): (3, False),                       # tag 1: two stream bytes + one extra
        (((2, 2),), None): (3, False),                       # tag 2
        (((3, 3),), None): (3, False),                       # tag 3
        (((128, 128),), ((0, 0),)): (2, False),              # 0x80, count 0: no unpacker call
        (((128, 128),), ((1, 255),)): (2, True),             # 0x80, count > 0: unpacker 0x8626 is open
        (((129, 129),), ((0, 255),)): (3, True),             # 0x81: value decode pure, post-step open
        (((0, 0), (4, 127), (130, 255)), None): (2, False),  # every other tag: two bytes
    }
    # the value-decode helper is pure and the caller routine stores five class-1 decodes
    assert doc["helpers"]["0x7B82_value_decode"]["pure"] is True
    stored = [s["stored_word"] for s in doc["callers"]["sites"]]
    assert stored == ["0x49e3", "0x49e5", "0x49e7", "0x49e9", "0x49eb"]
    # the stub run: index 2 (zero-skew parser) has no literal far caller
    assert doc["stub_model"]["index_2_far_literal_candidates"] == 0
    # menu helpers do not call the parser or the classifier directly
    assert all(not m["calls_parser"] for m in doc["menu_helpers"].values())
    json.loads((out / "por_ecl_native_framing_probe.json").read_text(encoding="utf-8"))
