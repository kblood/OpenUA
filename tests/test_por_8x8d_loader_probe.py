"""Tests for tools/por_8x8d_loader_probe.py (the START.EXE 0x7180 chain, static).

Synthetic MZ fixtures, hand-assembled, so each rule has a falsifier: a byte pattern inside an
immediate is not a caller, a straight-line window stops at a control transfer, a fixed global
read is not index evidence, an `inc` erases a forwarded frame word, and so on. The retail
anchor runs only when OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and is
skipped otherwise. Nothing here writes outside a temporary folder.
"""
import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, TESTS)
import por_8x8d_loader_probe as lp  # noqa: E402
import por_loadpieces_handler as h  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
RETAIL = os.environ.get(ENV)
needs_retail = pytest.mark.skipif(not RETAIL, reason="set %s to the PoR DOS install" % ENV)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def mz(code=None, size=0x1000) -> bytes:
    """A synthetic MZ image with a 0x200-byte header (cparhdr 0x20), as START.EXE has."""
    b = bytearray(size)
    b[0:2] = b"MZ"
    struct.pack_into("<H", b, 0x08, 0x20)
    for off, blob in (code or {}).items():
        assert off >= 0x200 and off + len(blob) <= size, off
        b[off:off + len(blob)] = blob
    return bytes(b)


def rel(site: int, target: int) -> bytes:
    """The rel16 operand of a near call at ``site`` (instruction length 3) to ``target``."""
    return struct.pack("<h", target - (site + 3))


PROLOGUE = b"\x55\x89\xe5"
CALLEE_RETF2 = PROLOGUE + b"\xca\x02\x00"      # one word argument, retf 2


def insns_of(blob: bytes) -> list:
    out, p = [], 0
    while p < len(blob):
        ins = h.decode(blob, p)
        out.append(ins)
        p = ins.end
    return out


def pushes_of(blob: bytes) -> list:
    return lp.simulate(insns_of(blob))["pushes"]


def word_class(blob: bytes) -> tuple:
    """Class and text of the single word pushed by the straight-line ``blob``."""
    words = [p for p in pushes_of(blob) if p["kind"] == "word"]
    assert len(words) == 1, words
    return lp.classify_word(words[0]["lo"], words[0]["hi"])


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _tree_hashes(root: Path) -> dict:
    out = {}
    for dirpath, _d, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(root).as_posix()] = _sha(p.read_bytes())
    return out


# --------------------------------------------------------------------------
# Routine profile: frame arguments, return width, walk boundary
# --------------------------------------------------------------------------

def test_profile_reads_frame_arguments_and_retf_width():
    code = {0x300: PROLOGUE + b"\x8a\x46\x06" + b"\x8a\x46\x08" + b"\x5d" + b"\xca\x04\x00"}
    p = lp.routine_profile(mz(code), 0x300)
    assert p["prologue"] is True
    assert p["frame_args_bp"] == [6, 8]
    assert p["return_bytes"] == 4
    assert p["ret_flow"] == "retf"
    assert p["ret_at"] == "0x030a"


def test_linear_walk_stops_at_first_return():
    code = {0x300: PROLOGUE + b"\x5d" + b"\xca\x04\x00" + b"\xcd\x21"}   # INT after the retf
    p = lp.routine_profile(mz(code), 0x300)
    assert p["instructions"] == 4                    # push bp, mov bp,sp, pop bp, retf
    assert p["int_calls"] == []


def test_routine_without_return_inside_walk_is_reported_not_decoded():
    code = {0x300: PROLOGUE + b"\x90" * 4}
    p = lp.routine_profile(mz(code, size=0x400), 0x300)
    assert p["status"] == "no-ret-within-walk"
    assert p["ret_at"] is None


# --------------------------------------------------------------------------
# Callers: decoded E8 sites, byte-pattern falsifiers, far literals, stubs, word hits
# --------------------------------------------------------------------------

def _caller_fixture(push_bytes: bytes, callee=0x340, callee_bytes=CALLEE_RETF2, caller=0x320):
    """A routine at ``caller`` that pushes ``push_bytes`` as one word, pushes cs, and calls
    ``callee`` near (the same-segment far-return idiom)."""
    site = caller + 3 + len(push_bytes) + 2          # after the push ax and the push cs
    body = PROLOGUE + push_bytes + b"\x50" + b"\x0e" + b"\xe8" + rel(site, callee)
    return mz({caller: body, callee: callee_bytes})


def test_near_caller_is_decoded_on_its_walk_and_traced():
    start = _caller_fixture(b"\xb0\x27")
    ovr = b"\x00" * 0x100
    res = lp.find_callers(start, ovr, 0x340)
    assert len(res["decoded"]) == 1
    site = res["decoded"][0]
    assert (site["file"], site["kind"], site["containing_routine"]) == ("START.EXE", "near", "0x0320")
    assert site["trace"]["frame_width_match"] is True
    assert site["trace"]["far_by_near"] is True
    assert [a["class"] for a in site["trace"]["args"]] == ["const"]
    assert site["verdict"] == "constants-and-locals-only"


def test_falsifier_e8_inside_an_immediate_is_not_a_decoded_caller():
    # B8 E8 00 00 is mov ax,0x00E8: the 0xE8 byte is an immediate, not an instruction boundary.
    code = {0x320: PROLOGUE + b"\xb8\xe8\x00" + b"\x00\x00" + b"\xc3", 0x327: b"\xc3"}
    start = mz(code)
    res = lp.find_callers(start, b"\x00" * 0x100, 0x327)
    assert res["decoded"] == []
    assert any(c["why"] == "decodes-as-call-off-walk" for c in res["candidates"])


def test_far_literal_resolves_under_the_start_image_model_and_zero_base_is_a_candidate():
    # seg*16 + off = 0x300, so the file target is 0x200 + 0x300 = 0x500 under the image model.
    code = {0x330: PROLOGUE + b"\x9a\x00\x01\x20\x00", 0x500: b"\xc3",
            0x3a0: b"\x9a\x00\x05\x00\x00"}
    start = mz(code)
    res = lp.find_callers(start, b"\x00" * 0x100, 0x500)
    far = [d for d in res["decoded"] if d["kind"] == "far"]
    assert len(far) == 1 and far[0]["model"] == "start-image"
    assert far[0]["containing_routine"] == "0x0330"
    zero = [c for c in res["candidates"] if c.get("model") == "zero-base-offset-only"]
    assert len(zero) == 1 and zero[0]["at"] == "0x03a0"


def test_stub_form_word_is_found_and_a_neighbour_word_is_not():
    hit = mz({0x3c0: b"\xcd\x3f\x00\x05\x00"})
    miss = mz({0x3c0: b"\xcd\x3f\x01\x05\x00"})
    assert lp.find_callers(hit, b"\x00" * 0x100, 0x500)["stub_form_hits"][0]["at"] == "0x03c0"
    assert lp.find_callers(miss, b"\x00" * 0x100, 0x500)["stub_form_hits"] == []


def test_word_table_hit_after_vroomm_descriptor_magic_is_labelled():
    start = mz({0x3d0: b"\xcd\x3f\x00\x00\x00\x05", 0x3e0: b"\x00\x05"})
    wt = lp.find_callers(start, b"\x00" * 0x100, 0x500)["word_table_hits"]["START.EXE"]
    assert wt["count"] == 2
    assert wt["after_vroomm_descriptor_magic"] == 1
    assert wt["first"] == ["0x03d4", "0x03e0"]


def test_containing_walk_is_none_for_a_site_not_on_any_walk():
    code = {0x320: PROLOGUE + b"\xb8\xe8\x00\x00\x00"}
    start = mz(code)
    assert lp.containing_walk(start, 0x324) is None


# --------------------------------------------------------------------------
# Argument sources (the straight-line simulation)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("blob,expected", [
    (b"\xb0\x27\x50", "const"),                       # mov al,0x27 ; push ax
    (b"\xb8\x34\x12\x50", "const"),                   # mov ax,0x1234 ; push ax
    (b"\x8a\x46\x06\x50", "frame-forward"),           # mov al,[bp+6] ; push ax
    (b"\x8a\x46\xfc\x50", "frame-local"),             # mov al,[bp-4] ; push ax
    (b"\x8a\x04\x50", "indexed-memory"),              # mov al,[si] ; push ax
    (b"\xa0\x1a\x4a\x50", "global-memory"),           # mov al,[0x4a1a] ; push ax
    (b"\x8d\x46\xfe\x50", "local-address"),           # lea ax,[bp-2] ; push ax
    (b"\x8a\x46\x06\x40\x50", "unknown"),             # ... ; inc ax ; push ax (forward lost)
    (b"\x8a\x46\x06\x04\x01\x50", "unknown"),         # ... ; add al,1 ; push ax (forward lost)
])
def test_pushed_word_source_classes(blob, expected):
    cls, _text = word_class(blob)
    assert cls == expected


def test_high_byte_is_never_claimed_when_it_is_not_established():
    _cls, text = word_class(b"\x8a\x46\x06\x50")
    assert "high byte not established" in text


def test_window_is_cut_at_the_previous_control_transfer():
    # push of 0x11 sits before a near call; it must not leak into the next call's arguments.
    body = (PROLOGUE + b"\xb0\x11\x50" + b"\xe8" + rel(0x306, 0x330)
            + b"\xb0\x27\x50" + b"\x0e" + b"\xe8" + rel(0x30d, 0x340) + b"\x5d" + b"\xca\x02\x00")
    start = mz({0x300: body, 0x330: b"\xc3", 0x340: CALLEE_RETF2})
    res = lp.find_callers(start, b"\x00" * 0x100, 0x340)
    args = res["decoded"][0]["trace"]["args"]
    assert len(args) == 1
    assert args[0]["source"].startswith("0x27")


def test_frame_width_mismatch_is_reported():
    start = _caller_fixture(b"\xb0\x27", callee_bytes=PROLOGUE + b"\xca\x04\x00")
    site = lp.find_callers(start, b"\x00" * 0x100, 0x340)["decoded"][0]
    assert site["trace"]["frame_width_match"] is False


def test_global_read_without_a_prior_store_is_not_a_restore():
    start = mz({0x380: PROLOGUE + b"\xa0\x1a\x4a" + b"\x50" + b"\x0e" + b"\xe8" + rel(0x388, 0x340),
                0x340: CALLEE_RETF2})
    site = lp.find_callers(start, b"\x00" * 0x100, 0x340)["decoded"][0]
    assert site["trace"]["args"][0]["class"] == "global-read"
    assert site["verdict"] == "global-state-argument"


def test_global_read_after_a_store_in_the_same_walk_is_a_restore():
    start = mz({0x3a0: PROLOGUE + b"\xa2\x1a\x4a" + b"\xa0\x1a\x4a" + b"\x50" + b"\x0e"
                + b"\xe8" + rel(0x3ab, 0x340), 0x340: CALLEE_RETF2})
    site = lp.find_callers(start, b"\x00" * 0x100, 0x340)["decoded"][0]
    assert site["trace"]["args"][0]["class"] == "global-restore"


def test_register_indexed_argument_flips_the_verdict():
    start = _caller_fixture(b"\x8a\x00")                       # mov al,[bx+si]
    site = lp.find_callers(start, b"\x00" * 0x100, 0x340)["decoded"][0]
    assert site["trace"]["args"][0]["class"] == "indexed-memory"
    assert site["verdict"] == "index-like-argument"


def test_forwarded_frame_word_is_followed_and_flagged():
    start = _caller_fixture(b"\x8a\x46\x06")
    site = lp.find_callers(start, b"\x00" * 0x100, 0x340)["decoded"][0]
    assert site["trace"]["forwards_frame"] is True
    assert site["verdict"] == "forwards-caller-frame"


@pytest.mark.parametrize("trace,expected", [
    ({"status": "traced", "args": [{"class": "indexed-memory"}, {"class": "global-read"}]},
     "index-like-argument"),
    ({"status": "traced", "args": [{"class": "unknown"}, {"class": "frame-forward"}]},
     "unclassified-argument"),
    ({"status": "traced", "args": [{"class": "global-restore"}, {"class": "frame-forward"}]},
     "global-state-argument"),
    ({"status": "traced", "args": [{"class": "frame-forward"}]}, "forwards-caller-frame"),
    ({"status": "traced", "args": [{"class": "const"}, {"class": "local-address"}]},
     "constants-and-locals-only"),
    ({"status": "not-on-walk"}, "not-traced"),
])
def test_verdict_priority(trace, expected):
    assert lp.verdict_for(trace) == expected


# --------------------------------------------------------------------------
# Routine facts: ports, INT, pixel-source operands, direct data references
# --------------------------------------------------------------------------

def test_port_writes_track_dx_and_invalidate_on_a_register_copy():
    good = mz({0x480: PROLOGUE + b"\xba\xce\x03" + b"\xb0\x05" + b"\xee"
               + b"\xba\xcf\x03" + b"\xb0\x02" + b"\xee" + b"\x5d\xc3"})
    ports = [p["port"] for p in lp.routine_profile(good, 0x480)["port_io"]]
    assert ports == ["0x03ce", "0x03cf"]
    lost = mz({0x4c0: PROLOGUE + b"\xba\xce\x03" + b"\x8b\xd0" + b"\xee" + b"\x5d\xc3"})
    assert [p["port"] for p in lp.routine_profile(lost, 0x4c0)["port_io"]] == [None]


def test_int_21h_is_reported_as_a_file_io_candidate():
    p = lp.routine_profile(mz({0x460: PROLOGUE + b"\xcd\x21\x5d\xc3"}), 0x460)
    assert p["int_calls"] == [{"at": "0x0463", "vector": "0x21"}]
    assert len(p["file_io_candidates"]) == 1


def test_pixel_source_operands_far_pointer_and_indexed_read_but_not_a_fixed_global():
    start = mz({0x400: PROLOGUE + b"\xc4\x7e\x06" + b"\x5d\xca\x04\x00",
                0x420: PROLOGUE + b"\x8a\x00" + b"\x5d\xca\x00\x00",
                0x440: PROLOGUE + b"\xa0\x1a\x4a" + b"\x5d\xc3"})
    far_ptr = lp.routine_profile(start, 0x400)["pixel_source_candidates"]
    assert [c["kind"] for c in far_ptr] == ["far-pointer-from-frame"]
    indexed = lp.routine_profile(start, 0x420)["pixel_source_candidates"]
    assert [c["kind"] for c in indexed] == ["indexed-read"]
    assert lp.routine_profile(start, 0x440)["pixel_source_candidates"] == []


def test_direct_references_are_decode_checked_and_classed_read_or_write():
    code = {0x400: b"\xc6\x06\x1e\x4a\x02"        # mov [0x4a1e],2        write
                   + b"\x80\x3e\x1e\x4a\x01"      # cmp byte [0x4a1e],1   read
                   + b"\xa2\x1e\x4a"              # mov [0x4a1e],al       write
                   + b"\xa0\x1e\x4a"              # mov al,[0x4a1e]       read
                   + b"\xb8\x1e\x4a"}             # mov ax,0x4a1e         immediate, not a ref
    refs = lp._direct_refs(mz(code), 0x4A1E)
    assert [r["rw"] for r in refs] == ["write", "read", "write", "read"]
    assert refs[0]["imm"] == "0x2"


def test_mode_writers_report_the_immediate_written():
    start = mz({0x400: b"\xc6\x06\x1e\x4a\x02", 0x410: b"\xc6\x06\x1e\x4a\x00"})
    writes = lp.mode_writers(start)["writes"]
    assert [w["imm"] for w in writes] == ["0x2", "0x0"]


def test_literal_offset_is_found_as_a_mov_immediate_only():
    start = mz({0x400: b"\xb8\x3a\x72", 0x410: b"\xb0\x3a\x72"})      # mov ax,0x723a ; mov al,0x3a
    refs = lp.literal_refs(start, b"\x00" * 0x100)
    assert [c["at"] for c in refs["START.EXE"]["imm_byte_candidates"]] == ["0x0400"]
    assert refs["GAME.OVR"]["imm_byte_candidates"] == []


# --------------------------------------------------------------------------
# Whole-analysis invariants (synthetic)
# --------------------------------------------------------------------------

def test_analysis_never_claims_a_binding_and_writes_no_mapping():
    start = mz(size=0x9000)
    doc = lp.analyze(start, b"\x00" * 0x100)
    assert doc["answer"] == "not-established"
    assert doc["binding_established"] is False
    assert doc["mappings"] == []
    assert doc["playable"] is False
    # no code at any chain entry in the fixture, so every entry is reported as having no caller
    assert set(doc["summary"]["entries_without_decoded_caller"]) == {hex(e) for _n, e in lp.CHAIN}


def make_install(root: Path, start: bytes, ovr: bytes, *, sub="POOLRAD") -> Path:
    d = root / sub
    d.mkdir(parents=True)
    (d / lp.EXE_NAME).write_bytes(start)
    (d / lp.OVR_NAME).write_bytes(ovr)
    return root


def test_probe_refuses_unpinned_files_without_the_flag(tmp_path, capsys):
    inst = make_install(tmp_path / "game", mz(size=0x9000), b"\x00" * 0x100)
    with pytest.raises(lp.ProbeError):
        lp.probe(inst, tmp_path / "out")
    assert lp.main(["--install", str(inst), "-o", str(tmp_path / "out")]) == 2


def test_probe_refuses_a_missing_install_and_an_output_inside_the_install(tmp_path):
    assert lp.main(["--install", str(tmp_path / "nowhere"), "-o", str(tmp_path / "out")]) == 2
    inst = make_install(tmp_path / "game", mz(size=0x9000), b"\x00" * 0x100)
    with pytest.raises(lp.PorSourceError):
        lp.probe(inst, inst / "POOLRAD" / "out", allow_unpinned=True)


def test_unpinned_run_is_flagged_not_retail_evidence_and_still_binds_nothing(tmp_path):
    inst = make_install(tmp_path / "game", mz(size=0x9000), b"\x00" * 0x100)
    doc, code = lp.probe(inst, tmp_path / "out", allow_unpinned=True)
    assert code == 1
    assert doc["retail_evidence"] is False
    assert doc["binding_established"] is False
    assert doc["diagnostics"]


def test_probe_outputs_are_deterministic_and_carry_no_absolute_paths(tmp_path):
    inst = make_install(tmp_path / "game", mz(size=0x9000), b"\x00" * 0x100)
    for name in ("a", "b"):
        doc, _code = lp.probe(inst, tmp_path / name, allow_unpinned=True)
        lp.write_outputs(doc, tmp_path / name)
    for f in ("por_8x8d_loader_probe.json", "por_8x8d_loader_probe_report.md"):
        assert (tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()
    text = (tmp_path / "a" / "por_8x8d_loader_probe.json").read_text(encoding="utf-8")
    assert str(tmp_path) not in text


def test_source_files_are_unchanged_by_the_run(tmp_path):
    inst = make_install(tmp_path / "game", mz(size=0x9000), b"\x00" * 0x100)
    before = _tree_hashes(inst)
    lp.probe(inst, tmp_path / "out", allow_unpinned=True)
    assert _tree_hashes(inst) == before


# --------------------------------------------------------------------------
# Retail anchor (skipped unless OPENUA_POR_INSTALL is set)
# --------------------------------------------------------------------------

@needs_retail
def test_retail_chain_callers_arguments_and_negative_results(tmp_path):
    install = Path(RETAIL)
    before = _tree_hashes(install.joinpath("POOLRAD") if install.joinpath("POOLRAD").is_dir() else install)
    doc, code = lp.probe(install, tmp_path / "retail", allow_unpinned=False)
    after = _tree_hashes(install.joinpath("POOLRAD") if install.joinpath("POOLRAD").is_dir() else install)
    assert before == after, "retail source changed during the run"
    assert code == 0 and doc["retail_evidence"] is True and doc["source_unchanged"] is True

    # 0x7180 (layout owner of the literal 8X8d1): four decoded callers, the same-segment idiom
    c = doc["callers"]["0x7180"]["decoded"]
    assert [(d["at"], d["containing_routine"], d["verdict"]) for d in c] == [
        ("0x7dc0", "0x7d74", "constants-and-locals-only"),
        ("0x7dd6", "0x7d74", "constants-and-locals-only"),
        ("0x7f57", "0x7e9c", "forwards-caller-frame"),
        ("0x7f71", "0x7e9c", "forwards-caller-frame"),
    ]
    assert all(d["trace"]["far_by_near"] for d in c)
    assert all(d["trace"]["frame_width_match"] for d in c)

    def values(site):
        return [a["source"].split(" ")[0] for a in site["trace"]["args"]]

    assert values(c[0]) == ["0x0", "0x0", "0x27", "0x18", "0x0", "0x0"]   # page 0, rows 0..24
    assert values(c[1]) == ["0x0", "0x0", "0x27", "0x18", "0x1", "0x0"]   # page 1
    assert [a["class"] for a in c[2]["trace"]["args"]][:4] == ["frame-forward"] * 4
    assert [a["class"] for a in c[2]["trace"]["args"]][4:] == ["const", "const"]

    # the fill colour is the forwarded [bp+6] byte of 0x7180 at its far call 0x7209
    assert doc["summary"]["owner_fill_color_source"]["source"].startswith("low byte [bp+6]")

    # 0x7169 (EGA page select): forwarded page from 0x7180, and a save/restore read at 0x7231
    v = {d["at"]: d["verdict"] for d in doc["callers"]["0x7169"]["decoded"]}
    assert v == {"0x71c5": "forwards-caller-frame", "0x7231": "global-state-argument"}
    assert doc["callers"]["0x70c9"]["decoded"][0]["at"] == "0x71c9"

    # 0x7e9c and 0x7831: callers forward the text window's frame words; 0x7831 has no caller
    assert [d["at"] for d in doc["callers"]["0x7e9c"]["decoded"]] == ["0x78aa", "0x7a78"]
    assert doc["callers"]["0x7831"]["decoded"] == []
    assert doc["callers"]["0x7d74"]["decoded"] == []
    assert doc["summary"]["entries_without_decoded_caller"] == ["0x7d74", "0x7831"]

    # no register-indexed argument anywhere on the chain; no INT in the chain
    assert doc["summary"]["index_like_call_sites"] == []
    assert doc["summary"]["routines_with_int_calls"] == []

    # byte-level negatives: no reference to the literal offset; the mode byte is written 3 times
    assert doc["literal"]["refs"]["START.EXE"]["imm_byte_candidates"] == []
    assert doc["literal"]["refs"]["START.EXE"]["direct_refs"] == []
    writes = [(w["at"], w["imm"]) for w in doc["video_mode"]["writes"]]
    assert writes == [("0x4484", "0x1"), ("0x44b3", "0x2"), ("0x44e2", "0x0")]

    # the one word-table hit for 0x7831 is the low word of a VROOMM descriptor's fileofs
    wt = doc["callers"]["0x7831"]["word_table_hits"]["START.EXE"]
    assert wt == {"count": 1, "after_vroomm_descriptor_magic": 1, "first": ["0x08ab"]}

    assert doc["binding_established"] is False and doc["mappings"] == []
