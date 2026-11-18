"""Tests for tools/por_wall_0111_bound_update_probe.py (module routines 0x0AF8:0x0432, 0x03D3 and 0x0491).

Synthetic fixtures (default, no install needed) build the three routines' bytes from the tool's own expected
listing at the module base, then check each claim with a mutated-byte falsifier that must change the result:
the decode and its cross-check, the expected listing, the control-flow exits and call sites, the register
inputs (upward-exposed reads), the bound-slot stores, the head-slot chain, the zero-size exit, the flag
producer/consumer pairs, the size and normalisation algebra, the identity in a dump, and the refusals.

The retail test runs only when OPENUA_POR_INSTALL names the local Pool of Radiance install and the pinned
dumps exist; it calls probe() and writes nothing.
"""
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_0111_bound_update_probe as bp  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
BASE = bp.EXPECT_BASE                     # 0xAC76, the module file base (module-target note)
LIVE_SEG = bp.MODULE_SEG + bp.EXPECT_LOAD  # 0x235E


def _synthetic_start() -> bytearray:
    """A fake START.EXE: the three routines' exact bytes (from the tool's expected listing) at the module base."""
    buf = bytearray(b"\xcc" * (BASE + 0x4C0))
    for entry in (bp.ENTRY_RELEASE, bp.ENTRY_LINK, bp.ENTRY_SIZE):
        for mo, hx, _text in bp.EXPECTED[entry]:
            raw = bytes.fromhex(hx)
            at = BASE + int(mo, 16)
            buf[at:at + len(raw)] = raw
    buf[BASE + 0x025F:BASE + 0x0262] = bytes.fromhex("e87101")   # the wrapper's call to 0x03D3, outside the routines
    return buf


def _patch(buf: bytearray, mo: int, old: str, new: str) -> bytearray:
    """Replace the bytes at module offset `mo` (hex strings, same length), failing if `old` is not there."""
    raw_old, raw_new = bytes.fromhex(old), bytes.fromhex(new)
    assert len(raw_old) == len(raw_new)
    at = BASE + mo
    assert bytes(buf[at:at + len(raw_old)]) == raw_old, "fixture bytes differ at 0x%04x" % mo
    buf[at:at + len(raw_new)] = raw_new
    return buf


def _doc(buf) -> dict:
    return bp.build_document(bytes(buf), b"", BASE, {}, [], {})


def _checks(buf) -> dict:
    return _doc(buf)["self_checks"]


# ---- baseline ---------------------------------------------------------------------------------

def test_baseline_synthetic_passes_every_self_check():
    doc = _doc(_synthetic_start())
    assert doc["self_checks_passed"] is True
    assert all(v is True for v in doc["self_checks"].values()), doc["self_checks"]
    assert doc["bounds_hypothesis"]["low_bound_written"] is False
    assert doc["bounds_hypothesis"]["high_bound_written_at"] == ["0x045f", "0x0463"]


def test_decode_text_is_register_exact_not_the_repo_text_form():
    # The repo decoder's text() prints `es add [di+4]` for 26 03 4d 04; the register is cx (ModRM 4d).
    buf = _synthetic_start()
    row = [r for r in bp.analyse_routines(bytes(buf), BASE)[bp.ENTRY_LINK]["listing"] if r["mo"] == "0x043a"][0]
    assert row["text"] == "add cx,es:[di+4]"
    assert row["defs"] == ["cx"]


def test_linear_decode_must_land_on_span_end():
    buf = bytes(_synthetic_start())
    bp.decode_span(buf, BASE, 0x0432, 0x0490)                 # 0x0490 is the last byte of the final ret
    with pytest.raises(bp.Refusal):
        bp.decode_span(buf, BASE, 0x0432, 0x0489)             # 0x0488 ret ends at 0x0489, not 0x048a


def test_unsupported_opcode_fails_closed():
    buf = _synthetic_start()
    _patch(buf, 0x0432, "8b", "0f")   # 0x0F is a two-byte opcode outside the subset
    with pytest.raises(bp.Unsupported):
        bp.analyse_routines(bytes(buf), BASE)


def test_cross_check_detects_a_wrong_length():
    buf = bytes(_synthetic_start())
    ins = bp.decode(buf, BASE + 0x0432, BASE)
    assert bp.cross_check(buf, ins)["ok"] is True
    bad = bp.Ins(off=ins.off, base=BASE, length=ins.length + 1, raw=ins.raw, name=ins.name, text=ins.text,
                 flow=ins.flow, target=ins.target, uses=ins.uses, defs=ins.defs, mems=ins.mems)
    assert bp.cross_check(buf, bad)["ok"] is False


# ---- falsifiers: the listing and the control flow ----------------------------------------------

def test_flipped_branch_changes_listing_and_flow():
    # 0x044d jnz 0x0489 -> jz 0x0489: same length, different flow.
    buf = _patch(_synthetic_start(), 0x044D, "75", "74")
    checks = _checks(buf)
    assert checks["listing_matches_expected"] is False
    assert _doc(buf)["self_checks_passed"] is False


def test_zero_size_branch_retargeted_changes_the_zero_exit_fact():
    # 0x03d5 jz 0x0431 -> jnz 0x0431: the zero-size exit no longer takes the jz.
    buf = _patch(_synthetic_start(), 0x03D5, "74", "75")
    zero = bp.zero_size_exit(bp.analyse_routines(bytes(buf), BASE))
    assert zero["jz_name"] == "jnz"
    assert _checks(buf)["zero_size_exit_is_clear_carry"] is False


def test_call_retargeted_to_a_non_entry_is_refused():
    # 0x0426 call 0x0432 -> call 0x0433: 0x0433 is no routine entry, so there is no callee summary.
    buf = _patch(_synthetic_start(), 0x0426, "e80900", "e80a00")
    with pytest.raises(bp.Refusal):
        _doc(buf)


def test_call_retargeted_to_the_size_helper_removes_the_link_caller():
    # 0x0426 call 0x0432 -> call 0x0491 (e8 68 00: 0x0429 + 0x68): a real summary, but not the link routine.
    buf = _patch(_synthetic_start(), 0x0426, "e80900", "e86800")
    doc = _doc(buf)
    assert doc["self_checks"]["link_callers_present"] is False
    assert doc["self_checks"]["listing_matches_expected"] is False
    assert doc["self_checks_passed"] is False


def test_branch_out_of_the_release_span_is_an_external_edge():
    buf = _patch(_synthetic_start(), 0x0421, "ed", "46")   # ja 0x040f -> ja 0x0468, the merge path in the link span
    rel = bp.analyse_routines(bytes(buf), BASE)[bp.ENTRY_RELEASE]
    assert rel["external_edges"] == ["0x0468"]
    assert _checks(buf)["no_external_edges"] is False


def test_store_behind_an_always_taken_branch_leaves_the_reachable_set():
    # 0x0457 jnz 0x0468 (75 0f) -> jmp 0x0468 (eb 0f): the stores at 0x045f/0x0463 and the ret at 0x0467 are
    # no longer reachable from the 0x0432 entry.
    buf = _patch(_synthetic_start(), 0x0457, "750f", "eb0f")
    link = bp.analyse_routines(bytes(buf), BASE)[bp.ENTRY_LINK]
    assert "0x045f" not in link["reachable"] and "0x0467" not in link["reachable"]
    doc = _doc(buf)
    assert doc["bounds_hypothesis"]["high_bound_written_at"] == []
    assert doc["self_checks"]["ret_sites_as_read"] is False


# ---- falsifiers: register inputs (upward-exposed reads) ---------------------------------------

def test_register_input_changes_when_first_read_changes():
    # 0x0432 mov ax,di -> mov ax,bx: di is no longer read before it is written on that path.
    buf = _patch(_synthetic_start(), 0x0432, "8bc7", "8bc3")
    doc = _doc(buf)
    link = doc["routines"]["0x0432"]
    assert "di" not in link["upward_exposed"]
    assert doc["self_checks"]["upward_exposed_0x0432"] is False


def test_release_inputs_are_ax_bx_cx_ds():
    r = bp.analyse_routines(bytes(_synthetic_start()), BASE)[bp.ENTRY_RELEASE]
    assert sorted(r["upward_exposed"]) == ["ax", "bx", "cx", "ds"]


def test_link_inputs_are_bx_cx_di_ds_es():
    r = bp.analyse_routines(bytes(_synthetic_start()), BASE)[bp.ENTRY_LINK]
    assert sorted(r["upward_exposed"]) == ["bx", "cx", "di", "ds", "es"]


# ---- falsifiers: the bounds and the head ------------------------------------------------------

def test_the_high_store_is_the_only_bound_store_in_the_link_routine():
    stores = bp.analyse_routines(bytes(_synthetic_start()), BASE)[bp.ENTRY_LINK]["stores"]
    ds_direct = [(s["at"], s["direct"]) for s in stores if s["seg"] == "ds" and s["direct"] is not None]
    assert ds_direct == [("0x045f", 0x4404), ("0x0463", 0x4406)]


def test_high_store_retargeted_to_the_low_bound_is_detected():
    # 0x0463 mov ds:[0x4406],es -> mov ds:[0x4402],es: the store now writes the low bound's segment word.
    buf = _patch(_synthetic_start(), 0x0463, "8c060644", "8c060244")
    doc = _doc(buf)
    assert doc["bounds_hypothesis"]["low_bound_written"] is True
    assert doc["self_checks"]["bound_low_never_written"] is False


def test_high_store_becoming_a_load_is_detected():
    # 0x045f mov ds:[0x4404],di -> mov di,ds:[0x4404]: the high offset is read, not written.
    buf = _patch(_synthetic_start(), 0x045F, "893e0444", "8b3e0444")
    doc = _doc(buf)
    assert doc["bounds_hypothesis"]["high_bound_written_at"] == ["0x0463"]
    assert doc["self_checks"]["bound_high_written_at_0x045f_and_0x0463"] is False


def test_head_load_retargeted_breaks_the_head_chain():
    # 0x0408 mov di,0x440c -> mov di,0x440d: the first iteration no longer starts at the head slot.
    buf = _patch(_synthetic_start(), 0x0408, "bf0c44", "bf0d44")
    assert _checks(buf)["head_chain_matched"] is False


def test_release_routine_writes_only_es_relative_memory():
    r = bp.analyse_routines(bytes(_synthetic_start()), BASE)[bp.ENTRY_RELEASE]
    assert r["stores"] and all(s["seg"] == "es" for s in r["stores"])


def test_string_moves_in_the_merge_path_are_non_rep_and_reachable():
    r = bp.analyse_routines(bytes(_synthetic_start()), BASE)[bp.ENTRY_LINK]
    ops = {row["mo"]: row["name"] for row in r["listing"]}
    assert ops["0x046f"] == "movsw" and ops["0x0471"] == "lodsw" and ops["0x0483"] == "stosw"
    assert "0x046f" in r["reachable"]
    raw = [row["hex"] for row in r["listing"] if row["mo"] == "0x046f"][0]
    assert not raw.startswith("f3")   # no rep prefix: this is not a bulk copy
    assert any(s["at"] == "0x046f" and s["seg"] == "es" for s in r["stores"])
    # Falsifier: a nop where movsw was removes that store and fails the listing.
    buf = _patch(_synthetic_start(), 0x046F, "a5", "90")
    r2 = bp.analyse_routines(bytes(buf), BASE)[bp.ENTRY_LINK]
    assert all(s["at"] != "0x046f" for s in r2["stores"])
    assert _checks(buf)["listing_matches_expected"] is False


# ---- falsifiers: the size and normalisation algebra -------------------------------------------

def test_size_model_is_round8_for_every_word():
    assert all(bp.size_model_round8(s) for s in range(1, 0x10000))


def test_size_model_identity_checked_at_the_carry_boundary():
    for s in (1, 7, 8, 9, 0xFFF8, 0xFFF9, 0xFFFF):
        dx, ax = bp.size_model(s)
        assert 16 * dx + ax == (s + 7) & ~7
        assert ax in (0, 8)


def test_size_claim_falls_when_the_decoded_sequence_changes():
    # 0x0498 shr dx,1 (d1 ea) -> shl dx,1 (d1 e2): the sequence no longer matches the reading.
    buf = _patch(_synthetic_start(), 0x0498, "d1ea", "d1e2")
    assert _checks(buf)["size_model_is_round8"] is False


def test_flag_pair_falls_when_the_consumer_is_separated_by_an_add():
    # 0x0494 mov dx,ax -> add dx,ax: an ALU op now sits between the flag producer at 0x0491 and the rcr at 0x0496.
    buf = _patch(_synthetic_start(), 0x0494, "8bd0", "03d0")
    assert _checks(buf)["flag_pairs_matched"] is False


def test_normalise_model_is_exact_below_32_and_not_at_32():
    assert bp.norm_model_ok() is True
    nh, nl = bp.normalise_model(32, 5)
    assert ((nh - 5) & 0xFFFF) * 16 + nl != 32     # the reading is only exact for lo sums below 32


# ---- callers ----------------------------------------------------------------------------------

def test_callers_of_the_three_routines_on_synthetic_bytes():
    start = bytes(_synthetic_start())
    c = bp.callers(start, b"", BASE)
    assert {s["at"] for s in c["0x0432"]["near_candidates_in_START"]} == {"0x0426", "0x042b"}
    assert {s["at"] for s in c["0x03D3"]["near_candidates_in_START"]} == {"0x025f"}
    assert "0x03f9" in {s["at"] for s in c["0x0491"]["near_candidates_in_START"]}


def test_far_calls_to_the_routines_are_counted_in_both_files():
    data = bytearray(b"\x00" * 64)
    data[10:15] = b"\x9a" + (0x0432).to_bytes(2, "little") + (0x0AF8).to_bytes(2, "little")
    got = bp._far_sites(bytes(data), 0x0AF8, 0x0432)
    assert got["far_call_file_offsets"] == ["0xA"]


# ---- identity in a dump -----------------------------------------------------------------------

def test_identity_agrees_then_disagrees_on_one_flipped_byte_in_a_dump():
    buf = bytes(_synthetic_start())
    load = bp.EXPECT_LOAD
    lin = LIVE_SEG * bp.PARA
    raw = bytearray(0x100000)
    for lo, hi in bp.SPAN_RANGES.values():
        raw[lin + lo: lin + hi + 1] = buf[BASE + lo: BASE + hi + 1]
    dump = ogm.Dump(bytes(raw), 0)
    ident = bp.span_identity(buf, BASE, dump, load)
    assert all(row["state"] == "memory-agrees-unique-placement" for row in ident.values())
    raw[lin + 0x045F] ^= 0xFF
    ident2 = bp.span_identity(buf, BASE, ogm.Dump(bytes(raw), 0), load)
    assert ident2["0x0432"]["state"] == "memory-disagrees"


def test_identity_reports_memory_not_covered():
    buf = bytes(_synthetic_start())
    ident = bp.span_identity(buf, BASE, ogm.Dump(b"\x00" * 16, 0), bp.EXPECT_LOAD)
    assert all(row["state"] == "memory-not-covered" for row in ident.values())


# ---- refusals and the CLI ---------------------------------------------------------------------

def test_cli_refuses_output_outside_data_work(tmp_path):
    assert bp.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")]) == 2


def test_cli_refuses_output_inside_the_install(tmp_path):
    install = bp.DATA_WORK / "por-wall-0111-bound-update-probe-test-install"
    out = install / "out"
    assert bp.main(["--install", str(install), "-o", str(out)]) == 2
    assert not out.exists()


def test_cli_refuses_an_unpinned_install(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"not the pinned overlay")
    (tmp_path / "START.EXE").write_bytes(b"not the pinned start")
    out = bp.DATA_WORK / "por-wall-0111-bound-update-probe-refusal-check"
    assert bp.main(["--install", str(tmp_path), "-o", str(out), "--dump", str(tmp_path / "x.bin")]) == 2
    assert not (out / "por_wall_0111_bound_update_probe.json").exists()


# ---- retail (gated) ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.environ.get(ENV), reason="set %s to the pinned POOLRAD install" % ENV)
def test_retail_probe_self_checks_pass():
    install = Path(os.environ[ENV])
    dumps = bp.DEFAULT_DUMPS
    if not all(p.exists() for p in dumps):
        pytest.skip("the pinned RAM dumps are not present")
    doc = bp.probe(install, dumps)
    assert doc["self_checks_passed"] is True, doc["self_checks"]
    assert doc["bounds_hypothesis"]["low_bound_written"] is False
    assert doc["bounds_hypothesis"]["high_bound_written_at"] == ["0x045f", "0x0463"]
