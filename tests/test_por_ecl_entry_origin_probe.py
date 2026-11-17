"""Tests for tools/por_ecl_entry_origin_probe.py.

Synthetic tests run everywhere: the access classifier, the cell-reference scan, the record model on a
hand-built block (including the copy-skip falsifier), and refusals on fake install folders.

Falsification tests mutate an in-memory copy of the pinned GAME.OVR (never the file) and assert that the
named byte check fails. They run when OPENUA_POR_INSTALL names the pinned POOLRAD folder and skip without it.
Retail tests (the 29-block consistency run and the skip grid) use the same gate and write only under
pytest's tmp_path.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl_entry_origin_probe as eo  # noqa: E402
import por_loadpieces_handler as h  # noqa: E402

INSTALL = os.environ.get("OPENUA_POR_INSTALL")
RETAIL = pytest.mark.skipif(not INSTALL or not Path(INSTALL, "GAME.OVR").is_file(),
                            reason="set OPENUA_POR_INSTALL to the pinned POOLRAD folder")
MODEL = {"cursor0": 0x9900, "disp": 0x6700, "skip": 2, "record_bytes": 4}


def _retail_ovr() -> bytes:
    return Path(INSTALL, "GAME.OVR").read_bytes()


def _mutate(data: bytes, off: int, old: str, new: str) -> bytes:
    """Replace ``old`` by ``new`` at ``off``; the old bytes must be there (the test is meaningful)."""
    o, n = bytes.fromhex(old.replace(" ", "")), bytes.fromhex(new.replace(" ", ""))
    assert len(o) == len(n), "mutation must keep the length"
    assert data[off:off + len(o)] == o, "expected %s at 0x%05x, found %s" % (old, off, data[off:off + len(o)].hex())
    return data[:off] + n + data[off + len(n):]


def _block_with_table(vaddrs, skip=2, size=0x1E00) -> bytes:
    """A block whose bytes at buffer index k are block[k + skip] = the PoR records, then the magic."""
    blk = bytearray(size)
    blk[0:2] = (0x1388).to_bytes(2, "little")
    for k, v in enumerate(vaddrs):
        base = 2 + 4 * k
        blk[base:base + 2] = (0x0101).to_bytes(2, "little")
        blk[base + 2:base + 4] = v.to_bytes(2, "little")
    return bytes(blk)


# ---------------------------------------------------------------------------------------------
# Synthetic: the decoder-level classifier and the cell scan
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("code,kind", [
    ("a1ed49", "load"),              # mov ax,[0x49ed]
    ("a3ed49", "store"),             # mov [0x49ed],ax
    ("c706ed490099", "store-imm"),   # mov word [0x49ed],0x9900
    ("ff06ed49", "inc"),             # inc word [0x49ed]
    ("c43ede49", "les"),             # les di,[0x49de]
    ("ff36e349", "push"),            # push word [0x49e3]
    ("8916e049", "store"),           # mov [0x49e0],dx
])
def test_access_kind_from_opcode(code, kind):
    data = bytes.fromhex(code) + b"\x90" * 4
    ins = h.decode(data, 0)
    assert eo.access_kind(ins) == kind


def test_cell_refs_finds_the_only_store_in_a_synthetic_buffer():
    data = b"\x90" * 8 + bytes.fromhex("a3de49") + b"\x90" * 8 + bytes.fromhex("c43ede49") + b"\x90" * 4
    refs = eo.cell_refs(data, frozenset({eo.PTR_OFF}))
    kinds = [(r["cell"], r["kind"], r["ins"].off) for r in refs]
    assert kinds == [("0x49DE", "store", 8), ("0x49DE", "les", 19)]


def test_pins_are_the_framing_probe_pins():
    import por_ecl_native_framing_probe as framing  # noqa: E402  (read-only; pins are not edited)
    assert eo.PINS == framing.PINS


# ---------------------------------------------------------------------------------------------
# Synthetic: the record model and the copy-skip falsifier
# ---------------------------------------------------------------------------------------------

def test_buffer_index_wraps_the_fetch_displacement():
    # vaddr 0x9914 with the 0x6700 displacement is buffer index 0x14 (the 16-bit add wraps)
    assert eo.buffer_index(0x9914, 0x6700) == 0x14
    assert eo.buffer_index(0x9900, 0x6700) == 0x0


def test_parse_model_reads_five_records_and_ends_after_the_table():
    vaddrs = [0x9914, 0x9975, 0x9A0E, 0x9A49, 0x9A5E]
    blk = _block_with_table(vaddrs, skip=2)
    res = eo.parse_model(blk, MODEL)
    assert res["ok"]
    assert [r["word"] for r in res["records"]] == vaddrs
    assert all(r["tag"] == 1 for r in res["records"])
    assert res["end"] == 0x9914           # 0x9900 + five records of four bytes
    assert eo.buffer_index(res["end"], MODEL["disp"]) + MODEL["skip"] == 22


@pytest.mark.parametrize("skip", [0, 1, 3, 4])
def test_copy_skip_falsifier_on_a_synthetic_block(skip):
    # the block is laid out with the table at block offset 2; any other skip misreads the records
    vaddrs = [0x9914, 0x9975, 0x9A0E, 0x9A49, 0x9A5E]
    blk = _block_with_table(vaddrs, skip=2)
    res = eo.parse_model(blk, dict(MODEL, skip=skip))
    assert not (res["ok"] and [r["word"] for r in res["records"]] == vaddrs)


def test_parse_model_refuses_a_closed_tag_violation():
    blk = bytearray(_block_with_table([0x9914] * 5))
    blk[3] = 0x80                         # first record's tag (block index 2 + 1) becomes tag 0x80
    res = eo.parse_model(bytes(blk), MODEL)
    assert not res["ok"] and "tag-not-closed" in res["reason"]


def test_byte_checks_do_not_pass_on_zero_bytes():
    checks = eo.byte_checks(bytes(70000))
    assert set(checks) == {"pointer_slot", "cursor_literals", "header_routine_0x7689", "operand_parser_0x74D3",
                           "value_decode_0x7B82", "loader_0x7814", "key_load_and_dispatch"}
    assert not any(c["ok"] for c in checks.values())


# ---------------------------------------------------------------------------------------------
# Synthetic: refusals (named, before any output is written)
# ---------------------------------------------------------------------------------------------

def _fake_install(tmp_path: Path, game: bytes, start: bytes = b"x") -> Path:
    inst = tmp_path / "POOLRAD"
    inst.mkdir()
    (inst / "GAME.OVR").write_bytes(game)
    (inst / "START.EXE").write_bytes(start)
    return inst


def test_refuses_an_unpinned_game_ovr(tmp_path):
    inst = _fake_install(tmp_path, b"not the pinned bytes")
    with pytest.raises(eo.ProbeRefusal, match="unpinned"):
        eo.load_pinned(inst)


def test_refuses_a_missing_install_file(tmp_path):
    inst = tmp_path / "POOLRAD"
    inst.mkdir()
    (inst / "START.EXE").write_bytes(b"x")          # GAME.OVR absent
    with pytest.raises(eo.ProbeRefusal, match="missing install file"):
        eo.load_pinned(inst)


def test_refuses_output_inside_the_install(tmp_path):
    inst = _fake_install(tmp_path, b"x")
    with pytest.raises(eo.ProbeRefusal, match="inside the install"):
        eo.validate_output_dir(inst, inst / "out")


def test_cli_refuses_output_outside_data_work(tmp_path):
    inst = _fake_install(tmp_path, b"x")
    with pytest.raises(eo.ProbeRefusal, match="outside data/work"):
        eo.validate_output_dir(inst, tmp_path / "elsewhere", cli=True)


# ---------------------------------------------------------------------------------------------
# Retail: byte checks on the pinned GAME.OVR, then falsifiers on mutated copies
# ---------------------------------------------------------------------------------------------

@RETAIL
def test_retail_byte_checks_all_pass():
    checks = eo.byte_checks(_retail_ovr())
    failed = [k for k, v in checks.items() if not v["ok"]]
    assert failed == []


@RETAIL
def test_retail_model_is_read_from_the_bytes():
    model = eo.model_from_bytes(eo.byte_checks(_retail_ovr()))
    assert model == {"cursor0": 0x9900, "disp": 0x6700, "skip": 2, "record_bytes": 4}


@RETAIL
def test_falsifier_wrong_pointer_slot_in_the_parser_body():
    # the parser's far-pointer load at 0x74F9 reads [0x49D2] instead of [0x49DE]
    data = _mutate(_retail_ovr(), 0x74F9, "c43ede49", "c43ed249")
    checks = eo.byte_checks(data)
    parser = checks["operand_parser_0x74D3"]
    assert not parser["ok"]
    assert "0x074F9" not in parser["facts"]["far_pointer_loads_in_body"]


@RETAIL
def test_falsifier_wrong_pointer_slot_in_the_loader_copy():
    data = _mutate(_retail_ovr(), 0x78BA, "c43ede49", "c43ed249")
    checks = eo.byte_checks(data)
    assert not checks["loader_0x7814"]["ok"]


@RETAIL
def test_falsifier_pointer_store_moved_to_another_cell():
    data = _mutate(_retail_ovr(), 0x0E640, "a3de49", "a3d249")
    checks = eo.byte_checks(data)
    assert not checks["pointer_slot"]["ok"]


@RETAIL
def test_falsifier_allocation_size_changed():
    data = _mutate(_retail_ovr(), 0x0E637 + 1, "001e", "001d")
    checks = eo.byte_checks(data)
    assert not checks["pointer_slot"]["ok"]


@RETAIL
def test_falsifier_cursor_write_removed_at_the_header_routine():
    # the literal store at 0x76C8 is replaced by NOPs: the routine no longer sets the cursor
    data = _mutate(_retail_ovr(), 0x76C8, "c706ed490099", "909090909090")
    checks = eo.byte_checks(data)
    assert not checks["header_routine_0x7689"]["ok"]
    assert not checks["cursor_literals"]["ok"]
    assert eo.model_from_bytes(checks) is None


@RETAIL
def test_falsifier_cursor_literal_shifted_by_two():
    data = _mutate(_retail_ovr(), 0x76C8, "c706ed490099", "c706ed490299")
    checks = eo.byte_checks(data)
    assert not checks["cursor_literals"]["ok"]
    assert eo.model_from_bytes(checks) is None


@RETAIL
def test_falsifier_displacement_changed_in_the_parser_fetch():
    # the tag fetch at 0x74FF uses displacement 0x6702 instead of 0x6700
    data = _mutate(_retail_ovr(), 0x74FF + 3, "0067", "0267")
    checks = eo.byte_checks(data)
    assert not checks["operand_parser_0x74D3"]["ok"]


@RETAIL
def test_falsifier_copy_skip_changed_in_the_loader_bytes():
    # add di,2 at 0x78B4 becomes add di,0
    data = _mutate(_retail_ovr(), 0x78B4 + 2, "0200", "0000")
    checks = eo.byte_checks(data)
    assert not checks["loader_0x7814"]["ok"]


@RETAIL
def test_falsifier_branch_inserted_between_store_and_first_parse():
    # xor ax,ax at 0x76D3 becomes jmp short +0: a branch in the straight-line window
    data = _mutate(_retail_ovr(), 0x76D3, "31c0", "eb00")
    checks = eo.byte_checks(data)
    assert not checks["header_routine_0x7689"]["ok"]
    assert checks["header_routine_0x7689"]["facts"]["branches_between_store_and_first_parse"]


@RETAIL
def test_falsifier_class_argument_not_one():
    # the first parser call's class push 'mov al,1' at 0x7720 becomes 'mov al,2'
    data = _mutate(_retail_ovr(), 0x7720 + 1, "01", "02")
    checks = eo.byte_checks(data)
    assert not checks["header_routine_0x7689"]["ok"]


@RETAIL
def test_falsifier_value_decode_formula_changed():
    # add ax,dx at 0x7B98 becomes sub ax,dx: the decoded word is no longer (extra<<8)|value
    data = _mutate(_retail_ovr(), 0x7B98, "03c2", "2bc2")
    checks = eo.byte_checks(data)
    assert not checks["value_decode_0x7B82"]["ok"]


@RETAIL
def test_falsifier_entry_slot_store_order_swapped():
    # the store of the second value decode goes to 0x49E7 instead of 0x49E5
    data = _mutate(_retail_ovr(), 0x7749 + 1, "e549", "e749")
    checks = eo.byte_checks(data)
    assert not checks["value_decode_0x7B82"]["ok"]


@RETAIL
def test_falsifier_key_load_displacement_changed():
    data = _mutate(_retail_ovr(), 0x937C + 12, "0067", "0267")
    checks = eo.byte_checks(data)
    assert not checks["key_load_and_dispatch"]["ok"]


@RETAIL
def test_retail_wrong_cursor_origin_fails_every_block(tmp_path):
    # the parse from 0x9902 (not 0x9900) must not reproduce any retail table
    dax_paths = sorted(Path(INSTALL).glob("ECL*.DAX"))
    decoded = eo.decoded_blocks(dax_paths)
    shifted = dict(MODEL, cursor0=0x9902)
    passed = 0
    for blk, vaddrs in decoded:
        res = eo.parse_model(blk, shifted)
        if res["ok"] and [r["word"] for r in res["records"]] == vaddrs:
            passed += 1
    assert passed == 0


@RETAIL
def test_retail_skip_grid_accepts_only_skip_two():
    dax_paths = sorted(Path(INSTALL).glob("ECL*.DAX"))
    grid = eo.skip_grid(dax_paths, MODEL)
    full = [g["skip"] for g in grid if g["passes"] == g["of"]]
    assert full == [2]
    assert all(g["of"] == 29 for g in grid)


@RETAIL
def test_retail_cli_report_is_conditional_with_origin_22(tmp_path):
    doc, rc = eo.probe(Path(INSTALL), tmp_path / "out")
    assert rc == 0
    assert doc["self_checks"] == {
        "inputs_unchanged": True, "byte_checks_pass": True, "model_read_from_bytes": True,
        "retail_blocks_ran": True, "retail_all_blocks_match": True, "copy_skip_pinned_by_retail": True,
    }
    v = doc["verdict"]
    assert v["origin_vaddr"] == "0x9914"
    assert v["origin_buffer_index"] == 20
    assert v["origin_block_offset"] == 22
    assert v["conditional"] is True and v["established"] is False
    assert (v["retail_blocks_matching"], v["retail_blocks_total"]) == (29, 29)
    assert v["retail_blocks_entry_slots_at_or_after_origin"] == 29


@RETAIL
def test_retail_write_outputs_under_tmp(tmp_path):
    doc, _ = eo.probe(Path(INSTALL), tmp_path / "out")
    eo.write_outputs(doc, tmp_path / "out")
    assert (tmp_path / "out" / eo.RESULT_JSON).is_file()
    assert (tmp_path / "out" / eo.RESULT_MD).is_file()
