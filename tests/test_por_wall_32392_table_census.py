"""Tests for tools/por_wall_32392_table_census.py (census of DS table-region accesses for GAME.OVR 0x32392).

Synthetic fixtures (default) check the access roles, the region matches (boundaries, direct versus
indexed, ES versus DS versus CS, BP-based), the bounded walk, the write-surface and immediate channels,
the START trampoline, and the refusals. Each claim has a mutated-byte falsification that must change the
result. The retail test runs only when OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and
is skipped otherwise; it reads the install read-only and writes only to a temporary folder.
"""
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_loadpieces_handler as h  # noqa: E402
import por_wall_32392_table_census as tc  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
W_ADDR = 0x2722
F_ADDR = 0x5E3A
Q_ADDR = 0x5E4E


def _ins(hexbytes: str) -> h.Insn:
    return h.decode(bytes.fromhex(hexbytes), 0)


def _role(hexbytes: str):
    ins = _ins(hexbytes)
    opnd = tc.operand(ins)
    return None if opnd is None else (opnd["role"], opnd["width"], opnd["segment"], opnd["space"])


def _matches(hexbytes: str) -> list[dict]:
    opnd = tc.operand(_ins(hexbytes))
    return [] if opnd is None else tc.region_matches(opnd)


def _unit(lo, hi, roots, label="u"):
    return {"label": label, "lo": lo, "hi": hi, "roots": roots, "header_offset": None,
            "status": "fixture", "fixups": None}


def _blob(placements: dict[int, str], size: int = 0x400) -> bytes:
    b = bytearray(size)
    for off, hexbytes in placements.items():
        data = bytes.fromhex(hexbytes)
        b[off:off + len(data)] = data
    return bytes(b)


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hexbytes, role, width", [
    ("8b062227", "read", 2),          # mov ax,[0x2722]
    ("8b852227", "read", 2),          # mov ax,[di+0x2722]
    ("89062227", "write", 2),         # mov [0x2722],ax
    ("88062227", "write", 1),         # mov [0x2722],al
    ("01062227", "rmw", 2),           # add [0x2722],ax
    ("03062227", "read", 2),          # add ax,[0x2722]
    ("39062227", "read", 2),          # cmp [0x2722],ax
    ("83062227" + "01", "rmw", 2),    # add word [0x2722],1
    ("c4853a5e", "far", 4),           # les ax,[di+0x5E3A]
    ("c5062227", "far", 4),           # lds ax,[0x2722]
    ("8d853a5e", "address", 0),       # lea ax,[di+0x5E3A]
    ("ff974e5e", "indirect", 2),      # call [bx+0x5E4E]
    ("a34e5e", "write", 2),           # mov [0x5E4E],ax (moffs)
    ("a14e5e", "read", 2),            # mov ax,[0x5E4E] (moffs)
])
def test_roles_and_widths(hexbytes, role, width):
    got = _role(hexbytes)
    assert got is not None and got[0] == role and got[1] == width, got


def test_role_mutation_load_to_store_changes_role():
    # 8B (mov r,r/m) is a read; 89 (mov r/m,r) with the same operand is a write.
    assert _role("8b062227")[0] == "read"
    assert _role("89062227")[0] == "write"


def test_role_mutation_add_direction_changes_rmw_to_read():
    # 01 (add r/m,r) is rmw; 03 (add r,r/m) with the same operand only reads.
    assert _role("01062227")[0] == "rmw"
    assert _role("03062227")[0] == "read"


def test_role_mutation_cmp_is_read_not_rmw():
    assert _role("39062227")[0] == "read"          # cmp r/m,r
    assert _role("01062227")[0] == "rmw"           # add r/m,r with the same operand


def test_register_only_operand_has_no_region_hit():
    # mov [di],ax has no displacement; the base register is unknown, so it cannot name a region.
    opnd = tc.operand(_ins("8905"))
    assert opnd["space"] == "indexed" and opnd["has_disp"] is False
    assert tc.region_matches(opnd) == []


def test_non_memory_instruction_has_no_operand():
    assert tc.operand(_ins("c3")) is None
    assert tc.operand(_ins("b83800")) is None       # mov ax,imm16


# ---------------------------------------------------------------------------
# Region matches and boundaries
# ---------------------------------------------------------------------------

def test_direct_word_straddling_region_end_matches():
    # Word at 0x272B covers 0x272B..0x272C; 0x272B is the last byte of W, so it overlaps.
    assert [m["region"] for m in _matches("8b062b27")] == ["W"]


def test_direct_word_starting_at_region_end_does_not_match():
    # Word at 0x272C starts one byte past W (half-open upper bound 0x272C).
    assert _matches("8b062c27") == []


def test_indexed_disp_at_region_start_matches_and_past_end_does_not():
    assert [m["region"] for m in _matches("8b852227")] == ["W"]           # disp 0x2722
    assert _matches("8b852c27") == []                                       # disp 0x272C
    assert [m["region"] for m in _matches("8b853a5e")] == ["F"]           # disp 0x5E3A


def test_mutated_displacement_moves_match_out_of_region():
    assert [m["region"] for m in _matches("8b852227")] == ["W"]
    assert _matches("8b852127") == []                                       # 0x2721 is below W


def test_es_prefix_matches_as_candidate_not_ds():
    hits = _matches("268b852227")
    assert hits and all(h_["match"].startswith("es-") for h_ in hits)
    assert hits[0]["region"] == "W"


def test_cs_prefix_never_matches():
    assert _matches("2e8b062227") == []


def test_mutated_es_prefix_back_to_ds_matches_as_ds():
    es = _matches("268b852227")
    ds = _matches("8b852227")
    assert es[0]["match"] == "es-indexed-disp-in-region"
    assert ds[0]["match"] == "indexed-disp-in-region"


def test_stack_operand_never_matches_region():
    assert _matches("8b46fe") == []                 # mov ax,[bp-2]
    assert tc.operand(_ins("8b46fe"))["space"] == "stack"


def test_lea_is_address_role_and_matches_region_span():
    opnd = tc.operand(_ins("8d853a5e"))
    assert opnd["role"] == "address" and opnd["width"] == 0
    assert [m["region"] for m in tc.region_matches(opnd)] == ["F"]


def test_ds_reassignment_kinds():
    assert tc.ds_reassign(_ins("8ed8")) == "mov-ds"          # mov ds,ax
    assert tc.ds_reassign(_ins("8ec0")) is None              # mov es,ax
    assert tc.ds_reassign(_ins("c5062227")) == "lds"
    assert tc.ds_reassign(_ins("1f")) == "pop-ds"
    assert tc.ds_reassign(_ins("1e")) is None                # push ds


# ---------------------------------------------------------------------------
# Bounded walk, writers and call paths
# ---------------------------------------------------------------------------

def test_writer_reached_by_near_call_has_root_path():
    # root A at 0x100: call B; B at 0x140 writes Q (mov [0x5E4E],ax).
    blob = _blob({0x100: "e83d00" + "c3", 0x140: "a34e5e" + "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert [w["proc"] for w in doc["writers"]] == [0x140]
    w = doc["writers"][0]
    assert w["regions_written"] == ["Q"]
    assert w["root_path_status"] == "root-path-found"
    assert w["reached_from_roots"] == [{"root": 0x100, "path": [0x100, 0x140]}]


def test_mutated_call_removes_root_path_and_walk():
    # Replace the near call with NOPs: B is never reached, so no root path and no walked write.
    blob = _blob({0x100: "909090" + "c3", 0x140: "a34e5e" + "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert doc["writers"] == []
    assert 0x140 not in doc["walked_proc_entries"]


def test_writer_reached_only_outside_unit_is_not_walked():
    # The near call targets 0x240, outside the unit span [0x100, 0x200): recorded, not followed.
    blob = _blob({0x100: "e83d01" + "c3", 0x240: "a34e5e" + "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    units = doc["units"][0]
    assert units["outside_unit_near_calls"] == 1
    assert doc["writers"] == []


def test_leaves_and_roots_outside_span_are_recorded_not_walked():
    # Four NOPs fill [0x100, 0x104); the RET at 0x104 ends beyond hi=0x104 and is dropped.
    blob = _blob({0x100: "90909090" + "c3", 0x300: "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x104, [0x100, 0x300])])
    u = doc["units"][0]
    assert u["leaves_span"] == 1
    assert u["roots_outside_span"] == [0x300]
    assert u["walked_procs"] == 1
    assert u["covered_bytes"] == 4


def test_mutated_leaf_inside_span_is_walked():
    blob = _blob({0x100: "90909090" + "c3", 0x300: "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x105, [0x100])])
    assert doc["units"][0]["leaves_span"] == 0
    assert doc["units"][0]["covered_bytes"] == 5


def test_decode_incomplete_is_reported():
    blob = _blob({0x100: "0f00" + "c3"})           # 0F two-byte escape: not decoded
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert doc["units"][0]["decode_incomplete"]
    assert doc["units"][0]["decode_incomplete"][0]["code"].startswith("unsupported-opcode-0x0f")


def test_write_surface_counts_register_only_and_string_stores():
    blob = _blob({0x100: "8905" + "aa" + "c3"})   # mov [di],ax ; stosb ; ret
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    kinds = sorted(s["kind"] for s in doc["write_surface"])
    assert kinds == ["register-only-write", "string-store"]


def test_mutated_disp_turns_register_surface_into_region_write():
    # mov [di+0x5E3A],ax has a displacement in F: a disp-carrying write, not a register-only one.
    blob = _blob({0x100: "89853a5e" + "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert doc["write_surface"] == []
    assert [a["region"] for a in doc["accesses"]] == ["F"]
    assert doc["writers"][0]["regions_written"] == ["F"]


def test_immediate_region_literal_and_register_write_in_same_proc():
    # mov di,0x5E3A ; mov [di],ax ; ret: the immediate names F and the write goes through DI.
    blob = _blob({0x100: "bf3a5e" + "8905" + "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert [r["region"] for r in doc["region_immediates"]] == ["F"]
    assert [s["kind"] for s in doc["write_surface_in_region_immediate_procs"]] == ["register-only-write"]


def test_mutated_immediate_outside_regions_clears_the_hit():
    blob = _blob({0x100: "bf005e" + "8905" + "c3"})   # mov di,0x5E00: below F
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert doc["region_immediates"] == []
    assert doc["write_surface_in_region_immediate_procs"] == []


def test_pointer_handoff_lists_far_calls_in_region_proc():
    # mov ax,[di+0x5E3A] ; call far 0x0464:0x0111 (9A off seg): the callee may receive a region pointer.
    blob = _blob({0x100: "8b853a5e" + "9a1101" + "6404" + "c3"})
    doc = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    row = doc["region_access_procs"][0]
    assert row["regions"] == ["F"] and row["proc"] == 0x100
    assert len(row["far_call_literals"]) == 1


def test_trampoline_continuation_inside_and_outside_copy():
    blob = _blob({0x100: "50" + "b83800" + "50" + "cb"})
    insns = tc.cp.explore(blob, 0x100, 50)["_insns"]
    assert [(c["imm"], c["inside_copy"]) for c in tc.find_continuations(insns, 0x9A)] == [(0x38, True)]
    assert [c["inside_copy"] for c in tc.find_continuations(insns, 0x30)] == [False]
    assert [c["inside_copy"] for c in tc.find_continuations(insns, None)] == [False]


def test_mutated_retf_removes_trampoline():
    blob = _blob({0x100: "50" + "b83800" + "50" + "c3"})   # ret instead of retf
    insns = tc.cp.explore(blob, 0x100, 50)["_insns"]
    assert tc.find_continuations(insns, 0x9A) == []


# ---------------------------------------------------------------------------
# Refusals and determinism
# ---------------------------------------------------------------------------

def test_unpinned_gameovr_is_refused(tmp_path):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"not the retail file")
    with pytest.raises(tc.CensusError):
        tc.read_pinned(install, "GAME.OVR")


def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    with pytest.raises(tc.CensusError):
        tc.probe(install, install / "out")


def test_cli_refuses_unpinned_install_with_exit_two(tmp_path, capsys):
    install = tmp_path / "POOLRAD"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"x")
    (install / "START.EXE").write_bytes(b"y")
    code = tc.main(["--install", str(install), "-o", str(tmp_path / "out")])
    assert code == 2
    assert "refused" in capsys.readouterr().err


def test_fixture_run_is_deterministic():
    blob = _blob({0x100: "e83d00" + "c3", 0x140: "a34e5e" + "c3"})
    a = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    b = tc.census_file(blob, "FIX", [_unit(0x100, 0x200, [0x100])])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---------------------------------------------------------------------------
# Retail (pin-gated)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.environ.get(ENV), reason=f"set {ENV} to the Pool of Radiance install")
def test_retail_census_facts(tmp_path):
    install = Path(os.environ[ENV])
    ovr_before = (install / "GAME.OVR").read_bytes()
    exe_before = (install / "START.EXE").read_bytes()
    out = tmp_path / "out"
    code = tc.main(["--install", str(install), "-o", str(out)])
    assert code == 1                                  # diagnostics: known decode gaps are reported
    doc = json.loads((out / "por_wall_32392_table_census.json").read_text(encoding="utf-8"))

    assert doc["source"]["files"][0]["sha256"] == tc.fr.PINNED["GAME.OVR"][1]
    assert doc["source"]["files"][1]["sha256"] == tc.fr.PINNED["START.EXE"][1]
    assert doc["playable"] is False and doc["mappings"] == [] and doc["events_emitted"] == 0

    owner = doc["subject"]["owner_stub"]
    assert owner["group_header"] == 0x42C2 and owner["stub_index"] == 2
    assert owner["stub_start"] == 0x42E3 and owner["fileofs"] == 0x32235 and owner["codesz"] == 0x2B2

    acc = doc["accesses"]["gameovr"]
    owner_hits = {(a["at"], a["region"], a["role"]) for a in acc if a["proc"] == 0x32392}
    assert (0x32444, "W", "read") in owner_hits          # mov ax,[di+0x2722]
    assert (0x3242E, "F", "read") in owner_hits          # mov ax,[di+0x5E3A]
    assert (0x32490, "F", "far") in owner_hits           # les di,[di+0x5E3A]
    assert (0x32476, "S", "read") in owner_hits          # push [0x4A22]
    assert (0x3247A, "S", "read") in owner_hits          # push [0x4A20]
    assert (0x324AF, "Q", "far") in owner_hits           # les di,[0x5E4E]

    v = doc["verdict"]
    assert v["write_or_rmw_records"] == 0 and v["writer_procedures"] == 0
    assert v["answer"] == "no-disp-carrying-writes-in-walked-code"
    assert v["table_binding"] == "not-established" and v["runtime_execution"] == "not-established"
    assert v["far_call_seg_fixup_listed"] + v["far_call_seg_not_fixup_listed"] == v["far_call_sites"]
    assert v["write_surface_records"] == 155
    assert v["region_access_procs"] == 11

    start = doc["start"]
    assert start["copy_len"] == 0x9A
    assert [c["imm"] for c in start["continuations"]] == [0x38]
    assert doc["diagnostics"] == ["decode-incomplete", "byte-conflicts-between-procedures"]

    again = tmp_path / "again"
    tc.main(["--install", str(install), "-o", str(again)])
    assert (out / "por_wall_32392_table_census.json").read_bytes() == \
        (again / "por_wall_32392_table_census.json").read_bytes()

    assert (install / "GAME.OVR").read_bytes() == ovr_before
    assert (install / "START.EXE").read_bytes() == exe_before
