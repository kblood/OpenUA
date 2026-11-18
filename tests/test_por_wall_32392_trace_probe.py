"""Tests for tools/por_wall_32392_trace_probe.py (static trace of GAME.OVR 0x32392).

Synthetic fixtures (default) check the access classification (LES far-pointer loads,
ES-scaled multiplies, indexed and direct DS operands), the uninitialised-local walk, the
inline DOS I/O and token and stride checks, and the refusals. Each claim has a mutated-byte
falsification that must change the result. The retail pin check runs only when
OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and is skipped otherwise.
The retail run reads the install read-only and writes only to a temporary folder.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_wall_32392_trace_probe as tp  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
E = 0x200          # record-index fixture entry
E_IO = 0x280       # near-call IO fixture entry
E_TOK = 0x300      # token fixture entry
E_MUL = 0x340      # stride-constant fixture entry
BLOB = 0x800


def _record_fixture(*, zero_writes=False, es_prefix=True, les_indexed=True, prologue=True):
    """Shape of the 0x32392 record path, shrunk to one procedure.

    E+0  push bp; mov bp,sp; sub sp,6; mov ax,[bp+10]; cmp ax,1
    E+12 jb  ZERO                     (arm taken when key == 0)
    E+14 mov byte [bp-1],1; jmp JOIN  (the nonzero arm writes the slot)
    ZERO mov byte [bp-1],0 | 4 nops   (zero_writes selects which)
    JOIN mov al,[bp-1]; xor ah,ah; mov di,ax
         les di,[di+0x5e3a]           (far pointer from a DS table)
         es mul word [di+0x11]        (stride read through the far pointer)
         add di,ax; add di,0x17; pop bp; ret
    """
    head = bytes([0x55 if prologue else 0x90, 0x89, 0xE5]) + b"\x83\xec\x06" + b"\x8b\x46\x0a" + b"\x3d\x01\x00"
    zero = b"\xc6\x46\xff\x00" if zero_writes else b"\x90\x90\x90\x90"
    arm = b"\xc6\x46\xff\x01" + b"\xeb" + bytes([len(zero)])
    jb = bytes([0x72, len(arm)])
    join = b"\x8a\x46\xff" + b"\x30\xe4" + b"\x8b\xf8"
    les = b"\xc4\xbd\x3a\x5e" if les_indexed else b"\x8b\xbd\x3a\x5e"
    mul = (b"\x26" if es_prefix else b"") + b"\xf7\x65\x11"
    tail = b"\x03\xf8" + b"\x83\xc7\x17" + b"\x5d\xc3"
    code = head + jb + arm + zero + join + les + mul + tail
    blob = bytearray(BLOB)
    blob[E:E + len(code)] = code
    return bytes(blob)


def _io_fixture(ah=0x3F):
    """E_IO calls E_IO+0x40, which sets AH and issues INT 21h."""
    blob = bytearray(BLOB)
    blob[E_IO:E_IO + 6] = b"\x55\x89\xe5\xe8\x3a\x00"   # call rel16 -> E_IO+6+0x3A = E_IO+0x40
    blob[E_IO + 6] = 0xC3
    callee = E_IO + 0x40
    blob[callee:callee + 5] = bytes([0xB4, ah, 0xCD, 0x21, 0xC3])
    return bytes(blob)


def _token_fixture(imm=0x380):
    blob = bytearray(BLOB)
    blob[E_TOK:E_TOK + 4] = bytes([0xBF, imm & 0xFF, imm >> 8, 0xC3])
    blob[0x380:0x387] = b"WALLDEF"
    return bytes(blob)


def _stride_fixture(imm=156):
    blob = bytearray(BLOB)
    blob[E_MUL:E_MUL + 8] = bytes([0xBA, imm & 0xFF, imm >> 8, 0xF7, 0xE2, 0xC3, 0x90, 0x90])
    return bytes(blob)


def test_record_fixture_shape_is_classified():
    doc = tp.analyse(_record_fixture(), entry=E)
    assert doc["entry"]["prologue_ok"] is True
    loads = doc["access"]["far_pointer_loads"]
    assert [(x["op"], x["space"], x["base"], x["disp"]) for x in loads] == [("les", "indexed", "di", 0x5E3A)]
    es = doc["access"]["es_scaled_multiplies"]
    assert len(es) == 1 and es[0]["disp"] == 0x11 and es[0]["segment"] == "es"
    assert doc["verdict"]["answer"] == "far-table-record-index-observed; wall-binding-not-established"
    assert doc["verdict"]["wall_binding"] == "not-established"
    assert doc["diagnostics"] == []


def test_uninit_read_is_found_on_the_zero_path_only_when_unwritten():
    doc = tp.analyse(_record_fixture(zero_writes=False), entry=E)
    slot = [u for u in doc["uninit_local_reads"] if u["slot_bp"] == -1]
    assert len(slot) == 1
    join = E + 12 + 2 + 6 + 4   # the join block starts after jb, arm, zero
    assert [r["at"] for r in slot[0]["reads"]] == [join]
    assert slot[0]["reads"][0]["path"][0] == E and slot[0]["reads"][0]["path"][-1] == join
    assert doc["verdict"]["uninit_local_read_sites"] == 1


def test_zero_arm_write_clears_uninit_read():
    doc = tp.analyse(_record_fixture(zero_writes=True), entry=E)
    assert doc["uninit_local_reads"] == []
    assert doc["verdict"]["uninit_local_read_sites"] == 0


def test_es_prefix_is_required_for_es_scaled_multiply():
    doc = tp.analyse(_record_fixture(es_prefix=False), entry=E)
    assert doc["access"]["es_scaled_multiplies"] == []
    assert doc["verdict"]["es_scaled_multiply_sites"] == 0
    assert any(x["op"] == "mul" and x["segment"] == "ds" for x in doc["access"]["indexed_accesses"])


def test_les_is_required_for_far_pointer_load():
    doc = tp.analyse(_record_fixture(les_indexed=False), entry=E)
    assert doc["access"]["far_pointer_loads"] == []
    assert doc["verdict"]["far_table_load_sites"] == 0
    assert doc["verdict"]["answer"] == "no-far-table-record-index-observed"


def test_prologue_mutation_is_a_diagnostic():
    doc = tp.analyse(_record_fixture(prologue=False), entry=E)
    assert doc["entry"]["prologue_ok"] is False
    assert "entry-prologue-absent" in doc["diagnostics"]
    assert doc["verdict"]["answer"] == "entry-prologue-absent"


def test_conditional_placement_is_recorded_not_measured():
    doc = tp.analyse(_record_fixture(), entry=E)
    pl = doc["placement"]
    assert pl["status"] == "conditional-not-measured"
    assert pl["owner_delta_measured"] is False
    assert pl["sibling_delta_assumed"] == 0x1866
    assert pl["stub_start"] == 0x42E3
    assert pl["entry_body_offset"] == tp.BODY_OFFSET == 0x15D
    assert doc["playable"] is False and doc["mappings"] == [] and doc["events_emitted"] == 0


def test_inline_int21_read_is_reported_and_mutation_clears_it():
    doc = tp.analyse(_io_fixture(0x3F), entry=E_IO)
    assert doc["closure"]["procs_explored"] == 2
    assert doc["verdict"]["dos_file_io_inline"] == 1
    assert doc["closure"]["dos_file_function_hits"][0]["function"] == "read"
    gone = tp.analyse(_io_fixture(0x4C), entry=E_IO)
    assert gone["verdict"]["dos_file_io_inline"] == 0


def test_wall_token_reference_is_reported_and_mutation_clears_it():
    doc = tp.analyse(_token_fixture(0x380), entry=E_TOK)
    hits = doc["closure"]["string_token_candidates"]
    assert [h["token"] for h in hits] == ["WALLDEF"]
    assert doc["verdict"]["wall_8x8d_dax_literal_refs"] == 1
    off = tp.analyse(_token_fixture(0x381), entry=E_TOK)
    assert off["verdict"]["wall_8x8d_dax_literal_refs"] == 0


def test_stride_156_constant_is_reported_and_mutation_clears_it():
    doc = tp.analyse(_stride_fixture(156), entry=E_MUL)
    assert doc["verdict"]["stride_constant_156_sites"] == 1
    assert doc["access"]["stride_constant_156_sites"][0]["at"] == E_MUL
    off = tp.analyse(_stride_fixture(157), entry=E_MUL)
    assert off["verdict"]["stride_constant_156_sites"] == 0


def test_analysis_is_deterministic():
    blob = _record_fixture()
    a = json.dumps(tp.analyse(blob, entry=E), sort_keys=True)
    b = json.dumps(tp.analyse(blob, entry=E), sort_keys=True)
    assert a == b


def _install_with_ovr(tmp_path: Path, payload: bytes) -> Path:
    inst = tmp_path / "install"
    inst.mkdir()
    (inst / "GAME.OVR").write_bytes(payload)
    return inst


def test_unpinned_input_is_refused_without_flag(tmp_path):
    inst = _install_with_ovr(tmp_path, b"\x00" * 100)
    out = tmp_path / "out"
    assert tp.main(["--install", str(inst), "-o", str(out)]) == 2
    assert not out.exists()


def test_output_inside_install_is_refused(tmp_path):
    inst = _install_with_ovr(tmp_path, b"\x00" * 100)
    assert tp.main(["--install", str(inst), "-o", str(inst / "sub")]) == 2
    assert not (inst / "sub").exists()


def test_unpinned_probe_with_flag_writes_only_out_and_reports_diagnostics(tmp_path):
    payload = bytes(0x40000)
    inst = _install_with_ovr(tmp_path, payload)
    before = hashlib.sha256((inst / "GAME.OVR").read_bytes()).hexdigest()
    out = tmp_path / "out"
    doc, code = tp.probe(inst, out, allow_unpinned=True)
    assert code == 1
    assert "unpinned-source" in doc["diagnostics"]
    assert "entry-prologue-absent" in doc["diagnostics"]
    assert (out / "por_wall_32392_trace_probe.json").is_file()
    assert hashlib.sha256((inst / "GAME.OVR").read_bytes()).hexdigest() == before
    assert sorted(p.name for p in inst.iterdir()) == ["GAME.OVR"]


@pytest.mark.skipif(not os.environ.get(ENV), reason=f"set {ENV} to the Pool of Radiance install")
def test_retail_pin_and_facts(tmp_path):
    install = Path(os.environ[ENV])
    ovr = next(c for c in (install / "GAME.OVR", install / "POOLRAD" / "GAME.OVR") if c.is_file())
    before = hashlib.sha256(ovr.read_bytes()).hexdigest()
    doc, code = tp.probe(install, tmp_path / "retail")
    assert hashlib.sha256(ovr.read_bytes()).hexdigest() == before == tp.ow.OVR_SHA
    assert doc["source"]["pin"] == "pinned" and doc["source"]["bytes"] == tp.ow.OVR_SIZE
    assert doc["entry"]["bytes"] == "5589e583ec068b46" and doc["entry"]["prologue_ok"] is True
    assert code == 0 and doc["diagnostics"] == []

    cl = doc["closure"]
    assert cl["procs_explored"] == 1 and cl["instructions_decoded"] == 127
    assert cl["near_closure_complete"] is True
    assert [f["at"] for f in cl["far_calls_not_followed"]] == [
        0x323FA, 0x3240C, 0x32411, 0x32416, 0x3241E, 0x3247E, 0x324C0, 0x324D7]

    v = doc["verdict"]
    assert v["answer"] == "far-table-record-index-observed; wall-binding-not-established"
    assert v["far_table_load_sites"] == 2 and v["es_scaled_multiply_sites"] == 1
    assert v["dos_file_io_inline"] == 0 and v["wall_8x8d_dax_literal_refs"] == 0
    assert v["stride_constant_156_sites"] == 0

    es = doc["access"]["es_scaled_multiplies"][0]
    assert es["at"] == 0x324A0 and es["disp"] == 0x11
    direct = {x["address"] for x in doc["access"]["ds_direct_accesses"]}
    assert direct == {0x4A20, 0x4A22, 0x5E4E, 0x5E50}
    idx = {(x["base"], x["disp"]) for x in doc["access"]["indexed_accesses"]}
    assert ("di", 0x5E3A) in idx and ("di", 0x2722) in idx

    reads = [r["at"] for u in doc["uninit_local_reads"] if u["slot_bp"] == -1 for r in u["reads"]]
    assert reads == [0x32423, 0x3243B, 0x32463, 0x32485]
