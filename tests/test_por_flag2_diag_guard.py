"""Guard the test-only passability-2 door diagnostics in boot.c."""
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "src" / "engine" / "boot.c"
TEXT = SOURCE.read_bytes().decode("utf-8")


def function_body(name: str, next_name: str) -> str:
    start = TEXT.index(name)
    end = TEXT.index(next_name, start)
    return TEXT[start:end]


def test_menu_logging_is_compile_time_diagnostic_only():
    body = function_body("static void l45f0_menu(short variant)",
                         "/* jt955's case-4 decision core")
    assert '#ifdef FRUA_DOOR_DIAG\n\tdbg_file_num("DOOR menu pick="' in body
    assert '#ifdef FRUA_DOOR_DIAG\n\tdbg_file_num("DOOR menu allowed="' in body


def test_strength_override_requires_both_test_macros():
    body = function_body("static int play_forward_allowed(void)\n{",
                         "/* L3af2 (CODE 21+0x3af2) — compute")
    gate = "#if defined(FRUA_DOOR_DIAG) && defined(FRUA_DOOR_STR25)"
    start = body.index(gate)
    end = body.index("#endif", start)
    override = body[start:end]
    assert "g_a5_long(-27928)" in override
    assert "[113] = 25" in override
    assert override.index("if (m != 0)") < override.index("[113] = 25")


def test_door_logs_read_the_selected_and_stored_edge_without_writing_it():
    body = function_body("static int play_forward_allowed(void)\n{",
                         "/* L3af2 (CODE 21+0x3af2) — compute")
    blocks = []
    pos = 0
    while True:
        try:
            start = body.index("#ifdef FRUA_DOOR_DIAG", pos)
        except ValueError:
            break
        end = body.index("#endif", start)
        blocks.append(body[start:end])
        pos = end + len("#endif")
    diagnostics = "\n".join(blocks)
    assert 'dbg_file_num("DOOR forward edge="' in diagnostics
    assert 'dbg_file_num("DOOR forward allowed="' in diagnostics
    assert 'dbg_file_num("DOOR stored edge 14,10 W="' in diagnostics
    # The diagnostic marker only surrounds logging and the optional STR write;
    # there is no door-byte assignment or call to the state-writing helper.
    assert "jt210((short)14, (short)10, (short)6)" in body
    assert "l493a(" not in body
