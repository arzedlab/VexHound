import pytest

from vexhound import __version__, banner
from vexhound.cli import build_parser, main


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_help_lists_all_commands(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for cmd in ("hunt", "scan", "classify", "confirm", "emulate", "hunt-llm"):
        assert cmd in out


def test_bare_invocation_shows_banner_and_help(capsys):
    assert main([]) == 0
    assert "VexHound" in capsys.readouterr().out


def test_parser_accepts_each_subcommand():
    parser = build_parser()
    for argv in (["hunt", "a.bin"], ["scan", "a.bin"], ["classify", "a.bin"],
                 ["confirm", "a.bin"], ["emulate", "a.bin"]):
        assert parser.parse_args(argv).command == argv[0]


def test_banner_has_no_escape_codes_when_disabled():
    banner.set_enabled(False)
    assert "\x1b[" not in banner.render("9.9.9")


def test_banner_colors_when_enabled():
    banner.set_enabled(True)
    try:
        assert "\x1b[" in banner.render("9.9.9")
    finally:
        banner.set_enabled(False)
