import pytest

from tizenpwn import cli


def test_preflight_parser_accepts_a_host() -> None:
    arguments = cli.build_parser().parse_args(
        ["preflight", "192.0.2.50"]
    )

    assert arguments.host == "192.0.2.50"
    assert arguments.sdb_timeout == 30.0


def test_probe_parser_requires_both_live_gates() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["cifs", "probe", "192.0.2.50"]
        )

    arguments = cli.build_parser().parse_args(
        [
            "cifs",
            "probe",
            "192.0.2.50",
            "--confirm",
            "TU7000-T-KTSU2AKUC-2743.0",
            "--accept-saved-profile",
        ]
    )

    assert arguments.confirm == "TU7000-T-KTSU2AKUC-2743.0"
    assert arguments.accept_saved_profile is True


def test_command_parser_requires_a_shell_command() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            [
                "cifs",
                "command",
                "192.0.2.50",
                "--confirm",
                "TU7000-T-KTSU2AKUC-2743.0",
                "--accept-saved-profile",
            ]
        )

    arguments = cli.build_parser().parse_args(
        [
            "cifs",
            "command",
            "192.0.2.50",
            "--confirm",
            "TU7000-T-KTSU2AKUC-2743.0",
            "--accept-saved-profile",
            "--command",
            "id",
            "--command",
            "uname -a",
        ]
    )

    assert arguments.command == ["id", "uname -a"]
    assert arguments.agent_timeout == 30.0


def test_global_output_option_is_accepted_before_the_subcommand() -> None:
    arguments = cli.build_parser().parse_args(
        ["-o", "json", "preflight", "192.0.2.50"]
    )

    assert arguments.output == "json"


def test_human_render_handles_nested_evidence() -> None:
    lines = cli.render_human(
        {
            "authenticated": True,
            "commands": [
                {"command": "id", "exit_code": 0},
            ],
        }
    )

    assert "authenticated: true" in lines
    assert "commands:" in lines
    assert any("command: id" in line for line in lines)
