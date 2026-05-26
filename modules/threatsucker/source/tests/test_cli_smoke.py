from typer.testing import CliRunner

from ngo_intel.cli import app


def test_cli_run_command_completes() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["run"])
    assert result.exit_code == 0, result.output
    assert "Pipeline complete" in result.output
