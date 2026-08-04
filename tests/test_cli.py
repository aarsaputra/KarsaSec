"""Unit tests for KarsaSec CLI commands."""

from pathlib import Path
from typer.testing import CliRunner
from karsasec import __version__
from karsasec.cli import app

runner = CliRunner()

def test_cli_version() -> None:
    """Test karsasec --version output."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout

def test_cli_doctor() -> None:
    """Test karsasec doctor health check command."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "KarsaSec Environment Health Check" in result.stdout
    assert "CLI Version" in result.stdout

def test_cli_scan(tmp_path: Path) -> None:
    """Test karsasec scan command on sample file."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text("eval(user_input)\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(sample_file), "--format", "console", "--no-color"])
    assert result.exit_code in (0, 1)
    assert "KARSASEC SECURITY SCAN REPORT" in result.stdout

def test_cli_review() -> None:
    """Test karsasec review command."""
    result = runner.invoke(app, ["review", "."])
    assert result.exit_code == 0
    assert "KarsaSec 4-Agent Security Review" in result.stdout
