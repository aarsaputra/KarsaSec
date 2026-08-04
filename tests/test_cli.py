"""Unit tests for KarsaSec CLI commands."""

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

def test_cli_scan() -> None:
    """Test karsasec scan command."""
    result = runner.invoke(app, ["scan", "."])
    assert result.exit_code == 0
    assert "KarsaSec Deterministic Scan" in result.stdout

def test_cli_review() -> None:
    """Test karsasec review command."""
    result = runner.invoke(app, ["review", "."])
    assert result.exit_code == 0
    assert "KarsaSec 4-Agent Security Review" in result.stdout
