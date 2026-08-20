from __future__ import annotations

from typer.testing import CliRunner

from karsasec.cli.main import app

runner = CliRunner()


def test_rules_validate_cli() -> None:
    result = runner.invoke(app, ["rules", "validate"])
    assert result.exit_code == 0
    assert "All security rules passed validation checks" in result.output


def test_rules_lint_cli() -> None:
    result = runner.invoke(app, ["rules", "lint"])
    assert result.exit_code == 0
    assert "No lint issues detected" in result.output


def test_rules_coverage_cli() -> None:
    result = runner.invoke(app, ["rules", "coverage"])
    assert result.exit_code == 0
    assert "KarsaSec Rule Coverage Matrix" in result.output


def test_rules_docs_cli(tmp_path) -> None:
    doc_dir = tmp_path / "rules_doc_test"
    result = runner.invoke(app, ["rules", "docs", "--output-dir", str(doc_dir)])
    assert result.exit_code == 0
    assert "Successfully generated" in result.output
    assert (doc_dir / "KS-PY-0001.md").exists()
