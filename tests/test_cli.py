"""Unit tests for KarsaSec CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from karsasec import __version__
from karsasec.cli import app
from karsasec.cli.commands.scan import execute_scan_command

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


def test_cli_scan_dockerfile(tmp_path: Path) -> None:
    """Test karsasec scan command on a Dockerfile target."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:latest\nCMD [\"echo\", \"hello\"]\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(dockerfile), "--format", "json"])
    assert result.exit_code in (0, 1)

    report = json.loads(result.stdout)
    assert report["metadata"]["files_scanned"] == 1
    assert isinstance(report["summary"]["total_findings"], int)
    assert report["errors"] == []


def test_cli_scan_with_rag(tmp_path: Path) -> None:
    """Test karsasec scan command with the RAG retrieval option."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text("print(\"hello\")\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(sample_file),
            "--format",
            "json",
            "--rag",
            "--rag-query",
            "ssrf",
        ],
    )
    assert result.exit_code in (0, 1)

    report = json.loads(result.stdout)
    assert "rag_context" in report
    assert isinstance(report["rag_context"], list)
    assert all(
        set(item) >= {"document_id", "score", "source_path", "text"}
        for item in report["rag_context"]
    )


def test_cli_scan_with_rag_corpus_path(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("print(\"hello\")\n", encoding="utf-8")
    corpus_dir = tmp_path / "public_corpus"
    corpus_dir.mkdir()
    (corpus_dir / "README.md").write_text("server-side request forgery example\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(sample_file),
            "--format",
            "json",
            "--rag",
            "--rag-corpus",
            str(corpus_dir),
            "--rag-query",
            "ssrf",
        ],
    )
    assert result.exit_code in (0, 1)

    report = json.loads(result.stdout)
    assert "rag_context" in report
    assert isinstance(report["rag_context"], list)


def test_cli_scan_with_context_search_alias(tmp_path: Path) -> None:
    """Test karsasec scan command using the context-search alias and rebuild flag."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text("print(\"hello\")\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(sample_file),
            "--format",
            "json",
            "--context-search",
            "--rag-query",
            "ssrf",
            "--rag-rebuild",
        ],
    )
    assert result.exit_code in (0, 1)

    report = json.loads(result.stdout)
    assert "rag_context" in report
    assert isinstance(report["rag_context"], list)
    assert all(
        set(item) >= {"document_id", "score", "source_path", "text"}
        for item in report["rag_context"]
    )


def test_scan_respects_gitignore_and_generated_file_exclusion(tmp_path: Path, capsys) -> None:
    """Scan should skip paths ignored by .gitignore and generated files by default."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / ".gitignore").write_text("vendor/\nnode_modules/\n*.generated.py\n", encoding="utf-8")

    (repo_root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (repo_root / "vendor").mkdir()
    (repo_root / "vendor" / "secret.py").write_text("print('skip')\n", encoding="utf-8")
    (repo_root / "node_modules").mkdir()
    (repo_root / "node_modules" / "pkg.js").write_text("console.log('skip')\n", encoding="utf-8")
    (repo_root / "generated.generated.py").write_text("print('skip')\n", encoding="utf-8")

    exit_code = execute_scan_command(repo_root, format_type="json", no_color=True)
    captured = capsys.readouterr()

    assert exit_code in (0, 1)
    assert "\"files_scanned\": 1" in captured.out


def test_cli_config() -> None:
    """Test karsasec config command output."""
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "default_llm_provider" in result.stdout


def test_scan_respects_yaml_exclude_config(tmp_path: Path, capsys) -> None:
    """Scan should honor exclude rules from a YAML config file."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "karsasec.yaml").write_text(
        "scan:\n  exclude:\n    - vendor\n",
        encoding="utf-8",
    )
    (repo_root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (repo_root / "vendor").mkdir()
    (repo_root / "vendor" / "secret.py").write_text("print('skip')\n", encoding="utf-8")

    exit_code = execute_scan_command(repo_root, format_type="json", no_color=True)
    captured = capsys.readouterr()

    assert exit_code in (0, 1)
    assert '"files_scanned": 1' in captured.out


def test_cli_init_creates_config_file(tmp_path: Path) -> None:
    """Test karsasec init command writes a default configuration file."""
    config_path = tmp_path / "karsasec.yaml"
    result = runner.invoke(app, ["init", str(config_path)])
    assert result.exit_code == 0
    assert config_path.exists()
    assert "scan:" in config_path.read_text(encoding="utf-8")


def test_cli_review() -> None:
    """Test karsasec review command."""
    result = runner.invoke(app, ["review", "."])
    assert result.exit_code == 0
    assert "KarsaSec 4-Agent Security Review" in result.stdout
