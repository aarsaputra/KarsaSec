"""Integration tests for FrameworkPass, PassManager, ArtifactStore, and CLI framework commands."""

from pathlib import Path

from typer.testing import CliRunner

from karsasec.analysis.framework import FrameworkPass
from karsasec.cli.main import app
from karsasec.runtime.artifact_store import ArtifactStore
from karsasec.runtime.pass_manager import PassManager

runner = CliRunner()


def test_framework_pass_execution():
    store = ArtifactStore()
    pm = PassManager()

    f_pass = FrameworkPass(target_path=Path("security_corpus/python/flask_django/vulnerable"))
    pm.register_pass(f_pass)

    res = pm.run_passes(store)
    assert res.get("FrameworkPass") is True

    assert store.has("framework_graph")
    assert store.has("framework_registry")
    assert store.has("framework_metadata")

    graph = store.get("framework_graph")
    metadata = store.get("framework_metadata")

    assert graph is not None
    assert metadata is not None
    assert len(metadata.detected_frameworks) > 0


def test_cli_framework_detect():
    result = runner.invoke(app, ["framework", "detect", "security_corpus/python/flask_django/vulnerable"])
    assert result.exit_code == 0
    assert "Framework Detection Results" in result.output or "No framework" in result.output


def test_cli_framework_stats():
    result = runner.invoke(app, ["framework", "stats", "security_corpus/python/flask_django/vulnerable"])
    assert result.exit_code == 0
    assert "Framework Statistics" in result.output


def test_cli_framework_export():
    result = runner.invoke(app, ["framework", "export", "security_corpus/python/flask_django/vulnerable", "--format", "json"])
    assert result.exit_code == 0
    assert '"graph"' in result.output


def test_cli_framework_visualize():
    result = runner.invoke(app, ["framework", "visualize", "security_corpus/python/flask_django/vulnerable"])
    assert result.exit_code == 0
    assert "Mermaid" in result.output
