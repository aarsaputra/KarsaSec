"""Unit tests for Project Detector module and multi-stage profiling pipeline."""

from pathlib import Path

from karsasec.parser.detector import detect_project


def test_detect_current_project(tmp_path: Path) -> None:
    """Test project detector on a mock python workspace."""
    (tmp_path / "app.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("django>=4.0\nfastapi", encoding="utf-8")

    profile = detect_project(tmp_path)
    assert "Python" in profile.languages
    assert "Django" in profile.frameworks
    assert "FastAPI" in profile.frameworks
    assert any(m.name == "requirements.txt" for m in profile.manifests)
    assert profile.total_files == 2
    assert profile.total_loc > 0
    assert profile.capabilities.supports_ast is True
    assert profile.capabilities.supports_cpg is True


def test_detect_js_project(tmp_path: Path) -> None:
    """Test detector on JS/Express project."""
    (tmp_path / "server.js").write_text("console.log('test');", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.2"}}', encoding="utf-8")

    profile = detect_project(tmp_path)
    assert "JavaScript" in profile.languages
    assert "Express" in profile.frameworks
    assert any(m.name == "package.json" for m in profile.manifests)
