"""Unit tests for FrameworkDetector confidence scoring."""

from pathlib import Path
from karsasec.parser.framework import FrameworkDetector

def test_framework_nextjs_confidence(tmp_path: Path) -> None:
    detector = FrameworkDetector()
    (tmp_path / "next.config.js").write_text("module.exports = {};", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies": {"next": "14.0.0"}}', encoding="utf-8")

    files = [Path("next.config.js"), Path("package.json")]
    confident_frameworks, matches = detector.detect(tmp_path, files)

    assert "Next.js" in confident_frameworks
    next_match = next(m for m in matches if m.name == "Next.js")
    assert next_match.confidence == "CONFIDENT"
    assert next_match.score >= 70

def test_framework_laravel_artisan(tmp_path: Path) -> None:
    detector = FrameworkDetector()
    (tmp_path / "artisan").write_text("#!/usr/bin/env php", encoding="utf-8")
    (tmp_path / "composer.json").write_text('{"require": {"laravel/framework": "^10.0"}}', encoding="utf-8")

    files = [Path("artisan"), Path("composer.json")]
    confident_frameworks, matches = detector.detect(tmp_path, files)

    assert "Laravel" in confident_frameworks
    laravel_match = next(m for m in matches if m.name == "Laravel")
    assert laravel_match.confidence == "CONFIDENT"
    assert laravel_match.score >= 70

def test_framework_fastapi_requirements(tmp_path: Path) -> None:
    detector = FrameworkDetector()
    (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('hello')", encoding="utf-8")

    files = [Path("requirements.txt"), Path("main.py")]
    confident_frameworks, matches = detector.detect(tmp_path, files)

    assert "FastAPI" in confident_frameworks
    fastapi_match = next(m for m in matches if m.name == "FastAPI")
    assert fastapi_match.score >= 70
