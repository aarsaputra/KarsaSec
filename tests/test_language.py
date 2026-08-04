"""Unit tests for LanguageDetector."""

from pathlib import Path
from karsasec.parser.language import LanguageDetector

def test_language_detector_by_extension() -> None:
    detector = LanguageDetector()
    files = [
        Path("main.py"),
        Path("app.js"),
        Path("index.ts"),
        Path("server.go"),
        Path("lib.rs"),
        Path("index.php"),
    ]
    languages = detector.detect(files)
    assert "Python" in languages
    assert "JavaScript" in languages
    assert "TypeScript" in languages
    assert "Go" in languages
    assert "Rust" in languages
    assert "PHP" in languages

def test_language_detector_by_manifest() -> None:
    detector = LanguageDetector()
    files = [Path("pyproject.toml"), Path("composer.json"), Path("go.mod")]
    languages = detector.detect(files)
    assert "Python" in languages
    assert "PHP" in languages
    assert "Go" in languages
