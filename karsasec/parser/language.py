"""Language Detector module for identifying programming languages by file extensions and manifests."""

from pathlib import Path

EXTENSION_MAP: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".php": "PHP",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".cs": "C#",
    ".html": "HTML",
    ".htm": "HTML",
    ".rb": "Ruby",
}

MANIFEST_LANGUAGE_MAP: dict[str, str] = {
    "package.json": "JavaScript/TypeScript",
    "composer.json": "PHP",
    "requirements.txt": "Python",
    "pyproject.toml": "Python",
    "pipfile": "Python",
    "setup.py": "Python",
    "go.mod": "Go",
    "cargo.toml": "Rust",
    "pom.xml": "Java",
    "build.gradle": "Java",
}


class LanguageDetector:
    """Detects programming languages present in a given list of project paths."""

    def __init__(self, extension_map: dict[str, str] = EXTENSION_MAP) -> None:
        self.extension_map = extension_map

    def detect(self, files: list[Path]) -> list[str]:
        """Scans relative file paths and returns a sorted list of detected unique language names."""
        languages: set[str] = set()

        for path in files:
            ext = path.suffix.lower()
            filename = path.name.lower()

            if ext in self.extension_map:
                languages.add(self.extension_map[ext])
            elif filename in MANIFEST_LANGUAGE_MAP:
                languages.add(MANIFEST_LANGUAGE_MAP[filename])

        return sorted(list(languages))
