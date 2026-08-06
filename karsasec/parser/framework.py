"""Framework Detector module implementing multi-indicator confidence scoring for framework discovery."""

import json
from pathlib import Path

from karsasec.core.context import FrameworkMatch


class FrameworkDetector:
    """Scored framework detector evaluating manifest dependencies and distinct file markers."""

    def detect(self, root_path: Path, files: list[Path]) -> tuple[list[str], list[FrameworkMatch]]:
        """Scans project files and calculates confidence scores for framework candidates.

        Returns:
            Tuple of (list of framework names with CONFIDENT or LIKELY status, list of all FrameworkMatch DTOs).
        """
        scores: dict[str, int] = {}
        file_set: set[str] = {p.as_posix().lower() for p in files}
        filename_set: set[str] = {p.name.lower() for p in files}

        # 1. Distinct file markers
        if "artisan" in filename_set:
            scores["Laravel"] = scores.get("Laravel", 0) + 50
        if any(f.startswith("next.config.") for f in filename_set):
            scores["Next.js"] = scores.get("Next.js", 0) + 50
        if "angular.json" in filename_set:
            scores["Angular"] = scores.get("Angular", 0) + 50
        if any(f.startswith("nuxt.config.") for f in filename_set):
            scores["Nuxt.js"] = scores.get("Nuxt.js", 0) + 50
        if any(f.startswith("vite.config.") for f in filename_set):
            scores["Vite"] = scores.get("Vite", 0) + 30

        # 2. Manifest content inspection
        for path in files:
            full_path = root_path / path
            filename = path.name.lower()

            if filename == "package.json":
                self._inspect_package_json(full_path, scores)
            elif filename == "composer.json":
                self._inspect_composer_json(full_path, scores)
            elif filename in ("requirements.txt", "pyproject.toml", "pipfile"):
                self._inspect_python_manifest(full_path, filename, scores)
            elif filename == "go.mod":
                self._inspect_go_mod(full_path, scores)

        # 3. Entry point indicators
        if "main.go" in filename_set or "cmd" in file_set:
            if "Gin" in scores:
                scores["Gin"] += 10
            if "Go Fiber" in scores:
                scores["Go Fiber"] += 10
        if "main.py" in filename_set or "app.py" in filename_set:
            if "FastAPI" in scores:
                scores["FastAPI"] += 10
            if "Flask" in scores:
                scores["Flask"] += 10

        matches: list[FrameworkMatch] = []
        confident_frameworks: list[str] = []

        for name, score in sorted(scores.items(), key=lambda item: item[1], reverse=True):
            if score >= 70:
                confidence = "CONFIDENT"
                confident_frameworks.append(name)
            elif score >= 40:
                confidence = "LIKELY"
                confident_frameworks.append(name)
            else:
                confidence = "POSSIBLE"

            matches.append(FrameworkMatch(name=name, score=score, confidence=confidence))

        return sorted(confident_frameworks), matches

    def _inspect_package_json(self, file_path: Path, scores: dict[str, int]) -> None:
        """Inspects npm dependencies in package.json."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            scores["JavaScript/Node.js"] = scores.get("JavaScript/Node.js", 0) + 20
            if "next" in deps:
                scores["Next.js"] = scores.get("Next.js", 0) + 40
            if "express" in deps:
                scores["Express"] = scores.get("Express", 0) + 50
            if "react" in deps:
                scores["React"] = scores.get("React", 0) + 40
            if "vue" in deps:
                scores["Vue.js"] = scores.get("Vue.js", 0) + 40
            if "nest" in deps or "@nestjs/core" in deps:
                scores["NestJS"] = scores.get("NestJS", 0) + 50
        except Exception:
            pass

    def _inspect_composer_json(self, file_path: Path, scores: dict[str, int]) -> None:
        """Inspects PHP composer dependencies."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            if "laravel/framework" in content:
                scores["Laravel"] = scores.get("Laravel", 0) + 40
            if "symfony/symfony" in content or "symfony/framework-bundle" in content:
                scores["Symfony"] = scores.get("Symfony", 0) + 50
        except Exception:
            pass

    def _inspect_python_manifest(self, file_path: Path, filename: str, scores: dict[str, int]) -> None:
        """Inspects Python dependencies."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            if "django" in content:
                scores["Django"] = scores.get("Django", 0) + 50
            if "fastapi" in content:
                scores["FastAPI"] = scores.get("FastAPI", 0) + 50
            if "flask" in content:
                scores["Flask"] = scores.get("Flask", 0) + 50
            if "uvicorn" in content:
                if "FastAPI" in scores:
                    scores["FastAPI"] += 20
        except Exception:
            pass

    def _inspect_go_mod(self, file_path: Path, scores: dict[str, int]) -> None:
        """Inspects Go modules in go.mod."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            if "github.com/gofiber/fiber" in content:
                scores["Go Fiber"] = scores.get("Go Fiber", 0) + 50
            if "github.com/gin-gonic/gin" in content:
                scores["Gin"] = scores.get("Gin", 0) + 50
        except Exception:
            pass
