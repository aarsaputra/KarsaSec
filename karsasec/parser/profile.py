"""Project Profiler module for aggregating workspace metadata, LOC, package managers, and capabilities."""

from pathlib import Path
from typing import List, Set, Tuple
from karsasec.core.context import ProjectCapabilities, ProjectProfile
from karsasec.parser.framework import FrameworkDetector
from karsasec.parser.language import LanguageDetector, MANIFEST_LANGUAGE_MAP

# Directory names to skip when profiling
SKIP_DIRS: Set[str] = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
    "dist", "build", "__pycache__", ".pytest_cache", ".next", "vendor"
}

# Package manager lockfile markers
PACKAGE_MANAGER_MARKERS = {
    "uv.lock": "uv",
    "poetry.lock": "Poetry",
    "Pipfile.lock": "Pipenv",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "composer.lock": "composer",
    "Cargo.lock": "Cargo",
    "go.sum": "go",
}

class ProjectProfiler:
    """Aggregates workspace files, counts LOC, detects package managers, and builds ProjectProfile."""

    def __init__(
        self,
        language_detector: LanguageDetector = LanguageDetector(),
        framework_detector: FrameworkDetector = FrameworkDetector()
    ) -> None:
        self.language_detector = language_detector
        self.framework_detector = framework_detector

    def profile(self, root_path: Path) -> ProjectProfile:
        """Executes full workspace profiling on target root_path."""
        resolved_root = root_path.resolve()

        if not resolved_root.exists():
            return ProjectProfile(root=resolved_root)

        source_files: List[Path] = []
        ignored_files: List[Path] = []
        manifests: List[Path] = []
        package_managers: Set[str] = set()

        total_files = 0
        total_loc = 0

        # Scan workspace tree
        if resolved_root.is_file():
            source_files.append(resolved_root.relative_to(resolved_root.parent))
            total_files = 1
            total_loc += self._count_loc(resolved_root)
            scan_root = resolved_root.parent
        else:
            scan_root = resolved_root
            for path in scan_root.rglob("*"):
                rel_path = path.relative_to(scan_root)
                parts = rel_path.parts

                # Check for skipped directories
                if any(p.startswith(".") or p in SKIP_DIRS for p in parts[:-1]):
                    ignored_files.append(rel_path)
                    continue

                if path.is_file():
                    total_files += 1
                    filename_lower = path.name.lower()

                    if any(p.startswith(".") or p in SKIP_DIRS for p in parts):
                        ignored_files.append(rel_path)
                        continue

                    source_files.append(rel_path)

                    # Manifest detection
                    if filename_lower in MANIFEST_LANGUAGE_MAP:
                        manifests.append(rel_path)

                    # Package manager detection
                    if filename_lower in PACKAGE_MANAGER_MARKERS:
                        package_managers.add(PACKAGE_MANAGER_MARKERS[filename_lower])

                    # Calculate LOC for text files
                    total_loc += self._count_loc(path)

        languages = self.language_detector.detect(source_files)
        frameworks, matches = self.framework_detector.detect(scan_root, source_files)

        # Build ProjectCapabilities
        capabilities = ProjectCapabilities(
            supports_ast=True,
            supports_cpg=True,
            supports_semgrep=False,
            supports_ai_fix=True,
        )

        return ProjectProfile(
            root=scan_root,
            languages=languages,
            frameworks=frameworks,
            framework_matches=matches,
            package_managers=sorted(list(package_managers)),
            manifests=manifests,
            source_files=source_files,
            ignored_files=ignored_files,
            total_files=total_files,
            total_loc=total_loc,
            capabilities=capabilities,
        )

    def _count_loc(self, file_path: Path) -> int:
        """Counts non-empty lines of code in a file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return sum(1 for line in content.splitlines() if line.strip())
        except Exception:
            return 0
