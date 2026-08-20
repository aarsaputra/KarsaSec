"""Unified Analysis Context representing the immutable state of a project audit."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """Dataclass representing a security finding."""

    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cwe_id: str
    file_path: str
    line_number: int
    evidence: str
    description: str
    recommendation: str
    confidence_score: float = 0.9


@dataclass(slots=True)
class ProjectCapabilities:
    """Capabilities supported for a target project by KarsaSec engines."""

    supports_ast: bool = True
    supports_cpg: bool = True
    supports_semgrep: bool = False
    supports_ai_fix: bool = True


@dataclass(slots=True)
class FrameworkMatch:
    """Detail of framework detection with confidence scoring."""

    name: str
    score: int
    confidence: str  # CONFIDENT, LIKELY, POSSIBLE


@dataclass(slots=True)
class ProjectProfile:
    """Centralized technical profile of the target project."""

    root: Path
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    framework_matches: list[FrameworkMatch] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    manifests: list[Path] = field(default_factory=list)
    source_files: list[Path] = field(default_factory=list)
    ignored_files: list[Path] = field(default_factory=list)
    total_files: int = 0
    total_loc: int = 0
    capabilities: ProjectCapabilities = field(default_factory=ProjectCapabilities)

    @property
    def root_path(self) -> Path:
        """Backward compatibility alias for root path."""
        return self.root

    @property
    def detected_languages(self) -> list[str]:
        """Backward compatibility alias for detected languages."""
        return self.languages

    @property
    def detected_frameworks(self) -> list[str]:
        """Backward compatibility alias for detected frameworks."""
        return self.frameworks

    @property
    def manifest_files(self) -> list[str]:
        """Backward compatibility alias for manifest files."""
        return [str(m) for m in self.manifests]


@dataclass
class AnalysisContext:
    """Unified context object shared across execution stages."""

    scan_id: str
    target_path: Path
    profile: ProjectProfile = field(default_factory=lambda: ProjectProfile(root=Path(".")))
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
