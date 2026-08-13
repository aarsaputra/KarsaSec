"""Read-only artifact interface for consuming SAST scan findings and verdicts (E13-1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karsasec.core.finding.model import Finding, QualifiedFinding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict
from karsasec.runtime.artifact_store import ArtifactStore


@dataclass(frozen=True)
class ScanArtifactContainer:
    """Immutable container wrapping a completed scan session's artifacts."""

    scan_id: str
    target_path: Path
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    verdicts: tuple[SecurityVerdict, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


class SecurityArtifactReader:
    """Read-only interface for retrieving findings, verdicts, and evidence context from SAST scans."""

    def __init__(self, store: ArtifactStore | None = None, container: ScanArtifactContainer | None = None) -> None:
        self._store = store
        self._container = container
        self._findings_by_id: dict[str, Finding] = {}
        self._verdicts_by_finding_id: dict[str, SecurityVerdict] = {}

        if container is not None:
            for finding in container.findings:
                self._findings_by_id[finding.finding_id] = finding
                if finding.verdict is not None and isinstance(finding.verdict, SecurityVerdict):
                    self._verdicts_by_finding_id[finding.finding_id] = finding.verdict

            for verdict in container.verdicts:
                # Associate verdict by verdict_id or sink_id if applicable
                self._verdicts_by_finding_id[verdict.verdict_id] = verdict

    @classmethod
    def from_findings(cls, findings: list[Finding], scan_id: str = "scan_default") -> SecurityArtifactReader:
        """Constructs a reader directly from a list of Finding objects."""
        container = ScanArtifactContainer(
            scan_id=scan_id,
            target_path=Path("."),
            findings=tuple(findings),
        )
        return cls(container=container)

    def get_findings(self) -> list[Finding]:
        """Returns all findings from the loaded scan session."""
        return list(self._findings_by_id.values())

    def get_finding(self, finding_id: str) -> Finding | None:
        """Retrieves a single finding by finding_id."""
        return self._findings_by_id.get(finding_id)

    def get_verdict(self, finding_id: str) -> SecurityVerdict | None:
        """Retrieves the SecurityVerdict bound to a finding."""
        finding = self.get_finding(finding_id)
        if finding is not None and finding.verdict is not None and isinstance(finding.verdict, SecurityVerdict):
            return finding.verdict
        return self._verdicts_by_finding_id.get(finding_id)

    def get_evidence(self, finding_id: str) -> Any | None:
        """Retrieves raw or enriched evidence associated with a finding."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return None
        if isinstance(finding, QualifiedFinding) and finding.enriched_evidence is not None:
            return finding.enriched_evidence
        return finding.evidence

    def get_provenance(self, finding_id: str) -> tuple[str, ...]:
        """Retrieves the ordered provenance path strings for a finding."""
        verdict = self.get_verdict(finding_id)
        if verdict is not None and verdict.provenance_path:
            return verdict.provenance_path
        finding = self.get_finding(finding_id)
        if finding is not None and hasattr(finding.evidence, "provenance_path") and finding.evidence.provenance_path:
            return tuple(finding.evidence.provenance_path)
        return ()

    def get_source_snippet(self, finding_id: str) -> str:
        """Retrieves the source snippet for a finding, falling back to read-only file access if needed."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return "UNKNOWN"
        if finding.evidence and hasattr(finding.evidence, "snippet") and finding.evidence.snippet:
            return finding.evidence.snippet.strip()

        # Safe read-only file snippet extraction fallback
        if finding.file_path and finding.file_path.exists() and finding.file_path.is_file():
            try:
                lines = finding.file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                target_line = finding.evidence.line if finding.evidence else 1
                if 1 <= target_line <= len(lines):
                    return lines[target_line - 1].strip()
            except Exception:
                pass
        return "UNKNOWN"
