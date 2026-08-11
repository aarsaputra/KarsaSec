"""Enhanced immutable Finding & QualifiedFinding models for security vulnerabilities (E12-3)."""

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from karsasec.core.finding.evidence import Evidence, FindingEvidence
from karsasec.rules.enums import Confidence, Severity


class QualificationState(StrEnum):
    """Deterministic state of a finding after qualification."""
    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    UNRESOLVED = "UNRESOLVED"
    REJECTED = "REJECTED"


def compute_stable_finding_fingerprint(
    rule_id: str,
    file_path: Path,
    snippet: str,
    line: int,
    cwe_id: str = "CWE-20",
) -> str:
    """Computes a deterministic, stable SHA-256 fingerprint for finding deduplication and diff tracking."""
    normalized_path = str(file_path).replace("\\", "/").lower()
    raw = f"{rule_id}|{normalized_path}|{line}|{snippet.strip()}|{cwe_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class Finding:
    """Immutable finding data structure representing a detected security vulnerability."""

    finding_id: str
    rule_id: str
    fingerprint: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe_id: str
    owasp: str
    file_path: Path
    evidence: Evidence
    description: str
    remediation: str
    rule_version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class QualifiedFinding(Finding):
    """Enriched finding with qualification decision state, evidence trail, and FP taxonomy reason."""

    qualification_state: QualificationState = QualificationState.CONFIRMED
    rejection_reason: Any | None = None
    enriched_evidence: FindingEvidence | None = None
