"""Enhanced immutable Finding model for security vulnerabilities with stable fingerprint identity."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from karsasec.core.finding.evidence import Evidence
from karsasec.rules.enums import Confidence, Severity


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
