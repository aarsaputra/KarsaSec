"""Enhanced immutable Finding model for security vulnerabilities."""

from dataclasses import dataclass
from pathlib import Path
from karsasec.core.finding.evidence import Evidence
from karsasec.rules.enums import Confidence, Severity

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
