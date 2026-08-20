"""Immutable Finding DTO representation for security findings."""

from dataclasses import dataclass
from pathlib import Path

from karsasec.rules.enums import Confidence, Severity


@dataclass(frozen=True)
class Finding:
    """Immutable finding data structure representing a detected security vulnerability."""

    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe_id: str
    owasp: str
    file_path: Path
    line: int
    column: int
    node_id: str
    rule_version: str
    parser_version: str
    evidence: str
    description: str
    remediation: str
