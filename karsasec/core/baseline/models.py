"""BaselineFinding, Baseline, and ComparisonResult models for vulnerability lifecycle management."""

from dataclasses import dataclass, field

from karsasec.core.finding.model import Finding


@dataclass(frozen=True)
class BaselineFinding:
    """Immutable baseline entry tracking a finding across scan sessions."""
    fingerprint: str
    rule_id: str
    severity: str
    file_path: str
    created_at: str

@dataclass(frozen=True)
class Baseline:
    """Immutable baseline container storing previously acknowledged vulnerability fingerprints."""
    findings: dict[str, BaselineFinding] = field(default_factory=dict)
    created_at: str = ""
    scanner_version: str = "0.1.0"

@dataclass(frozen=True)
class ComparisonResult:
    """Immutable comparison diff categorizing findings as NEW, EXISTING, FIXED, or REGRESSED."""
    new_findings: tuple[Finding, ...] = field(default_factory=tuple)
    existing_findings: tuple[Finding, ...] = field(default_factory=tuple)
    fixed_findings: tuple[BaselineFinding, ...] = field(default_factory=tuple)
    regressed_findings: tuple[Finding, ...] = field(default_factory=tuple)
