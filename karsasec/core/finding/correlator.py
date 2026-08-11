"""FindingCorrelator: deduplicates and correlates findings from multiple rules detecting vulnerabilities (E12-4).

Supports 4 correlation cases:
- Case A (Exact Duplicate): Same file, line, rule_id -> collapse duplicate.
- Case B (Semantic Duplicate): Same file, line, sink category, equivalent taint path -> merge into primary finding, preserving contributing rules.
- Case C (Different Vulnerabilities): Different sink category or materially different taint path -> preserve as independent findings.
- Case D (Conflicting Evidence): Contradictory evidence (e.g. TAINTED vs SANITIZED) -> transition to UNRESOLVED with EvidenceConflict attached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from karsasec.core.finding.conflict import EvidenceConflict, detect_evidence_conflict
from karsasec.core.finding.model import (
    CanonicalFindingIdentity,
    Finding,
    QualificationState,
    QualifiedFinding,
)

# Severity weights for canonical selection (keep highest severity when merging)
_SEVERITY_WEIGHT: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

_CONFIDENCE_WEIGHT: dict[str, int] = {
    "CONFIDENT": 3,
    "LIKELY": 2,
    "POSSIBLE": 1,
}


def _severity_weight(f: Finding) -> int:
    return _SEVERITY_WEIGHT.get(str(f.severity).upper(), 0)


def _confidence_weight(f: Finding) -> int:
    return _CONFIDENCE_WEIGHT.get(str(f.confidence).upper(), 0)


@dataclass(frozen=True)
class CanonicalFinding:
    """A deduplicated, correlated finding representing one semantic vulnerability (E12-4)."""

    primary: Finding
    correlated_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    semantic_fingerprint: str = ""
    exact_fingerprint: str = ""
    evidence_conflict: EvidenceConflict | None = None

    @property
    def rule_id(self) -> str:
        return self.primary.rule_id

    @property
    def file_path(self) -> Path:
        return self.primary.file_path


class FindingCorrelator:
    """Stateless correlator that deduplicates findings and manages evidence conflicts (E12-4)."""

    def __init__(self) -> None:
        self.exact_duplicate_count: int = 0
        self.semantic_duplicate_count: int = 0
        self.conflict_count: int = 0

    def correlate(self, findings: list[Finding] | tuple[Finding, ...]) -> tuple[CanonicalFinding, ...]:
        """Groups findings into exact and semantic equivalence classes.

        Pipeline position:
            Candidate Findings -> Qualifier -> FindingCorrelator -> QualificationEngine / Reporter
        """
        if not findings:
            self.exact_duplicate_count = 0
            self.semantic_duplicate_count = 0
            self.conflict_count = 0
            return ()

        # 1. First pass: Exact Deduplication (Case A: same file, line, rule_id)
        exact_groups: dict[str, list[Finding]] = {}
        for f in findings:
            ident = CanonicalFindingIdentity.from_finding(f)
            exact_key = ident.exact_key
            if exact_key not in exact_groups:
                exact_groups[exact_key] = []
            exact_groups[exact_key].append(f)

        exact_dups_found = sum(len(g) - 1 for g in exact_groups.values() if len(g) > 1)
        self.exact_duplicate_count = max(0, exact_dups_found)

        # Select primary finding for each exact group
        exact_primaries: list[Finding] = []
        for group in exact_groups.values():
            sorted_group = sorted(
                group,
                key=lambda f: (_severity_weight(f), _confidence_weight(f), f.rule_id),
                reverse=True,
            )
            exact_primaries.append(sorted_group[0])

        # 2. Second pass: Semantic Deduplication & Conflict Detection (Case B, C, D)
        semantic_groups: dict[str, list[Finding]] = {}
        for f in exact_primaries:
            ident = CanonicalFindingIdentity.from_finding(f)
            sem_key = ident.semantic_key
            if sem_key not in semantic_groups:
                semantic_groups[sem_key] = []
            semantic_groups[sem_key].append(f)

        canonical_list: list[CanonicalFinding] = []
        sem_dups_found = 0
        conflicts_found = 0

        for sem_key, group in semantic_groups.items():
            if len(group) > 1:
                sem_dups_found += len(group) - 1

            # Sort group: highest severity first, then highest confidence, then rule_id for tiebreak
            sorted_group = sorted(
                group,
                key=lambda f: (_severity_weight(f), _confidence_weight(f), f.rule_id),
                reverse=True,
            )
            primary = sorted_group[0]
            all_rule_ids = tuple(sorted({f.rule_id for f in group}))
            exact_ident = CanonicalFindingIdentity.from_finding(primary).exact_key

            # Detect Case D: Evidence Conflicts among correlated findings
            conflict: EvidenceConflict | None = None
            for i in range(len(sorted_group)):
                for j in range(i + 1, len(sorted_group)):
                    fa = sorted_group[i]
                    fb = sorted_group[j]
                    ev_a = getattr(fa, "enriched_evidence", fa.evidence)
                    ev_b = getattr(fb, "enriched_evidence", fb.evidence)
                    conflict = detect_evidence_conflict(ev_a, ev_b, fa.rule_id, fb.rule_id)
                    if conflict:
                        break
                if conflict:
                    break

            if conflict:
                conflicts_found += 1
                # Enforce invariant: CONFLICT → UNKNOWN → UNRESOLVED
                if isinstance(primary, QualifiedFinding):
                    primary = QualifiedFinding(
                        finding_id=primary.finding_id,
                        rule_id=primary.rule_id,
                        fingerprint=primary.fingerprint,
                        title=primary.title,
                        severity=primary.severity,
                        confidence=primary.confidence,
                        cwe_id=primary.cwe_id,
                        owasp=primary.owasp,
                        file_path=primary.file_path,
                        evidence=primary.evidence,
                        description=primary.description,
                        remediation=primary.remediation,
                        rule_version=primary.rule_version,
                        metadata=dict(primary.metadata),
                        qualification_state=QualificationState.UNRESOLVED,
                        rejection_reason=conflict.conflict_type.value,
                        enriched_evidence=primary.enriched_evidence,
                    )

            canonical_list.append(
                CanonicalFinding(
                    primary=primary,
                    correlated_rule_ids=all_rule_ids,
                    semantic_fingerprint=sem_key,
                    exact_fingerprint=exact_ident,
                    evidence_conflict=conflict,
                )
            )

        self.semantic_duplicate_count = max(0, sem_dups_found)
        self.conflict_count = conflicts_found

        # Canonical sort for deterministic output ordering
        canonical_list.sort(
            key=lambda c: (
                str(c.primary.file_path).replace("\\", "/"),
                c.primary.evidence.line if c.primary.evidence else 0,
                c.primary.rule_id,
            )
        )

        return tuple(canonical_list)

    def to_findings(self, canonical: tuple[CanonicalFinding, ...]) -> tuple[Finding, ...]:
        """Extracts primary Finding objects from CanonicalFinding collection, embedding provenance metadata."""
        result: list[Finding] = []
        for c in canonical:
            updated_meta = dict(c.primary.metadata)
            updated_meta["correlated_rules"] = list(c.correlated_rule_ids)
            updated_meta["semantic_fingerprint"] = c.semantic_fingerprint
            if c.evidence_conflict:
                updated_meta["evidence_conflict"] = c.evidence_conflict.to_dict()

            if isinstance(c.primary, QualifiedFinding):
                primary = QualifiedFinding(
                    finding_id=c.primary.finding_id,
                    rule_id=c.primary.rule_id,
                    fingerprint=c.primary.fingerprint,
                    title=c.primary.title,
                    severity=c.primary.severity,
                    confidence=c.primary.confidence,
                    cwe_id=c.primary.cwe_id,
                    owasp=c.primary.owasp,
                    file_path=c.primary.file_path,
                    evidence=c.primary.evidence,
                    description=c.primary.description,
                    remediation=c.primary.remediation,
                    rule_version=c.primary.rule_version,
                    metadata=updated_meta,
                    qualification_state=c.primary.qualification_state,
                    rejection_reason=c.primary.rejection_reason,
                    enriched_evidence=c.primary.enriched_evidence,
                )
            else:
                primary = Finding(
                    finding_id=c.primary.finding_id,
                    rule_id=c.primary.rule_id,
                    fingerprint=c.primary.fingerprint,
                    title=c.primary.title,
                    severity=c.primary.severity,
                    confidence=c.primary.confidence,
                    cwe_id=c.primary.cwe_id,
                    owasp=c.primary.owasp,
                    file_path=c.primary.file_path,
                    evidence=c.primary.evidence,
                    description=c.primary.description,
                    remediation=c.primary.remediation,
                    rule_version=c.primary.rule_version,
                    metadata=updated_meta,
                )
            result.append(primary)
        return tuple(result)
