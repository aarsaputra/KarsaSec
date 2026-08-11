"""FindingCorrelator: deduplicates and correlates findings from multiple rules detecting the same vulnerability.

Problem: Multiple rules (e.g. KS-OWASP-0010 and KS-PHP-SSRF-0001) can produce separate findings
for the same semantic vulnerability at the same source location. This produces duplicate reports.

Solution: Canonical semantic fingerprint per vulnerability. Findings sharing the same
fingerprint are merged into a single CanonicalFinding, retaining all contributing rule IDs.

Design principles (E10-3J):
- Deterministic: same input findings -> same canonical output, regardless of order
- Stateless: no side effects, no mutable state
- Conservative: only merges findings with identical CWE class, file, and line
- Transparent: correlated_rule_ids records all contributing rules for auditability
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from karsasec.core.finding.model import Finding

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


def _semantic_fingerprint(finding: Finding) -> str:
    """Compute a canonical semantic fingerprint for deduplication.

    Fingerprint is based on:
    - normalized file path
    - line number
    - CWE class (vulnerability category)
    - sink category (if enriched_evidence is present)
    - normalized sink expression (first 64 chars of snippet, stripped)

    NOT based on rule_id — intentionally, so findings from different rules
    detecting the same vulnerability at the same location are merged.
    """
    norm_path = str(finding.file_path).replace("\\", "/").lower()
    cwe = (finding.cwe_id or "CWE-0").upper()
    snippet_norm = (finding.evidence.snippet or "").strip()[:64]
    line = str(finding.evidence.line)

    sink_cat = ""
    if hasattr(finding, "enriched_evidence") and finding.enriched_evidence:
        sink_cat = getattr(finding.enriched_evidence, "sink_category", "") or ""

    raw = f"{norm_path}|{line}|{cwe}|{sink_cat}|{snippet_norm}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class CanonicalFinding:
    """A deduplicated, correlated finding representing one semantic vulnerability.

    primary: the highest-severity / highest-confidence Finding among all correlated matches.
    correlated_rule_ids: all rule IDs that contributed to this finding (ordered, deterministic).
    semantic_fingerprint: the deduplication key used to merge this group.
    """
    primary: Finding
    correlated_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    semantic_fingerprint: str = ""

    @property
    def rule_id(self) -> str:
        return self.primary.rule_id

    @property
    def file_path(self) -> Path:
        return self.primary.file_path


class FindingCorrelator:
    """Stateless correlator that deduplicates findings from multiple rules.

    Usage:
        correlator = FindingCorrelator()
        canonical = correlator.correlate(all_findings)
        # canonical is a tuple[CanonicalFinding, ...], deterministically ordered

    Pipeline position:
        Rule Matcher -> Candidate Findings -> FindingCorrelator -> FindingCollection -> Reporter
    """

    def correlate(self, findings: list[Finding] | tuple[Finding, ...]) -> tuple[CanonicalFinding, ...]:
        """Group findings by semantic fingerprint and produce one CanonicalFinding per group.

        When multiple findings share a fingerprint:
        - The canonical primary is the one with the highest severity, then highest confidence.
        - correlated_rule_ids lists all contributing rule IDs in sorted order for determinism.
        """
        if not findings:
            return ()

        # Group by semantic fingerprint
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            fp = _semantic_fingerprint(f)
            if fp not in groups:
                groups[fp] = []
            groups[fp].append(f)

        canonical: list[CanonicalFinding] = []
        for fp, group in groups.items():
            # Sort group: highest severity first, then highest confidence, then rule_id for tiebreak
            sorted_group = sorted(
                group,
                key=lambda f: (_severity_weight(f), _confidence_weight(f), f.rule_id),
                reverse=True,
            )
            primary = sorted_group[0]
            # Collect all unique rule IDs, sorted for determinism
            all_rule_ids = tuple(sorted({f.rule_id for f in group}))
            canonical.append(CanonicalFinding(
                primary=primary,
                correlated_rule_ids=all_rule_ids,
                semantic_fingerprint=fp,
            ))

        # Final sort: by file_path + line + rule_id for deterministic output order
        canonical.sort(key=lambda c: (
            str(c.primary.file_path),
            c.primary.evidence.line,
            c.primary.rule_id,
        ))

        return tuple(canonical)

    def to_findings(self, canonical: tuple[CanonicalFinding, ...]) -> tuple[Finding, ...]:
        """Extract primary Finding objects from CanonicalFinding collection.

        Use when downstream code expects tuple[Finding, ...] (e.g. reporter, baseline).
        Correlated rule metadata is embedded in Finding.metadata['correlated_rules'].
        Preserves QualifiedFinding instances without dropping qualification attributes.
        """
        result: list[Finding] = []
        from karsasec.core.finding.model import QualifiedFinding
        for c in canonical:
            if len(c.correlated_rule_ids) > 1:
                # Embed correlation metadata into the primary finding's metadata
                updated_meta = dict(c.primary.metadata)
                updated_meta["correlated_rules"] = list(c.correlated_rule_ids)
                updated_meta["semantic_fingerprint"] = c.semantic_fingerprint

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
            else:
                result.append(c.primary)
        return tuple(result)
