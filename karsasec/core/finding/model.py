"""Enhanced immutable Finding, QualifiedFinding, and CanonicalFindingIdentity models (E12-4)."""

from __future__ import annotations

import hashlib
import os
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


def normalize_finding_path(file_path: Path | str) -> str:
    """Normalizes file path for cross-platform deterministic identity calculation (E12-4).

    Handles Windows backslashes, redundant dot segments, and leading relative slashes.
    """
    raw_str = str(file_path).replace("\\", "/")
    # Remove redundant ./ prefix
    while raw_str.startswith("./"):
        raw_str = raw_str[2:]

    # Normalize path collapse
    parts = [p for p in raw_str.split("/") if p and p != "."]
    norm_parts: list[str] = []
    for p in parts:
        if p == ".." and norm_parts and norm_parts[-1] != "..":
            norm_parts.pop()
        else:
            norm_parts.append(p)

    res = "/".join(norm_parts)
    return res.lower() if os.name == "nt" else res


def compute_stable_finding_fingerprint(
    rule_id: str,
    file_path: Path | str,
    snippet: str,
    line: int,
    cwe_id: str = "CWE-20",
) -> str:
    """Computes a deterministic, stable SHA-256 fingerprint for finding deduplication and diff tracking."""
    normalized_path = normalize_finding_path(file_path)
    raw = f"{rule_id}|{normalized_path}|{line}|{snippet.strip()}|{cwe_id.upper()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class CanonicalFindingIdentity:
    """Canonical Identity representation distinguishing Exact vs Semantic identity (E12-4)."""

    exact_key: str
    semantic_key: str
    normalized_file: str
    line: int
    rule_id: str
    sink_category: str = "UNKNOWN"
    canonical_sink: str = ""
    canonical_taint_path: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def create(
        cls,
        file_path: Path | str,
        line: int,
        rule_id: str,
        snippet: str = "",
        sink_category: str = "UNKNOWN",
        sink_symbol: str = "",
        taint_path_hops: tuple[Any, ...] = field(default_factory=tuple),
        cwe_id: str = "CWE-0",
    ) -> CanonicalFindingIdentity:
        norm_path = normalize_finding_path(file_path)
        cwe = (cwe_id or "CWE-0").upper()
        snippet_norm = snippet.strip()[:64]

        # Canonicalize taint path hops to a deterministic string tuple
        path_strs: list[str] = []
        for hop in taint_path_hops:
            if hasattr(hop, "variable_name"):
                path_strs.append(str(hop.variable_name).strip())
            elif isinstance(hop, (list, tuple)):
                path_strs.append("->".join(str(x) for x in hop))
            else:
                path_strs.append(str(hop).strip())
        canonical_hops = tuple(path_strs)

        exact_raw = f"EXACT|{norm_path}|{line}|{rule_id}"
        exact_key = hashlib.sha256(exact_raw.encode("utf-8")).hexdigest()[:32]

        sink_ident = sink_symbol.strip() or snippet_norm
        hops_ident = "->".join(canonical_hops)
        semantic_raw = f"SEM|{norm_path}|{line}|{cwe}|{sink_category}|{sink_ident}|{hops_ident}"
        semantic_key = hashlib.sha256(semantic_raw.encode("utf-8")).hexdigest()[:32]

        return cls(
            exact_key=exact_key,
            semantic_key=semantic_key,
            normalized_file=norm_path,
            line=line,
            rule_id=rule_id,
            sink_category=sink_category,
            canonical_sink=sink_ident,
            canonical_taint_path=canonical_hops,
        )

    @classmethod
    def from_finding(cls, finding: Finding) -> CanonicalFindingIdentity:
        enriched = getattr(finding, "enriched_evidence", None)
        sink_cat = enriched.sink_category if enriched else "UNKNOWN"
        sink_sym = enriched.sink_symbol if enriched else ""
        hops = enriched.taint_path if enriched else ()
        snippet = finding.evidence.snippet if finding.evidence else ""

        return cls.create(
            file_path=finding.file_path,
            line=finding.evidence.line if finding.evidence else 0,
            rule_id=finding.rule_id,
            snippet=snippet,
            sink_category=sink_cat,
            sink_symbol=sink_sym,
            taint_path_hops=hops,
            cwe_id=finding.cwe_id,
        )


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence),
            "cwe_id": self.cwe_id,
            "owasp": self.owasp,
            "file_path": str(self.file_path),
            "evidence": self.evidence.to_dict() if hasattr(self.evidence, "to_dict") else str(self.evidence),
            "description": self.description,
            "remediation": self.remediation,
            "rule_version": self.rule_version,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class QualifiedFinding(Finding):
    """Enriched finding with qualification decision state, evidence trail, and FP taxonomy reason (E12-4)."""

    qualification_state: QualificationState = QualificationState.CONFIRMED
    rejection_reason: Any | None = None
    enriched_evidence: FindingEvidence | None = None

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "qualification_state": self.qualification_state.value if isinstance(self.qualification_state, QualificationState) else str(self.qualification_state),
            "rejection_reason": self.rejection_reason.value if hasattr(self.rejection_reason, "value") else (str(self.rejection_reason) if self.rejection_reason else None),
            "enriched_evidence": self.enriched_evidence.to_dict() if self.enriched_evidence and hasattr(self.enriched_evidence, "to_dict") else None,
        })
        return base
