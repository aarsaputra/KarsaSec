"""Bounded Security Finding Context Builder for AI explanation (E13-1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.core.finding.model import Finding, QualifiedFinding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict


@dataclass(frozen=True)
class SecurityFindingContext:
    """Immutable, evidence-grounded representation of a security finding for AI context feeding."""

    finding_id: str
    rule_id: str
    rule_title: str
    severity: str
    confidence: str
    cwe_id: str
    owasp: str
    file_path: str
    line_number: int
    snippet: str

    # Verdict metadata
    verdict_status: str
    verdict_confidence: str
    verdict_reasons: tuple[str, ...]
    evidence_fingerprint: str
    canonical_fingerprint: str

    # Dataflow & Evidence context
    source_location: str
    sink_location: str
    sink_category: str
    provenance_path: tuple[str, ...]
    sanitizer_evidence: tuple[str, ...]
    guard_evidence: tuple[str, ...]
    transformation_evidence: tuple[str, ...]
    sanitizer_constraints: tuple[str, ...]
    type_constraints: tuple[str, ...]

    # Isolation parameters
    variable_version: str  # SSA version e.g. $x#1
    call_context: str  # Call context ID/string
    branch_polarity: str  # TRUE / FALSE / UNKNOWN
    cross_file: bool

    # Metadata & Guidance
    description: str
    remediation_guidance: str
    context_lines: tuple[str, ...] = field(default_factory=tuple)
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes finding context to dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp": self.owasp,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "verdict_status": self.verdict_status,
            "verdict_confidence": self.verdict_confidence,
            "verdict_reasons": list(self.verdict_reasons),
            "evidence_fingerprint": self.evidence_fingerprint,
            "canonical_fingerprint": self.canonical_fingerprint,
            "source_location": self.source_location,
            "sink_location": self.sink_location,
            "sink_category": self.sink_category,
            "provenance_path": list(self.provenance_path),
            "sanitizer_evidence": list(self.sanitizer_evidence),
            "guard_evidence": list(list(self.guard_evidence)),
            "transformation_evidence": list(self.transformation_evidence),
            "sanitizer_constraints": list(self.sanitizer_constraints),
            "type_constraints": list(self.type_constraints),
            "variable_version": self.variable_version,
            "call_context": self.call_context,
            "branch_polarity": self.branch_polarity,
            "cross_file": self.cross_file,
            "description": self.description,
            "remediation_guidance": self.remediation_guidance,
            "context_lines": list(self.context_lines),
        }


class SecurityFindingContextBuilder:
    """Constructs a deterministic, evidence-grounded SecurityFindingContext without altering evidence."""

    @staticmethod
    def build(finding: Finding, verdict: SecurityVerdict | None = None) -> SecurityFindingContext:
        verdict_obj = verdict or (finding.verdict if isinstance(finding.verdict, SecurityVerdict) else None)

        # Basic metadata
        finding_id = finding.finding_id or "UNKNOWN"
        rule_id = finding.rule_id or "UNKNOWN"
        rule_title = finding.title or "Security Finding"
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        confidence = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
        cwe_id = (finding.cwe_id or "CWE-0").upper()
        owasp = finding.owasp or "NOT_AVAILABLE"
        file_path = str(finding.file_path)
        line_number = finding.evidence.line if finding.evidence else 0
        snippet = finding.evidence.snippet.strip() if finding.evidence and finding.evidence.snippet else "NOT_AVAILABLE"

        # Verdict info
        if verdict_obj is not None:
            verdict_status = (
                verdict_obj.status.value if hasattr(verdict_obj.status, "value") else str(verdict_obj.status)
            )
            verdict_conf = (
                verdict_obj.confidence.value
                if hasattr(verdict_obj.confidence, "value")
                else str(verdict_obj.confidence)
            )
            verdict_reasons = tuple(r.value if hasattr(r, "value") else str(r) for r in verdict_obj.reason_codes)
            ev_fp = verdict_obj.evidence_fingerprint or "NOT_AVAILABLE"
            can_fp = verdict_obj.canonical_fingerprint or finding.fingerprint or "NOT_AVAILABLE"
            sink_cat = verdict_obj.sink_category or "UNKNOWN"
            var_ver = verdict_obj.variable_version or "$x#0"
            call_ctx = verdict_obj.call_context or "GLOBAL"
            branch_pol = verdict_obj.branch_polarity or "UNKNOWN"
            prov_path = verdict_obj.provenance_path or ()
        else:
            verdict_status = "UNKNOWN"
            verdict_conf = "UNKNOWN"
            verdict_reasons = ("NO_VERDICT_OBJECT",)
            ev_fp = "NOT_AVAILABLE"
            can_fp = finding.fingerprint or "NOT_AVAILABLE"
            sink_cat = "UNKNOWN"
            var_ver = "$x#0"
            call_ctx = "GLOBAL"
            branch_pol = "UNKNOWN"
            prov_path = ()

        # Enriched evidence extraction if QualifiedFinding
        sanitizers: list[str] = []
        guards: list[str] = []
        transformations: list[str] = []
        sanitizer_constraints: list[str] = []
        type_constraints: list[str] = []
        source_loc = "UNKNOWN"
        sink_loc = f"{file_path}:{line_number}"
        cross_file = False

        if isinstance(finding, QualifiedFinding) and finding.enriched_evidence is not None:
            ee = finding.enriched_evidence
            if hasattr(ee, "source_symbol") and ee.source_symbol:
                source_loc = str(ee.source_symbol)
            elif hasattr(ee, "source_location") and ee.source_location:
                source_loc = str(ee.source_location)
            if hasattr(ee, "sink_symbol") and ee.sink_symbol:
                sink_loc = str(ee.sink_symbol)
            elif hasattr(ee, "sink_location") and ee.sink_location:
                sink_loc = str(ee.sink_location)
            if hasattr(ee, "sink_category") and ee.sink_category and sink_cat == "UNKNOWN":
                sink_cat = ee.sink_category
            if hasattr(ee, "sanitizer_symbol") and ee.sanitizer_symbol:
                sanitizers.append(str(ee.sanitizer_symbol))
            elif hasattr(ee, "sanitizers") and ee.sanitizers:
                sanitizers.extend([str(s) for s in ee.sanitizers])
            if hasattr(ee, "guards") and ee.guards:
                guards.extend([str(g) for g in ee.guards])
            if source_loc != "UNKNOWN" and sink_loc != sink_loc:
                cross_file = True
        elif finding.evidence:
            if hasattr(finding.evidence, "sanitizer_applied") and finding.evidence.sanitizer_applied:
                sanitizers.append(str(finding.evidence.sanitizer_applied))

        # Check evidence references in SecurityVerdict if present
        if verdict_obj and verdict_obj.evidence_references:
            for ref in verdict_obj.evidence_references:
                if ref.evidence_kind.name == "SANITIZER" or ref.evidence_kind == "SANITIZER":
                    sanitizers.append(f"{ref.source_node} -> {ref.description}")
                elif ref.evidence_kind.name == "GUARD" or ref.evidence_kind == "GUARD":
                    guards.append(f"{ref.source_node} ({ref.proof_status})")
                elif ref.evidence_kind.name == "TRANSFORMATION" or ref.evidence_kind == "TRANSFORMATION":
                    transformations.append(f"{ref.source_node} -> {ref.description}")

        ctx_lines = tuple(finding.evidence.context_lines) if finding.evidence and finding.evidence.context_lines else ()

        return SecurityFindingContext(
            finding_id=finding_id,
            rule_id=rule_id,
            rule_title=rule_title,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            owasp=owasp,
            file_path=file_path,
            line_number=line_number,
            snippet=snippet,
            verdict_status=verdict_status,
            verdict_confidence=verdict_conf,
            verdict_reasons=verdict_reasons,
            evidence_fingerprint=ev_fp,
            canonical_fingerprint=can_fp,
            source_location=source_loc,
            sink_location=sink_loc,
            sink_category=sink_cat,
            provenance_path=tuple(prov_path),
            sanitizer_evidence=tuple(sanitizers),
            guard_evidence=tuple(guards),
            transformation_evidence=tuple(transformations),
            sanitizer_constraints=tuple(sanitizer_constraints),
            type_constraints=tuple(type_constraints),
            variable_version=var_ver,
            call_context=call_ctx,
            branch_polarity=branch_pol,
            cross_file=cross_file,
            description=finding.description or "NOT_AVAILABLE",
            remediation_guidance=finding.remediation or "NOT_AVAILABLE",
            context_lines=ctx_lines,
            raw_metadata=finding.metadata or {},
        )
