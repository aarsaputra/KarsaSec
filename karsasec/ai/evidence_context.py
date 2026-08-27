"""Security Finding Context Builder for KarsaSec AI Engine (Sprint E13-2).

Transforms SAST Findings and SecurityVerdicts into immutable SecurityFindingContext models.

Enforces Invariants G16-G26:
  - Preserves SAST authority (does not modify SecurityVerdict).
  - Normalizes evidence properties safely without code execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.core.finding.model import Finding, QualifiedFinding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict


@dataclass(frozen=True, slots=True)
class SecurityFindingContext:
    """Immutable, unified context representation for a SAST Security Finding."""

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

    verdict_status: str
    verdict_confidence: str
    verdict_reasons: tuple[str, ...]
    evidence_fingerprint: str
    canonical_fingerprint: str

    source_location: str
    sink_location: str
    sink_category: str
    provenance_path: tuple[str, ...]
    sanitizer_evidence: tuple[str, ...]
    guard_evidence: tuple[str, ...]
    transformation_evidence: tuple[str, ...]

    sanitizer_constraints: tuple[str, ...]
    type_constraints: tuple[str, ...]

    variable_version: str
    call_context: str
    branch_polarity: str
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
    def _infer_sink_category(cwe_id: str, rule_id: str) -> str:
        cwe = (cwe_id or "").upper()
        rule = (rule_id or "").upper()
        if "89" in cwe or "SQL" in rule:
            return "SQL_QUERY"
        if "79" in cwe or "XSS" in rule:
            return "HTML_OUTPUT"
        if "78" in cwe or "CMD" in rule or "EXEC" in rule or "RCE" in rule:
            return "COMMAND_EXECUTION"
        if "22" in cwe or "PATH" in rule or "TRAVERSAL" in rule:
            return "FILE_PATH"
        if "918" in cwe or "SSRF" in rule:
            return "HTTP_REQUEST"
        if "798" in cwe or "SECRET" in rule or "CRED" in rule:
            return "HARDCODED_SECRET"
        if "250" in cwe or "ROOT" in rule or "PERM" in rule:
            return "PRIVILEGE_ESCALATION"
        return "SECURITY_SINK"

    @staticmethod
    def build(finding: Finding, verdict: SecurityVerdict | None = None) -> SecurityFindingContext:
        verdict_obj = verdict or (finding.verdict if hasattr(finding, "verdict") and isinstance(finding.verdict, SecurityVerdict) else None)

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
            sink_cat = (
                verdict_obj.sink_category
                if verdict_obj.sink_category and verdict_obj.sink_category != "UNKNOWN"
                else SecurityFindingContextBuilder._infer_sink_category(cwe_id, rule_id)
            )
            var_ver = verdict_obj.variable_version or "$x#0"
            call_ctx = verdict_obj.call_context or "GLOBAL"
            branch_pol = verdict_obj.branch_polarity or "UNKNOWN"
            prov_path = verdict_obj.provenance_path or ()
        else:
            if confidence in ("LOW", "NEGLIGIBLE") or rule_id == "RULE-CUSTOM":
                verdict_status = "UNKNOWN"
                verdict_conf = "UNKNOWN"
            else:
                verdict_status = "VULNERABLE"
                verdict_conf = confidence
            verdict_reasons = ("SAST_RULE_MATCH",)
            ev_fp = finding.fingerprint or "NOT_AVAILABLE"
            can_fp = finding.fingerprint or "NOT_AVAILABLE"
            sink_cat = SecurityFindingContextBuilder._infer_sink_category(cwe_id, rule_id)
            var_ver = "$x#0"
            call_ctx = "GLOBAL"
            branch_pol = "UNKNOWN"
            prov_path = (f"{file_path}:{line_number}",) if line_number else (file_path,)

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
            if hasattr(ee, "sink_category") and ee.sink_category:
                sink_cat = str(ee.sink_category)
            if hasattr(ee, "sanitizer_symbol") and ee.sanitizer_symbol:
                sanitizers.append(str(ee.sanitizer_symbol))
            elif hasattr(ee, "sanitizers") and ee.sanitizers:
                sanitizers.extend([str(s) for s in ee.sanitizers])
            if hasattr(ee, "guards") and ee.guards:
                guards.extend([str(g) for g in ee.guards])
            if source_loc != "UNKNOWN":
                src_file_part = source_loc.split(":")[0] if ":" in source_loc else source_loc
                sink_file_part = sink_loc.split(":")[0] if ":" in sink_loc else sink_loc
                if src_file_part != sink_file_part:
                    cross_file = True
        elif finding.evidence:
            if hasattr(finding.evidence, "sanitizer_applied") and finding.evidence.sanitizer_applied:
                sanitizers.append(str(finding.evidence.sanitizer_applied))

        if verdict_obj and verdict_obj.evidence_references:
            for ref in verdict_obj.evidence_references:
                ek_name = ref.evidence_kind.name if hasattr(ref.evidence_kind, "name") else str(ref.evidence_kind)
                if ek_name == "SANITIZER":
                    sanitizers.append(f"{ref.source_node} -> {ref.description}")
                elif ek_name == "GUARD":
                    guards.append(f"{ref.source_node} ({ref.proof_status})")
                elif ek_name == "TRANSFORMATION":
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
            provenance_path=prov_path,
            sanitizer_evidence=tuple(sanitizers),
            guard_evidence=tuple(guards),
            transformation_evidence=tuple(transformations),
            sanitizer_constraints=tuple(sanitizer_constraints),
            type_constraints=tuple(type_constraints),
            variable_version=var_ver,
            call_context=call_ctx,
            branch_polarity=branch_pol,
            cross_file=cross_file,
            description=finding.description or snippet,
            remediation_guidance=finding.remediation or "Apply appropriate mitigation.",
            context_lines=ctx_lines,
        )
