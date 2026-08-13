"""Unit tests for EvidenceReferenceValidator and VerdictConsistencyValidator (E13-1)."""

from __future__ import annotations

from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.explainer.validator import (
    EvidenceReferenceValidator,
    SecurityExplanationValidatorPipeline,
    VerdictConsistencyValidator,
)
from karsasec.ai.models import EvidenceClaim, ExplanationProvenance, SecurityExplanation


def _create_sample_context(
    verdict_status: str = "VULNERABLE",
    sanitizer_evidence: tuple[str, ...] = (),
) -> SecurityFindingContext:
    return SecurityFindingContext(
        finding_id="F-301",
        rule_id="RULE-SQLI",
        rule_title="SQL Injection",
        severity="HIGH",
        confidence="HIGH",
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path="db.py",
        line_number=10,
        snippet="query = f'SELECT * FROM u WHERE id={id}'",
        verdict_status=verdict_status,
        verdict_confidence="HIGH",
        verdict_reasons=("TAINT_REACHES_SINK",),
        evidence_fingerprint="ev_fp_301",
        canonical_fingerprint="can_fp_301",
        source_location="src/main.py:1",
        sink_location="db.py:10",
        sink_category="SQL_EXECUTION",
        provenance_path=("src/main.py:1", "db.py:10"),
        sanitizer_evidence=sanitizer_evidence,
        guard_evidence=(),
        transformation_evidence=(),
        sanitizer_constraints=(),
        type_constraints=(),
        variable_version="$id#1",
        call_context="GLOBAL",
        branch_polarity="UNKNOWN",
        cross_file=True,
        description="SQL injection",
        remediation_guidance="Parameterize query.",
    )


def test_evidence_reference_validator_rejects_hallucinated_sanitizer() -> None:
    context = _create_sample_context(sanitizer_evidence=())  # No sanitizers in SAST evidence

    explanation = SecurityExplanation(
        finding_id="F-301",
        summary="SQL Injection",
        vulnerability_type="CWE-89",
        why_vulnerable="Vulnerable flow.",
        source_analysis="src",
        sink_analysis="sink",
        data_flow_explanation="flow",
        security_impact="impact",
        guard_analysis="NOT_PROVEN",
        sanitizer_analysis="The input is sanitized using htmlspecialchars before execution.",  # Hallucinated claim!
        remediation_guidance="Fix it",
        limitations="None",
        evidence_claims=[
            EvidenceClaim(claim_type="SANITIZER", described_entity="htmlspecialchars", is_supported=True)
        ],
        provenance=ExplanationProvenance(
            finding_id="F-301",
            verdict_fingerprint="can_fp_301",
            evidence_fingerprint="ev_fp_301",
        ),
    )

    res = EvidenceReferenceValidator.validate(explanation, context)
    assert res.is_valid is False
    assert any("contains NO compatible sanitizer" in err for err in res.errors)


def test_evidence_reference_validator_accepts_negative_sanitizer_analysis() -> None:
    context = _create_sample_context(sanitizer_evidence=())

    explanation = SecurityExplanation(
        finding_id="F-301",
        summary="SQL Injection",
        vulnerability_type="CWE-89",
        why_vulnerable="Vulnerable flow.",
        source_analysis="src",
        sink_analysis="sink",
        data_flow_explanation="flow",
        security_impact="impact",
        guard_analysis="NOT_PROVEN",
        sanitizer_analysis="NONE COMPATIBLE — Absence of any sanitizer on flow path.",
        remediation_guidance="Fix it",
        limitations="None",
        provenance=ExplanationProvenance(
            finding_id="F-301",
            verdict_fingerprint="can_fp_301",
            evidence_fingerprint="ev_fp_301",
        ),
    )

    res = EvidenceReferenceValidator.validate(explanation, context)
    assert res.is_valid is True


def test_verdict_consistency_validator_rejects_safe_claim_on_vulnerable_verdict() -> None:
    context = _create_sample_context(verdict_status="VULNERABLE")

    explanation = SecurityExplanation(
        finding_id="F-301",
        summary="This finding is safe and not vulnerable.",  # Contradicts VULNERABLE verdict!
        vulnerability_type="CWE-89",
        why_vulnerable="Flow is harmless false positive.",
        source_analysis="src",
        sink_analysis="sink",
        data_flow_explanation="flow",
        security_impact="None",
        guard_analysis="NOT_PROVEN",
        sanitizer_analysis="NONE COMPATIBLE",
        remediation_guidance="Fix it",
        limitations="None",
        provenance=ExplanationProvenance(
            finding_id="F-301",
            verdict_fingerprint="can_fp_301",
            evidence_fingerprint="ev_fp_301",
        ),
    )

    res = VerdictConsistencyValidator.validate(explanation, context)
    assert res.is_valid is False
    assert any("contradicting deterministic SAST verdict" in err for err in res.errors)


def test_validator_pipeline_sanitizes_uncaught_claims() -> None:
    context = _create_sample_context(verdict_status="VULNERABLE", sanitizer_evidence=())

    explanation = SecurityExplanation(
        finding_id="F-301",
        summary="The finding is safe",
        vulnerability_type="CWE-89",
        why_vulnerable="Vulnerable",
        source_analysis="src",
        sink_analysis="sink",
        data_flow_explanation="flow",
        security_impact="impact",
        guard_analysis="NOT_PROVEN",
        sanitizer_analysis="The parameter is sanitized using strip_tags.",
        remediation_guidance="Fix",
        limitations="None",
        provenance=ExplanationProvenance(
            finding_id="F-301",
            verdict_fingerprint="can_fp_301",
            evidence_fingerprint="ev_fp_301",
        ),
    )

    is_valid, corrected, errors = SecurityExplanationValidatorPipeline.validate_and_sanitize(explanation, context)
    assert is_valid is False
    assert len(errors) >= 1
    assert "NONE COMPATIBLE" in corrected.sanitizer_analysis
    assert "Confirmed Vulnerable" in corrected.summary
