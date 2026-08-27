"""Remediation Planner for KarsaSec AI Engine (Sprint E13-3).

Transforms SAST findings, verdicts, RCA evidence, and sink semantics into structured RemediationStrategy models.

Enforces Invariants:
  - G1: UNKNOWN != SAFE (UNKNOWN/NOT_PROVEN evidence forces MANUAL_REVIEW_REQUIRED).
  - G2: Sink Semantics Authority (Derives strategy from SinkCompatibilityMatrix category & RCA mechanism).
  - G5: Evidence Grounding (All strategies bind strictly to source evidence references).
"""

from __future__ import annotations

from karsasec.ai.evidence_context import SecurityFindingContext, SecurityFindingContextBuilder
from karsasec.ai.models import KnowledgeReference
from karsasec.ai.rca.models import (
    FalsePositiveAssessment,
    ReflectionStatus,
    RootCauseAnalysis,
    RootCauseCategory,
)
from karsasec.ai.remediation.models import RemediationStrategy, RemediationStrategyType
from karsasec.ai.remediation.policy import RemediationCapability, RemediationPolicy
from karsasec.ai.retrieval.adapter import KnowledgeChunk
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict, VerdictStatus


class RemediationPlanner:
    """Evidence-grounded Remediation Planner component."""

    @staticmethod
    def plan(
        finding: Finding,
        verdict: SecurityVerdict | None = None,
        context: SecurityFindingContext | None = None,
        rca: RootCauseAnalysis | None = None,
        knowledge_chunks: list[KnowledgeChunk] | None = None,
    ) -> RemediationStrategy:
        """Derive structured remediation strategy from evidence and sink semantics."""
        # 1. Enforce safety policy
        RemediationPolicy.assert_allowed(RemediationCapability.GENERATE_PLAN)

        ctx = context or SecurityFindingContextBuilder.build(finding, verdict=verdict)
        k_chunks = knowledge_chunks or []
        ev_refs = tuple(ctx.provenance_path) if ctx.provenance_path else (f"{ctx.file_path}:{ctx.line_number}",)

        # 2. Invariant G1: Check for UNKNOWN / NOT_PROVEN / CONTRADICTORY states
        is_unknown_verdict = ctx.verdict_status in (
            VerdictStatus.UNKNOWN.value,
            VerdictStatus.NOT_PROVEN.value,
            VerdictStatus.UNKNOWN,
            VerdictStatus.NOT_PROVEN,
        ) or (verdict is not None and verdict.status in (VerdictStatus.UNKNOWN, VerdictStatus.NOT_PROVEN))
        is_unproven_rca = rca is not None and (
            rca.reflection_status
            in (ReflectionStatus.NOT_PROVEN, ReflectionStatus.UNKNOWN, ReflectionStatus.CONTRADICTORY)
            or rca.false_positive_risk == FalsePositiveAssessment.NOT_PROVEN
            or rca.root_cause_category == RootCauseCategory.CONTRADICTORY_EVIDENCE
        )

        if is_unknown_verdict or is_unproven_rca:
            strat_type = RemediationStrategyType.MANUAL_REVIEW_REQUIRED
            fp = RemediationStrategy.compute_fingerprint(
                finding_id=ctx.finding_id,
                category=rca.root_cause_category if rca else "UNKNOWN_EVIDENCE",
                strategy_type=strat_type,
                target_file=ctx.file_path,
                evidence_refs=ev_refs,
            )
            return RemediationStrategy(
                finding_id=ctx.finding_id,
                root_cause_category=rca.root_cause_category if rca else RootCauseCategory.UNKNOWN_ROOT_CAUSE,
                strategy_type=strat_type,
                rationale="Evidence is UNKNOWN, NOT_PROVEN, or contradictory. Automated remediation is withheld to preserve SAST authority (Invariant G1).",
                target_file=ctx.file_path,
                target_locations=(f"{ctx.file_path}:{ctx.line_number}",),
                affected_symbols=(ctx.variable_version,),
                evidence_references=ev_refs,
                knowledge_references=tuple(
                    KnowledgeReference(
                        chunk_id=c.chunk_id,
                        title=c.title,
                        source=c.source,
                        relevance_score=c.relevance_score,
                    )
                    for c in k_chunks
                ),
                confidence=0.0,
                assumptions=("Evidence incomplete or unproven.",),
                limitations=("Manual security review required before remediation.",),
                strategy_fingerprint=fp,
            )

        # 3. Derive remediation strategy from sink semantics & RCA root cause category
        rca_cat = rca.root_cause_category if rca else RootCauseCategory.MISSING_SANITIZATION
        sink_cat = ctx.sink_category.upper() if ctx.sink_category else ""

        strat_type = RemediationPlanner._derive_strategy_type(sink_cat, rca_cat, ctx.rule_id, ctx.cwe_id)
        rationale = (
            f"Remediation strategy '{strat_type.value}' selected for sink category '{sink_cat}' "
            f"and root cause mechanism '{rca_cat.value if hasattr(rca_cat, 'value') else str(rca_cat)}' at {ctx.sink_location}."
        )

        k_refs = tuple(
            KnowledgeReference(
                chunk_id=c.chunk_id,
                title=c.title,
                source=c.source,
                relevance_score=c.relevance_score,
            )
            for c in k_chunks
        )

        fp = RemediationStrategy.compute_fingerprint(
            finding_id=ctx.finding_id,
            category=rca_cat,
            strategy_type=strat_type,
            target_file=ctx.file_path,
            evidence_refs=ev_refs,
        )

        affected_symbol = (
            rca.primary_cause_step.variable_version
            if rca and rca.primary_cause_step and rca.primary_cause_step.variable_version
            else ctx.variable_version
        )

        return RemediationStrategy(
            finding_id=ctx.finding_id,
            root_cause_category=rca_cat,
            strategy_type=strat_type,
            rationale=rationale,
            target_file=ctx.file_path,
            target_locations=(f"{ctx.file_path}:{ctx.line_number}",),
            affected_symbols=(affected_symbol,),
            evidence_references=ev_refs,
            knowledge_references=k_refs,
            confidence=1.0,
            assumptions=("SAST taint provenance is complete and verified.",),
            limitations=("Strategy proposal must be validated by human reviewer before application.",),
            strategy_fingerprint=fp,
        )

    @staticmethod
    def _derive_strategy_type(
        sink_category: str,
        rca_category: RootCauseCategory | str,
        rule_id: str,
        cwe_id: str = "",
    ) -> RemediationStrategyType:
        rule_u = rule_id.upper()
        sink_u = sink_category.upper()
        cwe_u = cwe_id.upper()
        rca_str = rca_category.value if hasattr(rca_category, "value") else str(rca_category)

        # 1. Hardcoded secrets / credentials MUST map to REMOVE_SECRET
        if "SECRET" in sink_u or "SECRET" in rule_u or "CRED" in rule_u or "798" in rule_u or "798" in cwe_u:
            return RemediationStrategyType.REMOVE_SECRET

        if rca_str == RootCauseCategory.INCOMPATIBLE_SANITIZATION.value:
            return RemediationStrategyType.REPLACE_UNSAFE_API

        if rca_str in (RootCauseCategory.SSA_REASSIGNMENT.value, RootCauseCategory.UNSAFE_ASSIGNMENT.value):
            return RemediationStrategyType.CONSTRAIN_DATA_FLOW

        # 2. Direct vulnerability mapping based on rule_id, sink_category, and cwe_id
        if "XSS" in sink_u or "XSS" in rule_u or "79" in rule_u or "79" in cwe_u:
            return RemediationStrategyType.ADD_OUTPUT_ENCODING

        if "SQL" in sink_u or "SQL" in rule_u or "89" in rule_u or ("89" in cwe_u and "89" in rule_u):
            return RemediationStrategyType.ADD_PARAMETERIZATION

        if "COMMAND" in sink_u or "EXEC" in sink_u or "SHELL" in sink_u or "CMD" in rule_u or "78" in rule_u or "78" in cwe_u:
            return RemediationStrategyType.REPLACE_UNSAFE_API

        if "AUTH" in sink_u or "AUTHORIZATION" in rule_u or "PERM" in rule_u or "250" in rule_u or "285" in rule_u or "285" in cwe_u:
            return RemediationStrategyType.ADD_AUTHORIZATION_CHECK

        if "CSRF" in sink_u or "CSRF" in rule_u or "352" in rule_u or "352" in cwe_u:
            return RemediationStrategyType.ADD_CSRF_PROTECTION

        if "PATH" in sink_u or "TRAVERSAL" in rule_u or "FILE" in sink_u or "98" in rule_u or "22" in rule_u or "22" in cwe_u:
            return RemediationStrategyType.ADD_INPUT_VALIDATION

        if "SSRF" in sink_u or "SSRF" in rule_u or "918" in rule_u or "918" in cwe_u:
            return RemediationStrategyType.ADD_INPUT_VALIDATION

        if "CONFIG" in sink_u or "CONFIG" in rule_u or "16" in rule_u or "16" in cwe_u:
            return RemediationStrategyType.FIX_INSECURE_CONFIGURATION

        return RemediationStrategyType.ADD_INPUT_VALIDATION
