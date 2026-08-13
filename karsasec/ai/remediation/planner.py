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
        is_unknown_verdict = ctx.verdict_status in (VerdictStatus.UNKNOWN.value, VerdictStatus.NOT_PROVEN.value, VerdictStatus.UNKNOWN, VerdictStatus.NOT_PROVEN) or (verdict is not None and verdict.status in (VerdictStatus.UNKNOWN, VerdictStatus.NOT_PROVEN))
        is_unproven_rca = (
            rca is not None
            and (
                rca.reflection_status in (ReflectionStatus.NOT_PROVEN, ReflectionStatus.UNKNOWN, ReflectionStatus.CONTRADICTORY)
                or rca.false_positive_risk == FalsePositiveAssessment.NOT_PROVEN
                or rca.root_cause_category == RootCauseCategory.CONTRADICTORY_EVIDENCE
            )
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

        strat_type = RemediationPlanner._derive_strategy_type(sink_cat, rca_cat, ctx.rule_id)
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
    ) -> RemediationStrategyType:
        """Derive strategy type based on sink semantics and RCA mechanism."""
        rca_str = rca_category.value if hasattr(rca_category, "value") else str(rca_category)

        if rca_str == RootCauseCategory.INCOMPATIBLE_SANITIZATION.value:
            return RemediationStrategyType.REPLACE_UNSAFE_API

        if rca_str in (RootCauseCategory.SSA_REASSIGNMENT.value, RootCauseCategory.UNSAFE_ASSIGNMENT.value):
            return RemediationStrategyType.CONSTRAIN_DATA_FLOW

        if "SQL" in sink_category or "SQL" in rule_id.upper():
            return RemediationStrategyType.ADD_PARAMETERIZATION

        if "HTML" in sink_category or "XSS" in sink_category or "XSS" in rule_id.upper():
            return RemediationStrategyType.ADD_OUTPUT_ENCODING

        if "AUTH" in sink_category or "AUTHORIZATION" in rule_id.upper() or "PERM" in rule_id.upper():
            return RemediationStrategyType.ADD_AUTHORIZATION_CHECK

        if "CSRF" in sink_category or "CSRF" in rule_id.upper():
            return RemediationStrategyType.ADD_CSRF_PROTECTION

        if "SECRET" in sink_category or "SECRET" in rule_id.upper() or "CRED" in rule_id.upper():
            return RemediationStrategyType.REMOVE_SECRET

        if "HEADER" in sink_category or "HEADER" in rule_id.upper():
            return RemediationStrategyType.ADD_SECURITY_HEADER

        if "CONFIG" in sink_category or "CONFIG" in rule_id.upper():
            return RemediationStrategyType.FIX_INSECURE_CONFIGURATION

        if "COMMAND" in sink_category or "EXEC" in sink_category or "SHELL" in sink_category:
            return RemediationStrategyType.REPLACE_UNSAFE_API

        return RemediationStrategyType.ADD_INPUT_VALIDATION
