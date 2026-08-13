"""False Positive Risk Assessor (E13-2).

Enforces Security Invariants:
  - G16: SAST Authority Preservation (Assesses evidence quality risk ONLY, NEVER mutates SecurityVerdict.status).
  - G18: UNKNOWN != SAFE (UNKNOWN state maps to NOT_PROVEN, never to SAFE/LOW_RISK).
  - G26: Deterministic classification based on evidence completeness.
"""

from __future__ import annotations

from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.rca.evidence_graph import EvidenceGraph
from karsasec.ai.rca.models import FalsePositiveAssessment, EvidenceReflection, ReflectionStatus


class FalsePositiveRiskAssessor:
    """Evaluates false-positive risk rating based on evidence quality and completeness."""

    @staticmethod
    def assess(
        ctx: SecurityFindingContext,
        graph: EvidenceGraph,
        reflection: EvidenceReflection,
    ) -> FalsePositiveAssessment:
        """Determines false-positive assessment rating."""

        if reflection.status in (ReflectionStatus.NOT_PROVEN, ReflectionStatus.UNKNOWN) or reflection.unresolved_calls:
            return FalsePositiveAssessment.NOT_PROVEN

        if reflection.status == ReflectionStatus.CONTRADICTORY:
            return FalsePositiveAssessment.NOT_PROVEN

        if ctx.verdict_status == "SAFE" or (ctx.sanitizer_evidence and ctx.verdict_status != "VULNERABLE"):
            return FalsePositiveAssessment.LOW_RISK

        if reflection.continuity_proven and not reflection.gaps and ctx.verdict_status == "VULNERABLE":
            return FalsePositiveAssessment.HIGH_RISK

        if reflection.continuity_proven:
            return FalsePositiveAssessment.MEDIUM_RISK

        return FalsePositiveAssessment.NOT_PROVEN
