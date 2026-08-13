"""Evidence Reflection Engine for KarsaSec AI Engine (E13-2).

Enforces Security Invariants:
  - G17: Evidence-Bounded Reasoning (Explicitly report missing evidence as NOT_PROVEN / gaps).
  - G18: UNKNOWN != SAFE (Never converts UNKNOWN / NOT_PROVEN states to SAFE).
  - G19: Contradiction Transparency (Reports contradictory evidence explicitly).
  - G24: Interprocedural Evidence Integrity (Identifies unresolved calls/returns).
"""

from __future__ import annotations

from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.rca.evidence_graph import EvidenceGraph, GraphNodeType
from karsasec.ai.rca.models import (
    Contradiction,
    EvidenceGap,
    EvidenceReflection,
    ReflectionStatus,
)
from karsasec.graph.dataflow.semantic_evidence import ProofStatus, SemanticEvidenceBundle


class EvidenceReflectionEngine:
    """Reflects on evidence completeness, missing steps, and contradictions."""

    @staticmethod
    def reflect(
        ctx: SecurityFindingContext,
        graph: EvidenceGraph,
        bundle: SemanticEvidenceBundle | None = None,
    ) -> EvidenceReflection:
        """Analyzes evidence graph and context to produce EvidenceReflection."""
        gaps: list[EvidenceGap] = []
        contradictions: list[Contradiction] = []
        unresolved_calls: list[str] = []
        continuity_proven = True

        # 1. Check Source -> Sink continuity
        has_source = any(n.node_type == GraphNodeType.SOURCE for n in graph.nodes)
        has_sink = any(n.node_type == GraphNodeType.SINK for n in graph.nodes)

        if not has_source:
            gaps.append(
                EvidenceGap(
                    gap_id="gap_missing_source",
                    missing_type="MISSING_SOURCE",
                    description="Source origin of input taint is not explicitly recorded in evidence.",
                    location=ctx.file_path,
                )
            )
            continuity_proven = False

        if not has_sink:
            gaps.append(
                EvidenceGap(
                    gap_id="gap_missing_sink",
                    missing_type="MISSING_SINK",
                    description="Security sink node is not explicitly recorded in evidence.",
                    location=ctx.file_path,
                )
            )
            continuity_proven = False

        # 2. Check for UNKNOWN / NOT_PROVEN states
        if ctx.verdict_status == "UNKNOWN":
            gaps.append(
                EvidenceGap(
                    gap_id="gap_unknown_verdict",
                    missing_type="UNKNOWN_VERDICT",
                    description="Security verdict state is UNKNOWN.",
                    location=ctx.file_path,
                )
            )
            continuity_proven = False

        # 3. Check for unresolved call contexts / dynamic calls
        if bundle and bundle.proof_status in (ProofStatus.UNKNOWN, ProofStatus.NON_CONVERGED):
            unresolved_calls.append(f"Unresolved dataflow in sink {bundle.sink_node_id}")
            gaps.append(
                EvidenceGap(
                    gap_id="gap_non_converged",
                    missing_type="UNRESOLVED_CALL",
                    description=f"Interprocedural fixpoint proof status is {bundle.proof_status}.",
                    location=ctx.file_path,
                )
            )
            continuity_proven = False

        # 4. Check for Contradictions
        # Example: Branch polarity contradictions or contradictory proof statuses
        if ctx.sanitizer_evidence and ctx.verdict_status == "VULNERABLE":
            # Note: This is an incompatible sanitizer rather than a contradiction, but if proof status is PROVEN SAFE vs VULNERABLE:
            pass

        if "CONTRADICTORY_EVIDENCE" in ctx.verdict_reasons:
            contradictions.append(
                Contradiction(
                    contradiction_id="contradiction_01",
                    description="SAST engine detected contradictory evidence during fixpoint iteration.",
                    conflicting_nodes=tuple(n.node_id for n in graph.nodes),
                )
            )

        # 5. Determine overall ReflectionStatus
        if contradictions:
            status = ReflectionStatus.CONTRADICTORY
        elif not continuity_proven or gaps or unresolved_calls:
            status = ReflectionStatus.NOT_PROVEN if gaps else ReflectionStatus.UNKNOWN
        elif ctx.verdict_status == "VULNERABLE":
            status = ReflectionStatus.PROVEN
        else:
            status = ReflectionStatus.PROVEN

        return EvidenceReflection(
            status=status,
            gaps=tuple(gaps),
            contradictions=tuple(contradictions),
            continuity_proven=continuity_proven,
            unresolved_calls=tuple(unresolved_calls),
        )
