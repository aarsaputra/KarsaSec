"""Deterministic Root Cause Analyzer (E13-2).

Enforces Security Invariants:
  - G16: SAST Authority Preservation (Does NOT alter SecurityVerdict).
  - G17: Evidence-Bounded Reasoning (Every step in the chain maps to actual evidence).
  - G23: Sink-Specific Semantics (Relies on SAST SinkCompatibilityMatrix results passed via context).
  - G26: Byte-for-byte deterministic classification and evidence chain generation.
"""

from __future__ import annotations


from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.rca.evidence_graph import EvidenceGraph, GraphNodeType
from karsasec.ai.rca.models import (
    RootCauseCategory,
    RootCauseStep,
)
from karsasec.graph.dataflow.semantic_evidence import SemanticEvidenceBundle


class RootCauseAnalyzer:
    """Deterministic analyzer identifying the primary root cause category and step chain."""

    @staticmethod
    def analyze(
        ctx: SecurityFindingContext,
        graph: EvidenceGraph,
        bundle: SemanticEvidenceBundle | None = None,
    ) -> tuple[RootCauseCategory, RootCauseStep | None, tuple[RootCauseStep, ...]]:
        """Determines primary root cause category, primary cause step, and evidence chain."""
        chain: list[RootCauseStep] = []

        # 1. Convert Graph nodes into RootCauseSteps in order
        for idx, node in enumerate(graph.nodes):
            step = RootCauseStep(
                step_id=f"step_{idx+1}",
                node_id=node.node_id,
                evidence_kind=str(node.node_type),
                file_path=node.file_path,
                line_number=node.line_number,
                statement=node.statement,
                variable_name=node.variable_name,
                variable_version=node.variable_version,
                call_context=node.call_context,
                branch_polarity=node.branch_polarity,
                proof_status=node.proof_status,
                description=node.description,
            )
            chain.append(step)

        # 2. Categorize primary root cause based on evidence properties
        category: RootCauseCategory

        if ctx.verdict_status == "UNKNOWN" or "NO_VERDICT_OBJECT" in ctx.verdict_reasons:
            category = RootCauseCategory.UNKNOWN_ROOT_CAUSE
        elif ctx.sanitizer_evidence:
            # Sanitizer present but finding is VULNERABLE -> Incompatible for this sink category
            category = RootCauseCategory.INCOMPATIBLE_SANITIZATION
        elif ctx.guard_evidence and ctx.verdict_status == "VULNERABLE":
            category = RootCauseCategory.CONTROL_FLOW_GUARD_FAILURE
        elif ctx.cross_file:
            category = RootCauseCategory.CROSS_FILE_PROPAGATION
        elif len(ctx.provenance_path) > 2:
            category = RootCauseCategory.INTERPROCEDURAL_PROPAGATION
        elif "#" in ctx.variable_version and not ctx.variable_version.endswith("#1"):
            category = RootCauseCategory.SSA_REASSIGNMENT
        elif ctx.verdict_status == "VULNERABLE":
            category = RootCauseCategory.MISSING_SANITIZATION
        else:
            category = RootCauseCategory.UNKNOWN_ROOT_CAUSE

        # 3. Identify Primary Cause Step (earliest step responsible)
        primary_step: RootCauseStep | None = None

        if category == RootCauseCategory.INCOMPATIBLE_SANITIZATION:
            for step in chain:
                if step.evidence_kind == GraphNodeType.SANITIZER.value:
                    primary_step = step
                    break
        elif category == RootCauseCategory.CONTROL_FLOW_GUARD_FAILURE:
            for step in chain:
                if step.evidence_kind == GraphNodeType.GUARD.value:
                    primary_step = step
                    break
        elif category == RootCauseCategory.CROSS_FILE_PROPAGATION or category == RootCauseCategory.INTERPROCEDURAL_PROPAGATION:
            for step in chain:
                if step.evidence_kind in (GraphNodeType.CROSS_FILE.value, GraphNodeType.CALL.value):
                    primary_step = step
                    break

        if primary_step is None and chain:
            # Default primary cause step is source or first step
            primary_step = chain[0]

        return category, primary_step, tuple(chain)
