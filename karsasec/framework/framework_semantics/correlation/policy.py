"""Relationship policy layer enforcing 'No evidence, no edge' and emitting diagnostics."""

from __future__ import annotations

from typing import Any

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.framework_semantics.correlation.contracts import RelationshipCandidate, ResolutionStatus
from karsasec.framework.framework_semantics.correlation.diagnostics import (
    create_ambiguous_diagnostic,
    create_unresolved_diagnostic,
)
from karsasec.framework.framework_semantics.correlation.resolver import ResolutionResult
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType


class RelationshipPolicy:
    """Enforces relationship creation policies and converts ResolutionResult into candidates."""

    @staticmethod
    def apply_policy(
        source_id: str,
        target_ref: str,
        edge_type: SemanticEdgeType,
        resolution_result: ResolutionResult,
        state: CorrelationState,
        unresolved_code: ErrorCode = ErrorCode.MISSING_HANDLER,
        ambiguous_code: ErrorCode = ErrorCode.AMBIGUOUS_CONTROLLER,
        confidence: float = 1.0,
        attributes: dict[str, Any] | None = None,
        evidence: tuple[str, ...] = (),
    ) -> RelationshipCandidate | None:
        """Apply policy: create candidate if RESOLVED; emit diagnostic if AMBIGUOUS or UNRESOLVED."""
        if resolution_result.status == ResolutionStatus.RESOLVED and resolution_result.matched_id:
            candidate = RelationshipCandidate(
                source_id=source_id,
                target_id=resolution_result.matched_id,
                edge_type=edge_type,
                status=ResolutionStatus.RESOLVED,
                resolution_method=resolution_result.method,
                confidence=confidence,
                evidence=evidence,
                attributes=attributes or {},
            )
            state.add_candidate(candidate)
            return candidate

        elif resolution_result.status == ResolutionStatus.AMBIGUOUS:
            diag = create_ambiguous_diagnostic(
                code=ambiguous_code,
                target_name=target_ref,
                candidate_count=len(resolution_result.matched_ids),
                evidence=f"Target reference '{target_ref}' matched candidate IDs: {resolution_result.matched_ids}",
            )
            state.add_diagnostic(diag)
            return None

        else:  # UNRESOLVED
            diag = create_unresolved_diagnostic(
                code=unresolved_code,
                target_name=target_ref,
                evidence=f"No matching semantic candidate found for target reference '{target_ref}'",
            )
            state.add_diagnostic(diag)
            return None
