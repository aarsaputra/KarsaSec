"""Pre-emission graph invariant validator."""

from __future__ import annotations

from karsasec.framework.framework_semantics.correlation.diagnostics import create_invariant_diagnostic
from karsasec.framework.framework_semantics.correlation.state import CorrelationState


class GraphValidator:
    """Enforces graph invariants before graph emission."""

    @staticmethod
    def validate(state: CorrelationState) -> bool:
        """Validate state invariants. Emits Severity.ERROR diagnostics on violation. Returns True if valid."""
        is_valid = True
        node_ids = set(state.nodes.keys())

        # Check node ID uniqueness (dictionary inherently ensures unique keys)
        for candidate in state.candidates:
            if candidate.source_id not in node_ids:
                diag = create_invariant_diagnostic(
                    message=f"Edge source_id '{candidate.source_id}' does not exist in graph nodes.",
                    evidence=f"Edge target: {candidate.target_id}, Type: {candidate.edge_type}",
                )
                state.add_diagnostic(diag)
                is_valid = False

            if candidate.target_id not in node_ids:
                diag = create_invariant_diagnostic(
                    message=f"Edge target_id '{candidate.target_id}' does not exist in graph nodes.",
                    evidence=f"Edge source: {candidate.source_id}, Type: {candidate.edge_type}",
                )
                state.add_diagnostic(diag)
                is_valid = False

            if candidate.source_id == candidate.target_id:
                diag = create_invariant_diagnostic(
                    message=f"Invalid self-edge detected for node ID '{candidate.source_id}'.",
                    evidence=f"Type: {candidate.edge_type}",
                )
                state.add_diagnostic(diag)
                is_valid = False

        return is_valid
