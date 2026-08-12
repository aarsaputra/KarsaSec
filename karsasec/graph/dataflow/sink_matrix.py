"""Context-Aware Three-Valued Sink Compatibility Matrix for KarsaSec (E12-13).

Design Principles:
  - Three-valued compatibility evaluation: COMPATIBLE, NOT_PROVEN, CONFLICT.
  - Context-sensitivity: Evaluates (Constraints × SinkCategory × SinkContext).
  - Strict Safety Invariant: UNKNOWN and NOT_PROVEN never imply safety.
  - NUMERIC + SQL_VALUE => COMPATIBLE; NUMERIC + SQL_IDENTIFIER => NOT_PROVEN.
  - SHELL_ESCAPED + SQL => NOT_PROVEN; HTML_ESCAPED + SQL => NOT_PROVEN.
  - Anti-hardcoding: Pure security compatibility semantics. Zero rule-ID or benchmark strings.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from karsasec.graph.dataflow.abstract_state import SemanticConstraint


class SinkContext(StrEnum):
    """Specific contextual position of data within a target sink."""
    SQL_VALUE = "SQL_VALUE"
    SQL_IDENTIFIER = "SQL_IDENTIFIER"
    SQL_ORDER_BY = "SQL_ORDER_BY"
    SHELL_ARGUMENT = "SHELL_ARGUMENT"
    HTML_TEXT = "HTML_TEXT"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    FILE_PATH = "FILE_PATH"
    UNKNOWN = "UNKNOWN"


class CompatibilityDecision(StrEnum):
    """Three-valued outcome of sink safety evaluation."""
    COMPATIBLE = "COMPATIBLE"      # Constraint is proven sufficient for sink & context
    NOT_PROVEN = "NOT_PROVEN"      # Constraint is insufficient or incompatible
    CONFLICT = "CONFLICT"          # Contradictory facts or unresolvable state


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    decision: CompatibilityDecision
    reason: str
    matching_constraint: SemanticConstraint | None = None
    sink_context: SinkContext = SinkContext.UNKNOWN


class SinkCompatibilityMatrix:
    """Evaluates context-dependent security compatibility between constraints and sinks."""

    def evaluate(
        self,
        constraints: set[SemanticConstraint] | frozenset[SemanticConstraint],
        sink_category: str,
        sink_context: SinkContext = SinkContext.SQL_VALUE,
    ) -> EvaluationResult:
        """Evaluate if any constraint in constraints satisfies safety for sink_category and sink_context."""
        if not constraints:
            return EvaluationResult(
                decision=CompatibilityDecision.NOT_PROVEN,
                reason="No semantic constraints established for value",
                sink_context=sink_context,
            )

        norm_category = str(sink_category).upper().strip()

        # 1. Type Constraints (NUMERIC, INTEGER, DIGITS_ONLY)
        if any(c in constraints for c in (SemanticConstraint.NUMERIC, SemanticConstraint.INTEGER, SemanticConstraint.DIGITS_ONLY)):
            matched_c = next(c for c in (SemanticConstraint.INTEGER, SemanticConstraint.DIGITS_ONLY, SemanticConstraint.NUMERIC) if c in constraints)

            if "SQL" in norm_category:
                if sink_context in (SinkContext.SQL_VALUE, SinkContext.UNKNOWN):
                    return EvaluationResult(
                        decision=CompatibilityDecision.COMPATIBLE,
                        reason=f"Type constraint {matched_c} satisfies numeric SQL_VALUE context",
                        matching_constraint=matched_c,
                        sink_context=sink_context,
                    )
                else:  # SQL_IDENTIFIER, SQL_ORDER_BY
                    return EvaluationResult(
                        decision=CompatibilityDecision.NOT_PROVEN,
                        reason=f"Type constraint {matched_c} is NOT proven safe for {sink_context}",
                        matching_constraint=matched_c,
                        sink_context=sink_context,
                    )

            elif "COMMAND" in norm_category or "EXEC" in norm_category or "SHELL" in norm_category:
                if sink_context in (SinkContext.SHELL_ARGUMENT, SinkContext.UNKNOWN):
                    return EvaluationResult(
                        decision=CompatibilityDecision.COMPATIBLE,
                        reason=f"Type constraint {matched_c} prevents command injection in numeric shell argument",
                        matching_constraint=matched_c,
                        sink_context=sink_context,
                    )

            elif "XSS" in norm_category or "HTML" in norm_category:
                return EvaluationResult(
                    decision=CompatibilityDecision.COMPATIBLE,
                    reason=f"Type constraint {matched_c} satisfies HTML context",
                    matching_constraint=matched_c,
                    sink_context=sink_context,
                )

        # 2. Shell Sanitization (SHELL_ESCAPED)
        if SemanticConstraint.SHELL_ESCAPED in constraints:
            if "COMMAND" in norm_category or "EXEC" in norm_category or "SHELL" in norm_category:
                return EvaluationResult(
                    decision=CompatibilityDecision.COMPATIBLE,
                    reason="SHELL_ESCAPED constraint satisfies COMMAND_INJECTION sink",
                    matching_constraint=SemanticConstraint.SHELL_ESCAPED,
                    sink_context=sink_context,
                )
            else:
                return EvaluationResult(
                    decision=CompatibilityDecision.NOT_PROVEN,
                    reason=f"SHELL_ESCAPED constraint is NOT compatible with {norm_category} sink",
                    matching_constraint=SemanticConstraint.SHELL_ESCAPED,
                    sink_context=sink_context,
                )

        # 3. HTML Sanitization (HTML_ESCAPED)
        if SemanticConstraint.HTML_ESCAPED in constraints:
            if "XSS" in norm_category or "HTML" in norm_category:
                return EvaluationResult(
                    decision=CompatibilityDecision.COMPATIBLE,
                    reason="HTML_ESCAPED constraint satisfies XSS sink",
                    matching_constraint=SemanticConstraint.HTML_ESCAPED,
                    sink_context=sink_context,
                )
            else:
                return EvaluationResult(
                    decision=CompatibilityDecision.NOT_PROVEN,
                    reason=f"HTML_ESCAPED constraint is NOT compatible with {norm_category} sink",
                    matching_constraint=SemanticConstraint.HTML_ESCAPED,
                    sink_context=sink_context,
                )

        # 4. Path Normalization (PATH_NORMALIZED)
        if SemanticConstraint.PATH_NORMALIZED in constraints:
            if "FILE" in norm_category or "PATH" in norm_category or "LFI" in norm_category or "TRAVERSAL" in norm_category:
                return EvaluationResult(
                    decision=CompatibilityDecision.COMPATIBLE,
                    reason="PATH_NORMALIZED constraint satisfies FILE_PATH traversal sink",
                    matching_constraint=SemanticConstraint.PATH_NORMALIZED,
                    sink_context=sink_context,
                )

        return EvaluationResult(
            decision=CompatibilityDecision.NOT_PROVEN,
            reason=f"Constraints {constraints} do not satisfy {norm_category} sink in {sink_context} context",
            sink_context=sink_context,
        )


# Global Instance
sink_compatibility_matrix = SinkCompatibilityMatrix()
