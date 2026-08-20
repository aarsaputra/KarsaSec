"""Evidence Conflict model and classification for contradictory evidence handling (E12-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ConflictCategory(StrEnum):
    """Categories of evidence conflict when combining candidate findings or taint analysis paths."""

    TAINT_STATE_CONFLICT = "TAINT_STATE_CONFLICT"
    SANITIZER_CONFLICT = "SANITIZER_CONFLICT"
    SINK_CATEGORY_CONFLICT = "SINK_CATEGORY_CONFLICT"
    SOURCE_CATEGORY_CONFLICT = "SOURCE_CATEGORY_CONFLICT"
    QUALIFICATION_CONFLICT = "QUALIFICATION_CONFLICT"
    RULE_EVIDENCE_CONFLICT = "RULE_EVIDENCE_CONFLICT"


@dataclass(frozen=True)
class EvidenceConflict:
    """Immutable representation of contradictory security evidence across rules or taint flows (E12-4).

    Invariant: CONFLICT → UNKNOWN / UNRESOLVED.
    Evidence conflicts must never be silently resolved into false certainty.
    """

    conflict_type: ConflictCategory
    evidence_a: Any
    evidence_b: Any
    originating_rules: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""
    resolution: str = "UNRESOLVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_type": self.conflict_type.value
            if isinstance(self.conflict_type, ConflictCategory)
            else str(self.conflict_type),
            "evidence_a": self.evidence_a.to_dict() if hasattr(self.evidence_a, "to_dict") else str(self.evidence_a),
            "evidence_b": self.evidence_b.to_dict() if hasattr(self.evidence_b, "to_dict") else str(self.evidence_b),
            "originating_rules": list(self.originating_rules),
            "reason": self.reason,
            "resolution": self.resolution,
        }


def detect_evidence_conflict(
    ev_a: Any,
    ev_b: Any,
    rule_a: str = "",
    rule_b: str = "",
) -> EvidenceConflict | None:
    """Detects whether two evidence items or qualification outcomes contain contradictory claims."""
    if ev_a is None or ev_b is None:
        return None

    # Check qualification state conflict (e.g. CONFIRMED vs REJECTED)
    state_a = getattr(ev_a, "qualification_state", None) or getattr(ev_a, "state", None)
    state_b = getattr(ev_b, "qualification_state", None) or getattr(ev_b, "state", None)

    rules = tuple(sorted({r for r in (rule_a, rule_b) if r}))

    if state_a and state_b and str(state_a) != str(state_b):
        if {str(state_a), str(state_b)} == {"CONFIRMED", "REJECTED"}:
            return EvidenceConflict(
                conflict_type=ConflictCategory.QUALIFICATION_CONFLICT,
                evidence_a=ev_a,
                evidence_b=ev_b,
                originating_rules=rules,
                reason=f"Rule/qualification disagreement: {state_a} vs {state_b}.",
                resolution="UNRESOLVED",
            )

    # Check taint state conflict (e.g. TAINTED vs SANITIZED)
    ts_a = getattr(ev_a, "taint_state", None)
    ts_b = getattr(ev_b, "taint_state", None)
    if ts_a and ts_b and str(ts_a) != str(ts_b):
        if {str(ts_a), str(ts_b)} == {"TAINTED", "SANITIZED"}:
            return EvidenceConflict(
                conflict_type=ConflictCategory.TAINT_STATE_CONFLICT,
                evidence_a=ev_a,
                evidence_b=ev_b,
                originating_rules=rules,
                reason=f"Contradictory taint state: {ts_a} vs {ts_b}.",
                resolution="UNRESOLVED",
            )

    return None
