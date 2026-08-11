"""Immutable Evidence, FindingEvidence, and EvidenceCompleteness models (E12-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.graph.dataflow.model import TaintPathHop, TaintState


class ProvenanceStatus(StrEnum):
    """Explicit status for evidence provenance fields."""
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class Evidence:
    """Immutable evidence representation containing vulnerable code snippet and context lines."""
    snippet: str
    line: int
    column: int
    context_lines: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet": self.snippet,
            "line": self.line,
            "column": self.column,
            "context_lines": list(self.context_lines),
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class FindingEvidence:
    """Enriched evidence provenance capturing deep data-flow, sink semantics, and sanitizer details (E12-4)."""
    snippet: str
    line: int
    column: int
    rule_id: str = ""
    node_type: str = "UNKNOWN"
    matched_text: str = ""
    sink_symbol: str = ""
    sink_category: str = "UNKNOWN"
    source_symbol: str = ""
    source_category: str = "UNKNOWN"
    taint_state: TaintState = TaintState.UNKNOWN
    constant_resolution: str = "UNKNOWN"
    sanitizer_symbol: str = ""
    sanitizer_capability: str = "NONE"
    taint_path: tuple[TaintPathHop, ...] = field(default_factory=tuple)
    ast_match: bool = True
    semantic_match: bool = False
    qualification_state: str = "UNKNOWN"
    rejection_reason: str = ""
    context_lines: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet": self.snippet,
            "line": self.line,
            "column": self.column,
            "rule_id": self.rule_id,
            "node_type": self.node_type,
            "matched_text": self.matched_text,
            "sink_symbol": self.sink_symbol,
            "sink_category": self.sink_category,
            "source_symbol": self.source_symbol,
            "source_category": self.source_category,
            "taint_state": self.taint_state.value if isinstance(self.taint_state, TaintState) else str(self.taint_state),
            "constant_resolution": self.constant_resolution,
            "sanitizer_symbol": self.sanitizer_symbol,
            "sanitizer_capability": self.sanitizer_capability,
            "taint_path": [hop.to_dict() if hasattr(hop, "to_dict") else str(hop) for hop in self.taint_path],
            "ast_match": self.ast_match,
            "semantic_match": self.semantic_match,
            "qualification_state": self.qualification_state,
            "rejection_reason": self.rejection_reason,
            "context_lines": list(self.context_lines),
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class EvidenceCompleteness:
    """Deterministic validator assessing whether evidence is structurally complete for qualification (E12-4)."""

    is_complete: bool
    status: ProvenanceStatus
    missing_fields: tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""

    @classmethod
    def evaluate(cls, evidence: FindingEvidence | None, target_state: str = "CONFIRMED") -> EvidenceCompleteness:
        """Evaluates whether evidence is complete for target qualification state.

        Missing evidence must never be converted into false certainty or default safety.
        """
        if evidence is None:
            return cls(
                is_complete=False,
                status=ProvenanceStatus.UNKNOWN,
                missing_fields=("evidence",),
                explanation="No evidence object associated with finding.",
            )

        missing: list[str] = []
        if not evidence.snippet:
            missing.append("snippet")
        if evidence.line <= 0:
            missing.append("line")

        state_upper = target_state.upper()
        if state_upper == "CONFIRMED":
            if evidence.sink_category in ("", "UNKNOWN") and not evidence.sink_symbol:
                missing.append("sink_category/symbol")

        elif state_upper == "REJECTED":
            if not evidence.rejection_reason:
                missing.append("rejection_reason")

        if missing:
            return cls(
                is_complete=False,
                status=ProvenanceStatus.UNKNOWN,
                missing_fields=tuple(missing),
                explanation=f"Evidence is missing required fields for {state_upper}: {', '.join(missing)}.",
            )

        return cls(
            is_complete=True,
            status=ProvenanceStatus.KNOWN,
            missing_fields=(),
            explanation=f"Evidence complete and valid for {state_upper}.",
        )
