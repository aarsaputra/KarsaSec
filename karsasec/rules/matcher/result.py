"""Immutable RuleMatch model representing rule evaluation outcome."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleMatch:
    """Immutable result representing the evaluation of a Rule against an ASTNode."""
    matched: bool
    rule_id: str
    node_id: str
    matched_symbol: str | None = None
    matched_text: str | None = None
    matched_predicates: tuple[str, ...] = field(default_factory=tuple)
    failure_reason: str | None = None
    evaluation_time_ns: int = 0
