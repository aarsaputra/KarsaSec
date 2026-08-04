"""Immutable RuleMatch model representing rule evaluation outcome."""

from dataclasses import dataclass, field
from typing import Optional, Tuple

@dataclass(frozen=True)
class RuleMatch:
    """Immutable result representing the evaluation of a Rule against an ASTNode."""
    matched: bool
    rule_id: str
    node_id: str
    matched_symbol: Optional[str] = None
    matched_text: Optional[str] = None
    matched_predicates: Tuple[str, ...] = field(default_factory=tuple)
    failure_reason: Optional[str] = None
    evaluation_time_ns: int = 0
