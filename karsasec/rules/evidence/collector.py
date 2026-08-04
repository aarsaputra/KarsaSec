"""Evidence collection structures for dynamic security confidence calculation."""

from dataclasses import dataclass, field
from typing import List, Optional
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.schema import Rule

@dataclass(slots=True)
class EvidenceItem:
    """Individual evidence artifact contributing positive or negative weight to security confidence."""
    description: str
    score_impact: int
    evidence_type: str  # "SINK", "SOURCE", "SANITIZER", "FRAMEWORK"

@dataclass(slots=True)
class EvidenceReport:
    """Report summarizing collected evidence items and computed total score."""
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    total_score: int = 0

class EvidenceCollector:
    """Extracts security evidence items from matched AST nodes and source context."""

    def collect(
        self,
        node: ASTNode,
        rule: Rule,
        source_bytes: Optional[bytes] = None,
        matched_symbol: Optional[str] = None,
    ) -> EvidenceReport:
        """Gathers evidence items based on matched symbol, node properties, and rule evidence specifications."""
        items: List[EvidenceItem] = []

        # 1. Dangerous Sink Evidence
        sink_symbol = matched_symbol or (rule.condition.symbol_triggers[0] if rule.condition.symbol_triggers else "dangerous_sink")
        items.append(
            EvidenceItem(
                description=f"Matched dangerous sink symbol '{sink_symbol}'",
                score_impact=40,
                evidence_type="SINK",
            )
        )

        # 2. Rule Evidence Weights (Schema v2)
        if rule.evidence and rule.evidence.score_weights:
            for ev_name, weight in rule.evidence.score_weights.items():
                items.append(
                    EvidenceItem(
                        description=f"Rule evidence specification weight: {ev_name}",
                        score_impact=weight,
                        evidence_type="RULE_WEIGHT",
                    )
                )

        total_score = sum(item.score_impact for item in items)
        return EvidenceReport(evidence_items=items, total_score=total_score)
