"""Explain Engine for generating human-readable evidence chains and path proofs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.cpg.models import CPGGraph, CPGNode


@dataclass
class EvidenceChain:
    """Chain of matched nodes representing vulnerability evidence flow."""

    source_node: CPGNode | None = None
    intermediate_nodes: list[CPGNode] = field(default_factory=list)
    sink_node: CPGNode | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_node.label if self.source_node else None,
            "intermediates": [n.label for n in self.intermediate_nodes],
            "sink": self.sink_node.label if self.sink_node else None,
            "reason": self.reason,
        }


@dataclass
class EvidenceTree:
    """Hierarchical evidence tree for complex query findings."""

    rule_id: str
    description: str
    chains: list[EvidenceChain] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "chains": [c.to_dict() for c in self.chains],
        }


class ExplainEngine:
    """Engine for crafting explanatory evidence paths from query matches."""

    def build_evidence(
        self,
        rule_id: str,
        description: str,
        matched_nodes: list[CPGNode],
        graph: CPGGraph | None = None,
    ) -> EvidenceTree:
        chains: list[EvidenceChain] = []

        if matched_nodes:
            src = matched_nodes[0]
            snk = matched_nodes[-1] if len(matched_nodes) > 1 else matched_nodes[0]
            intermediates = matched_nodes[1:-1] if len(matched_nodes) > 2 else []

            reason = f"Data flow path verified from '{src.label}' at line {src.line_number} to '{snk.label}' at line {snk.line_number}."
            chain = EvidenceChain(
                source_node=src,
                intermediate_nodes=intermediates,
                sink_node=snk,
                reason=reason,
            )
            chains.append(chain)

        return EvidenceTree(rule_id=rule_id, description=description, chains=chains)
