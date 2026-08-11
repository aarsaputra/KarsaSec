"""Deterministic Graph Security Rule Engine evaluating FrameworkSemanticGraph against declarative GraphSecurityRule definitions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from karsasec.core.finding.collection import FindingCollection
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.framework.framework_semantics.rules.predicates import (
    GraphRuleEvaluationContext,
    evaluate_condition_block,
)
from karsasec.framework.framework_semantics.rules.registry import GraphRuleRegistry
from karsasec.framework.framework_semantics.rules.schema import GraphSecurityRule
from karsasec.framework.semantic_models import FrameworkSemanticGraph, FrameworkSemanticNode


def compute_graph_finding_fingerprint(
    rule_id: str,
    primary_node_id: str,
    evidence_node_ids: Sequence[str],
    evidence_edge_ids: Sequence[str],
) -> str:
    """Computes a 100% deterministic SHA-256 fingerprint for finding identity and deduplication."""
    canonical_payload = [
        rule_id,
        primary_node_id,
        sorted(list(set(evidence_node_ids))),
        sorted(list(set(evidence_edge_ids))),
    ]
    raw_bytes = json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw_bytes).hexdigest()[:32]


class GraphSecurityRuleEngine:
    """Deterministic Graph Security Rule Engine evaluating semantic rules against FrameworkSemanticGraph."""

    def __init__(self, registry: GraphRuleRegistry | None = None) -> None:
        self.registry = registry or GraphRuleRegistry()

    def evaluate(
        self,
        graph: FrameworkSemanticGraph,
        rules: Sequence[GraphSecurityRule] | None = None,
    ) -> FindingCollection:
        """Evaluates graph against specified rules (or all registered rules) and returns FindingCollection.

        The evaluation is 100% deterministic and byte-for-byte identical across runs and input orderings.
        """
        eval_rules = list(rules) if rules is not None else list(self.registry.list_rules())
        # Canonical rule ordering
        eval_rules.sort(key=lambda r: r.id)

        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for rule in eval_rules:
            # Filter candidate target nodes in graph ordered deterministically by node ID
            candidate_nodes = graph.filter(rule.target_node_type)

            for target_node in candidate_nodes:
                ctx = GraphRuleEvaluationContext(
                    graph=graph,
                    max_depth=rule.traversal.max_depth,
                    max_nodes_visited=rule.traversal.max_nodes_visited,
                    max_edges_examined=rule.traversal.max_edges_examined,
                )

                res = evaluate_condition_block(target_node, rule.conditions, ctx, depth=0)
                if res.matched:
                    all_ev_nodes = tuple(sorted(set([target_node.id] + list(res.evidence_node_ids))))
                    all_ev_edges = tuple(sorted(set(res.evidence_edge_ids)))

                    fingerprint = compute_graph_finding_fingerprint(
                        rule_id=rule.id,
                        primary_node_id=target_node.id,
                        evidence_node_ids=all_ev_nodes,
                        evidence_edge_ids=all_ev_edges,
                    )

                    if fingerprint in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fingerprint)

                    finding = self._create_finding(rule, target_node, fingerprint, all_ev_nodes, all_ev_edges)
                    findings.append(finding)

        # Sort findings deterministically by fingerprint
        sorted_findings = tuple(sorted(findings, key=lambda f: f.fingerprint))
        return FindingCollection(findings=sorted_findings)

    def _create_finding(
        self,
        rule: GraphSecurityRule,
        node: FrameworkSemanticNode,
        fingerprint: str,
        evidence_node_ids: tuple[str, ...],
        evidence_edge_ids: tuple[str, ...],
    ) -> Finding:
        loc = node.origin.location_info
        file_path = Path(loc.file_path) if loc and loc.file_path else Path("framework/graph")
        line = loc.line if loc and loc.line > 0 else 1
        column = loc.column if loc and loc.column > 0 else 1

        cwe = str(rule.metadata.get("cwe", "CWE-20"))
        owasp = str(rule.metadata.get("owasp", "A07:2021-Identification and Authentication Failures"))
        title = str(rule.metadata.get("name", rule.id))

        message = rule.output.message.format(node=node) if "{node." in rule.output.message else rule.output.message

        ev_meta = {
            "primary_node_id": node.id,
            "primary_node_type": node.node_type.value,
            "evidence_node_ids": list(evidence_node_ids),
            "evidence_edge_ids": list(evidence_edge_ids),
        }

        evidence = Evidence(
            snippet=node.name,
            line=line,
            column=column,
            context_lines=(),
            metadata=ev_meta,
        )

        return Finding(
            finding_id=f"finding-{fingerprint[:8]}",
            rule_id=rule.id,
            fingerprint=fingerprint,
            title=title,
            severity=rule.output.severity,
            confidence=rule.output.confidence,
            cwe_id=cwe,
            owasp=owasp,
            file_path=file_path,
            evidence=evidence,
            description=message,
            remediation=rule.output.remediation,
            rule_version=rule.version,
            metadata={
                "framework": rule.framework,
                "node_id": node.id,
                "node_type": node.node_type.value,
            },
        )
