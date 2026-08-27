"""FindingCorrelator implementing O(F+C) candidate indexing, Disjoint-Set / Union-Find correlation, evidence graph construction, and evidence compatibility guards for Sprint E13."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from typing import TYPE_CHECKING

from karsasec.analysis.confidence_calibrator import ConfidenceCalibrator
from karsasec.analysis.evidence_graph import (
    EvidenceEdge,
    EvidenceEdgeType,
    EvidenceGraph,
    EvidenceNode,
    EvidenceNodeType,
)
from karsasec.analysis.vulnerability_cluster import VulnerabilityCluster

if TYPE_CHECKING:
    from karsasec.analysis.security_finding import SecurityFinding
    from karsasec.analysis.security_finding_store import SecurityFindingStore

logger = logging.getLogger("karsasec.analysis.finding_correlator")


class UnionFind:
    """Deterministic Disjoint-Set / Union-Find (DSU) algorithm with path compression."""

    def __init__(self, elements: Sequence[str]) -> None:
        self.parent: dict[str, str] = {e: e for e in elements}

    def find(self, i: str) -> str:
        if self.parent[i] == i:
            return i
        self.parent[i] = self.find(self.parent[i])
        return self.parent[i]

    def union(self, i: str, j: str) -> None:
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            # Deterministic union order (smaller lex string becomes parent)
            if root_i < root_j:
                self.parent[root_j] = root_i
            else:
                self.parent[root_i] = root_j

    def components(self) -> list[list[str]]:
        groups: dict[str, list[str]] = defaultdict(list)
        for elem in self.parent:
            root = self.find(elem)
            groups[root].append(elem)
        return [sorted(group) for group in sorted(groups.values(), key=lambda g: sorted(g)[0])]


def evidence_compatible(a: SecurityFinding, b: SecurityFinding) -> bool:
    """Evaluates explicit evidence compatibility guard between two findings.

    INV-E13-CORR-26: Shared source alone MUST NOT merge unrelated sink vulnerabilities.
    INV-E13-CORR-10: Cross vulnerability-class isolation MUST be enforced.
    """
    # 1. Vulnerability class must match
    if a.vulnerability_class != b.vulnerability_class:
        return False

    # 2. Same flow ID -> Compatible
    if a.flow_id == b.flow_id and a.flow_id != "missing_flow":
        return True

    # 3. Same source fact AND same sink fact -> Compatible
    if (
        a.source_fact_id == b.source_fact_id
        and a.sink_fact_id == b.sink_fact_id
        and a.source_fact_id != "missing_source"
    ):
        return True

    # 4. Same source node AND same sink node -> Compatible
    if (
        a.source_node_id == b.source_node_id
        and a.sink_node_id == b.sink_node_id
        and a.source_node_id != "missing_node"
    ):
        return True

    # 5. Extract call context from forensic evidence if available
    a_context = dict(a.flow_evidence).get("call_context")
    b_context = dict(b.flow_evidence).get("call_context")
    if (
        a.source_fact_id == b.source_fact_id
        and a.vulnerability_class == b.vulnerability_class
        and a_context is not None
        and a_context == b_context
    ):
        return True

    return False


def build_cluster_evidence_graph(
    findings: Sequence[SecurityFinding],
    cluster_id: str,
) -> EvidenceGraph:
    """Constructs an EvidenceGraph representing the complete evidence chain for a cluster.

    INV-E13-CORR-34: EvidenceGraph MUST NOT mutate CPGGraph.
    """
    nodes: list[EvidenceNode] = []
    edges: list[EvidenceEdge] = []

    # Cluster node
    cluster_node = EvidenceNode.create(
        node_type=EvidenceNodeType.CLUSTER,
        label=f"Cluster:{cluster_id[:8]}",
        identity_payload=cluster_id,
        attributes={"cluster_id": cluster_id},
    )
    nodes.append(cluster_node)

    for f in findings:
        # Finding node
        f_node = EvidenceNode.create(
            node_type=EvidenceNodeType.FINDING,
            label=f"Finding:{f.rule_key}",
            identity_payload=f.finding_id,
            attributes={"finding_id": f.finding_id, "rule_key": f.rule_key, "severity": f.severity},
        )
        nodes.append(f_node)

        # Finding -> Cluster Edge
        edges.append(
            EvidenceEdge.create(
                source_node_id=f_node.node_id,
                target_node_id=cluster_node.node_id,
                edge_type=EvidenceEdgeType.FINDING_SUPPORTS_CLUSTER,
            )
        )

        # Source node
        src_node = EvidenceNode.create(
            node_type=EvidenceNodeType.SOURCE,
            label=f"Source:{f.source_node_id}",
            identity_payload=f.source_fact_id,
            attributes={"fact_id": f.source_fact_id, "node_id": f.source_node_id},
        )
        nodes.append(src_node)

        # Sink node
        snk_node = EvidenceNode.create(
            node_type=EvidenceNodeType.SINK,
            label=f"Sink:{f.sink_node_id}",
            identity_payload=f.sink_fact_id,
            attributes={"fact_id": f.sink_fact_id, "node_id": f.sink_node_id},
        )
        nodes.append(snk_node)

        # Source -> Sink Edge
        edges.append(
            EvidenceEdge.create(
                source_node_id=src_node.node_id,
                target_node_id=snk_node.node_id,
                edge_type=EvidenceEdgeType.SOURCE_TO_SINK,
            )
        )

        # Finding -> Source/Sink Edges
        edges.append(
            EvidenceEdge.create(
                source_node_id=f_node.node_id,
                target_node_id=src_node.node_id,
                edge_type=EvidenceEdgeType.FINDING_SUPPORTS_FLOW,
            )
        )

        # Sanitizer node (if present)
        san_dict = dict(f.sanitizer_evidence)
        if san_dict.get("has_valid_barrier") == "True":
            b_name = san_dict.get("barrier_name", "barrier")
            san_node = EvidenceNode.create(
                node_type=EvidenceNodeType.SANITIZER,
                label=f"Sanitizer:{b_name}",
                identity_payload=f"{f.finding_id}:{b_name}",
                attributes={"barrier_name": b_name},
            )
            nodes.append(san_node)
            edges.append(
                EvidenceEdge.create(
                    source_node_id=src_node.node_id,
                    target_node_id=san_node.node_id,
                    edge_type=EvidenceEdgeType.SANITIZER_ON_FLOW,
                )
            )

    return EvidenceGraph.create(nodes=nodes, edges=edges)


class FindingCorrelator:
    """Correlates security findings into vulnerability clusters using indexed retrieval and DSU component merging."""

    def __init__(self, calibrator: ConfidenceCalibrator | None = None) -> None:
        self.calibrator = calibrator or ConfidenceCalibrator()

    def correlate(
        self,
        finding_source: Sequence[SecurityFinding] | SecurityFindingStore,
    ) -> tuple[VulnerabilityCluster, ...]:
        """Correlates findings into VulnerabilityClusters in O(F + C) target complexity.

        Returns deterministically sorted clusters.
        """
        findings = finding_source.all() if hasattr(finding_source, "all") else list(finding_source)
        if not findings:
            return ()

        # 1. Normalize findings and sort deterministically by finding_id
        sorted_findings = sorted(findings, key=lambda f: f.finding_id)
        finding_map = {f.finding_id: f for f in sorted_findings}

        # 2. Build Candidate Indexes (O(F) construction)
        source_index: dict[str, list[SecurityFinding]] = defaultdict(list)
        sink_index: dict[str, list[SecurityFinding]] = defaultdict(list)
        flow_index: dict[str, list[SecurityFinding]] = defaultdict(list)
        node_pair_index: dict[tuple[str, str], list[SecurityFinding]] = defaultdict(list)

        for f in sorted_findings:
            source_index[f.source_fact_id].append(f)
            sink_index[f.sink_fact_id].append(f)
            flow_index[f.flow_id].append(f)
            node_pair_index[(f.source_node_id, f.sink_node_id)].append(f)

        # 3. Generate Candidate Pairs (O(C) candidate retrieval)
        candidate_pairs: set[tuple[str, str]] = set()

        for group in source_index.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    pair = tuple(sorted((group[i].finding_id, group[j].finding_id)))
                    candidate_pairs.add((pair[0], pair[1]))

        for group in sink_index.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    pair = tuple(sorted((group[i].finding_id, group[j].finding_id)))
                    candidate_pairs.add((pair[0], pair[1]))

        for group in flow_index.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    pair = tuple(sorted((group[i].finding_id, group[j].finding_id)))
                    candidate_pairs.add((pair[0], pair[1]))

        for group in node_pair_index.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    pair = tuple(sorted((group[i].finding_id, group[j].finding_id)))
                    candidate_pairs.add((pair[0], pair[1]))

        # 4. Union-Find Component Merging
        uf = UnionFind([f.finding_id for f in sorted_findings])

        for f1_id, f2_id in sorted(candidate_pairs):
            f1 = finding_map[f1_id]
            f2 = finding_map[f2_id]
            if evidence_compatible(f1, f2):
                uf.union(f1_id, f2_id)

        # 5. Build VulnerabilityCluster for each component
        components = uf.components()
        clusters: list[VulnerabilityCluster] = []

        for component_ids in components:
            comp_findings = [finding_map[fid] for fid in component_ids]

            # Primary vulnerability class from findings
            vulnerability_class = comp_findings[0].vulnerability_class

            # Calibrate confidence, status, and severity
            calib_res = self.calibrator.calibrate(comp_findings)

            # Build temporary cluster ID to construct evidence graph
            src_facts = [f.source_fact_id for f in comp_findings]
            snk_facts = [f.sink_fact_id for f in comp_findings]
            fl_ids = [f.flow_id for f in comp_findings]
            src_nodes = [f.source_node_id for f in comp_findings]
            snk_nodes = [f.sink_node_id for f in comp_findings]

            cluster = VulnerabilityCluster.create(
                vulnerability_class=vulnerability_class,
                finding_ids=component_ids,
                source_fact_ids=src_facts,
                sink_fact_ids=snk_facts,
                flow_ids=fl_ids,
                source_nodes=src_nodes,
                sink_nodes=snk_nodes,
                shared_contexts=(),
                confidence=calib_res.calibrated_confidence,
                severity=calib_res.severity,
                status=calib_res.status,
                evidence_count=len(comp_findings),
            )
            clusters.append(cluster)

        # 6. Sort clusters deterministically by cluster_id
        return tuple(sorted(clusters, key=lambda c: c.cluster_id))
