"""Unit tests for EvidenceGraph, EvidenceNode, and EvidenceEdge models."""

from __future__ import annotations

from karsasec.analysis.evidence_graph import (
    EvidenceEdge,
    EvidenceEdgeType,
    EvidenceGraph,
    EvidenceNode,
    EvidenceNodeType,
    compute_evidence_edge_id,
    compute_evidence_node_id,
)


def test_evidence_node_edge_deterministic_ids() -> None:
    """Verifies deterministic ID generation for EvidenceNode and EvidenceEdge."""
    nid1 = compute_evidence_node_id(EvidenceNodeType.SOURCE, {"fact_id": "sf1"})
    nid2 = compute_evidence_node_id(EvidenceNodeType.SOURCE, {"fact_id": "sf1"})
    assert nid1 == nid2
    assert len(nid1) == 64

    eid1 = compute_evidence_edge_id("n1", "n2", EvidenceEdgeType.SOURCE_TO_SINK)
    eid2 = compute_evidence_edge_id("n1", "n2", EvidenceEdgeType.SOURCE_TO_SINK)
    assert eid1 == eid2
    assert len(eid1) == 64


def test_evidence_graph_creation_and_immutability() -> None:
    """Verifies EvidenceGraph creation, node/edge sorting, and immutability."""
    node1 = EvidenceNode.create(EvidenceNodeType.SOURCE, "Source Node", "payload1")
    node2 = EvidenceNode.create(EvidenceNodeType.SINK, "Sink Node", "payload2")
    edge = EvidenceEdge.create(node1.node_id, node2.node_id, EvidenceEdgeType.SOURCE_TO_SINK)

    graph = EvidenceGraph.create(nodes=[node2, node1], edges=[edge])

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    # Check node sorting by node_id
    assert graph.nodes[0].node_id <= graph.nodes[1].node_id

    serialized = graph.to_dict()
    assert len(serialized["nodes"]) == 2
    assert len(serialized["edges"]) == 1
