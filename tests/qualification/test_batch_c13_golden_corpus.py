"""Batch C13 Attack Graph Construction Golden Corpus Qualification Test Suite (250 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.attack_graph.engine import AttackGraphConstructionEngine
from karsasec.analysis.attack_graph.models import (
    AttackEdge,
    AttackNode,
    EdgeType,
    ImpactNode,
    NodeType,
)

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]


def create_fixture_graph(idx: int, category: str):
    lang = LANGUAGES[idx % len(LANGUAGES)]
    if category == "TP":
        n1 = AttackNode(f"n1_{idx}", NodeType.ROOT_CAUSE, f"ROOT_CAUSE_{idx}", "param")
        n2 = AttackNode(f"n2_{idx}", NodeType.CAPABILITY, f"CAPABILITY_{idx}", f"cap_{lang}")
        n3 = ImpactNode(f"n3_{idx}", NodeType.IMPACT, f"IMPACT_{idx}", "impact_target")
        e1 = AttackEdge(f"e1_{idx}", f"n1_{idx}", f"n2_{idx}", EdgeType.ENABLES)
        e2 = AttackEdge(f"e2_{idx}", f"n2_{idx}", f"n3_{idx}", EdgeType.EXECUTES)
        return ([n1, n2, n3], [e1, e2], "VALID")
    elif category == "TN":
        n1 = AttackNode(f"n1_{idx}", NodeType.ROOT_CAUSE, f"ROOT_CAUSE_{idx}", "param", resolution="SAFE")
        n2 = AttackNode(f"n2_{idx}", NodeType.CAPABILITY, f"CAPABILITY_{idx}", f"cap_{lang}", resolution="SAFE")
        e1 = AttackEdge(f"e1_{idx}", f"n1_{idx}", f"n2_{idx}", EdgeType.ENABLES)
        return ([n1, n2], [e1], "SAFE")
    elif category == "UNKNOWN":
        n1 = AttackNode(f"n1_{idx}", NodeType.UNKNOWN, f"UNKNOWN_CAUSE_{idx}", "param", resolution="UNKNOWN")
        n2 = AttackNode(f"n2_{idx}", NodeType.CAPABILITY, f"CAPABILITY_{idx}", f"cap_{lang}")
        e1 = AttackEdge(f"e1_{idx}", f"n1_{idx}", f"n2_{idx}", EdgeType.ENABLES)
        return ([n1, n2], [e1], "INV-C13-04_VIOLATION")
    elif category == "CYCLE":
        n1 = AttackNode(f"n1_{idx}", NodeType.ROOT_CAUSE, f"ROOT_CAUSE_{idx}", "param")
        n2 = AttackNode(f"n2_{idx}", NodeType.CAPABILITY, f"CAPABILITY_{idx}", f"cap_{lang}")
        e1 = AttackEdge(f"e1_{idx}", f"n1_{idx}", f"n2_{idx}", EdgeType.ENABLES)
        e2 = AttackEdge(f"e2_{idx}", f"n2_{idx}", f"n1_{idx}", EdgeType.ESCALATES_TO)
        return ([n1, n2], [e1, e2], "INV-C13-03_VIOLATION")
    else:  # MULTI_HOP
        n1 = AttackNode(f"n1_{idx}", NodeType.ROOT_CAUSE, f"SSRF_{idx}", "url")
        n2 = AttackNode(f"n2_{idx}", NodeType.CAPABILITY, f"METADATA_{idx}", "169.254.169.254")
        n3 = AttackNode(f"n3_{idx}", NodeType.CAPABILITY, f"CREDENTIAL_{idx}", "AWS_KEY")
        n4 = ImpactNode(f"n4_{idx}", NodeType.IMPACT, f"DATA_LOSS_{idx}", "S3_BUCKET")
        e1 = AttackEdge(f"e1_{idx}", f"n1_{idx}", f"n2_{idx}", EdgeType.ENABLES)
        e2 = AttackEdge(f"e2_{idx}", f"n2_{idx}", f"n3_{idx}", EdgeType.EXPOSES)
        e3 = AttackEdge(f"e3_{idx}", f"n3_{idx}", f"n4_{idx}", EdgeType.DESTROYS)
        return ([n1, n2, n3, n4], [e1, e2, e3], "VALID")


TP_FIXTURES = [create_fixture_graph(i, "TP") for i in range(1, 51)]
TN_FIXTURES = [create_fixture_graph(i, "TN") for i in range(1, 51)]
UNKNOWN_FIXTURES = [create_fixture_graph(i, "UNKNOWN") for i in range(1, 51)]
CYCLE_FIXTURES = [create_fixture_graph(i, "CYCLE") for i in range(1, 51)]
MULTI_HOP_FIXTURES = [create_fixture_graph(i, "MULTI_HOP") for i in range(1, 51)]


@pytest.mark.parametrize("nodes,edges,expected", TP_FIXTURES)
def test_tp_fixtures(nodes, edges, expected) -> None:
    engine = AttackGraphConstructionEngine()
    graph = engine.build_graph("TP_GRAPH", nodes, edges)
    assert graph.to_dict()["resolution"] == "VULNERABLE"


@pytest.mark.parametrize("nodes,edges,expected", TN_FIXTURES)
def test_tn_fixtures(nodes, edges, expected) -> None:
    engine = AttackGraphConstructionEngine()
    graph = engine.build_graph("TN_GRAPH", nodes, edges)
    assert graph.to_dict()["resolution"] == "SAFE"


@pytest.mark.parametrize("nodes,edges,expected", UNKNOWN_FIXTURES)
def test_unknown_fixtures_rejected(nodes, edges, expected) -> None:
    engine = AttackGraphConstructionEngine()
    with pytest.raises(ValueError, match="INV-C13-04 Violation"):
        engine.build_graph("UNKNOWN_GRAPH", nodes, edges)


@pytest.mark.parametrize("nodes,edges,expected", CYCLE_FIXTURES)
def test_cycle_fixtures_rejected(nodes, edges, expected) -> None:
    engine = AttackGraphConstructionEngine()
    with pytest.raises(ValueError, match="INV-C13-03 Violation"):
        engine.build_graph("CYCLE_GRAPH", nodes, edges)


@pytest.mark.parametrize("nodes,edges,expected", MULTI_HOP_FIXTURES)
def test_multi_hop_fixtures(nodes, edges, expected) -> None:
    engine = AttackGraphConstructionEngine()
    graph = engine.build_graph("MULTI_HOP_GRAPH", nodes, edges)
    assert graph.to_dict()["resolution"] == "VULNERABLE"
    assert graph.to_dict()["path_length"] == 3


def test_c13_determinism() -> None:
    """Section Determinism: Verifies repeated attack graph generation yields 100% identical dictionary representation."""
    engine = AttackGraphConstructionEngine()
    g1 = engine.build_chain_m_ssrf_metadata_credential_compromise("DET_1")
    g2 = engine.build_chain_m_ssrf_metadata_credential_compromise("DET_1")
    assert g1.to_dict() == g2.to_dict()
