"""Adversarial Verification Suite for Fail-Closed Security Semantics (E9.5.12).

Validates:
- Corrupted index handling
- Malformed AST steps & missing predicates
- Missing SSA / Call Context metadata
- Invalid depth bounds
- Fundamental Invariant: UNKNOWN != SAFE
"""

import pytest
from karsasec.cpg.index import CPGIndex
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.query.ast import PredicateNode, QueryNode, QueryStep, StepType
from karsasec.query.optimizer import QueryOptimizer
from karsasec.query.traversal_engine import MultiHopTraversalEngine


@pytest.fixture
def fail_closed_graph() -> CPGGraph:
    graph = CPGGraph()
    # Node missing explicit SSA and call context metadata
    n1 = CPGNode("n1", NodeType.AST, "n1", file_path="app.py", line_number=10)
    graph.add_node(n1)
    return graph


def test_missing_metadata_defaults_safely(fail_closed_graph):
    """Nodes missing SSA or context metadata fall back to deterministic 'v0'/'global' state."""
    engine = MultiHopTraversalEngine(fail_closed_graph)
    state = engine._get_node_state("n1")
    assert state == ("n1", "v0", "global")


def test_malformed_ast_predicate_eval(fail_closed_graph):
    """Evaluating a query with an unsupported or unknown operator fails closed (returns empty list, never fabricated SAFE node)."""
    optimizer = QueryOptimizer()

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("UNKNOWN_OP", "id", "n1")),),
    )

    results = optimizer.evaluate_query(query, fail_closed_graph)
    assert results == []


def test_negative_depth_traversal_fail_closed(fail_closed_graph):
    """Negative depth traversal fails closed by returning False / empty path."""
    engine = MultiHopTraversalEngine(fail_closed_graph)

    assert engine.reachability("n1", "n1", max_depth=-5) is False
    assert engine.bfs_reachability("n1", "n1", max_depth=-1) is False
    assert engine.dfs_reachability("n1", "n1", max_depth=-1) is False


def test_corrupted_index_object_fallback(fail_closed_graph):
    """If index object contains invalid or corrupted lookup entries, candidate validation filters them out safely."""
    optimizer = QueryOptimizer()
    index = CPGIndex(fail_closed_graph)

    # Inject corrupted/non-existent candidate ID into index by_id table
    index.by_id["corrupted_id"] = CPGNode("corrupted_id", NodeType.AST, "corrupted_id")

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "id", "corrupted_id")),),
    )

    # Evaluator MUST filter out 'corrupted_id' because it does not exist in authoritative fail_closed_graph.nodes
    results = optimizer.evaluate_query(query, fail_closed_graph, index=index)
    assert results == []


def test_unknown_not_safe_invariant(fail_closed_graph):
    """Invariant: UNKNOWN != SAFE. Incomplete evidence must never produce a fabricated SAFE verdict."""
    optimizer = QueryOptimizer()

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "non_existent", "val")),),
    )

    results = optimizer.evaluate_query(query, fail_closed_graph)
    assert len(results) == 0
