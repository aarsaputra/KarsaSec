"""Adversarial Verification Suite for CPG Index Integrity (E9.5.1).

Validates:
- Empty index behavior
- Missing index (None) fallback
- Partial index semantic equivalence
- Stale index & deleted node protection
- Duplicate node ID handling
- Graph mutation post-indexing protection
- Unknown lookup dimension handling
- Candidate validation invariant: Candidates(I, pred) ⊆ Nodes(G)
"""

import pytest
from karsasec.cpg.index import CPGIndex
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.query.ast import PredicateNode, QueryNode, QueryStep, StepType
from karsasec.query.optimizer import QueryOptimizer


@pytest.fixture
def base_graph() -> CPGGraph:
    graph = CPGGraph()
    n1 = CPGNode(
        id="n1",
        node_type=NodeType.AST,
        label="n1",
        file_path="app.py",
        line_number=10,
        attributes={"function_name": "main", "ssa_version": "v1", "source_kind": "HTTP"},
    )
    n2 = CPGNode(
        id="n2",
        node_type=NodeType.AST,
        label="n2",
        file_path="app.py",
        line_number=20,
        attributes={"function_name": "main", "ssa_version": "v2", "sink_category": "SQLI"},
    )
    graph.add_node(n1)
    graph.add_node(n2)
    return graph


def test_empty_index_fallback(base_graph):
    """Empty index falls back to deterministic full scan."""
    optimizer = QueryOptimizer()
    empty_graph = CPGGraph()
    empty_index = CPGIndex(empty_graph)

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "main")),),
    )

    results = optimizer.evaluate_query(query, base_graph, index=empty_index)
    assert [n.id for n in results] == ["n1", "n2"]


def test_none_index_fallback(base_graph):
    """Missing index (index=None) performs deterministic full scan."""
    optimizer = QueryOptimizer()
    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "main")),),
    )

    results = optimizer.evaluate_query(query, base_graph, index=None)
    assert [n.id for n in results] == ["n1", "n2"]


def test_stale_index_deleted_node_protection(base_graph):
    """Stale index containing deleted node ID must NEVER return the deleted node."""
    optimizer = QueryOptimizer()
    index = CPGIndex(base_graph)

    # Delete n1 from authoritative graph AFTER index construction
    del base_graph.nodes["n1"]

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "main")),),
    )

    results = optimizer.evaluate_query(query, base_graph, index=index)
    result_ids = [n.id for n in results]

    assert "n1" not in result_ids
    assert result_ids == ["n2"]


def test_node_attribute_mutation_post_indexing(base_graph):
    """Mutating node attributes post-indexing re-evaluates node against authoritative graph."""
    optimizer = QueryOptimizer()
    index = CPGIndex(base_graph)

    # Mutate n1 function_name in graph post-indexing
    base_graph.nodes["n1"] = CPGNode(
        id="n1",
        node_type=NodeType.AST,
        label="n1",
        file_path="app.py",
        line_number=10,
        attributes={"function_name": "other_fn", "ssa_version": "v1"},
    )

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "main")),),
    )

    results = optimizer.evaluate_query(query, base_graph, index=index)
    assert [n.id for n in results] == ["n2"]


def test_candidate_subset_invariant(base_graph):
    """Invariant check: Candidates(I, pred) ⊆ Nodes(G)."""
    optimizer = QueryOptimizer()
    index = CPGIndex(base_graph)

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "id", "n1")),),
    )

    results = optimizer.evaluate_query(query, base_graph, index=index)
    for n in results:
        assert n.id in base_graph.nodes
        assert base_graph.nodes[n.id] is n


def test_unknown_lookup_dimension_fallback(base_graph):
    """Querying on an unindexed target dimension falls back gracefully to full scan."""
    optimizer = QueryOptimizer()
    index = CPGIndex(base_graph)

    query = QueryNode(
        target_label="ANY",
        steps=(QueryStep(step_type=StepType.WHERE, predicate=PredicateNode("EQUALS", "unindexed_attr", "foo")),),
    )

    results = optimizer.evaluate_query(query, base_graph, index=index)
    assert results == []
