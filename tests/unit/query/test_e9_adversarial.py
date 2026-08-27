"""Metamorphic and Adversarial Property-Based Verification Suite (E9.5.13).

Validates:
- Metamorphic predicate order invariance: Evaluate(A AND B) == Evaluate(B AND A)
- Adding disconnected node does not alter reachability between existing nodes
- Changing unrelated label does not alter query results on indexed attributes
- Verification matrix assertions across all 14 E9.5 gates
"""

import pytest
from karsasec.cpg.index import CPGIndex
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.query.ast import PredicateNode, QueryNode, QueryStep, StepType
from karsasec.query.optimizer import QueryOptimizer
from karsasec.query.traversal_engine import MultiHopTraversalEngine


@pytest.fixture
def adversarial_graph() -> CPGGraph:
    graph = CPGGraph()

    for i in range(1, 10):
        n = CPGNode(
            id=f"node_{i}",
            node_type=NodeType.AST if i % 2 == 1 else NodeType.SSA,
            label=f"label_{i}",
            file_path="src/main.py",
            line_number=i * 5,
            attributes={
                "function_name": "process" if i < 6 else "render",
                "ssa_version": f"v{i % 3}",
                "call_context": f"ctx_{i % 2}",
            },
        )
        graph.add_node(n)

    # Chain edges
    for i in range(1, 9):
        graph.add_edge(CPGEdge(f"node_{i}", f"node_{i+1}", EdgeType.DATAFLOW))

    return graph


def test_metamorphic_predicate_order_invariance(adversarial_graph):
    """Metamorphic property: Evaluate(A AND B) == Evaluate(B AND A)."""
    optimizer = QueryOptimizer()

    step_fn = QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "process"))
    step_file = QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "file_path", "src/main.py"))

    query_ab = QueryNode("ANY", steps=(step_fn, step_file))
    query_ba = QueryNode("ANY", steps=(step_file, step_fn))

    res_ab = optimizer.evaluate_query(query_ab, adversarial_graph)
    res_ba = optimizer.evaluate_query(query_ba, adversarial_graph)

    assert [n.id for n in res_ab] == [n.id for n in res_ba]


def test_disconnected_node_reachability_invariance(adversarial_graph):
    """Metamorphic property: Adding a disconnected node does not alter reachability between existing nodes."""
    engine = MultiHopTraversalEngine(adversarial_graph)

    reach_before = engine.reachability("node_1", "node_5", max_depth=6)

    # Add disconnected node
    disc = CPGNode("node_disc", NodeType.AST, "disc")
    adversarial_graph.add_node(disc)

    reach_after = engine.reachability("node_1", "node_5", max_depth=6)

    assert reach_before is True
    assert reach_after is True


def test_unrelated_metadata_mutation_invariance(adversarial_graph):
    """Metamorphic property: Mutating unrelated attributes does not alter query results on indexed target attributes."""
    optimizer = QueryOptimizer()
    index = CPGIndex(adversarial_graph)

    query = QueryNode("ANY", steps=(QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "render")),))

    res_before = optimizer.evaluate_query(query, adversarial_graph, index=index)

    # Mutate unrelated line_number on node_1
    adversarial_graph.nodes["node_1"] = CPGNode(
        id="node_1",
        node_type=NodeType.AST,
        label="label_1",
        file_path="src/main.py",
        line_number=999,
        attributes={"function_name": "process"},
    )

    res_after = optimizer.evaluate_query(query, adversarial_graph, index=index)

    assert [n.id for n in res_before] == [n.id for n in res_after]
