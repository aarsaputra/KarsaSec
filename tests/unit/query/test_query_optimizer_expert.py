"""Comprehensive Expert Unit Test Suite for Sprint E9 CPG Query Optimizer & Multi-Hop Traversal Engine.

Validates Invariants:
- INV-E9-QUERY-01: Deterministic Query Plan
- INV-E9-QUERY-02: Filter Pushdown Semantic Preservation
- INV-E9-QUERY-03: Index/Full-Scan Equivalence
- INV-E9-QUERY-04: Cycle Safety
- INV-E9-QUERY-05: Depth Bound
- INV-E9-QUERY-06: Reachability Determinism
- INV-E9-QUERY-07: UNKNOWN != SAFE
- INV-E9-QUERY-08: SHA256 Plan Fingerprint
"""

import pytest
from karsasec.cpg.index import CPGIndex
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.query.ast import PredicateNode, QueryNode, QueryStep, StepType
from karsasec.query.optimizer import QueryOptimizer
from karsasec.query.traversal_engine import MultiHopTraversalEngine



@pytest.fixture
def sample_cpg_graph() -> CPGGraph:
    """Constructs a deterministic CPGGraph with cyclic edges and SSA attributes."""
    graph = CPGGraph()

    # Nodes
    n1 = CPGNode(
        id="n1",
        node_type=NodeType.AST,
        label="n1",
        file_path="app.py",
        line_number=10,
        attributes={"function_name": "main", "ssa_version": "v1", "call_context": "ctx_a", "source_kind": "HTTP_REQUEST"},
    )
    n2 = CPGNode(
        id="n2",
        node_type=NodeType.SSA,
        label="n2",
        file_path="app.py",
        line_number=12,
        attributes={"function_name": "main", "ssa_version": "v2", "call_context": "ctx_a"},
    )
    n3 = CPGNode(
        id="n3",
        node_type=NodeType.DATAFLOW,
        label="n3",
        file_path="app.py",
        line_number=15,
        attributes={"function_name": "process", "ssa_version": "v1", "call_context": "ctx_b", "sink_category": "SQL_INJECTION"},
    )
    n4 = CPGNode(
        id="n4",
        node_type=NodeType.TAINT,
        label="n4",
        file_path="db.py",
        line_number=20,
        attributes={"function_name": "execute", "ssa_version": "v3", "call_context": "ctx_c"},
    )

    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)
    graph.add_node(n4)

    # Edges: n1 -> n2 -> n3 -> n4 and cyclic n3 -> n1
    graph.add_edge(CPGEdge("n1", "n2", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n2", "n3", EdgeType.CALL))
    graph.add_edge(CPGEdge("n3", "n4", EdgeType.TAINT))
    graph.add_edge(CPGEdge("n3", "n1", EdgeType.CFG_FLOW))  # Cycle

    return graph


def test_inv_e9_query_01_deterministic_query_plan():
    """INV-E9-QUERY-01: Identical AST produces identical plan & deterministic predicate priority ordering."""
    optimizer = QueryOptimizer()

    step_dataflow = QueryStep(
        step_type=StepType.WHERE,
        predicate=PredicateNode(operator="DATAFLOW", target="flow", value="untrusted"),
    )
    step_id = QueryStep(
        step_type=StepType.WHERE,
        predicate=PredicateNode(operator="EQUALS", target="id", value="n1"),
    )
    step_fn = QueryStep(
        step_type=StepType.WHERE,
        predicate=PredicateNode(operator="EQUALS", target="function_name", value="main"),
    )

    query_ast = QueryNode(target_label="AST", steps=(step_dataflow, step_fn, step_id))
    optimized_ast = optimizer.optimize_ast(query_ast)

    # Priority order: Exact ID (0) -> Function Name (2) -> Dataflow (7)
    targets = [s.predicate.target for s in optimized_ast.steps if s.predicate]
    assert targets == ["id", "function_name", "flow"]


def test_inv_e9_query_02_filter_pushdown_semantic_preservation(sample_cpg_graph):
    """INV-E9-QUERY-02: Optimized query produces identical result set as unoptimized query."""
    optimizer = QueryOptimizer()

    step1 = QueryStep(
        step_type=StepType.WHERE,
        predicate=PredicateNode(operator="EQUALS", target="function_name", value="main"),
    )
    step2 = QueryStep(
        step_type=StepType.WHERE,
        predicate=PredicateNode(operator="EQUALS", target="file_path", value="app.py"),
    )

    query_unoptimized = QueryNode(target_label="ANY", steps=(step1, step2))
    query_optimized = optimizer.optimize_ast(query_unoptimized)

    res_unoptimized = optimizer.evaluate_query(query_unoptimized, sample_cpg_graph)
    res_optimized = optimizer.evaluate_query(query_optimized, sample_cpg_graph)

    assert [n.id for n in res_unoptimized] == [n.id for n in res_optimized]
    assert [n.id for n in res_optimized] == ["n1", "n2"]


def test_inv_e9_query_03_index_full_scan_equivalence(sample_cpg_graph):
    """INV-E9-QUERY-03: Evaluation with CPGIndex produces identical node set as Full Scan."""
    optimizer = QueryOptimizer()
    index = CPGIndex(sample_cpg_graph)

    query = QueryNode(
        target_label="ANY",
        steps=(
            QueryStep(
                step_type=StepType.WHERE,
                predicate=PredicateNode(operator="EQUALS", target="function_name", value="main"),
            ),
        ),
    )

    res_with_index = optimizer.evaluate_query(query, sample_cpg_graph, index=index)
    res_full_scan = optimizer.evaluate_query(query, sample_cpg_graph, index=None)

    assert [n.id for n in res_with_index] == [n.id for n in res_full_scan]
    assert [n.id for n in res_with_index] == ["n1", "n2"]


def test_inv_e9_query_04_cycle_safety(sample_cpg_graph):
    """INV-E9-QUERY-04: Traversing cyclic CPG graph terminates cleanly without infinite loop."""
    engine = MultiHopTraversalEngine(sample_cpg_graph)

    # Graph contains n1 -> n2 -> n3 -> n1 (cycle)
    has_cycle = engine.detect_cycles("n1", max_depth=10)
    assert has_cycle is True

    # Reachability must terminate and succeed despite cycle
    reachable = engine.reachability("n1", "n4", max_depth=10)
    assert reachable is True


def test_inv_e9_query_05_depth_bound(sample_cpg_graph):
    """INV-E9-QUERY-05: Traversal strictly respects max_depth limit."""
    engine = MultiHopTraversalEngine(sample_cpg_graph)

    # n1 to n4 requires 3 hops (n1 -> n2 -> n3 -> n4)
    assert engine.reachability("n1", "n4", max_depth=2) is False
    assert engine.reachability("n1", "n4", max_depth=3) is True


def test_inv_e9_query_06_reachability_determinism(sample_cpg_graph):
    """INV-E9-QUERY-06: BFS and DFS reachability are deterministic across multiple executions."""
    engine = MultiHopTraversalEngine(sample_cpg_graph)

    bfs_res1 = engine.bfs_reachability("n1", "n4", max_depth=5)
    bfs_res2 = engine.bfs_reachability("n1", "n4", max_depth=5)
    dfs_res1 = engine.dfs_reachability("n1", "n4", max_depth=5)
    dfs_res2 = engine.dfs_reachability("n1", "n4", max_depth=5)

    assert bfs_res1 is True
    assert bfs_res2 is True
    assert dfs_res1 is True
    assert dfs_res2 is True



def test_inv_e9_query_07_unknown_not_safe(sample_cpg_graph):
    """INV-E9-QUERY-07: Querying for non-existent node returns empty list (never fabricates SAFE node)."""
    optimizer = QueryOptimizer()

    query = QueryNode(
        target_label="ANY",
        steps=(
            QueryStep(
                step_type=StepType.WHERE,
                predicate=PredicateNode(operator="EQUALS", target="id", value="non_existent_id"),
            ),
        ),
    )

    res = optimizer.evaluate_query(query, sample_cpg_graph)
    assert res == []


def test_inv_e9_query_08_sha256_plan_fingerprint():
    """INV-E9-QUERY-08: Plan fingerprint returns a valid 64-char SHA256 hex string."""
    optimizer = QueryOptimizer()

    query_ast = QueryNode(
        target_label="AST",
        steps=(
            QueryStep(
                step_type=StepType.WHERE,
                predicate=PredicateNode(operator="EQUALS", target="id", value="n1"),
            ),
        ),
    )

    fingerprint = optimizer.compute_plan_fingerprint(query_ast)

    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in fingerprint)
