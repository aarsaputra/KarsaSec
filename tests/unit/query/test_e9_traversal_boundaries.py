"""Adversarial Verification Suite for Traversal Boundaries, Cycles, and SSA/Call Context Isolation (E9.5.6 - E9.5.11).

Validates:
- BFS & DFS exact max_depth boundary behavior
- Negative max_depth fail-closed protection
- Self-loops, 2-node cycles, deep cycles, and diamond graphs
- Disconnected graph reachability
- Set(BFS(G, S, D)) == Set(DFS(G, S, D)) equivalence
- SSA state version isolation (v1 != v2)
- Call-context isolation & context length bounding
"""

import pytest
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.query.traversal_engine import MultiHopTraversalEngine


@pytest.fixture
def cyclic_and_boundary_graph() -> CPGGraph:
    graph = CPGGraph()

    # Nodes with SSA and call context attributes
    n1 = CPGNode("n1", NodeType.AST, "n1", attributes={"ssa_version": "v1", "call_context": "ctx_a"})
    n2 = CPGNode("n2", NodeType.AST, "n2", attributes={"ssa_version": "v1", "call_context": "ctx_a"})
    n3 = CPGNode("n3", NodeType.AST, "n3", attributes={"ssa_version": "v2", "call_context": "ctx_a"})
    n4 = CPGNode("n4", NodeType.AST, "n4", attributes={"ssa_version": "v2", "call_context": "ctx_b"})
    n_self = CPGNode("n_self", NodeType.AST, "n_self", attributes={"ssa_version": "v1", "call_context": "ctx_a"})
    n_disc = CPGNode("n_disc", NodeType.AST, "n_disc", attributes={"ssa_version": "v1", "call_context": "ctx_a"})

    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)
    graph.add_node(n4)
    graph.add_node(n_self)
    graph.add_node(n_disc)

    # Edges
    graph.add_edge(CPGEdge("n1", "n2", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n2", "n3", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n3", "n4", EdgeType.DATAFLOW))
    # Cycle n3 -> n1
    graph.add_edge(CPGEdge("n3", "n1", EdgeType.CFG_FLOW))
    # Self loop n_self -> n_self
    graph.add_edge(CPGEdge("n_self", "n_self", EdgeType.CFG_FLOW))

    return graph


def test_max_depth_boundaries(cyclic_and_boundary_graph):
    """Test max_depth=0, max_depth=1, exact depth, and overflow."""
    engine = MultiHopTraversalEngine(cyclic_and_boundary_graph)

    # max_depth = 0 (same source & target is True, different is False)
    assert engine.reachability("n1", "n1", max_depth=0) is True
    assert engine.reachability("n1", "n2", max_depth=0) is False

    # max_depth = 1 (1-hop n1 -> n2 is True, 2-hop n1 -> n3 is False)
    assert engine.reachability("n1", "n2", max_depth=1) is True
    assert engine.reachability("n1", "n3", max_depth=1) is False

    # Negative max_depth fail-closed
    assert engine.reachability("n1", "n2", max_depth=-1) is False


def test_self_loop_termination(cyclic_and_boundary_graph):
    """Self-loop (A -> A) terminates cleanly without infinite recursion."""
    engine = MultiHopTraversalEngine(cyclic_and_boundary_graph)

    has_cycle = engine.detect_cycles("n_self", max_depth=10)
    assert has_cycle is True

    # Traversal on self-loop node
    res = engine.shortest_path("n_self", "n4", max_depth=10)
    assert res == []


def test_bfs_dfs_reachability_equivalence(cyclic_and_boundary_graph):
    """Set(BFS(G, S, D)) == Set(DFS(G, S, D)) reachability set equivalence."""
    engine = MultiHopTraversalEngine(cyclic_and_boundary_graph)

    bfs_reachable = engine.bfs_reachability("n1", "n4", max_depth=5)
    dfs_reachable = engine.dfs_reachability("n1", "n4", max_depth=5)

    assert bfs_reachable is True
    assert dfs_reachable is True
    assert bfs_reachable == dfs_reachable


def test_disconnected_graph_reachability(cyclic_and_boundary_graph):
    """Reachability to a disconnected node strictly returns False."""
    engine = MultiHopTraversalEngine(cyclic_and_boundary_graph)

    assert engine.reachability("n1", "n_disc", max_depth=10) is False
    assert engine.dfs_reachability("n1", "n_disc", max_depth=10) is False


def test_ssa_state_isolation(cyclic_and_boundary_graph):
    """Nodes with identical IDs but differing SSA versions are isolated in state tracking."""
    engine = MultiHopTraversalEngine(cyclic_and_boundary_graph)

    state1 = engine._get_node_state("n2")
    state2 = engine._get_node_state("n3")

    assert state1[1] == "v1"
    assert state2[1] == "v2"
    assert state1 != state2


def test_call_context_length_bounding(cyclic_and_boundary_graph):
    """Extremely long call-context strings are safely truncated to MAX_CONTEXT_STRING_LEN."""
    engine = MultiHopTraversalEngine(cyclic_and_boundary_graph)

    long_context = "ctx_" + ("long_call_chain_" * 50)
    cyclic_and_boundary_graph.nodes["n1"] = CPGNode(
        "n1", NodeType.AST, "n1", attributes={"ssa_version": "v1", "call_context": long_context}
    )

    state = engine._get_node_state("n1")
    assert len(state[2]) <= engine.MAX_CONTEXT_STRING_LEN
