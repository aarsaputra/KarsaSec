"""Unit tests for ProjectGraph, ProjectGraphBuilder, and GraphQueryAPI."""

import tempfile
from pathlib import Path

from karsasec.graph.builder import ProjectGraphBuilder
from karsasec.graph.edge import EdgeType, GraphEdge, ResolutionMechanism
from karsasec.graph.graph import ProjectGraph
from karsasec.graph.node import GraphNode, NodeKind, Visibility
from karsasec.graph.query import GraphQueryAPI
from karsasec.parser.python_parser import python_parser_plugin
from karsasec.semantic.resolver import SemanticResolver


def test_graph_node_and_edge_creation() -> None:
    """Verify GraphNode and GraphEdge dataclasses store required rich metadata."""
    node = GraphNode(
        uuid="node123",
        kind=NodeKind.FUNCTION,
        language="Python",
        qualified_name="app.services.UserService.authenticate",
        namespace="app.services",
        signature="(username, password)",
        visibility=Visibility.PUBLIC,
        file_path=Path("/app/services.py"),
        line=42,
        column=4,
    )
    assert node.uuid == "node123"
    assert node.kind == NodeKind.FUNCTION
    assert node.qualified_name == "app.services.UserService.authenticate"
    assert node.visibility == Visibility.PUBLIC
    assert node.line == 42

    edge = GraphEdge(
        caller_id="node123",
        callee_id="node456",
        edge_type=EdgeType.CALLS,
        confidence=0.95,
        resolved_symbol="db.query",
        resolved_by=ResolutionMechanism.ALIAS_TRACKER,
        call_site_id="site789",
    )
    assert edge.caller_id == "node123"
    assert edge.callee_id == "node456"
    assert edge.edge_type == EdgeType.CALLS
    assert edge.resolved_by == ResolutionMechanism.ALIAS_TRACKER


def test_project_graph_indexing() -> None:
    """ProjectGraph must index nodes by UUID and qname, and edges by caller/callee."""
    pg = ProjectGraph()
    n1 = GraphNode(uuid="n1", qualified_name="mod.fn1")
    n2 = GraphNode(uuid="n2", qualified_name="mod.fn2")
    pg.add_node(n1)
    pg.add_node(n2)

    e1 = GraphEdge(caller_id="n1", callee_id="n2", edge_type=EdgeType.CALLS)
    pg.add_edge(e1)

    assert pg.get_node("n1") == n1
    assert pg.get_node_by_qname("mod.fn1") == n1
    assert len(pg.get_outgoing("n1")) == 1
    assert pg.get_outgoing("n1")[0].callee_id == "n2"
    assert len(pg.get_incoming("n2")) == 1
    assert pg.get_incoming("n2")[0].caller_id == "n1"


def test_project_graph_builder_multi_file() -> None:
    """ProjectGraphBuilder must aggregate multi-file ASTs and construct DEFINES, IMPORTS, and CALLS edges."""
    code_b = """
def execute_query(sql):
    import sqlite3
    conn = sqlite3.connect("db.sq3")
    conn.execute(sql)
"""
    code_a = """
from file_b import execute_query

def handle_user_input(user_data):
    execute_query(user_data)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        path_b = Path(tmpdir) / "file_b.py"
        path_a = Path(tmpdir) / "file_a.py"
        path_b.write_text(code_b)
        path_a.write_text(code_a)

        res_b = python_parser_plugin.parse_file(path_b)
        res_a = python_parser_plugin.parse_file(path_a)

        resolver = SemanticResolver()
        graph_b = resolver.resolve_file(res_b.root)
        graph_a = resolver.resolve_file(res_a.root)

        builder = ProjectGraphBuilder()
        pg = builder.build([res_b.root, res_a.root], {path_b: graph_b, path_a: graph_a})

        # Verify Module nodes exist
        assert "file_a" in pg.node_by_qname or any(n.qualified_name == "file_a" for n in pg.nodes.values())
        assert "file_b" in pg.node_by_qname or any(n.qualified_name == "file_b" for n in pg.nodes.values())

        # Verify Function nodes exist
        fn_a = pg.get_node_by_qname("file_a.handle_user_input")
        fn_b = pg.get_node_by_qname("file_b.execute_query")
        assert fn_a is not None, "Expected GraphNode for file_a.handle_user_input"
        assert fn_b is not None, "Expected GraphNode for file_b.execute_query"

        # Verify CALLS edge exists between handle_user_input and execute_query
        outgoing_a = pg.get_outgoing(fn_a.uuid)
        call_edges = [e for e in outgoing_a if e.edge_type == EdgeType.CALLS]
        assert any(e.callee_id == fn_b.uuid for e in call_edges), (
            f"Expected CALLS edge from {fn_a.qualified_name} to {fn_b.qualified_name}"
        )


def test_graph_query_api() -> None:
    """GraphQueryAPI must correctly perform reachability, shortest_path, and symbol lookups."""
    pg = ProjectGraph()

    # Create chain: controller -> service -> repository -> db
    n_ctrl = GraphNode(uuid="ctrl", kind=NodeKind.FUNCTION, qualified_name="app.controller.handle")
    n_svc = GraphNode(uuid="svc", kind=NodeKind.FUNCTION, qualified_name="app.service.process")
    n_repo = GraphNode(uuid="repo", kind=NodeKind.FUNCTION, qualified_name="app.repository.save")
    n_db = GraphNode(uuid="db", kind=NodeKind.FUNCTION, qualified_name="db.execute")

    for n in (n_ctrl, n_svc, n_repo, n_db):
        pg.add_node(n)

    e1 = GraphEdge(caller_id="ctrl", callee_id="svc", edge_type=EdgeType.CALLS, resolved_symbol="app.service.process")
    e2 = GraphEdge(caller_id="svc", callee_id="repo", edge_type=EdgeType.CALLS, resolved_symbol="app.repository.save")
    e3 = GraphEdge(caller_id="repo", callee_id="db", edge_type=EdgeType.CALLS, resolved_symbol="db.execute")

    for e in (e1, e2, e3):
        pg.add_edge(e)

    query = GraphQueryAPI(pg)

    # 1. find_symbol
    found = query.find_symbol("handle")
    assert len(found) == 1 and found[0].uuid == "ctrl"

    # 2. find_definition
    defn = query.find_definition("app.service.process")
    assert defn is not None and defn.uuid == "svc"

    # 3. reachable
    assert query.reachable("ctrl", "db") is True
    assert query.reachable("db", "ctrl") is False

    # 4. shortest_path
    path = query.shortest_path("ctrl", "db")
    assert len(path) == 3
    assert path[0].caller_id == "ctrl" and path[0].callee_id == "svc"
    assert path[1].caller_id == "svc" and path[1].callee_id == "repo"
    assert path[2].caller_id == "repo" and path[2].callee_id == "db"

    # 5. successors & predecessors
    succ_ctrl = query.successors("ctrl")
    assert len(succ_ctrl) == 1 and succ_ctrl[0].uuid == "svc"

    pred_db = query.predecessors("db")
    assert len(pred_db) == 1 and pred_db[0].uuid == "repo"

    # 6. find_calls
    calls_to_repo = query.find_calls("app.repository.save")
    assert len(calls_to_repo) == 1 and calls_to_repo[0].caller_id == "svc"
