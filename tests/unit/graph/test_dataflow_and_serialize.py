"""Unit tests for DataflowEngine and GraphSerializer (SQLite & JSON)."""

import tempfile
from pathlib import Path
from karsasec.graph.dataflow import (
    DataflowEngine,
    DataflowNode,
    DataflowEdge,
    DataflowEdgeType,
)
from karsasec.graph.serialize import GraphSerializer
from karsasec.graph.graph import ProjectGraph
from karsasec.graph.node import GraphNode, NodeKind, Visibility
from karsasec.graph.edge import GraphEdge, EdgeType, ResolutionMechanism


def test_dataflow_engine_tracing() -> None:
    """DataflowEngine must trace flow from source to sink through multi-step assignments."""
    engine = DataflowEngine()

    n_src = DataflowNode(node_id="src", name="user_input", is_source=True)
    n_a = DataflowNode(node_id="var_a", name="a")
    n_b = DataflowNode(node_id="var_b", name="b")
    n_sink = DataflowNode(node_id="sink", name="os.system", is_sink=True)

    for n in (n_src, n_a, n_b, n_sink):
        engine.add_node(n)

    # user_input -> a -> b -> os.system
    engine.add_flow("src", "var_a", DataflowEdgeType.ASSIGNMENT, "a = user_input")
    engine.add_flow("var_a", "var_b", DataflowEdgeType.ASSIGNMENT, "b = a")
    engine.add_flow("var_b", "sink", DataflowEdgeType.PARAMETER_PASS, "os.system(b)")

    paths = engine.trace_flow("src", "sink")
    assert len(paths) == 1
    p = paths[0]
    assert len(p.nodes) == 4
    assert [n.node_id for n in p.nodes] == ["src", "var_a", "var_b", "sink"]
    assert len(p.edges) == 3

    sources = engine.find_sources("sink")
    assert len(sources) == 1 and sources[0].node_id == "src"

    sinks = engine.find_sinks("src")
    assert len(sinks) == 1 and sinks[0].node_id == "sink"


def test_graph_serializer_sqlite_roundtrip() -> None:
    """GraphSerializer must save ProjectGraph to SQLite and load back identical structures."""
    pg = ProjectGraph()

    n1 = GraphNode(
        uuid="n1",
        kind=NodeKind.FUNCTION,
        language="Python",
        qualified_name="app.main.run",
        signature="()",
        visibility=Visibility.PUBLIC,
        file_path=Path("/app/main.py"),
        line=10,
        column=0,
    )
    n2 = GraphNode(
        uuid="n2",
        kind=NodeKind.FUNCTION,
        language="Python",
        qualified_name="os.system",
        signature="(cmd)",
        visibility=Visibility.PUBLIC,
        file_path=None,
        line=1,
        column=0,
    )
    pg.add_node(n1)
    pg.add_node(n2)

    e1 = GraphEdge(
        caller_id="n1",
        callee_id="n2",
        edge_type=EdgeType.CALLS,
        confidence=0.9,
        resolved_symbol="os.system",
        resolved_by=ResolutionMechanism.AST_NATIVE,
        call_site_id="site_1",
    )
    pg.add_edge(e1)

    serializer = GraphSerializer()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "graph.sqlite"
        serializer.save_sqlite(pg, db_path)

        assert db_path.exists()

        loaded_pg = serializer.load_sqlite(db_path)
        assert len(loaded_pg.nodes) == 2
        assert len(loaded_pg.edges) == 1

        loaded_n1 = loaded_pg.get_node("n1")
        assert loaded_n1 is not None
        assert loaded_n1.qualified_name == "app.main.run"
        assert loaded_n1.kind == NodeKind.FUNCTION

        loaded_e1 = loaded_pg.edges[0]
        assert loaded_e1.caller_id == "n1"
        assert loaded_e1.callee_id == "n2"
        assert loaded_e1.edge_type == EdgeType.CALLS


def test_graph_serializer_json_roundtrip() -> None:
    """GraphSerializer must save ProjectGraph to JSON and load back identical structures."""
    pg = ProjectGraph()

    n1 = GraphNode(
        uuid="mod1",
        kind=NodeKind.MODULE,
        language="JavaScript",
        qualified_name="auth.service",
    )
    pg.add_node(n1)

    serializer = GraphSerializer()

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "graph.json"
        serializer.save_json(pg, json_path)

        assert json_path.exists()

        loaded_pg = serializer.load_json(json_path)
        assert len(loaded_pg.nodes) == 1
        loaded_n1 = loaded_pg.get_node("mod1")
        assert loaded_n1 is not None
        assert loaded_n1.kind == NodeKind.MODULE
