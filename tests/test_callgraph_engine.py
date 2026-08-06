from pathlib import Path

from karsasec.analysis.callgraph.builder import CallGraphBuilder
from karsasec.analysis.callgraph.models import CallEdge, CallGraph, CallNode
from karsasec.parser.ast_nodes import CallNode as ASTCallNode
from karsasec.parser.ast_nodes import FileNode, FunctionNode, Position


def test_callgraph_models() -> None:
    graph = CallGraph()
    node1 = CallNode(
        id="app.py::get_user::10",
        name="get_user",
        language="Python",
        file_path="app.py",
        line_number=10,
        parameters=["user_id"],
    )
    node2 = CallNode(
        id="app.py::execute_query::20",
        name="execute_query",
        language="Python",
        file_path="app.py",
        line_number=20,
        parameters=["sql"],
    )

    graph.add_node(node1)
    graph.add_node(node2)

    edge = CallEdge(
        caller_id="app.py::get_user::10",
        callee_name="execute_query",
        line_number=12,
        arguments=["sql"],
        target_node_id="app.py::execute_query::20",
    )
    graph.add_edge(edge)

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.get_callees_for_caller("app.py::get_user::10")[0].callee_name == "execute_query"
    assert graph.get_callers_for_callee("execute_query")[0].caller_id == "app.py::get_user::10"

    d = graph.to_dict()
    assert d["total_nodes"] == 2
    assert d["total_edges"] == 1


def test_callgraph_builder() -> None:
    file_node = FileNode(
        node_id="root_file",
        file_path=Path("main.py"),
        language="Python",
        start=Position(1, 0),
        end=Position(30, 0),
    )

    caller = FunctionNode(
        node_id="fn_caller",
        parent_id="root_file",
        name="handle_request",
        language="Python",
        file_path=Path("main.py"),
        start=Position(10, 0),
        end=Position(15, 0),
        parameters=["req"],
    )

    callee_decl = FunctionNode(
        node_id="fn_callee",
        parent_id="root_file",
        name="execute_raw_sql",
        language="Python",
        file_path=Path("main.py"),
        start=Position(20, 0),
        end=Position(25, 0),
        parameters=["query"],
    )

    call_site = ASTCallNode(
        node_id="call_site_1",
        parent_id="fn_caller",
        language="Python",
        file_path=Path("main.py"),
        start=Position(12, 0),
        end=Position(12, 10),
        function_name="execute_raw_sql",
        arguments=["query"],
    )

    file_node.nodes_map = {
        "root_file": file_node,
        "fn_caller": caller,
        "fn_callee": callee_decl,
        "call_site_1": call_site,
    }

    builder = CallGraphBuilder()
    cg = builder.build_from_file_nodes([file_node])

    assert len(cg.nodes) == 2
    assert len(cg.edges) == 1
    assert cg.edges[0].callee_name == "execute_raw_sql"
    assert cg.edges[0].caller_id == "main.py::handle_request::10"
