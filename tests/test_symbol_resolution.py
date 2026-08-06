from pathlib import Path

from karsasec.analysis.symbol.models import Symbol, SymbolGraph
from karsasec.analysis.symbol.resolver import SymbolResolver
from karsasec.parser.ast_nodes import AssignmentNode, FileNode, FunctionNode, ImportNode, Position


def test_symbol_graph_models() -> None:
    graph = SymbolGraph()
    sym = Symbol(
        id="app.py::db::10",
        name="db",
        qualified_name="sqlite3.Connection",
        scope_name="file_scope",
        symbol_type="INSTANCE",
        file_path="app.py",
        line_number=10,
    )
    graph.add_symbol(sym)
    graph.add_import("sqlite3", "sqlite3")
    graph.bind_identifier("db", "app.py::db::10")

    assert graph.get_symbol_by_id("app.py::db::10") is not None
    assert graph.resolve_identifier("db").qualified_name == "sqlite3.Connection"
    assert graph.get_import_target("sqlite3") == "sqlite3"

    d = graph.to_dict()
    assert d["total_symbols"] == 1
    assert "db" in d["identifier_bindings"]


def test_symbol_resolver() -> None:
    file_node = FileNode(
        node_id="root",
        file_path=Path("main.py"),
        language="Python",
        start=Position(1, 0),
        end=Position(30, 0),
    )

    imp = ImportNode(
        node_id="imp_1",
        parent_id="root",
        language="Python",
        file_path=Path("main.py"),
        start=Position(1, 0),
        end=Position(1, 20),
        module_name="sqlite3",
    )

    fn = FunctionNode(
        node_id="fn_1",
        parent_id="root",
        language="Python",
        file_path=Path("main.py"),
        name="connect_db",
        start=Position(5, 0),
        end=Position(10, 0),
    )

    assign = AssignmentNode(
        node_id="assign_1",
        parent_id="fn_1",
        language="Python",
        file_path=Path("main.py"),
        start=Position(7, 0),
        end=Position(7, 30),
        target="db",
        value_expression="sqlite3.connect('app.db')",
    )

    file_node.nodes_map = {
        "root": file_node,
        "imp_1": imp,
        "fn_1": fn,
        "assign_1": assign,
    }

    resolver = SymbolResolver()
    sg = resolver.build_symbol_graph([file_node])

    assert len(sg.symbols) == 2
    resolved_db = sg.resolve_identifier("db")
    assert resolved_db is not None
    assert resolved_db.qualified_name == "sqlite3.db"
