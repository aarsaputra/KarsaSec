"""Unit test suite for KarsaSec Platform Capability Layer (IR, Symbol Index, Query DSL, and Plugin SDK)."""

from pathlib import Path

from karsasec.index.symbol_store import SymbolEntry, SymbolStore
from karsasec.ir.builder import ir_builder
from karsasec.ir.nodes import IRCall
from karsasec.query.dsl import Query
from karsasec.sdk.api import AnalysisAPIVersion, PluginManifest, PluginSDK


def test_generic_ir_builder() -> None:
    """Verify Generic IR nodes construction and abstraction."""
    call_node = ir_builder.build_call("node_123", "os.system", line=15)
    assert isinstance(call_node, IRCall)
    assert call_node.callee == "os.system"
    assert call_node.line == 15

    assign_node = ir_builder.build_assign("node_124", "cmd", call_node, line=15)
    assert assign_node.target.name == "cmd"
    assert assign_node.value == call_node


def test_symbol_store_indexing() -> None:
    """Verify persistent SymbolStore registration and lookup."""
    store = SymbolStore()
    entry = SymbolEntry(
        name="execute_command",
        qualified_name="app.controllers.execute_command",
        kind="function",
        file_path=Path("app/controllers.py"),
        line=42,
    )
    store.register(entry)

    retrieved = store.lookup("app.controllers.execute_command")
    assert retrieved is not None
    assert retrieved.kind == "function"
    assert retrieved.line == 42


def test_query_engine_fluent_dsl() -> None:
    """Verify Query Engine and Predicate DSL evaluation."""
    query = Query.function_call().where_callee("eval")
    mock_node = type("MockNode", (), {"callee": "eval"})()

    assert query.matches(mock_node) is True

    mock_node_safe = type("MockNode", (), {"callee": "print"})()
    assert query.matches(mock_node_safe) is False


def test_plugin_sdk_manifest_validation() -> None:
    """Verify PluginSDK manifest validation and version compatibility."""
    sdk = PluginSDK()
    manifest = PluginManifest(
        name="RustParserPlugin",
        version="1.0.0",
        author="KarsaSec Core Team",
        api_version=AnalysisAPIVersion.V2,
        capabilities_provided=["ast", "symbol"],
    )

    assert sdk.register_plugin(manifest) is True
    assert len(sdk.list_plugins()) == 1
    assert sdk.list_plugins()[0].name == "RustParserPlugin"
