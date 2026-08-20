"""Integration tests for cross-file SymbolPredicate resolution using CallGraph + VisitorContext."""

import tempfile
from pathlib import Path

from karsasec.graph.builder import CallGraphBuilder
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.python_parser import python_parser_plugin
from karsasec.rules.matcher.predicates.symbol import SymbolPredicate
from karsasec.rules.matcher.statistics import MatcherStatistics
from karsasec.rules.schema import validate_rule_dict
from karsasec.semantic.resolver import SemanticResolver


def _make_rule(symbol_trigger: str) -> object:
    """Helper to construct a properly compiled CompiledRule."""
    from karsasec.rules.matcher.compiler import RuleCompiler

    rule_dict = {
        "rule": {"id": "KS-PY-9999"},
        "metadata": {"name": "Test XFile Rule", "enabled": True, "author": "test", "version": "1.0"},
        "target": {"languages": ["Python"]},
        "match": {"language": "Python", "ast_node_types": ["call"]},
        "condition": {"symbol_triggers": [symbol_trigger]},
        "output": {"severity": "HIGH", "confidence": "CONFIDENT", "message": "Test", "remediation": "Fix it"},
    }
    rule = validate_rule_dict(rule_dict)
    return RuleCompiler().compile(rule)


def test_symbol_predicate_cross_file_callgraph_resolution() -> None:
    """SymbolPredicate must detect dangerous sink in file A resolved via callee in file B through CallGraph."""
    # file_b defines dangerous function
    code_b = """
def dangerous_exec(cmd):
    import subprocess
    subprocess.call(cmd, shell=True)
"""
    # file_a calls dangerous function imported from file_b
    code_a = """
from file_b import dangerous_exec

def handle_request(user_input):
    dangerous_exec(user_input)
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

        builder = CallGraphBuilder()
        cg = builder.build(
            [res_b.root, res_a.root],
            {path_b: graph_b, path_a: graph_a},
        )

        # Find a call node in file_a's AST (dangerous_exec call)
        call_nodes = [n for n in res_a.root.nodes_map.values() if n.node_type == "call"]
        assert call_nodes, "Expected at least one call node in file_a"

        # Set up VisitorContext with call_graph
        source_bytes_a = path_a.read_bytes()
        visitor_ctx = VisitorContext(
            file_node=res_a.root,
            language="Python",
            file_path=path_a,
            semantic_graph=graph_a,
            call_graph=cg,
        )

        pred = SymbolPredicate()
        stats = MatcherStatistics()

        # The trigger "dangerous_exec" should match via CallGraph resolution
        compiled_rule = _make_rule("dangerous_exec")

        matched_any = False
        for call_node in call_nodes:
            result, trigger, matched_text = pred.evaluate(
                node=call_node,
                compiled_rule=compiled_rule,
                context=visitor_ctx,
                stats=stats,
                source_bytes=source_bytes_a,
            )
            if result:
                matched_any = True
                assert trigger == "dangerous_exec"
                break

        assert matched_any, (
            "SymbolPredicate must detect 'dangerous_exec' cross-file via CallGraph. "
            "Make sure the call node was indexed into call_site_to_edge."
        )


def test_symbol_predicate_external_call_no_false_positive() -> None:
    """External calls (unresolvable callee) should NOT produce false positives via CallGraph."""
    code = """
import os
os.listdir("/tmp")
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        res = python_parser_plugin.parse_file(f_path)
        resolver = SemanticResolver()
        graph = resolver.resolve_file(res.root)

        builder = CallGraphBuilder()
        cg = builder.build([res.root], {f_path: graph})

        source_bytes = f_path.read_bytes()
        visitor_ctx = VisitorContext(
            file_node=res.root,
            language="Python",
            file_path=f_path,
            semantic_graph=graph,
            call_graph=cg,
        )

        pred = SymbolPredicate()
        stats = MatcherStatistics()
        # Trigger is something that does NOT exist anywhere in the code
        compiled_rule = _make_rule("subprocess.Popen")

        call_nodes = [n for n in res.root.nodes_map.values() if n.node_type == "call"]
        for call_node in call_nodes:
            result, _, _ = pred.evaluate(
                node=call_node,
                compiled_rule=compiled_rule,
                context=visitor_ctx,
                stats=stats,
                source_bytes=source_bytes,
            )
            # listdir is NOT subprocess.Popen — no false positive
            assert not result, f"False positive on node: {call_node.node_type}"

    finally:
        f_path.unlink()


def test_visitor_context_call_graph_field_exists() -> None:
    """Verify VisitorContext correctly accepts and exposes call_graph field."""
    from karsasec.parser.ast_nodes import FileNode, Position

    dummy_file_node = FileNode(
        node_id="abc",
        node_type="file",
        language="Python",
        byte_start=0,
        byte_end=0,
        start=Position(1, 0),
        end=Position(1, 0),
    )
    ctx = VisitorContext(file_node=dummy_file_node, call_graph=None)
    assert ctx.call_graph is None

    class FakeGraph:
        pass

    ctx2 = VisitorContext(file_node=dummy_file_node, call_graph=FakeGraph())
    assert isinstance(ctx2.call_graph, FakeGraph)


def test_scan_context_call_graph_field_exists() -> None:
    """Verify ScanContext correctly accepts and exposes call_graph field."""
    from karsasec.core.execution.context import ScanContext
    from karsasec.parser.ast_nodes import FileNode, Position

    dummy_file_node = FileNode(
        node_id="abc",
        node_type="file",
        language="Python",
        byte_start=0,
        byte_end=0,
        start=Position(1, 0),
        end=Position(1, 0),
    )
    ctx = ScanContext(file_node=dummy_file_node, source_bytes=b"", call_graph=None)
    assert ctx.call_graph is None

    class FakeGraph:
        pass

    ctx2 = ScanContext(file_node=dummy_file_node, source_bytes=b"", call_graph=FakeGraph())
    assert isinstance(ctx2.call_graph, FakeGraph)
