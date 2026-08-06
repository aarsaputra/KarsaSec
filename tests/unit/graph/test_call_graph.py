"""Unit tests for Call Graph Builder, Scope WeakRef cycles, and thread-safe registry."""

import gc
import tempfile
import threading
import weakref
from pathlib import Path

from karsasec.graph.builder import CallGraphBuilder
from karsasec.graph.types import CallType
from karsasec.parser.python_parser import python_parser_plugin
from karsasec.rules.registry import RuleRegistry
from karsasec.rules.schema import validate_rule_dict
from karsasec.semantic.resolver import Scope, ScopeType, SemanticResolver


def test_scope_weakref_garbage_collection() -> None:
    """Verifies that Scope hierarchical parent links use weakref and don't leak memory."""
    # Enable GC and collect first
    gc.collect()

    parent = Scope(ScopeType.GLOBAL)
    child = Scope(ScopeType.FUNCTION, parent=parent)

    # Verify parent is resolved
    assert child.parent is parent

    # Verify deleting parent allows it to be collected
    parent_ref = weakref.ref(parent)
    del parent
    gc.collect()

    # The child scope should now have parent as None because it was garbage collected
    assert child.parent is None
    assert parent_ref() is None


def test_thread_safe_registry() -> None:
    """Verifies that RuleRegistry handles concurrent registrations and lookups safely."""
    registry = RuleRegistry()
    num_threads = 10
    loops = 50
    errors = []

    def worker(tid: int) -> None:
        try:
            for i in range(loops):
                rule_id = f"KS-THR{tid:01d}-{i:04d}"
                # Construct mock rule
                rule_dict = {
                    "rule": {"id": rule_id},
                    "metadata": {"name": f"Mock Rule {rule_id}", "enabled": True, "author": "test", "version": "1.0"},
                    "target": {"languages": ["Python"]},
                    "match": {"language": "Python", "ast_node_types": ["call"]},
                    "condition": {"symbol_triggers": ["eval"]},
                    "output": {"severity": "INFO", "confidence": "CONFIDENT", "message": "Test rule", "remediation": "test"}
                }
                rule = validate_rule_dict(rule_dict)
                registry.register(rule)
                # Lookup
                ret = registry.get_rule_by_id(rule_id)
                assert ret is not None
                assert ret.id == rule_id
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Registry thread safety errors: {errors}"
    assert len(registry.list_rules()) == num_threads * loops


def test_call_graph_single_file_and_recursion() -> None:
    """Tests CallGraphBuilder on single file local calls and recursion."""
    code = """
def recurse(x):
    if x > 0:
        recurse(x - 1)

def helper():
    return 42

def main():
    helper()
    recurse(3)
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = python_parser_plugin.parse_file(f_path)
        assert parse_result.root is not None

        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)

        builder = CallGraphBuilder()
        cg = builder.build([parse_result.root], {f_path: graph})

        # Verify function nodes
        nodes = list(cg.nodes.values())
        func_names = {node.name for node in nodes}
        assert "recurse" in func_names
        assert "helper" in func_names
        assert "main" in func_names

        # Find main node
        main_node = [n for n in nodes if n.name == "main"][0]
        helper_node = [n for n in nodes if n.name == "helper"][0]
        recurse_node = [n for n in nodes if n.name == "recurse"][0]

        # Verify edges from main
        callees_of_main = cg.get_callees(main_node.node_id)
        callee_names = {c.name for c in callees_of_main}
        assert "helper" in callee_names
        assert "recurse" in callee_names

        # Verify helper has helper_node node_id
        helper_edges = cg.callee_to_edges.get(helper_node.node_id, [])
        assert len(helper_edges) == 1
        assert helper_edges[0].caller_id == main_node.node_id

        # Verify recursion edge (recurse -> recurse)
        recurse_callees = cg.get_callees(recurse_node.node_id)
        assert recurse_node.node_id in [c.node_id for c in recurse_callees]

    finally:
        f_path.unlink()


def test_call_graph_cross_file_resolution() -> None:
    """Tests CallGraphBuilder resolving calls across different files."""
    code_b = """
def target_function():
    return "secret"
"""
    code_a = """
import file_b

def caller_function():
    file_b.target_function()
"""
    # Create temporary directory to hold both files
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
        cg = builder.build([res_b.root, res_a.root], {path_b: graph_b, path_a: graph_a})

        # Find target and caller nodes
        nodes = list(cg.nodes.values())
        target_node = [n for n in nodes if n.name == "target_function"][0]
        caller_node = [n for n in nodes if n.name == "caller_function"][0]

        # Verify cross-file call edge
        callees = cg.get_callees(caller_node.node_id)
        assert target_node.node_id in [c.node_id for c in callees]


def test_call_graph_class_methods() -> None:
    """Tests CallGraphBuilder resolving method calls inside classes."""
    code = """
class MyService:
    def perform_action(self):
        self.log_event()

    def log_event(self):
        print("Logged")
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = python_parser_plugin.parse_file(f_path)
        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)

        builder = CallGraphBuilder()
        cg = builder.build([parse_result.root], {f_path: graph})

        # Verify nodes and their class owner metadata
        nodes = list(cg.nodes.values())
        action_node = [n for n in nodes if n.name == "perform_action"][0]
        log_node = [n for n in nodes if n.name == "log_event"][0]

        assert action_node.class_owner == "MyService"
        assert log_node.class_owner == "MyService"

        # Verify edge from perform_action to log_event
        callees = cg.get_callees(action_node.node_id)
        assert log_node.node_id in [c.node_id for c in callees]

        edges = cg.caller_to_edges.get(action_node.node_id, [])
        assert len(edges) == 1
        assert edges[0].call_type == CallType.DYNAMIC

    finally:
        f_path.unlink()
