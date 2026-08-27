"""Adversarial security test suite for SEC-001 (CWE-20 Substring Sanitizer Bypass Prevention)."""

import pytest
from types import SimpleNamespace

from karsasec.analysis.rule_engine import _match_symbol_name, evaluate_sanitizer_barrier
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType


def test_sec_001_match_symbol_name_prevents_substring_spoofing():
    # Negative cases (Must NOT match substring within longer identifier)
    assert _match_symbol_name("user_int_converter", "int") is False
    assert _match_symbol_name("print_int_status", "int") is False
    assert _match_symbol_name("internal_dispatch", "int") is False
    assert _match_symbol_name("my_shlex_quote_wrapper", "shlex.quote") is False
    assert _match_symbol_name("custom_basename_func", "basename") is False

    # Positive cases (Exact name & Fully Qualified Name suffix matching)
    assert _match_symbol_name("int", "int") is True
    assert _match_symbol_name("builtins.int", "int") is True
    assert _match_symbol_name("shlex.quote", "shlex.quote") is True
    assert _match_symbol_name("os.path.basename", "basename") is True
    assert _match_symbol_name("basename", "basename") is True


def test_sec_001_evaluate_sanitizer_barrier_adversarial_flow():
    graph = CPGGraph()
    # Node 1: Spoofed sanitizer function name 'user_int_converter'
    n1 = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="user_int_converter", attributes={"name": "user_int_converter"})
    graph.add_node(n1)

    flow = SimpleNamespace(
        sanitizer_nodes=["n1"],
    )

    # Evaluate against SQL sink category (which requires 'int' or 'sanitize_sql')
    result = evaluate_sanitizer_barrier(flow, "sql", graph)

    # SEC-001 Hardening Requirement: Spoofed function MUST NOT be accepted as a valid barrier
    assert result.has_valid_barrier is False
    assert result.barrier_name is None


def test_sec_001_evaluate_sanitizer_barrier_legitimate_flow():
    graph = CPGGraph()
    # Node 1: Legitimate FQN 'builtins.int'
    n1 = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="builtins.int", attributes={"name": "builtins.int"})
    graph.add_node(n1)

    flow = SimpleNamespace(
        sanitizer_nodes=["n1"],
    )

    result = evaluate_sanitizer_barrier(flow, "sql", graph)

    assert result.has_valid_barrier is True
    assert result.barrier_name == "builtins.int"
