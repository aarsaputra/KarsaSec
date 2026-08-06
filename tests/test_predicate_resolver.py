from __future__ import annotations

import pytest

from karsasec.rules.predicate_resolver import (
    PredicateCycleError,
    PredicateDefinition,
    PredicateNotFoundError,
    PredicateResolver,
)


def test_load_all_predicates() -> None:
    resolver = PredicateResolver()
    resolver.load_all_predicates()
    pred = resolver.get_predicate("sql_injection")
    assert pred.name == "sql_injection"
    assert pred.metadata["cwe"] == "CWE-89"
    assert "exec" in pred.condition["symbol_triggers"]


def test_resolve_rule_dict() -> None:
    resolver = PredicateResolver()
    rule_raw = {
        "rule": {"id": "KS-TEST-0001"},
        "uses": {"predicate": "command_injection"},
        "metadata": {
            "name": "Test Rule Using Shared Predicate",
            "author": "KarsaSec",
            "version": "1.0",
            "created": "2026-08-06",
            "tags": ["test"],
        },
        "target": {"languages": ["Python"]},
        "analysis": {"engine": "AST", "behavior": "SINK"},
        "match": {"language": "Python", "ast_node_types": ["call"]},
        "output": {
            "severity": "HIGH",
            "confidence": "CONFIDENT",
            "message": "Command injection detected via predicate.",
            "remediation": "Sanitize inputs.",
        },
    }

    resolved = resolver.resolve_rule_dict(rule_raw)
    assert resolved["metadata"]["cwe"] == "CWE-78"
    assert resolved["metadata"]["owasp"] == "A03:2021-Injection"
    assert "exec" in resolved["condition"]["symbol_triggers"]
    assert "pattern" in resolved["condition"]


def test_predicate_not_found() -> None:
    resolver = PredicateResolver()
    with pytest.raises(PredicateNotFoundError):
        resolver.get_predicate("non_existent_predicate_123")


def test_benchmark_loading_time() -> None:
    resolver = PredicateResolver()
    dummy_rules = [
        {"rule": {"id": f"KS-BENCH-{i}"}, "uses": {"predicate": "sql_injection"}}
        for i in range(100)
    ]
    res = resolver.benchmark_loading_time(dummy_rules)
    assert res["total_rules"] == 100
    assert res["resolved_predicates"] == 100
    assert res["latency_ms"] < 100.0
