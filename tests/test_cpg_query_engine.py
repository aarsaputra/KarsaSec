"""Comprehensive Unit, Integration, and Snapshot Regression tests for CPG Query Engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from karsasec.cpg import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.query import (
    AND,
    CONTAINS,
    EXISTS,
    NOT,
    OR,
    REGEX,
    Edge,
    ExecutionContext,
    ExplainEngine,
    File,
    Function,
    MultiHopTraversalEngine,
    Node,
    PredicateEngine,
    PredicateNode,
    QueryCache,
    QueryExecutor,
    QueryNode,
    QueryOptimizer,
    QueryPlanner,
    QueryProfiler,
    Sanitizer,
    Sink,
    Source,
    Variable,
)
from karsasec.rules.adapter import LegacyRuleAdapter
from karsasec.rules.compiler import RuleCompiler
from karsasec.rules.runtime import SemanticRuleRuntime
from karsasec.rules.validator import RuleValidationError, RuleValidator


def test_query_ast_serialization() -> None:
    q_ast = Function("execute").where(language="python").outgoing("CALL").build()
    json_str = q_ast.to_json()

    loaded = QueryNode.from_json(json_str)
    assert loaded.target_label == "FUNCTION"
    assert len(loaded.steps) == 3
    assert loaded.steps[0].predicate is not None
    assert loaded.steps[0].predicate.value == "execute"


def test_fluent_dsl_builders() -> None:
    n = Node("CFG").where(label="stmt").build()
    f = Function("main").build()
    v = Variable("user_input").build()
    file_q = File("app.py").build()
    src = Source("req").build()
    snk = Sink("eval").build()
    san = Sanitizer("escape").build()
    e = Edge("DATAFLOW").build()

    assert n.target_label == "CFG"
    assert f.target_label == "FUNCTION"
    assert v.target_label == "SSA"
    assert file_q.target_label == "AST"
    assert src.target_label == "SOURCE"
    assert snk.target_label == "SINK"
    assert san.target_label == "SANITIZER"
    assert e.target_label == "EDGE"


def test_predicate_engine_evaluation() -> None:
    node = CPGNode(
        id="n1", node_type=NodeType.FUNCTION, label="db.execute", file_path="db.py", attributes={"language": "python"}
    )

    p_eq = PredicateNode(operator="EQUALS", target="label", value="db.execute")
    p_and = AND(p_eq, CONTAINS("file_path", "db"))
    p_or = OR(p_eq, REGEX("label", "non_existent"))
    p_not = NOT(REGEX("label", "non_existent"))
    p_exists = EXISTS("file_path")

    assert PredicateEngine.evaluate(p_eq, node) is True
    assert PredicateEngine.evaluate(p_and, node) is True
    assert PredicateEngine.evaluate(p_or, node) is True
    assert PredicateEngine.evaluate(p_not, node) is True
    assert PredicateEngine.evaluate(p_exists, node) is True


def test_query_planner_and_optimizer() -> None:
    q_ast = Function("main").where(language="python").outgoing("CFG_FLOW").build()

    planner = QueryPlanner()
    raw_plan = planner.create_plan(q_ast)
    assert raw_plan.op_type == "TRAVERSE" or raw_plan.op_type == "FILTER"

    optimizer = QueryOptimizer()
    opt_plan = optimizer.optimize(raw_plan)
    assert opt_plan is not None


def test_query_executor_and_traversal() -> None:
    graph = CPGGraph()
    n1 = CPGNode(
        id="n1", node_type=NodeType.FUNCTION, label="main", file_path="app.py", attributes={"function_name": "main"}
    )
    n2 = CPGNode(
        id="n2",
        node_type=NodeType.CFG,
        label="query = request.args",
        file_path="app.py",
        attributes={"function_name": "foo"},
    )
    n3 = CPGNode(
        id="n3",
        node_type=NodeType.CFG,
        label="db.execute(query)",
        file_path="app.py",
        attributes={"function_name": "bar"},
    )

    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)

    graph.add_edge(CPGEdge("n1", "n2", EdgeType.CFG_FLOW))
    graph.add_edge(CPGEdge("n2", "n3", EdgeType.CFG_FLOW))

    planner = QueryPlanner()
    optimizer = QueryOptimizer()
    executor = QueryExecutor()
    ctx = ExecutionContext()

    q_ast = Function("main").build()
    plan = optimizer.optimize(planner.create_plan(q_ast))
    results = executor.execute(plan, graph, context=ctx)

    assert len(results) == 1
    assert results[0].id == "n1"

    traversal = MultiHopTraversalEngine(graph)
    assert traversal.reachability("n1", "n3") is True
    assert traversal.bidirectional_bfs("n1", "n3") == ["n1", "n2", "n3"]


def test_query_cache_and_profiler() -> None:
    cache = QueryCache(max_size=10)
    cache.put("q1", [1, 2, 3])
    assert cache.get("q1") == [1, 2, 3]
    assert cache.get("q2") is None
    assert cache.hit_ratio == 0.5

    profiler = QueryProfiler()
    profiler.start_stage("TestStage")
    profiler.stop_stage("TestStage")
    report = profiler.report()
    assert "TestStage" in report["stage_timings_ms"]


def test_explain_engine() -> None:
    n1 = CPGNode(id="n1", node_type=NodeType.CFG, label="user_input = request.args", line_number=10)
    n2 = CPGNode(id="n2", node_type=NodeType.CFG, label="db.execute(user_input)", line_number=15)

    explainer = ExplainEngine()
    tree = explainer.build_evidence("SQLI_01", "SQL Injection vulnerability", [n1, n2])

    assert tree.rule_id == "SQLI_01"
    assert len(tree.chains) == 1
    assert "user_input" in tree.chains[0].reason


def test_rule_validator_and_compiler() -> None:
    val = RuleValidator()
    val.validate({"id": "R1", "severity": "HIGH", "pattern": "eval(...)"})

    with pytest.raises(RuleValidationError):
        val.validate({"invalid": True})

    compiler = RuleCompiler()
    q_ast, plan = compiler.compile({"id": "R1", "severity": "HIGH", "pattern": "eval(...)"})
    assert q_ast.target_label == "FUNCTION"
    assert plan.op_type is not None


def test_legacy_rule_adapter_and_semantic_runtime() -> None:
    graph = CPGGraph()
    n1 = CPGNode(
        id="n1",
        node_type=NodeType.FUNCTION,
        label="eval(user_data)",
        file_path="app.py",
        line_number=5,
        attributes={"language": "python"},
    )
    graph.add_node(n1)

    legacy_yaml_rule = {
        "id": "PY_EVAL_INJECTION",
        "title": "Arbitrary Code Execution via eval",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "language": "python",
        "pattern": "eval",
        "cwe": "CWE-95",
        "owasp": "A03:2021-Injection",
        "description": "Use of eval with untrusted input leads to code execution.",
        "remediation": "Avoid eval; use safe ast.literal_eval.",
    }

    adapter = LegacyRuleAdapter()
    q_ast = adapter.adapt(legacy_yaml_rule)
    assert q_ast.target_label == "FUNCTION"

    runtime = SemanticRuleRuntime()
    findings = runtime.execute_rule(legacy_yaml_rule, graph)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY_EVAL_INJECTION"
    assert findings[0].severity.value == "CRITICAL"
    assert findings[0].file_path == Path("app.py")
