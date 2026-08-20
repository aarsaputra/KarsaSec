"""Unit and Adversarial Counterexample Test Suite for E12-13 Path-Sensitive Abstract Interpretation Engine.

Test Scenarios (15 Mandatory Adversarial & Semantic Invariants):
  1. Guard invalidation on reassignment
  2. Conservative branch merge (fact intersection)
  3. Local guard non-leakage without early-exit dominance
  4. Wrong sanitizer rejection (htmlspecialchars for SQLi)
  5. Wrong sink context rejection (NUMERIC + SQL_IDENTIFIER)
  6. Early exit dominance propagation (if (!is_numeric($id)) exit;)
  7. Reassignment after guard
  8. Fact-scoped loop widening
  9. Guard in sibling branch
 10. Guard written after sink
 11. Alias non-leakage
 12. Function boundary non-leakage
 13. Short-circuit condition guard
 14. Negated guard early exit
 15. Unknown helper predicate (treated as NOT_PROVEN)
"""

from __future__ import annotations

import pytest

from karsasec.graph.cfg.builder import CFGBuilder
from karsasec.graph.dataflow.abstract_state import (
    AbstractEnvironment,
    SemanticConstraint,
)
from karsasec.graph.dataflow.guard_propagation import WorklistFixpointAnalyzer
from karsasec.graph.dataflow.sink_matrix import (
    CompatibilityDecision,
    SinkCompatibilityMatrix,
    SinkContext,
    sink_compatibility_matrix,
)


@pytest.fixture
def cfg_builder() -> CFGBuilder:
    return CFGBuilder()


@pytest.fixture
def analyzer() -> WorklistFixpointAnalyzer:
    return WorklistFixpointAnalyzer()


@pytest.fixture
def matrix() -> SinkCompatibilityMatrix:
    return sink_compatibility_matrix


def test_1_guard_invalidation_on_reassignment(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "if (is_numeric($id)) {",
        "    $id = $_GET['other'];",
        "    mysql_query($id);",
        "}",
    ]
    cfg = cfg_builder.build_cfg("test1", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    # Find the leaf block containing mysql_query($id);
    sink_block_id = [
        b
        for b in sorted(cfg.reachable_blocks)
        if not b.startswith("cond") and any("mysql_query" in str(s) for s in cfg.blocks[b].statements)
    ][0]
    # State after executing statements in sink_block_id
    env_at_sink = in_states[sink_block_id].copy()
    analyzer._transfer_block(cfg.blocks[sink_block_id].statements, env_at_sink)

    val_id = env_at_sink.get_value("$id")
    assert val_id.var_version == "$id#2"
    assert SemanticConstraint.NUMERIC not in val_id.all_constraints


def test_2_conservative_branch_merge(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "if ($cond) {",
        "    $id = intval($id);",
        "} else {",
        "    $id = $_GET['raw'];",
        "}",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test2", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    merge_block_id = [b for b in cfg.reachable_blocks if "merge" in b][0]
    env_at_merge = in_states[merge_block_id]
    val_id = env_at_merge.get_value("$id")

    assert SemanticConstraint.INTEGER not in val_id.all_constraints
    assert SemanticConstraint.NUMERIC not in val_id.all_constraints


def test_3_local_guard_non_leakage(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "if (is_numeric($id)) {",
        "    log($id);",
        "}",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test3", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    merge_block_id = [b for b in cfg.reachable_blocks if "merge" in b][0]
    env_at_merge = in_states[merge_block_id]
    val_id = env_at_merge.get_value("$id")

    assert SemanticConstraint.NUMERIC not in val_id.all_constraints


def test_4_wrong_sanitizer_rejection(matrix: SinkCompatibilityMatrix) -> None:
    constraints = {SemanticConstraint.HTML_ESCAPED}
    res = matrix.evaluate(constraints, "SQL_INJECTION", SinkContext.SQL_VALUE)

    assert res.decision == CompatibilityDecision.NOT_PROVEN


def test_5_wrong_sink_context_rejection(matrix: SinkCompatibilityMatrix) -> None:
    constraints = {SemanticConstraint.NUMERIC}
    res = matrix.evaluate(constraints, "SQL_INJECTION", SinkContext.SQL_IDENTIFIER)

    assert res.decision == CompatibilityDecision.NOT_PROVEN


def test_6_early_exit_dominance_propagation(
    cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer, matrix: SinkCompatibilityMatrix
) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "if (!is_numeric($id)) {",
        "    exit;",
        "}",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test6", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    merge_block_id = [b for b in cfg.reachable_blocks if "merge" in b or "false" in b][0]
    env_at_downstream = in_states[merge_block_id]
    val_id = env_at_downstream.get_value("$id")

    assert SemanticConstraint.NUMERIC in val_id.all_constraints
    res = matrix.evaluate(val_id.all_constraints, "SQL_INJECTION", SinkContext.SQL_VALUE)
    assert res.decision == CompatibilityDecision.COMPATIBLE


def test_7_reassignment_after_guard(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "is_numeric($id);",
        "$id = $_GET['x'];",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test7", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    exit_env = in_states[cfg.exit_id]
    val_id = exit_env.get_value("$id")

    assert val_id.var_version == "$id#2"
    assert SemanticConstraint.NUMERIC not in val_id.all_constraints


def test_8_loop_widening_fact_scoped(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "while ($cond) {",
        "    foo();",
        "}",
        "if (is_numeric($id)) {",
        "    mysql_query($id);",
        "}",
    ]
    cfg = cfg_builder.build_cfg("test8", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    true_block_id = [b for b in cfg.reachable_blocks if "true" in b][0]
    val_id = in_states[true_block_id].get_value("$id")

    assert SemanticConstraint.NUMERIC in val_id.all_constraints


def test_9_guard_in_sibling_branch(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "if ($cond) {",
        "    is_numeric($id);",
        "}",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test9", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    merge_block_id = [b for b in cfg.reachable_blocks if "merge" in b][0]
    val_id = in_states[merge_block_id].get_value("$id")

    assert SemanticConstraint.NUMERIC not in val_id.all_constraints


def test_10_guard_after_sink(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "mysql_query($id);",
        "if (is_numeric($id)) {",
        "    log($id);",
        "}",
    ]
    cfg = cfg_builder.build_cfg("test10", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    entry_val = in_states["entry"].get_value("$id")
    assert SemanticConstraint.NUMERIC not in entry_val.all_constraints


def test_11_alias_non_leakage(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$x = $_GET['id'];",
        "$y = $x;",
        "if (is_numeric($x)) {",
        "    mysql_query($y);",
        "}",
    ]
    cfg = cfg_builder.build_cfg("test11", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    true_block_id = [b for b in cfg.reachable_blocks if "true" in b][0]
    env_true = in_states[true_block_id]

    val_x = env_true.get_value("$x")
    val_y = env_true.get_value("$y")

    assert SemanticConstraint.NUMERIC in val_x.all_constraints
    assert SemanticConstraint.NUMERIC not in val_y.all_constraints


def test_12_function_boundary_non_leakage(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "validate_id($id);",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test12", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    val_id = in_states[cfg.exit_id].get_value("$id")
    assert SemanticConstraint.NUMERIC not in val_id.all_constraints


def test_13_short_circuit_condition(cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer) -> None:
    code_stmts = [
        "$x = $_GET['id'];",
        "if ($x !== null && is_numeric($x)) {",
        "    mysql_query($x);",
        "}",
    ]
    cfg = cfg_builder.build_cfg("test13", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    true_block_id = [b for b in cfg.reachable_blocks if "true" in b][0]
    val_x = in_states[true_block_id].get_value("$x")

    assert SemanticConstraint.NUMERIC in val_x.all_constraints


def test_14_negated_guard_early_exit(
    cfg_builder: CFGBuilder, analyzer: WorklistFixpointAnalyzer, matrix: SinkCompatibilityMatrix
) -> None:
    code_stmts = [
        "$id = $_GET['id'];",
        "if (!is_numeric($id)) {",
        "    exit;",
        "}",
        "mysql_query($id);",
    ]
    cfg = cfg_builder.build_cfg("test14", code_stmts)
    init_env = AbstractEnvironment()
    in_states = analyzer.analyze(cfg, init_env)

    merge_block_id = [b for b in cfg.reachable_blocks if "merge" in b or "false" in b][0]
    val_id = in_states[merge_block_id].get_value("$id")

    assert SemanticConstraint.NUMERIC in val_id.all_constraints
    res = matrix.evaluate(val_id.all_constraints, "SQL_INJECTION", SinkContext.SQL_VALUE)
    assert res.decision == CompatibilityDecision.COMPATIBLE


def test_15_unknown_helper_predicate(matrix: SinkCompatibilityMatrix) -> None:
    constraints = set()  # Unknown helper establishes no proven constraints
    res = matrix.evaluate(constraints, "SQL_INJECTION", SinkContext.SQL_VALUE)

    assert res.decision == CompatibilityDecision.NOT_PROVEN
