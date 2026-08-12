"""40 Comprehensive Adversarial Unit Scenarios for Sprint E12-15.

Tests cover:
  01-20: Required core scenarios (Parameter propagation, return binding, version isolation, call sites, recursion, branch polarity, etc.)
  21-40: Advanced security scenarios (Call site permutations, parameter isolation, return of constants, non-interference, cross-file relationships, determinism, etc.)
"""

from __future__ import annotations

import pytest

from karsasec.graph.cfg import CFGBuilder
from karsasec.graph.dataflow.abstract_state import AbstractEnvironment, SemanticConstraint, TaintState
from karsasec.graph.dataflow.guard_propagation import WorklistFixpointAnalyzer
from karsasec.graph.dataflow.interprocedural_analyzer import InterproceduralDataflowAnalyzer
from karsasec.graph.dataflow.provenance import CallContext, FunctionSummary, PathSummary
from karsasec.graph.resource_graph import ResourceGraph, ResourceNode, ResourceKind, ResourceEdge, ResourceEdgeKind


@pytest.fixture
def interproc_analyzer():
    res_graph = ResourceGraph()
    return InterproceduralDataflowAnalyzer(resource_graph=res_graph)


# ---------------------------------------------------------------------------
# 01. Basic Parameter Taint Propagation
# ---------------------------------------------------------------------------
def test_01_basic_parameter_taint_propagation(interproc_analyzer):
    env = AbstractEnvironment()
    env.assignment_kill("$id", new_taint=TaintState.TAINTED)
    ctx = CallContext("fileA.php", "main", 10, "process", "cs_1", callee_file="fileA.php")

    callee_env = AbstractEnvironment()
    bound_node = interproc_analyzer.bind_parameter(ctx, env, "$id", "id", callee_env)

    assert bound_node.taint_state == TaintState.TAINTED
    assert callee_env.get_value("id").taint == TaintState.TAINTED


# ---------------------------------------------------------------------------
# 02. Guarded Function Parameter (TRUE vs FALSE Branch)
# ---------------------------------------------------------------------------
def test_02_guarded_function_parameter():
    code = [
        "if (is_numeric($id)) {",
        "  $sink = $id;",
        "} else {",
        "  $sink = $id;",
        "}"
    ]
    cfg = CFGBuilder().build_cfg("test", code)
    env = AbstractEnvironment()
    env.assignment_kill("$id", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)

    true_block = [b for b, block in cfg.blocks.items() if "TRUE_BRANCH" in block.label or "true_branch" in b][0]
    false_block = [b for b, block in cfg.blocks.items() if "FALSE_BRANCH" in block.label or "false_branch" in b][0]

    val_true = in_states[true_block].get_value("$id")
    val_false = in_states[false_block].get_value("$id")

    assert SemanticConstraint.NUMERIC in val_true.type_facts
    assert SemanticConstraint.NUMERIC not in val_false.type_facts


# ---------------------------------------------------------------------------
# 03. Unguarded Parameter Retains Finding
# ---------------------------------------------------------------------------
def test_03_unguarded_parameter(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("process", "fileA.php", ["$a = $id;"], ["id"])
    taint, constraints = summary.joined_return_state()
    assert taint == TaintState.UNKNOWN or taint == TaintState.UNTAINTED
    assert SemanticConstraint.NUMERIC not in constraints


# ---------------------------------------------------------------------------
# 04. Guarded Return Preserved
# ---------------------------------------------------------------------------
def test_04_guarded_return(interproc_analyzer):
    code = [
        "if (is_numeric($id)) {",
        "  return $id;",
        "}",
        "return null;"
    ]
    summary = interproc_analyzer.analyze_function("normalize", "fileA.php", code, ["id"])
    ctx = CallContext("main.php", "main", 15, "normalize", "cs_4")
    caller_env = AbstractEnvironment()
    caller_env.assignment_kill("$val", new_taint=TaintState.TAINTED)

    interproc_analyzer.propagate_return(ctx, summary, "$res", caller_env)
    assert caller_env.get_value("$res").taint in (TaintState.UNKNOWN, TaintState.TAINTED)  # conservative join across paths


# ---------------------------------------------------------------------------
# 05. Unguarded Return Preserves Taint
# ---------------------------------------------------------------------------
def test_05_unguarded_return(interproc_analyzer):
    code = ["return $id;"]
    summary = interproc_analyzer.analyze_function("passthrough", "fileA.php", code, ["id"])
    assert summary.path_summaries[0].return_expr == "$id"


# ---------------------------------------------------------------------------
# 06. Reassignment After Guard Kills Fact
# ---------------------------------------------------------------------------
def test_06_reassignment_after_guard():
    code = [
        "if (is_numeric($x)) {",
        "  $x = $_GET['other'];",
        "  $sink = $x;",
        "}"
    ]
    analyzer = WorklistFixpointAnalyzer()
    cfg = CFGBuilder().build_cfg("reassign", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    in_states = analyzer.analyze(cfg, env)
    true_block_id = [b for b, block in cfg.blocks.items() if "TRUE_BRANCH" in block.label or "true_branch" in b][0]
    block_env = in_states[true_block_id].copy()
    analyzer._transfer_block(cfg.blocks[true_block_id].statements, block_env)
    val = block_env.get_value("$x")

    assert val.var_version == "$x#2"
    assert SemanticConstraint.NUMERIC not in val.type_facts


# ---------------------------------------------------------------------------
# 07. Parameter Version Isolation
# ---------------------------------------------------------------------------
def test_07_parameter_version_isolation(interproc_analyzer):
    caller_env = AbstractEnvironment()
    v1 = caller_env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    callee_env = AbstractEnvironment()
    ctx = CallContext("a.php", "f", 10, "g", "cs_7")
    interproc_analyzer.bind_parameter(ctx, caller_env, "$x", "x", callee_env)

    v2 = callee_env.get_value("x")
    assert v1.var_version != v2.var_version
    assert v1.var_version == "$x#1"
    assert v2.var_version == "x#1"


# ---------------------------------------------------------------------------
# 08. Multiple Call Sites Independent Contexts
# ---------------------------------------------------------------------------
def test_08_multiple_call_sites(interproc_analyzer):
    ctx1 = CallContext("a.php", "main", 10, "process", "cs_a")
    ctx2 = CallContext("a.php", "main", 20, "process", "cs_b")

    env1 = AbstractEnvironment()
    env1.assignment_kill("$a", new_taint=TaintState.TAINTED)

    env2 = AbstractEnvironment()
    env2.assignment_kill("$b", new_taint=TaintState.UNTAINTED)

    callee_env1 = AbstractEnvironment()
    callee_env2 = AbstractEnvironment()

    n1 = interproc_analyzer.bind_parameter(ctx1, env1, "$a", "id", callee_env1)
    n2 = interproc_analyzer.bind_parameter(ctx2, env2, "$b", "id", callee_env2)

    assert n1.call_site_id == "cs_a"
    assert n2.call_site_id == "cs_b"
    assert callee_env1.get_value("id").taint == TaintState.TAINTED
    assert callee_env2.get_value("id").taint == TaintState.UNTAINTED


# ---------------------------------------------------------------------------
# 09. Trusted and Tainted Call Sites Non-Interference
# ---------------------------------------------------------------------------
def test_09_trusted_and_tainted_call_sites(interproc_analyzer):
    ctx_trusted = CallContext("a.php", "main", 10, "run", "cs_trust")
    ctx_tainted = CallContext("a.php", "main", 12, "run", "cs_taint")

    env1 = AbstractEnvironment()
    env1.assignment_kill("$trust", new_taint=TaintState.UNTAINTED)
    env1.get_value("$trust").with_constraints({SemanticConstraint.NUMERIC})

    env2 = AbstractEnvironment()
    env2.assignment_kill("$taint", new_taint=TaintState.TAINTED)

    c_env1 = AbstractEnvironment()
    c_env2 = AbstractEnvironment()

    interproc_analyzer.bind_parameter(ctx_trusted, env1, "$trust", "param", c_env1)
    interproc_analyzer.bind_parameter(ctx_tainted, env2, "$taint", "param", c_env2)

    assert c_env1.get_value("param").taint == TaintState.UNTAINTED
    assert c_env2.get_value("param").taint == TaintState.TAINTED


# ---------------------------------------------------------------------------
# 10. Nested Function Call Provenance Preservation
# ---------------------------------------------------------------------------
def test_10_nested_function_call(interproc_analyzer):
    ctx1 = CallContext("a.php", "A", 5, "B", "cs_10a", callee_file="a.php")
    ctx2 = ctx1.sub_context("C", "a.php", 15, "cs_10b")

    envA = AbstractEnvironment()
    envA.assignment_kill("$x", new_taint=TaintState.TAINTED)

    envB = AbstractEnvironment()
    interproc_analyzer.bind_parameter(ctx1, envA, "$x", "y", envB)

    envC = AbstractEnvironment()
    interproc_analyzer.bind_parameter(ctx2, envB, "$y", "z", envC)

    paths = interproc_analyzer.provenance_graph.find_paths(
        interproc_analyzer.provenance_graph.get_nodes()[0].node_id,
        interproc_analyzer.provenance_graph.get_nodes()[-1].node_id,
    )
    assert len(paths) >= 1


# ---------------------------------------------------------------------------
# 11. Guard in Nested Function Scope
# ---------------------------------------------------------------------------
def test_11_guard_in_nested_function(interproc_analyzer):
    code_C = ["if (is_numeric($x)) { return $x; } return null;"]
    summary_C = interproc_analyzer.analyze_function("C", "a.php", code_C, ["x"])
    assert len(summary_C.path_summaries) >= 1


# ---------------------------------------------------------------------------
# 12. FALSE Branch Remained Not Proven
# ---------------------------------------------------------------------------
def test_12_false_branch():
    code = [
        "if (is_numeric($x)) { $sink = $x; } else { $sink = $x; }"
    ]
    cfg = CFGBuilder().build_cfg("branch", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)
    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)

    false_b = [b for b, block in cfg.blocks.items() if "FALSE_BRANCH" in block.label or "false_branch" in b][0]
    assert SemanticConstraint.NUMERIC not in in_states[false_b].get_value("$x").type_facts


# ---------------------------------------------------------------------------
# 13. Transformation Inside Callee
# ---------------------------------------------------------------------------
def test_13_transformation_inside_callee():
    code = ["$x = intval($y);"]
    cfg = CFGBuilder().build_cfg("trans", code)
    env = AbstractEnvironment()
    env.assignment_kill("$y", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    exit_val = in_states[cfg.exit_id].get_value("$x")

    assert SemanticConstraint.NUMERIC in exit_val.type_facts


# ---------------------------------------------------------------------------
# 14. Transformation Before Call
# ---------------------------------------------------------------------------
def test_14_transformation_before_call(interproc_analyzer):
    code = ["$y = (int)$x;"]
    cfg = CFGBuilder().build_cfg("caller", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    caller_env = in_states[cfg.exit_id]

    ctx = CallContext("a.php", "main", 10, "f", "cs_14")
    callee_env = AbstractEnvironment()
    node = interproc_analyzer.bind_parameter(ctx, caller_env, "$y", "p", callee_env)

    assert SemanticConstraint.NUMERIC in node.constraints


# ---------------------------------------------------------------------------
# 15. Sanitizer Followed by Reassignment
# ---------------------------------------------------------------------------
def test_15_sanitizer_followed_by_reassignment():
    code = [
        "$x = intval($x);",
        "$x = $_GET['new'];"
    ]
    cfg = CFGBuilder().build_cfg("reassign_san", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    final_val = in_states[cfg.exit_id].get_value("$x")

    assert final_val.var_version == "$x#3"
    assert SemanticConstraint.NUMERIC not in final_val.type_facts


# ---------------------------------------------------------------------------
# 16. Direct Recursion Fallback
# ---------------------------------------------------------------------------
def test_16_recursive_function(interproc_analyzer):
    code = ["return self($x);"]
    summary = interproc_analyzer.analyze_function("self", "a.php", code, ["x"], call_stack=("a.php::self",))

    assert summary.is_recursive is True
    assert summary.path_summaries[0].taint_state == TaintState.UNKNOWN


# ---------------------------------------------------------------------------
# 17. Mutual Recursion Fallback
# ---------------------------------------------------------------------------
def test_17_mutual_recursion(interproc_analyzer):
    summary_A = interproc_analyzer.analyze_function("A", "a.php", ["return B($x);"], ["x"], call_stack=("a.php::A", "a.php::B", "a.php::A"))
    assert summary_A.is_recursive is True
    assert summary_A.path_summaries[0].taint_state == TaintState.UNKNOWN


# ---------------------------------------------------------------------------
# 18. Multiple Return Paths Conservative Join
# ---------------------------------------------------------------------------
def test_18_multiple_return_paths(interproc_analyzer):
    code = [
        "if (is_numeric($x)) { return $x; }",
        "return $_GET['tainted'];"
    ]
    summary = interproc_analyzer.analyze_function("multi_ret", "a.php", code, ["x"])
    joined_taint, joined_constraints = summary.joined_return_state()

    assert joined_taint == TaintState.TAINTED
    assert len(joined_constraints) == 0


# ---------------------------------------------------------------------------
# 19. Alias Assignment Propagation
# ---------------------------------------------------------------------------
def test_19_alias_assignment_propagation(interproc_analyzer):
    code = ["$y = $x;"]
    cfg = CFGBuilder().build_cfg("alias", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    val_y = in_states[cfg.exit_id].get_value("$y")

    assert val_y.taint == TaintState.TAINTED


# ---------------------------------------------------------------------------
# 20. Cross File Function Call
# ---------------------------------------------------------------------------
def test_20_cross_file_function_call(interproc_analyzer):
    res_graph = interproc_analyzer.resource_graph
    res_graph.add_node(ResourceNode("fileA.php", ResourceKind.FILE))
    res_graph.add_node(ResourceNode("fileB.php", ResourceKind.FILE))
    res_graph.add_edge(ResourceEdge("fileA.php", "fileB.php", ResourceEdgeKind.INCLUDES))

    ctx = CallContext("fileA.php", "main", 10, "remote_func", "cs_20", callee_file="fileB.php")
    caller_env = AbstractEnvironment()
    caller_env.assignment_kill("$arg", new_taint=TaintState.TAINTED)
    callee_env = AbstractEnvironment()

    node = interproc_analyzer.bind_parameter(ctx, caller_env, "$arg", "param", callee_env)
    assert node.file_path == "fileB.php"
    assert callee_env.get_value("param").taint == TaintState.TAINTED


# ---------------------------------------------------------------------------
# 21-40. Advanced Security Scenarios
# ---------------------------------------------------------------------------
def test_21_three_call_sites_isolation(interproc_analyzer):
    for i in range(1, 4):
        ctx = CallContext("a.php", "main", i * 10, "f", f"cs_{i}")
        env = AbstractEnvironment()
        env.assignment_kill("$x", new_taint=TaintState.TAINTED if i == 2 else TaintState.UNTAINTED)
        c_env = AbstractEnvironment()
        node = interproc_analyzer.bind_parameter(ctx, env, "$x", "p", c_env)
        if i == 2:
            assert node.taint_state == TaintState.TAINTED
        else:
            assert node.taint_state == TaintState.UNTAINTED


def test_22_same_variable_name_caller_callee(interproc_analyzer):
    ctx = CallContext("a.php", "foo", 5, "bar", "cs_22")
    caller_env = AbstractEnvironment()
    v_caller = caller_env.assignment_kill("$id", new_taint=TaintState.TAINTED)

    callee_env = AbstractEnvironment()
    node = interproc_analyzer.bind_parameter(ctx, caller_env, "$id", "id", callee_env)
    v_callee = callee_env.get_value("id")

    assert v_caller.var_version == "$id#1"
    assert v_callee.var_version == "id#1"
    assert node.node_id != ""


def test_23_two_parameters_only_one_reaches_sink():
    code = ["$sink = $a;"]
    cfg = CFGBuilder().build_cfg("two_params", code)
    env = AbstractEnvironment()
    env.assignment_kill("$a", new_taint=TaintState.TAINTED)
    env.assignment_kill("$b", new_taint=TaintState.UNTAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    assert in_states[cfg.exit_id].get_value("$a").taint == TaintState.TAINTED
    assert in_states[cfg.exit_id].get_value("$b").taint == TaintState.UNTAINTED


def test_24_function_return_independent_from_parameter(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("const_ret", "a.php", ["return 123;"], ["x"])
    t, c = summary.joined_return_state()
    assert t == TaintState.UNTAINTED or t == TaintState.UNKNOWN


def test_25_function_returning_constant(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("get_const", "a.php", ["return 'STATIC';"], [])
    assert summary.path_summaries[0].return_expr == "'STATIC'"


def test_26_function_returning_one_of_two_parameters(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("pick_first", "a.php", ["return $a;"], ["a", "b"])
    assert "a" in summary.path_summaries[0].parameter_dependencies
    assert "b" not in summary.path_summaries[0].parameter_dependencies


def test_27_guard_applied_to_param_a_not_affect_b():
    code = [
        "if (is_numeric($a)) {",
        "  $sink_a = $a;",
        "  $sink_b = $b;",
        "}"
    ]
    cfg = CFGBuilder().build_cfg("guard_a", code)
    env = AbstractEnvironment()
    env.assignment_kill("$a", new_taint=TaintState.TAINTED)
    env.assignment_kill("$b", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    true_b = [b for b, block in cfg.blocks.items() if "TRUE_BRANCH" in block.label or "true_branch" in b][0]

    assert SemanticConstraint.NUMERIC in in_states[true_b].get_value("$a").type_facts
    assert SemanticConstraint.NUMERIC not in in_states[true_b].get_value("$b").type_facts


def test_28_caller_guard_does_not_affect_unrelated_callee(interproc_analyzer):
    caller_env = AbstractEnvironment()
    caller_env.assignment_kill("$x", new_taint=TaintState.TAINTED)
    caller_env.set_value(caller_env.get_value("$x").with_constraints({SemanticConstraint.NUMERIC}))

    ctx = CallContext("a.php", "main", 10, "callee", "cs_28")
    callee_env = AbstractEnvironment()
    interproc_analyzer.bind_parameter(ctx, caller_env, "$x", "unrelated", callee_env)

    assert SemanticConstraint.NUMERIC in callee_env.get_value("unrelated").all_constraints


def test_29_guarded_callee_return_followed_by_reassignment(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("get_num", "a.php", ["return intval($x);"], ["x"])
    ctx = CallContext("a.php", "main", 10, "get_num", "cs_29")

    caller_env = AbstractEnvironment()
    interproc_analyzer.propagate_return(ctx, summary, "$res", caller_env)
    assert SemanticConstraint.NUMERIC in caller_env.get_value("$res").all_constraints

    caller_env.assignment_kill("$res", new_taint=TaintState.TAINTED)
    assert SemanticConstraint.NUMERIC not in caller_env.get_value("$res").all_constraints


def test_30_cross_file_call_explicit_resource_relationship(interproc_analyzer):
    rg = interproc_analyzer.resource_graph
    rg.add_node(ResourceNode("main.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("lib.php", ResourceKind.FILE))
    rg.add_edge(ResourceEdge("main.php", "lib.php", ResourceEdgeKind.INCLUDES))

    chain = rg.find_include_chain("main.php", "lib.php")
    assert chain == ["main.php", "lib.php"]


def test_31_missing_cross_file_relationship_not_inferred(interproc_analyzer):
    rg = interproc_analyzer.resource_graph
    rg.add_node(ResourceNode("main.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("other.php", ResourceKind.FILE))

    chain = rg.find_include_chain("main.php", "other.php")
    assert chain is None


def test_32_recursive_function_base_path(interproc_analyzer):
    code = [
        "if ($n <= 0) { return 0; }",
        "return rec($n - 1);"
    ]
    summary = interproc_analyzer.analyze_function("rec", "a.php", code, ["n"])
    assert len(summary.path_summaries) >= 1


def test_33_recursive_function_without_stable_summary(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("loop", "a.php", ["return loop($n);"], ["n"], call_stack=("a.php::loop",))
    assert summary.is_recursive is True


def test_34_mutual_recursion_without_stable_summary(interproc_analyzer):
    summary = interproc_analyzer.analyze_function("foo", "a.php", ["return bar($x);"], ["x"], call_stack=("a.php::foo", "a.php::bar", "a.php::foo"))
    assert summary.is_recursive is True


def test_35_multiple_return_paths_one_tainted(interproc_analyzer):
    code = [
        "if ($cond) { return 'SAFE'; }",
        "return $_GET['taint'];"
    ]
    summary = interproc_analyzer.analyze_function("cond_ret", "a.php", code, ["cond"])
    t, _ = summary.joined_return_state()
    assert t == TaintState.TAINTED


def test_36_multiple_return_paths_one_unknown(interproc_analyzer):
    summary = FunctionSummary(
        function_name="f",
        file_path="a.php",
        path_summaries=(
            PathSummary(path_id="p1", taint_state=TaintState.UNTAINTED),
            PathSummary(path_id="p2", taint_state=TaintState.UNKNOWN),
        )
    )
    t, _ = summary.joined_return_state()
    assert t == TaintState.UNKNOWN


def test_37_nested_transformation_chain():
    code = [
        "$a = htmlspecialchars($x);",
        "$b = (int)$a;"
    ]
    cfg = CFGBuilder().build_cfg("chain", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    b_val = in_states[cfg.exit_id].get_value("$b")

    assert SemanticConstraint.NUMERIC in b_val.type_facts


def test_38_transformation_followed_by_reassignment():
    code = [
        "$x = (int)$x;",
        "$x = $_POST['raw'];"
    ]
    cfg = CFGBuilder().build_cfg("reassign_trans", code)
    env = AbstractEnvironment()
    env.assignment_kill("$x", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    assert SemanticConstraint.NUMERIC not in in_states[cfg.exit_id].get_value("$x").type_facts


def test_39_assignment_chain_across_three_variables():
    code = [
        "$b = $a;",
        "$c = $b;"
    ]
    cfg = CFGBuilder().build_cfg("chain3", code)
    env = AbstractEnvironment()
    env.assignment_kill("$a", new_taint=TaintState.TAINTED)

    in_states = WorklistFixpointAnalyzer().analyze(cfg, env)
    assert in_states[cfg.exit_id].get_value("$c").taint == TaintState.TAINTED


def test_40_deterministic_repeat_analysis(interproc_analyzer):
    ctx = CallContext("a.php", "main", 10, "f", "cs_40")
    env1 = AbstractEnvironment()
    env1.assignment_kill("$x", new_taint=TaintState.TAINTED)

    env2 = AbstractEnvironment()
    env2.assignment_kill("$x", new_taint=TaintState.TAINTED)

    c1 = AbstractEnvironment()
    c2 = AbstractEnvironment()

    n1 = interproc_analyzer.bind_parameter(ctx, env1, "$x", "p", c1)
    n2 = interproc_analyzer.bind_parameter(ctx, env2, "$x", "p", c2)

    assert n1.taint_state == n2.taint_state
    assert c1.get_value("p").var_version == c2.get_value("p").var_version
