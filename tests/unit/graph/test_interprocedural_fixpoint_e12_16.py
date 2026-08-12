"""Adversarial Unit Test Suite for Sprint E12-16 — Whole-Program Interprocedural Fixpoint & Call Graph Semantic Correlation.

Comprehensive coverage of 50 adversarial scenarios spanning 11 categories:
  - Call Graph (8 tests)
  - Summary & Fingerprinting (9 tests)
  - Context Isolation (4 tests)
  - SSA & Alias Chains (5 tests)
  - Fixpoint & Tarjan SCC (6 tests)
  - UNKNOWN & Dynamic Dispatch (5 tests)
  - Cross-File & ResourceGraph Integration (5 tests)
  - Security Invariants & Monotonicity (8 tests)
"""

from __future__ import annotations


from karsasec.graph.dataflow.abstract_state import (
    AbstractEnvironment,
    SemanticConstraint,
    TaintState,
    join_taint_state,
)
from karsasec.graph.dataflow.call_graph import (
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    CallResolutionStatus,
)
from karsasec.graph.dataflow.interprocedural_analyzer import InterproceduralDataflowAnalyzer
from karsasec.graph.dataflow.interprocedural_solver import InterproceduralSolver
from karsasec.graph.dataflow.provenance import (
    CallContext,
    FunctionSummary,
    PathSummary,
    ProvenanceNodeKind,
    SummaryStatus,
)
from karsasec.graph.dataflow.summary_applicator import SummaryApplicator
from karsasec.graph.resource_graph import ResourceEdge, ResourceEdgeKind, ResourceGraph, ResourceKind, ResourceNode


# ==============================================================================
# CATEGORY 1: CALL GRAPH & TARJAN SCC (Tests 1-8)
# ==============================================================================

def test_01_basic_call_graph_construction():
    cg = CallGraph()
    n1 = CallGraphNode("fileA.php::main", "fileA.php", "main")
    n2 = CallGraphNode("fileA.php::foo", "fileA.php", "foo")
    cg.add_function(n1)
    cg.add_function(n2)
    e = CallGraphEdge("fileA.php::main", "fileA.php::foo", "cs_10", line_number=10)
    cg.add_call(e)

    assert len(cg.nodes()) == 2
    assert len(cg.edges()) == 1
    assert cg.get_callees("fileA.php::main") == [n2]
    assert cg.get_callers("fileA.php::foo") == [n1]


def test_02_nested_call_graph():
    cg = CallGraph()
    nA = CallGraphNode("fA", "f.php", "A")
    nB = CallGraphNode("fB", "f.php", "B")
    nC = CallGraphNode("fC", "f.php", "C")
    for n in (nA, nB, nC):
        cg.add_function(n)

    cg.add_call(CallGraphEdge("fA", "fB", "cs_1"))
    cg.add_call(CallGraphEdge("fB", "fC", "cs_2"))

    assert cg.get_callees("fA")[0].node_id == "fB"
    assert cg.get_callees("fB")[0].node_id == "fC"


def test_03_direct_recursion_scc():
    cg = CallGraph()
    nA = CallGraphNode("fA", "f.php", "A")
    cg.add_function(nA)
    cg.add_call(CallGraphEdge("fA", "fA", "cs_rec"))

    sccs = cg.strongly_connected_components()
    assert len(sccs) == 1
    assert sccs[0] == ["fA"]


def test_04_mutual_recursion_scc():
    cg = CallGraph()
    nA = CallGraphNode("fA", "f.php", "A")
    nB = CallGraphNode("fB", "f.php", "B")
    cg.add_function(nA)
    cg.add_function(nB)
    cg.add_call(CallGraphEdge("fA", "fB", "cs_1"))
    cg.add_call(CallGraphEdge("fB", "fA", "cs_2"))

    sccs = cg.strongly_connected_components()
    assert len(sccs) == 1
    assert sorted(sccs[0]) == ["fA", "fB"]


def test_05_three_node_cycle_scc():
    cg = CallGraph()
    for name in ("A", "B", "C"):
        cg.add_function(CallGraphNode(name, "f.php", name))
    cg.add_call(CallGraphEdge("A", "B", "cs1"))
    cg.add_call(CallGraphEdge("B", "C", "cs2"))
    cg.add_call(CallGraphEdge("C", "A", "cs3"))

    sccs = cg.strongly_connected_components()
    assert len(sccs) == 1
    assert sorted(sccs[0]) == ["A", "B", "C"]


def test_06_multiple_sccs():
    cg = CallGraph()
    for name in ("A", "B", "C", "D"):
        cg.add_function(CallGraphNode(name, "f.php", name))

    # A -> B -> A (SCC 1), C -> D (SCC 2, SCC 3)
    cg.add_call(CallGraphEdge("A", "B", "cs1"))
    cg.add_call(CallGraphEdge("B", "A", "cs2"))
    cg.add_call(CallGraphEdge("B", "C", "cs3"))
    cg.add_call(CallGraphEdge("C", "D", "cs4"))

    sccs = cg.strongly_connected_components()
    assert len(sccs) == 3  # ['D'], ['C'], ['A', 'B']


def test_07_disconnected_graph_scc():
    cg = CallGraph()
    cg.add_function(CallGraphNode("A", "f.php", "A"))
    cg.add_function(CallGraphNode("B", "f.php", "B"))

    sccs = cg.strongly_connected_components()
    assert len(sccs) == 2


def test_08_deterministic_call_graph_ordering():
    cg1 = CallGraph()
    cg2 = CallGraph()

    nodes = [CallGraphNode(f"node_{i}", "f.php", f"func_{i}") for i in range(10)]
    for n in reversed(nodes):
        cg1.add_function(n)

    for n in nodes:
        cg2.add_function(n)

    assert [n.node_id for n in cg1.nodes()] == [n.node_id for n in cg2.nodes()]


# ==============================================================================
# CATEGORY 2: SUMMARY & FINGERPRINTING (Tests 9-17)
# ==============================================================================

def test_09_parameter_dependency_summary():
    ps = PathSummary(path_id="p1", return_expr="$x", parameter_dependencies=("x",))
    fs = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(ps,))
    assert fs.path_summaries[0].parameter_dependencies == ("x",)


def test_10_return_dependency_summary():
    ps = PathSummary(path_id="p1", return_expr="$x", taint_state=TaintState.TAINTED)
    fs = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(ps,))
    taint, _ = fs.joined_return_state()
    assert taint == TaintState.TAINTED


def test_11_parameter_constraint_summary():
    ps = PathSummary(path_id="p1", return_expr="$x", param_constraints=(("x", "NUMERIC"),))
    assert ps.param_constraints == (("x", "NUMERIC"),)


def test_12_return_constraint_summary():
    ps = PathSummary(path_id="p1", return_expr="intval($x)", constraints=frozenset([SemanticConstraint.NUMERIC]))
    fs = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(ps,))
    _, consts = fs.joined_return_state()
    assert SemanticConstraint.NUMERIC in consts


def test_13_transformation_summary():
    ps = PathSummary(path_id="p1", return_expr="htmlspecialchars($x)", transformations=("htmlspecialchars",))
    assert "htmlspecialchars" in ps.transformations


def test_14_guard_summary():
    ps = PathSummary(path_id="p1", return_expr="$x", guards=("is_numeric",), is_guarded=True)
    assert ps.is_guarded is True
    assert "is_numeric" in ps.guards


def test_15_sink_dependency_summary():
    ps = PathSummary(path_id="p1", sink_dependencies=("mysql_query",))
    assert "mysql_query" in ps.sink_dependencies


def test_16_multiple_return_paths_summary():
    p1 = PathSummary(path_id="p1", taint_state=TaintState.UNTAINTED, constraints=frozenset([SemanticConstraint.NUMERIC]))
    p2 = PathSummary(path_id="p2", taint_state=TaintState.TAINTED, constraints=frozenset())
    fs = FunctionSummary("foo", "f.php", path_summaries=(p1, p2))

    t, c = fs.joined_return_state()
    assert t == TaintState.TAINTED
    assert len(c) == 0  # Intersection of NUMERIC and empty is empty


def test_17_canonical_semantic_fingerprint():
    p1 = PathSummary(path_id="p1", return_expr="$x", taint_state=TaintState.TAINTED)
    fs1 = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(p1,))
    fs2 = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(p1,))

    assert fs1.semantic_fingerprint() == fs2.semantic_fingerprint()
    assert len(fs1.semantic_fingerprint()) == 64  # SHA-256 hex string


# ==============================================================================
# CATEGORY 3: CONTEXT ISOLATION (Tests 18-21)
# ==============================================================================

def test_18_two_call_sites_independent_context():
    ctx1 = CallContext("fileA.php", "main", 10, "foo", "cs_10")
    ctx2 = CallContext("fileA.php", "main", 20, "foo", "cs_20")
    assert ctx1.call_site_id != ctx2.call_site_id


def test_19_trusted_vs_tainted_call_site_isolation():
    applicator = SummaryApplicator()
    ps = PathSummary(path_id="p1", return_expr="$x", parameter_dependencies=("x",))
    fs = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(ps,))

    env1 = AbstractEnvironment()
    env1.assignment_kill("a", new_taint=TaintState.UNTAINTED)
    ctx1 = CallContext("f.php", "main", 1, "foo", "cs1")
    env1_out = applicator.apply_summary(ctx1, fs, ["a"], "res1", env1)

    env2 = AbstractEnvironment()
    env2.assignment_kill("b", new_taint=TaintState.TAINTED)
    ctx2 = CallContext("f.php", "main", 2, "foo", "cs2")
    env2_out = applicator.apply_summary(ctx2, fs, ["b"], "res2", env2)

    assert env1_out.get_value("res1").taint == TaintState.UNTAINTED
    assert env2_out.get_value("res2").taint == TaintState.TAINTED


def test_20_nested_call_context():
    ctx1 = CallContext("fileA.php", "main", 10, "foo", "cs_10", callee_file="fileB.php")
    sub_ctx = ctx1.sub_context("bar", "fileC.php", 15, "cs_15")

    assert sub_ctx.caller_function == "foo"
    assert sub_ctx.callee_function == "bar"
    assert sub_ctx.depth == 1


def test_21_context_depth_isolation():
    ctx = CallContext("f.php", "main", 1, "foo", "cs1", depth=5)
    assert ctx.depth == 5


# ==============================================================================
# CATEGORY 4: SSA & ALIAS CHAINS (Tests 22-26)
# ==============================================================================

def test_22_reassignment_kills_prior_constraints():
    env = AbstractEnvironment()
    val1 = env.assignment_kill("x", new_taint=TaintState.TAINTED)
    val1 = val1.with_constraints({SemanticConstraint.NUMERIC})
    env.set_value(val1)

    val2 = env.assignment_kill("x", new_taint=TaintState.TAINTED)
    assert val2.var_version == "x#2"
    assert len(val2.all_constraints) == 0


def test_23_alias_1_hop():
    env = AbstractEnvironment()
    env.assignment_kill("a", new_taint=TaintState.TAINTED)
    val_b = env.assignment_kill("b", new_taint=env.get_value("a").taint)
    assert val_b.taint == TaintState.TAINTED


def test_24_alias_multi_hop():
    env = AbstractEnvironment()
    env.assignment_kill("a", new_taint=TaintState.TAINTED)
    env.assignment_kill("b", new_taint=env.get_value("a").taint)
    env.assignment_kill("c", new_taint=env.get_value("b").taint)
    assert env.get_value("c").taint == TaintState.TAINTED


def test_25_alias_10_hop():
    env = AbstractEnvironment()
    env.assignment_kill("v0", new_taint=TaintState.TAINTED)
    for i in range(1, 11):
        prev = f"v{i-1}"
        curr = f"v{i}"
        env.assignment_kill(curr, new_taint=env.get_value(prev).taint)
    assert env.get_value("v10").taint == TaintState.TAINTED


def test_26_parameter_version_isolation():
    applicator = SummaryApplicator()
    fs = FunctionSummary("foo", "f.php", parameters=("x",))
    env = AbstractEnvironment()
    env.assignment_kill("x", new_taint=TaintState.TAINTED)
    ctx = CallContext("f.php", "main", 1, "foo", "cs1")

    applicator.apply_summary(ctx, fs, ["x"], "", env)
    nodes = applicator.provenance_graph.get_nodes()
    param_nodes = [n for n in nodes if n.kind == ProvenanceNodeKind.PARAMETER]

    assert len(param_nodes) == 1
    assert param_nodes[0].var_version == "x#cs1"


# ==============================================================================
# CATEGORY 5: FIXPOINT & TARJAN SCC (Tests 27-32)
# ==============================================================================

def test_27_acyclic_convergence():
    solver = InterproceduralSolver()
    cg = CallGraph()
    cg.add_function(CallGraphNode("foo", "f.php", "foo"))
    res = solver.solve(cg)
    assert "foo" in res


def test_28_direct_recursive_convergence():
    solver = InterproceduralSolver()
    cg = CallGraph()
    cg.add_function(CallGraphNode("foo", "f.php", "foo"))
    cg.add_call(CallGraphEdge("foo", "foo", "cs1"))

    res = solver.solve(cg)
    assert res["foo"].is_recursive is True


def test_29_mutual_recursive_convergence():
    solver = InterproceduralSolver()
    cg = CallGraph()
    cg.add_function(CallGraphNode("A", "f.php", "A"))
    cg.add_function(CallGraphNode("B", "f.php", "B"))
    cg.add_call(CallGraphEdge("A", "B", "cs1"))
    cg.add_call(CallGraphEdge("B", "A", "cs2"))

    res = solver.solve(cg)
    assert res["A"].is_recursive is True
    assert res["B"].is_recursive is True


def test_30_three_node_scc_convergence():
    solver = InterproceduralSolver()
    cg = CallGraph()
    for name in ("A", "B", "C"):
        cg.add_function(CallGraphNode(name, "f.php", name))
    cg.add_call(CallGraphEdge("A", "B", "cs1"))
    cg.add_call(CallGraphEdge("B", "C", "cs2"))
    cg.add_call(CallGraphEdge("C", "A", "cs3"))

    res = solver.solve(cg)
    assert len(res) == 3


def test_31_non_convergence_fallback():
    solver = InterproceduralSolver(max_scc_iterations=0)
    cg = CallGraph()
    cg.add_function(CallGraphNode("A", "f.php", "A"))
    cg.add_call(CallGraphEdge("A", "A", "cs1"))

    res = solver.solve(cg)
    assert res["A"].status == SummaryStatus.NON_CONVERGED


def test_32_iteration_bound():
    solver = InterproceduralSolver(max_scc_iterations=5)
    assert solver.max_scc_iterations == 5


# ==============================================================================
# CATEGORY 6: UNKNOWN & DYNAMIC DISPATCH (Tests 33-37)
# ==============================================================================

def test_33_unresolved_function():
    analyzer = InterproceduralDataflowAnalyzer()
    target = analyzer.resolve_call_target("f.php", "non_existent_func")
    assert target is None


def test_34_dynamic_function_name():
    analyzer = InterproceduralDataflowAnalyzer()
    target = analyzer.resolve_call_target("f.php", "$fn")
    assert target is None


def test_35_dynamic_method():
    cg = CallGraph()
    e = CallGraphEdge("A", "B", "cs1", resolution_status=CallResolutionStatus.DYNAMIC)
    cg.add_call(e)
    assert cg.edges()[0].resolution_status == CallResolutionStatus.DYNAMIC


def test_36_missing_definition_summary():
    solver = InterproceduralSolver()
    fs = solver._analyze_single_node("missing_node", CallGraph())
    assert fs.status == SummaryStatus.UNKNOWN


def test_37_ambiguous_definition():
    e = CallGraphEdge("A", "B", "cs1", resolution_status=CallResolutionStatus.MULTIPLE)
    assert e.resolution_status == CallResolutionStatus.MULTIPLE


# ==============================================================================
# CATEGORY 7: CROSS-FILE & RESOURCEGRAPH (Tests 38-42)
# ==============================================================================

def test_38_valid_include_call():
    rg = ResourceGraph()
    rg.add_node(ResourceNode("fileA.php", ResourceKind.FILE, path="fileA.php"))
    rg.add_node(ResourceNode("fileB.php", ResourceKind.FILE, path="fileB.php"))
    rg.add_edge(ResourceEdge("fileA.php", "fileB.php", ResourceEdgeKind.INCLUDES))

    analyzer = InterproceduralDataflowAnalyzer(rg)
    node_b = CallGraphNode("fileB.php::foo", "fileB.php", "foo")
    analyzer.call_graph.add_function(node_b)

    target = analyzer.resolve_call_target("fileA.php", "foo")
    assert target is not None
    assert target.node_id == "fileB.php::foo"


def test_39_unrelated_same_name_function():
    rg = ResourceGraph()
    rg.add_node(ResourceNode("fileA.php", ResourceKind.FILE, path="fileA.php"))
    rg.add_node(ResourceNode("fileB.php", ResourceKind.FILE, path="fileB.php"))

    analyzer = InterproceduralDataflowAnalyzer(rg)
    node_b = CallGraphNode("fileB.php::foo", "fileB.php", "foo")
    analyzer.call_graph.add_function(node_b)

    target = analyzer.resolve_call_target("fileA.php", "foo")
    assert target is None  # No include link between fileA.php and fileB.php


def test_40_missing_include():
    rg = ResourceGraph()
    analyzer = InterproceduralDataflowAnalyzer(rg)
    target = analyzer.resolve_call_target("fileA.php", "bar")
    assert target is None


def test_41_multiple_definitions():
    cg = CallGraph()
    n1 = CallGraphNode("f1.php::foo", "f1.php", "foo")
    n2 = CallGraphNode("f2.php::foo", "f2.php", "foo")
    cg.add_function(n1)
    cg.add_function(n2)

    assert len(cg.nodes()) == 2


def test_42_cross_file_recursion():
    rg = ResourceGraph()
    rg.add_node(ResourceNode("fileA.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("fileB.php", ResourceKind.FILE))
    rg.add_edge(ResourceEdge("fileA.php", "fileB.php", ResourceEdgeKind.INCLUDES))
    rg.add_edge(ResourceEdge("fileB.php", "fileA.php", ResourceEdgeKind.INCLUDES))

    assert rg.find_include_chain("fileA.php", "fileB.php") == ["fileA.php", "fileB.php"]


# ==============================================================================
# CATEGORY 8: SECURITY INVARIANTS & MONOTONICITY (Tests 43-50)
# ==============================================================================

def test_43_taint_retained_after_unknown():
    res = join_taint_state(TaintState.TAINTED, TaintState.UNKNOWN)
    assert res == TaintState.TAINTED


def test_44_unknown_never_becomes_safe():
    res = join_taint_state(TaintState.UNKNOWN, TaintState.UNTAINTED)
    assert res == TaintState.UNKNOWN
    assert res != TaintState.UNTAINTED


def test_45_sanitizer_cannot_suppress_unrelated_taint():
    res = join_taint_state(TaintState.SANITIZED, TaintState.TAINTED)
    assert res == TaintState.TAINTED


def test_46_reassignment_invalidates_guard():
    env = AbstractEnvironment()
    val = env.assignment_kill("x", new_taint=TaintState.CONSTRAINED)
    val = val.with_constraints({SemanticConstraint.NUMERIC})
    env.set_value(val)

    # Reassign
    val2 = env.assignment_kill("x", new_taint=TaintState.TAINTED)
    assert SemanticConstraint.NUMERIC not in val2.all_constraints
    assert val2.taint == TaintState.TAINTED


def test_47_guarded_path_remains_path_specific():
    p1 = PathSummary(path_id="true_br", taint_state=TaintState.CONSTRAINED, constraints=frozenset([SemanticConstraint.NUMERIC]))
    p2 = PathSummary(path_id="false_br", taint_state=TaintState.TAINTED, constraints=frozenset())
    fs = FunctionSummary("foo", "f.php", path_summaries=(p1, p2))

    t, c = fs.joined_return_state()
    assert t == TaintState.TAINTED
    assert len(c) == 0


def test_48_mixed_return_paths_remain_conservative():
    p1 = PathSummary(path_id="p1", taint_state=TaintState.UNTAINTED)
    p2 = PathSummary(path_id="p2", taint_state=TaintState.TAINTED)
    fs = FunctionSummary("foo", "f.php", path_summaries=(p1, p2))

    t, _ = fs.joined_return_state()
    assert t == TaintState.TAINTED


def test_49_sink_dependency_retained():
    p1 = PathSummary(path_id="p1", sink_dependencies=("exec",))
    fs = FunctionSummary("foo", "f.php", path_summaries=(p1,))
    assert fs.path_summaries[0].sink_dependencies == ("exec",)


def test_50_provenance_preserved_after_summary_application():
    applicator = SummaryApplicator()
    ps = PathSummary(path_id="p1", return_expr="$x", parameter_dependencies=("x",))
    fs = FunctionSummary("foo", "f.php", parameters=("x",), path_summaries=(ps,))

    env = AbstractEnvironment()
    env.assignment_kill("arg", new_taint=TaintState.TAINTED)
    ctx = CallContext("f.php", "main", 10, "foo", "cs10")

    env_out = applicator.apply_summary(ctx, fs, ["arg"], "res", env)
    pg = applicator.provenance_graph

    assert len(pg.get_nodes()) >= 3
    assert len(pg.get_edges()) >= 2
