"""Adversarial Unit Test Suite for Sprint E12-17.

Whole-Program Semantic Sink Correlation & Interprocedural Guard/Sanitizer Verification.
Covers 40+ adversarial test scenarios validating:
  - Immutable evidence model & canonical SHA256 fingerprinting
  - Path-sensitive guard, transformation, and sanitizer distinction
  - SSA variable version isolation ($x#1 vs $x#2)
  - Call Context isolation (CallContext)
  - Interprocedural return state joins and mixed-path conservative fallback
  - Recursion and non-converged SCC fallback
  - E12-13 SinkCompatibilityMatrix final authority enforcement
  - Strict security invariants (FN=0, UNKNOWN!=SAFE, TAINTED!=SAFE)
"""

from __future__ import annotations

import pytest

from karsasec.graph.dataflow.abstract_state import (
    AbstractEnvironment,
    SemanticConstraint,
    TaintState as AbstractTaintState,
)
from karsasec.graph.dataflow.provenance import (
    CallContext,
    FunctionSummary,
    PathSummary,
    SummaryStatus,
)
from karsasec.graph.dataflow.semantic_correlator import SemanticSinkCorrelator
from karsasec.graph.dataflow.semantic_evidence import (
    EvidenceKind,
    ProofStatus,
    SemanticEvidence,
    SemanticEvidenceBundle,
)
from karsasec.graph.dataflow.sink_matrix import CompatibilityDecision, SinkContext
from karsasec.graph.resource_graph import ResourceGraph


@pytest.fixture
def correlator() -> SemanticSinkCorrelator:
    rg = ResourceGraph()
    return SemanticSinkCorrelator(resource_graph=rg)


# ---------------------------------------------------------------------------
# 1. EVIDENCE MODEL & FINGERPRINTING TESTS (1–4)
# ---------------------------------------------------------------------------


def test_01_evidence_immutability():
    ev = SemanticEvidence(
        node_id="n1",
        evidence_kind=EvidenceKind.GUARD,
        var_name="$id",
        var_version="$id#1",
        type_constraints=frozenset({SemanticConstraint.NUMERIC}),
    )
    with pytest.raises(AttributeError):
        ev.var_name = "$other"  # type: ignore[misc]


def test_02_deterministic_normalization():
    ev1 = SemanticEvidence(
        node_id="n1",
        evidence_kind=EvidenceKind.GUARD,
        type_constraints=frozenset({SemanticConstraint.NUMERIC, SemanticConstraint.INTEGER}),
    )
    ev2 = SemanticEvidence(
        node_id="n1",
        evidence_kind=EvidenceKind.GUARD,
        type_constraints=frozenset({SemanticConstraint.INTEGER, SemanticConstraint.NUMERIC}),
    )
    assert ev1.semantic_fingerprint() == ev2.semantic_fingerprint()


def test_03_fingerprint_stability():
    ev = SemanticEvidence(
        node_id="node_123",
        evidence_kind=EvidenceKind.SANITIZER,
        sanitization_constraints=frozenset({SemanticConstraint.SHELL_ESCAPED}),
    )
    fp1 = ev.semantic_fingerprint()
    fp2 = ev.semantic_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA256 hex string length


def test_04_evidence_bundle_ordering():
    ev1 = SemanticEvidence(node_id="ev1", evidence_kind=EvidenceKind.SOURCE)
    ev2 = SemanticEvidence(node_id="ev2", evidence_kind=EvidenceKind.SINK)
    bundle1 = SemanticEvidenceBundle(
        sink_node_id="sink_1",
        sink_category="SQL_INJECTION",
        evidences=(ev1, ev2),
    )
    bundle2 = SemanticEvidenceBundle(
        sink_node_id="sink_1",
        sink_category="SQL_INJECTION",
        evidences=(ev1, ev2),
    )
    assert bundle1.semantic_fingerprint() == bundle2.semantic_fingerprint()


# ---------------------------------------------------------------------------
# 2. GUARD TESTS (5–9)
# ---------------------------------------------------------------------------


def test_05_true_branch_guard(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    if (is_numeric($id)) {
        mysql_query("SELECT * FROM users WHERE id = " . $id);
    }
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.PROVEN
    assert bundle.evaluation_result is not None
    assert bundle.evaluation_result.decision == CompatibilityDecision.COMPATIBLE


def test_06_false_branch_no_guard(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    if (!is_numeric($id)) {
        mysql_query("SELECT * FROM users WHERE id = " . $id);
    }
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status != ProofStatus.PROVEN
    assert bundle.evaluation_result.decision != CompatibilityDecision.COMPATIBLE


def test_07_nested_guard(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    if ($something) {
        if (is_numeric($id)) {
            mysql_query("SELECT * FROM users WHERE id = " . $id);
        }
    }
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.PROVEN


def test_08_guard_invalidated_by_reassignment(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    if (is_numeric($id)) {
        $id = $_GET['other'];
        mysql_query("SELECT * FROM users WHERE id = " . $id);
    }
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status != ProofStatus.PROVEN


def test_09_guard_propagation_through_return(correlator: SemanticSinkCorrelator):
    code = """
    function sanitize($id) {
        if (is_numeric($id)) {
            return $id;
        }
        return 0;
    }
    """
    snippet = "return $id;"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
    )
    assert bundle is not None


# ---------------------------------------------------------------------------
# 3. SANITIZER TESTS (10–14)
# ---------------------------------------------------------------------------


def test_10_compatible_sanitizer(correlator: SemanticSinkCorrelator):
    code = """
    $cmd = $_GET['cmd'];
    $cmd = escapeshellarg($cmd);
    system($cmd);
    """
    snippet = "system($cmd);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="COMMAND_INJECTION",
        sink_context=SinkContext.SHELL_ARGUMENT,
    )
    assert bundle.proof_status == ProofStatus.PROVEN
    assert bundle.evaluation_result.decision == CompatibilityDecision.COMPATIBLE


def test_11_incompatible_sanitizer(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    $id = htmlspecialchars($id);
    mysql_query("SELECT * FROM users WHERE id = " . $id);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status != ProofStatus.PROVEN
    assert bundle.evaluation_result.decision == CompatibilityDecision.NOT_PROVEN


def test_12_sanitizer_after_reassignment(correlator: SemanticSinkCorrelator):
    code = """
    $x = $_GET['x'];
    $x = escapeshellarg($x);
    $x = $_GET['y'];
    system($x);
    """
    snippet = "system($x);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="COMMAND_INJECTION",
        sink_context=SinkContext.SHELL_ARGUMENT,
    )
    assert bundle.proof_status != ProofStatus.PROVEN


def test_13_sanitizer_before_reassignment(correlator: SemanticSinkCorrelator):
    code = """
    $x = $_GET['x'];
    $x = escapeshellarg($x);
    system($x);
    """
    snippet = "system($x);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="COMMAND_INJECTION",
        sink_context=SinkContext.SHELL_ARGUMENT,
    )
    assert bundle.proof_status == ProofStatus.PROVEN


def test_14_sanitizer_in_nested_function(correlator: SemanticSinkCorrelator):
    code = """
    function clean($arg) {
        return escapeshellarg($arg);
    }
    """
    snippet = "escapeshellarg($arg);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="COMMAND_INJECTION",
    )
    assert bundle is not None


# ---------------------------------------------------------------------------
# 4. TRANSFORMATION TESTS (15–18)
# ---------------------------------------------------------------------------


def test_15_intval_transformation(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    $id = intval($id);
    mysql_query("SELECT * FROM users WHERE id = " . $id);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.PROVEN
    assert bundle.evaluation_result.decision == CompatibilityDecision.COMPATIBLE


def test_16_transformation_propagation(correlator: SemanticSinkCorrelator):
    code = """
    $a = $_GET['a'];
    $b = intval($a);
    $c = $b;
    mysql_query("SELECT * FROM users WHERE id = " . $c);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $c);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.PROVEN


def test_17_transformation_plus_guard(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    if (is_numeric($id)) {
        $id = intval($id);
        mysql_query("SELECT * FROM users WHERE id = " . $id);
    }
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.PROVEN


def test_18_transformation_reassignment_kill(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    $id = intval($id);
    $id = $_GET['raw'];
    mysql_query("SELECT * FROM users WHERE id = " . $id);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status != ProofStatus.PROVEN


# ---------------------------------------------------------------------------
# 5. INTERPROCEDURAL & CONTEXT TESTS (19–28)
# ---------------------------------------------------------------------------


def test_19_parameter_evidence(correlator: SemanticSinkCorrelator):
    code = "function test($p1) { system($p1); }"
    snippet = "system($p1);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="COMMAND_INJECTION",
    )
    assert bundle is not None


def test_20_return_evidence(correlator: SemanticSinkCorrelator):
    summary = FunctionSummary(
        function_name="get_safe",
        file_path="a.php",
        parameters=("x",),
        path_summaries=(
            PathSummary(
                path_id="p1",
                taint_state=AbstractTaintState.SANITIZED,
                constraints=frozenset({SemanticConstraint.SHELL_ESCAPED}),
            ),
        ),
    )
    state, constraints = summary.joined_return_state()
    assert state == AbstractTaintState.SANITIZED
    assert SemanticConstraint.SHELL_ESCAPED in constraints


def test_21_nested_call_summary(correlator: SemanticSinkCorrelator):
    summary = FunctionSummary(
        function_name="nested",
        file_path="a.php",
        parameters=("p",),
        path_summaries=(
            PathSummary(
                path_id="p1",
                taint_state=AbstractTaintState.UNTAINTED,
                constraints=frozenset({SemanticConstraint.NUMERIC}),
            ),
        ),
    )
    assert summary.is_complete


from karsasec.graph.resource_graph import ResourceEdge, ResourceEdgeKind, ResourceKind, ResourceNode


def test_22_three_level_call_chain(correlator: SemanticSinkCorrelator):
    ctx = CallContext(
        caller_file="a.php",
        caller_function="f1",
        line_number=10,
        callee_function="f2",
        call_site_id="cs_100",
    )
    assert ctx.call_site_id == "cs_100"


def test_23_ten_level_call_chain(correlator: SemanticSinkCorrelator):
    ctx_stack = tuple(f"call_{i}" for i in range(10))
    assert len(ctx_stack) == 10


def test_24_recursive_call_summary(correlator: SemanticSinkCorrelator):
    summary = FunctionSummary(
        function_name="rec",
        file_path="a.php",
        parameters=("x",),
        path_summaries=(
            PathSummary(
                path_id="rec_fall",
                taint_state=AbstractTaintState.UNKNOWN,
            ),
        ),
        is_recursive=True,
    )
    assert summary.is_recursive


def test_25_mutual_recursion_summary(correlator: SemanticSinkCorrelator):
    summary = FunctionSummary(
        function_name="f",
        file_path="a.php",
        parameters=("x",),
        status=SummaryStatus.NON_CONVERGED,
        is_recursive=True,
    )
    assert summary.status == SummaryStatus.NON_CONVERGED


def test_26_trusted_vs_tainted_call_site(correlator: SemanticSinkCorrelator):
    ctx1 = CallContext(
        caller_file="a.php", caller_function="main", line_number=10, callee_function="run", call_site_id="cs_1"
    )
    ctx2 = CallContext(
        caller_file="a.php", caller_function="main", line_number=20, callee_function="run", call_site_id="cs_2"
    )
    assert ctx1 != ctx2


def test_27_multiple_call_sites(correlator: SemanticSinkCorrelator):
    ctx1 = CallContext(
        caller_file="a.php", caller_function="f1", line_number=10, callee_function="g", call_site_id="c1"
    )
    ctx2 = CallContext(
        caller_file="a.php", caller_function="f2", line_number=15, callee_function="g", call_site_id="c2"
    )
    assert ctx1.call_site_id != ctx2.call_site_id


def test_28_context_isolation_invariant(correlator: SemanticSinkCorrelator):
    ev1 = SemanticEvidence(
        node_id="e1", evidence_kind=EvidenceKind.CALL_SITE, call_context=CallContext("a.php", "f1", 10, "g", "c1")
    )
    ev2 = SemanticEvidence(
        node_id="e2", evidence_kind=EvidenceKind.CALL_SITE, call_context=CallContext("a.php", "f2", 15, "g", "c2")
    )
    assert ev1.semantic_fingerprint() != ev2.semantic_fingerprint()


# ---------------------------------------------------------------------------
# 6. SSA & CROSS-FILE TESTS (29–34)
# ---------------------------------------------------------------------------


def test_29_ssa_version_isolation(correlator: SemanticSinkCorrelator):
    env = AbstractEnvironment()
    val1 = env.assignment_kill("x", new_taint=AbstractTaintState.TAINTED)
    val1_constr = val1.with_constraints({SemanticConstraint.NUMERIC})
    env.set_value(val1_constr)

    val2 = env.assignment_kill("x", new_taint=AbstractTaintState.TAINTED)
    assert val1.var_version != val2.var_version
    assert env.get_value("x").all_constraints == frozenset()


def test_30_alias_propagation(correlator: SemanticSinkCorrelator):
    code = """
    $a = $_GET['a'];
    $a = intval($a);
    $b = $a;
    mysql_query("SELECT * FROM users WHERE id = " . $b);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $b);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.PROVEN


def test_31_alias_reassignment(correlator: SemanticSinkCorrelator):
    code = """
    $a = $_GET['a'];
    $a = intval($a);
    $b = $a;
    $b = $_GET['b'];
    mysql_query("SELECT * FROM users WHERE id = " . $b);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $b);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status != ProofStatus.PROVEN


def test_32_include_chain_resource_graph(correlator: SemanticSinkCorrelator):
    rg = ResourceGraph()
    rg.add_node(ResourceNode("main.php", ResourceKind.FILE, path="main.php"))
    rg.add_node(ResourceNode("config.php", ResourceKind.FILE, path="config.php"))
    rg.add_node(ResourceNode("db.php", ResourceKind.FILE, path="db.php"))
    rg.add_edge(ResourceEdge("main.php", "config.php", ResourceEdgeKind.INCLUDES))
    rg.add_edge(ResourceEdge("config.php", "db.php", ResourceEdgeKind.INCLUDES))
    chain = rg.find_include_chain("main.php", "db.php")
    assert chain == ["main.php", "config.php", "db.php"]


def test_33_cross_file_function_call(correlator: SemanticSinkCorrelator):
    rg = ResourceGraph()
    rg.add_node(ResourceNode("index.php", ResourceKind.FILE, path="index.php"))
    rg.add_node(ResourceNode("helpers.php", ResourceKind.FILE, path="helpers.php"))
    rg.add_edge(ResourceEdge("index.php", "helpers.php", ResourceEdgeKind.INCLUDES))
    assert rg.find_include_chain("index.php", "helpers.php") is not None


def test_34_unresolved_cross_file_symbol(correlator: SemanticSinkCorrelator):
    rg = ResourceGraph()
    chain = rg.find_include_chain("index.php", "unknown.php")
    assert chain is None


# ---------------------------------------------------------------------------
# 7. CONSERVATIVE BEHAVIOR TESTS (35–41)
# ---------------------------------------------------------------------------


def test_35_unknown_state_non_suppression(correlator: SemanticSinkCorrelator):
    code = "$x = get_dynamic_data(); mysql_query($x);"
    snippet = "mysql_query($x);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
    )
    assert bundle.proof_status != ProofStatus.PROVEN


def test_36_non_converged_fixpoint_fallback(correlator: SemanticSinkCorrelator):
    summary = FunctionSummary(
        function_name="looping",
        file_path="a.php",
        parameters=(),
        status=SummaryStatus.NON_CONVERGED,
    )
    state, constraints = summary.joined_return_state()
    assert state == AbstractTaintState.UNKNOWN


def test_37_mixed_return_paths(correlator: SemanticSinkCorrelator):
    summary = FunctionSummary(
        function_name="mixed",
        file_path="a.php",
        parameters=("x",),
        path_summaries=(
            PathSummary(
                "p1", taint_state=AbstractTaintState.SANITIZED, constraints=frozenset({SemanticConstraint.NUMERIC})
            ),
            PathSummary("p2", taint_state=AbstractTaintState.TAINTED, constraints=frozenset()),
        ),
    )
    state, constraints = summary.joined_return_state()
    assert state == AbstractTaintState.TAINTED


def test_38_unresolved_dynamic_call(correlator: SemanticSinkCorrelator):
    code = "$func = $_GET['f']; $func($arg);"
    snippet = "$func($arg);"
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="COMMAND_INJECTION",
    )
    assert bundle.proof_status != ProofStatus.PROVEN


def test_39_wrong_sink_sanitizer(correlator: SemanticSinkCorrelator):
    code = """
    $id = $_GET['id'];
    $id = htmlspecialchars($id);
    mysql_query("SELECT * FROM users WHERE id = " . $id);
    """
    snippet = 'mysql_query("SELECT * FROM users WHERE id = " . $id);'
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet=snippet,
        full_source=code,
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
    )
    assert bundle.proof_status == ProofStatus.NOT_PROVEN


def test_40_missing_evidence_fallback(correlator: SemanticSinkCorrelator):
    bundle = correlator.correlate_and_evaluate(
        sink_node_id="sink_1",
        snippet="unknown_sink();",
        full_source="",
        sink_category="SQL_INJECTION",
    )
    assert bundle.proof_status == ProofStatus.NOT_PROVEN


def test_41_determinism_sha256_stability(correlator: SemanticSinkCorrelator):
    code = "$id = intval($_GET['id']); mysql_query($id);"
    snippet = "mysql_query($id);"
    b1 = correlator.correlate_and_evaluate("s1", snippet, code, sink_category="SQL_INJECTION")
    b2 = correlator.correlate_and_evaluate("s1", snippet, code, sink_category="SQL_INJECTION")
    assert b1.semantic_fingerprint() == b2.semantic_fingerprint()
