"""Adversarial Unit Test Suite for Sprint E12-18 (45 Required Scenarios).

Tests:
- SecurityVerdict domain models & deterministic SHA-256 fingerprinting
- SecurityDecisionEngine & authority preservation (G1 & G2)
- SemanticFindingCorrelator & SSA/Context/Branch isolation (G4, G5, G6, G7)
- SARIF export evidence attachment & legacy finding compatibility
- Determinism & zero benchmark hardcoding (G8 & G10)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.core.reporting.sarif_reporter import SARIFReporter
from karsasec.core.reporting.target import FileTarget
from karsasec.graph.dataflow.abstract_state import SemanticConstraint
from karsasec.graph.dataflow.finding_correlator import SemanticFindingCorrelator
from karsasec.graph.dataflow.security_decision import SecurityDecisionEngine
from karsasec.graph.dataflow.security_verdict import (
    DecisionReason,
    SecurityVerdict,
    VerdictConfidence,
    VerdictStatus,
    compute_evidence_fingerprint,
)
from karsasec.graph.dataflow.semantic_evidence import (
    EvidenceKind,
    ProofStatus,
    SemanticEvidence,
    SemanticEvidenceBundle,
)
from karsasec.graph.dataflow.sink_matrix import CompatibilityDecision, EvaluationResult, SinkContext
from karsasec.rules.enums import Confidence, Severity


@pytest.fixture
def decision_engine() -> SecurityDecisionEngine:
    return SecurityDecisionEngine()


@pytest.fixture
def correlator() -> SemanticFindingCorrelator:
    return SemanticFindingCorrelator()


# ---------------------------------------------------------------------------
# Tests 1-4: Basic Verdict Statuses
# ---------------------------------------------------------------------------


def test_01_vulnerable_verdict(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.NOT_PROVEN,
        reason="No compatible constraint found for SQL_VALUE",
        matching_constraint=None,
        sink_context=SinkContext.SQL_VALUE,
    )
    ev = SemanticEvidence(
        node_id="ev1",
        evidence_kind=EvidenceKind.SOURCE,
        proof_status=ProofStatus.PROVEN,
        var_name="$_GET['id']",
        description="Untrusted user input",
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle, rule_id="KS-SQL-01", line_number=10)
    assert verdict.status == VerdictStatus.VULNERABLE
    assert DecisionReason.TAINT_REACHES_SINK in verdict.reason_codes


def test_02_safe_verdict(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.COMPATIBLE,
        reason="TYPE_NUMERIC is safe in SQL_VALUE",
        matching_constraint=SemanticConstraint.NUMERIC,
        sink_context=SinkContext.SQL_VALUE,
    )
    ev = SemanticEvidence(
        node_id="ev2",
        evidence_kind=EvidenceKind.GUARD,
        proof_status=ProofStatus.PROVEN,
        var_name="$id",
        type_constraints=frozenset({SemanticConstraint.NUMERIC}),
        description="is_numeric check proven",
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        sink_context=SinkContext.SQL_VALUE,
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
        aggregated_constraints={SemanticConstraint.NUMERIC},
    )
    verdict = decision_engine.evaluate_verdict(bundle, rule_id="KS-SQL-01", line_number=15)
    assert verdict.status == VerdictStatus.SAFE
    assert verdict.confidence == VerdictConfidence.HIGH
    assert DecisionReason.GUARD_PROVEN in verdict.reason_codes


def test_03_unknown_verdict(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        proof_status=ProofStatus.NOT_PROVEN,
    )
    verdict = decision_engine.evaluate_verdict(bundle, rule_id="KS-SQL-01")
    assert verdict.status == VerdictStatus.UNKNOWN
    assert DecisionReason.UNKNOWN_EVIDENCE in verdict.reason_codes


def test_04_not_proven_verdict(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink2",
        sink_category="COMMAND_INJECTION",
        proof_status=ProofStatus.NOT_PROVEN,
    )
    verdict = decision_engine.evaluate_verdict(bundle, rule_id="KS-CMD-01")
    assert verdict.status in (VerdictStatus.UNKNOWN, VerdictStatus.NOT_PROVEN)


# ---------------------------------------------------------------------------
# Tests 5-6: Invariant G1 & G2 Tests
# ---------------------------------------------------------------------------


def test_05_unknown_never_becomes_safe(decision_engine: SecurityDecisionEngine) -> None:
    # ProofStatus is NOT_PROVEN, but someone claims COMPATIBLE without PROVEN proof status
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.COMPATIBLE,
        reason="Claimed compatible",
        matching_constraint=SemanticConstraint.NUMERIC,
        sink_context=SinkContext.SQL_VALUE,
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        proof_status=ProofStatus.NOT_PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status != VerdictStatus.SAFE


def test_06_tainted_cannot_silently_become_safe(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.NOT_PROVEN,
        reason="Incompatible",
        matching_constraint=None,
        sink_context=SinkContext.SQL_VALUE,
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.VULNERABLE


# ---------------------------------------------------------------------------
# Tests 7-11: Sanitizers, Guards, Transformations Evidence
# ---------------------------------------------------------------------------


def test_07_compatible_sanitizer(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.COMPATIBLE,
        reason="HTML_ESCAPED compatible with HTML_TEXT",
        matching_constraint=SemanticConstraint.HTML_ESCAPED,
        sink_context=SinkContext.HTML_TEXT,
    )
    ev = SemanticEvidence(
        node_id="ev_san",
        evidence_kind=EvidenceKind.SANITIZER,
        proof_status=ProofStatus.PROVEN,
        var_name="$x",
        sanitization_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_xss",
        sink_category="XSS",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.SAFE
    assert DecisionReason.SANITIZER_COMPATIBLE in verdict.reason_codes


def test_08_incompatible_sanitizer(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.NOT_PROVEN,
        reason="HTML_ESCAPED is incompatible with SQL_VALUE",
        matching_constraint=None,
        sink_context=SinkContext.SQL_VALUE,
    )
    ev = SemanticEvidence(
        node_id="ev_san2",
        evidence_kind=EvidenceKind.SANITIZER,
        proof_status=ProofStatus.PROVEN,
        var_name="$x",
        sanitization_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_sql",
        sink_category="SQL_INJECTION",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.VULNERABLE
    assert DecisionReason.SANITIZER_INCOMPATIBLE in verdict.reason_codes


def test_09_compatible_guard(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.COMPATIBLE,
        reason="TYPE_NUMERIC compatible",
        matching_constraint=SemanticConstraint.NUMERIC,
        sink_context=SinkContext.SQL_VALUE,
    )
    ev = SemanticEvidence(
        node_id="ev_g1",
        evidence_kind=EvidenceKind.GUARD,
        proof_status=ProofStatus.PROVEN,
        var_name="$id",
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.SAFE
    assert DecisionReason.GUARD_PROVEN in verdict.reason_codes


def test_10_unproven_guard(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        proof_status=ProofStatus.NOT_PROVEN,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.UNKNOWN
    assert DecisionReason.GUARD_NOT_PROVEN in verdict.reason_codes


def test_11_transformation_evidence(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.COMPATIBLE,
        reason="SHELL_ESCAPED compatible",
        matching_constraint=SemanticConstraint.SHELL_ESCAPED,
        sink_context=SinkContext.SHELL_ARGUMENT,
    )
    ev = SemanticEvidence(
        node_id="ev_tf",
        evidence_kind=EvidenceKind.TRANSFORMATION,
        proof_status=ProofStatus.PROVEN,
        var_name="$cmd",
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_cmd",
        sink_category="COMMAND_INJECTION",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.SAFE
    assert DecisionReason.TRANSFORMATION_PROVEN in verdict.reason_codes


# ---------------------------------------------------------------------------
# Tests 12-16: Provenance & Analysis Boundaries
# ---------------------------------------------------------------------------


def test_12_source_provenance(decision_engine: SecurityDecisionEngine) -> None:
    ev = SemanticEvidence(
        node_id="ev_src",
        evidence_kind=EvidenceKind.SOURCE,
        var_name="$_GET['user']",
        provenance_path=("$_GET['user']", "$user", "sink"),
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink1",
        sink_category="SQL_INJECTION",
        evidences=(ev,),
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert "$_GET['user']" in verdict.source_ids
    assert verdict.provenance_path == ("$_GET['user']", "$user", "sink")


def test_13_sink_provenance(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_eval_99",
        sink_category="CODE_INJECTION",
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.sink_id == "sink_eval_99"
    assert verdict.sink_category == "CODE_INJECTION"


def test_14_mixed_evidence(decision_engine: SecurityDecisionEngine) -> None:
    ev1 = SemanticEvidence(node_id="e1", evidence_kind=EvidenceKind.SOURCE, var_name="$_POST['data']")
    ev2 = SemanticEvidence(node_id="e2", evidence_kind=EvidenceKind.GUARD, proof_status=ProofStatus.PROVEN)
    eval_res = EvaluationResult(
        decision=CompatibilityDecision.COMPATIBLE,
        reason="ok",
        matching_constraint=SemanticConstraint.NUMERIC,
        sink_context=SinkContext.SQL_VALUE,
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_mix",
        sink_category="SQL_INJECTION",
        evidences=(ev1, ev2),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert len(verdict.evidence_references) == 2


def test_15_missing_evidence(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(sink_node_id="sink_none", sink_category="UNKNOWN")
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.UNKNOWN
    assert len(verdict.evidence_references) == 0


def test_16_non_converged_evidence(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_loop", sink_category="SQL_INJECTION", proof_status=ProofStatus.NOT_PROVEN
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Tests 17-22: SSA, Call Context & Branch Polarity Isolation
# ---------------------------------------------------------------------------


def test_17_ssa_1_2_isolation(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        variable_version="$x#1",
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        variable_version="$x#2",
    )
    key1 = correlator.compute_correlation_key(v1)
    key2 = correlator.compute_correlation_key(v2)
    assert key1 != key2


def test_18_reassignment_invalidation(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="sink_reassign",
        sink_category="SQL_INJECTION",
        proof_status=ProofStatus.NOT_PROVEN,
    )
    verdict = decision_engine.evaluate_verdict(bundle, variable_version="$x#2")
    assert DecisionReason.SSA_VERSION_ISOLATED in verdict.reason_codes
    assert verdict.variable_version == "$x#2"


def test_19_call_context_isolation(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        call_context="ctx_tainted",
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.SAFE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, call_context="ctx_trusted"
    )
    key1 = correlator.compute_correlation_key(v1)
    key2 = correlator.compute_correlation_key(v2)
    assert key1 != key2


def test_20_true_branch_guard(decision_engine: SecurityDecisionEngine) -> None:
    verdict = decision_engine.evaluate_verdict(
        SemanticEvidenceBundle(sink_node_id="s1", sink_category="SQL_INJECTION"),
        branch_polarity="TRUE",
    )
    assert verdict.branch_polarity == "TRUE"


def test_21_false_branch_guard(decision_engine: SecurityDecisionEngine) -> None:
    verdict = decision_engine.evaluate_verdict(
        SemanticEvidenceBundle(sink_node_id="s1", sink_category="SQL_INJECTION"),
        branch_polarity="FALSE",
    )
    assert verdict.branch_polarity == "FALSE"


def test_22_branch_polarity_isolation(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.SAFE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, branch_polarity="TRUE"
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        branch_polarity="FALSE",
    )
    key1 = correlator.compute_correlation_key(v1)
    key2 = correlator.compute_correlation_key(v2)
    assert key1 != key2


# ---------------------------------------------------------------------------
# Tests 23-25: Specific Sink Category vs Sanitizer Tests
# ---------------------------------------------------------------------------


def test_23_sql_sink_html_sanitizer(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        CompatibilityDecision.NOT_PROVEN,
        reason="HTML_ESCAPED incompatible with SQL",
        sink_context=SinkContext.SQL_VALUE,
    )
    ev = SemanticEvidence(
        node_id="e1",
        evidence_kind=EvidenceKind.SANITIZER,
        sanitization_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="s1",
        sink_category="SQL_INJECTION",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.VULNERABLE


def test_24_html_sink_html_sanitizer(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        CompatibilityDecision.COMPATIBLE,
        reason="HTML_ESCAPED compatible with XSS",
        matching_constraint=SemanticConstraint.HTML_ESCAPED,
        sink_context=SinkContext.HTML_TEXT,
    )
    ev = SemanticEvidence(
        node_id="e1",
        evidence_kind=EvidenceKind.SANITIZER,
        sanitization_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="s1",
        sink_category="XSS",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.SAFE


def test_25_shell_sink_unrelated_sanitizer(decision_engine: SecurityDecisionEngine) -> None:
    eval_res = EvaluationResult(
        CompatibilityDecision.NOT_PROVEN, reason="Unrelated sanitizer", sink_context=SinkContext.SHELL_ARGUMENT
    )
    ev = SemanticEvidence(
        node_id="e1",
        evidence_kind=EvidenceKind.SANITIZER,
        sanitization_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="s1",
        sink_category="COMMAND_INJECTION",
        evidences=(ev,),
        proof_status=ProofStatus.PROVEN,
        evaluation_result=eval_res,
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.VULNERABLE


# ---------------------------------------------------------------------------
# Tests 26-31: Authority & Determinism Tests
# ---------------------------------------------------------------------------


def test_26_matrix_authority_preservation(decision_engine: SecurityDecisionEngine) -> None:
    # Ensure decision_engine delegates authority to matrix result
    eval_res = EvaluationResult(
        CompatibilityDecision.NOT_PROVEN, reason="Denied by matrix", sink_context=SinkContext.SQL_VALUE
    )
    bundle = SemanticEvidenceBundle(
        sink_node_id="s1", sink_category="SQL_INJECTION", proof_status=ProofStatus.PROVEN, evaluation_result=eval_res
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.VULNERABLE
    assert verdict.compatibility_decision == "NOT_PROVEN"


def test_27_deterministic_reason_codes(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="s1", sink_category="SQL_INJECTION", proof_status=ProofStatus.NOT_PROVEN
    )
    v1 = decision_engine.evaluate_verdict(bundle)
    v2 = decision_engine.evaluate_verdict(bundle)
    assert v1.reason_codes == v2.reason_codes


def test_28_deterministic_evidence_ordering(decision_engine: SecurityDecisionEngine) -> None:
    ev1 = SemanticEvidence(node_id="e1", evidence_kind=EvidenceKind.SOURCE, var_name="$a")
    ev2 = SemanticEvidence(node_id="e2", evidence_kind=EvidenceKind.GUARD, var_name="$b")
    bundle = SemanticEvidenceBundle(sink_node_id="s1", sink_category="SQL_INJECTION", evidences=(ev1, ev2))
    v1 = decision_engine.evaluate_verdict(bundle)
    v2 = decision_engine.evaluate_verdict(bundle)
    assert [ev.evidence_id for ev in v1.evidence_references] == [ev.evidence_id for ev in v2.evidence_references]


def test_29_deterministic_fingerprint() -> None:
    fp1 = compute_evidence_fingerprint(
        "R1", "SQL", "f.php", "foo", 10, "v1", "ctx", "TRUE", ("s1",), ("p1",), (DecisionReason.TAINT_REACHES_SINK,), ()
    )
    fp2 = compute_evidence_fingerprint(
        "R1", "SQL", "f.php", "foo", 10, "v1", "ctx", "TRUE", ("s1",), ("p1",), (DecisionReason.TAINT_REACHES_SINK,), ()
    )
    assert fp1 == fp2
    assert len(fp1) == 32


def test_30_fingerprint_changes_when_evidence_changes() -> None:
    fp1 = compute_evidence_fingerprint(
        "R1", "SQL", "f.php", "foo", 10, "v1", "ctx", "TRUE", ("s1",), ("p1",), (DecisionReason.TAINT_REACHES_SINK,), ()
    )
    fp2 = compute_evidence_fingerprint(
        "R1", "SQL", "f.php", "foo", 10, "v2", "ctx", "TRUE", ("s1",), ("p1",), (DecisionReason.TAINT_REACHES_SINK,), ()
    )
    assert fp1 != fp2


def test_31_equivalent_evidence_gives_same_fingerprint() -> None:
    # Different order of source IDs should produce same canonical fingerprint
    fp1 = compute_evidence_fingerprint(
        "R1",
        "SQL",
        "f.php",
        "foo",
        10,
        "v1",
        "ctx",
        "TRUE",
        ("s1", "s2"),
        ("p1",),
        (DecisionReason.TAINT_REACHES_SINK,),
        (),
    )
    fp2 = compute_evidence_fingerprint(
        "R1",
        "SQL",
        "f.php",
        "foo",
        10,
        "v1",
        "ctx",
        "TRUE",
        ("s2", "s1"),
        ("p1",),
        (DecisionReason.TAINT_REACHES_SINK,),
        (),
    )
    assert fp1 == fp2


# ---------------------------------------------------------------------------
# Tests 32-37: Finding Correlation
# ---------------------------------------------------------------------------


def test_32_finding_correlation(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10
    )
    groups = correlator.correlate_verdicts([v1, v2])
    assert len(groups) == 1
    assert groups[0].verdict_count == 2


def test_33_source_distinct_findings_not_merged(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, source_ids=("srcA",)
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, source_ids=("srcB",)
    )
    groups = correlator.correlate_verdicts([v1, v2])
    assert len(groups) == 2


def test_34_context_distinct_findings_not_merged(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, call_context="ctx1"
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, call_context="ctx2"
    )
    groups = correlator.correlate_verdicts([v1, v2])
    assert len(groups) == 2


def test_35_ssa_distinct_findings_not_merged(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        variable_version="$x#1",
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        variable_version="$x#2",
    )
    groups = correlator.correlate_verdicts([v1, v2])
    assert len(groups) == 2


def test_36_branch_distinct_findings_not_merged(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.SAFE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, branch_polarity="TRUE"
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "R1",
        "s1",
        "SQL",
        "f.php",
        "func",
        10,
        branch_polarity="FALSE",
    )
    groups = correlator.correlate_verdicts([v1, v2])
    assert len(groups) == 2


def test_37_equivalent_findings_merged(correlator: SemanticFindingCorrelator) -> None:
    v1 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, source_ids=("src1",)
    )
    v2 = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "R1", "s1", "SQL", "f.php", "func", 10, source_ids=("src1",)
    )
    groups = correlator.correlate_verdicts([v1, v2])
    assert len(groups) == 1


# ---------------------------------------------------------------------------
# Tests 38-42: SARIF Integration & Finding Compatibility
# ---------------------------------------------------------------------------


def test_38_sarif_verdict_property(tmp_path: Path) -> None:
    v = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "KS-SQL-01", "s1", "SQL", "index.php", "main", 10
    )
    ev = Evidence(snippet="query($id)", line=10, column=1)
    f = Finding(
        "f1",
        "KS-SQL-01",
        "fp1",
        "SQLi",
        Severity.HIGH,
        Confidence.CONFIDENT,
        "CWE-89",
        "A1",
        Path("index.php"),
        ev,
        "desc",
        "rem",
        verdict=v,
    )

    sarif_file = tmp_path / "report.sarif"
    reporter = SARIFReporter()
    exec_res = ExecutionResult("s1", "2026-08-12", 1, 1, 1, findings=(f,))
    target = FileTarget(sarif_file)
    reporter.generate(exec_res, target)

    content = sarif_file.read_text()
    assert "karsasec.verdict" in content
    assert "VULNERABLE" in content


def test_39_sarif_evidence_fingerprint(tmp_path: Path) -> None:
    v = SecurityVerdict.create(
        VerdictStatus.VULNERABLE, VerdictConfidence.HIGH, "KS-SQL-01", "s1", "SQL", "index.php", "main", 10
    )
    ev = Evidence(snippet="query($id)", line=10, column=1)
    f = Finding(
        "f1",
        "KS-SQL-01",
        "fp1",
        "SQLi",
        Severity.HIGH,
        Confidence.CONFIDENT,
        "CWE-89",
        "A1",
        Path("index.php"),
        ev,
        "desc",
        "rem",
        verdict=v,
    )

    sarif_file = tmp_path / "report.sarif"
    reporter = SARIFReporter()
    target = FileTarget(sarif_file)
    reporter.generate(ExecutionResult("s1", "2026-08-12", 1, 1, 1, findings=(f,)), target)

    content = sarif_file.read_text()
    assert "karsasec.evidence_fingerprint" in content
    assert v.evidence_fingerprint in content


def test_40_sarif_reason_codes(tmp_path: Path) -> None:
    v = SecurityVerdict.create(
        VerdictStatus.VULNERABLE,
        VerdictConfidence.HIGH,
        "KS-SQL-01",
        "s1",
        "SQL",
        "index.php",
        "main",
        10,
        reason_codes=(DecisionReason.TAINT_REACHES_SINK, DecisionReason.SANITIZER_INCOMPATIBLE),
    )
    ev = Evidence(snippet="query($id)", line=10, column=1)
    f = Finding(
        "f1",
        "KS-SQL-01",
        "fp1",
        "SQLi",
        Severity.HIGH,
        Confidence.CONFIDENT,
        "CWE-89",
        "A1",
        Path("index.php"),
        ev,
        "desc",
        "rem",
        verdict=v,
    )

    sarif_file = tmp_path / "report.sarif"
    reporter = SARIFReporter()
    target = FileTarget(sarif_file)
    reporter.generate(ExecutionResult("s1", "2026-08-12", 1, 1, 1, findings=(f,)), target)

    content = sarif_file.read_text()
    assert "karsasec.reason_codes" in content
    assert "TAINT_REACHES_SINK" in content


def test_41_legacy_finding_compatibility() -> None:
    ev = Evidence(snippet="eval($x)", line=5, column=1)
    f = Finding(
        "f_leg",
        "KS-EVAL-01",
        "fp_leg",
        "Eval Injection",
        Severity.HIGH,
        Confidence.CONFIDENT,
        "CWE-95",
        "A3",
        Path("legacy.php"),
        ev,
        "desc",
        "rem",
    )
    assert f.verdict is None
    d = f.to_dict()
    assert "verdict" not in d


def test_42_verdict_none_compatibility(tmp_path: Path) -> None:
    ev = Evidence(snippet="eval($x)", line=5, column=1)
    f = Finding(
        "f_leg",
        "KS-EVAL-01",
        "fp_leg",
        "Eval Injection",
        Severity.HIGH,
        Confidence.CONFIDENT,
        "CWE-95",
        "A3",
        Path("legacy.php"),
        ev,
        "desc",
        "rem",
    )

    sarif_file = tmp_path / "legacy.sarif"
    reporter = SARIFReporter()
    target = FileTarget(sarif_file)
    reporter.generate(ExecutionResult("s1", "2026-08-12", 1, 1, 1, findings=(f,)), target)

    content = sarif_file.read_text()
    assert "legacy.php" in content
    assert "karsasec.verdict" not in content


# ---------------------------------------------------------------------------
# Tests 43-45: Edge Cases & Anti-Hardcoding
# ---------------------------------------------------------------------------


def test_43_unknown_evidence_preserved(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(sink_node_id="s1", sink_category="CUSTOM_SINK", proof_status=ProofStatus.NOT_PROVEN)
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status == VerdictStatus.UNKNOWN


def test_44_non_converged_state_preserved(decision_engine: SecurityDecisionEngine) -> None:
    bundle = SemanticEvidenceBundle(
        sink_node_id="s1", sink_category="RECURSIVE_SINK", proof_status=ProofStatus.NOT_PROVEN
    )
    verdict = decision_engine.evaluate_verdict(bundle)
    assert verdict.status != VerdictStatus.SAFE


def test_45_no_benchmark_hardcoding() -> None:
    import inspect
    import karsasec.graph.dataflow.security_decision as sd
    import karsasec.graph.dataflow.security_verdict as sv

    sd_source = inspect.getsource(sd)
    sv_source = inspect.getsource(sv)

    for word in ("dvwa", "benchmark", "fixture"):
        assert word not in sd_source.lower(), f"Benchmark string '{word}' found in security_decision.py"
        assert word not in sv_source.lower(), f"Benchmark string '{word}' found in security_verdict.py"
