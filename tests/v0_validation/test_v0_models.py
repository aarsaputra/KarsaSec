"""Unit and invariant tests for Phase V0 domain models and canonical identity schema."""

from __future__ import annotations

from karsasec.validation.v0_models import (
    BenchmarkSample,
    GroundTruthFinding,
    ValidationRunResult,
    ValidationScorecard,
    deterministic_id,
)


def test_deterministic_id_format_and_stability():
    payload = {"b": 2, "a": 1}
    did1 = deterministic_id("V0-TEST:v1:", payload)
    did2 = deterministic_id("V0-TEST:v1:", {"a": 1, "b": 2})

    assert len(did1) == 64
    assert did1 == did2


def test_ground_truth_finding_creation():
    gt = GroundTruthFinding.create(
        vuln_class="SQL_INJECTION",
        expected_severity="HIGH",
        expected_decision="BLOCK",
        expected_admission="BLOCKED",
    )

    assert gt.truth_id.startswith("")
    assert len(gt.truth_id) == 64
    assert gt.vuln_class == "SQL_INJECTION"
    assert gt.to_dict()["vuln_class"] == "SQL_INJECTION"


def test_benchmark_sample_creation():
    gt = GroundTruthFinding.create(vuln_class="XSS")
    sample = BenchmarkSample.create(
        category="xss",
        name="XSS Sample",
        vulnerable_code="print(user_input)",
        fixed_code="print(html.escape(user_input))",
        mutated_code="print(f'{user_input}')",
        ground_truth=gt,
    )

    assert len(sample.sample_id) == 64
    assert sample.category == "xss"
    assert sample.ground_truth.vuln_class == "XSS"


def test_validation_run_result_creation():
    res = ValidationRunResult.create(
        sample_id="a" * 64,
        actual_findings=("SQL_INJECTION",),
        actual_decision="BLOCK",
        actual_admission="BLOCKED",
        is_true_positive=True,
        is_false_positive=False,
        is_false_negative=False,
        mutation_detected=True,
    )

    assert len(res.result_id) == 64
    assert res.is_true_positive is True


def test_validation_scorecard_creation():
    sc = ValidationScorecard.create(
        total_samples=11,
        true_positives=11,
        false_positives=0,
        false_negatives=0,
        tp_rate=100.0,
        fp_rate=0.0,
        mutation_sensitivity_score=100.0,
        gate_status="PASS",
    )

    assert len(sc.scorecard_id) == 64
    assert sc.gate_status == "PASS"
    assert sc.tp_rate == 100.0
