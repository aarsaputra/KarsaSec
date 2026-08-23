"""Unit tests verifying Dynamic Metric & Wilson 95% CI Computation (INV-G5.3-07)."""

from karsasec.benchmark.independent_evaluator import IndependentEvaluator
from karsasec.benchmark.statistics import wilson_interval


def test_wilson_interval_mathematical_precision() -> None:
    p, low, high = wilson_interval(70, 70, confidence=0.95)
    assert p == 1.0
    assert 0.94 <= low <= 0.96
    assert high >= 0.9999

    p_dvwa, low_dvwa, high_dvwa = wilson_interval(22, 24, confidence=0.95)
    assert round(p_dvwa, 4) == 0.9167
    assert 0.74 <= low_dvwa <= 0.76
    assert 0.97 <= high_dvwa <= 0.98


def test_independent_evaluator_metrics_schema() -> None:
    evaluator = IndependentEvaluator()
    raw_preds = [
        {"case_id": "C_001", "findings": {"SQL_INJECTION": "VULNERABLE"}},
        {"case_id": "C_002", "findings": {"SQL_INJECTION": "SAFE"}},
    ]
    manifest = {
        "cases": [
            {"vulnerability_id": "C_001", "CWE": "CWE-89", "expected_status": "VULNERABLE"},
            {"vulnerability_id": "C_002", "CWE": "CWE-89", "expected_status": "SAFE"},
        ]
    }

    metrics = evaluator.evaluate_manifest(raw_preds, manifest)
    assert "wilson_95_ci" in metrics
    assert "precision" in metrics["wilson_95_ci"]
    assert "recall" in metrics["wilson_95_ci"]
    assert "edc" in metrics["wilson_95_ci"]
