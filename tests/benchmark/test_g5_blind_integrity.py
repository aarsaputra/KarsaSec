"""Adversarial Unit Tests for Blind Detector Runner & Independent Evaluator (INVARIANT G5.1-01 & G5.1-02).

Verifies:
1. Detector receives ONLY source_code, language, framework.
2. Detector does NOT receive ground-truth CWE or expected status.
3. Multi-property scan runs independently across all supported security properties.
4. Independent Evaluator computes Epistemic Decision Correctness (EDC) and Wilson CIs.
"""

from karsasec.benchmark.blind_runner import BlindDetectorRunner
from karsasec.benchmark.independent_evaluator import IndependentEvaluator


def test_blind_detector_runner_no_ground_truth_leakage() -> None:
    runner = BlindDetectorRunner()

    snippet = "String id = request.getParameter('id'); db.execute('SELECT * FROM users WHERE id = ' + id);"
    res = runner.analyze_blind(snippet, language="Java", framework="Servlet")

    assert "findings" in res
    assert "SQL_INJECTION" in res["findings"]
    assert "CROSS_SITE_SCRIPTING" in res["findings"]

    # Without CWE hint, detector identifies SQL_INJECTION as VULNERABLE
    assert res["findings"]["SQL_INJECTION"] == "VULNERABLE"


def test_independent_evaluator_metrics() -> None:
    evaluator = IndependentEvaluator()

    raw_preds = [
        {"case_id": "TC_001", "findings": {"SQL_INJECTION": "VULNERABLE"}},
        {"case_id": "TC_002", "findings": {"SQL_INJECTION": "SAFE"}},
    ]
    manifest = {
        "cases": [
            {"vulnerability_id": "TC_001", "CWE": "CWE-89", "expected_status": "VULNERABLE"},
            {"vulnerability_id": "TC_002", "CWE": "CWE-89", "expected_status": "SAFE"},
        ]
    }

    metrics = evaluator.evaluate_manifest(raw_preds, manifest)
    assert metrics["strict_precision"] == 1.0
    assert metrics["strict_recall"] == 1.0
    assert metrics["epistemic_decision_correctness"] == 1.0
    assert "wilson_95_ci" in metrics
