"""Unit tests verifying Knowledge Regression Isolation (INV-G5.4-04)."""

from karsasec.benchmark.knowledge_regression import compare_metrics


def test_compare_metrics_detects_recall_regression() -> None:
    baseline = {"precision": 1.0, "recall": 1.0, "specificity": 1.0, "fpr": 0.0, "edc": 1.0}
    candidate = {"precision": 1.0, "recall": 0.95, "specificity": 1.0, "fpr": 0.0, "edc": 0.95}
    res = compare_metrics(baseline, candidate)
    assert res["status"] == "KNOWLEDGE_EXPANSION_REGRESSION"
    assert res["has_regression"] is True


def test_compare_metrics_detects_insufficient_data() -> None:
    baseline = {"precision": 1.0, "recall": 1.0}
    candidate = {}
    res = compare_metrics(baseline, candidate)
    assert res["status"] == "INSUFFICIENT_DATA"


def test_compare_metrics_passes_equal_or_better() -> None:
    baseline = {"precision": 0.9, "recall": 0.9, "specificity": 0.9, "fpr": 0.1, "edc": 0.9}
    candidate = {"precision": 0.95, "recall": 0.95, "specificity": 0.95, "fpr": 0.05, "edc": 0.95}
    res = compare_metrics(baseline, candidate)
    assert res["status"] == "PASS"
    assert res["has_regression"] is False
