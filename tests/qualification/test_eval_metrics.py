"""Unit tests for precision, recall, and quantitative evaluation metrics engine."""

import pytest
from karsasec.eval.metrics import EvaluationMetrics
from karsasec.eval.runner import BenchmarkEvaluator


def test_evaluation_metrics_calculations():
    """Verify mathematical calculations for precision, recall, f1, and false positive rate."""
    metrics = EvaluationMetrics(
        total_samples=100,
        true_positives=40,
        false_positives=0,
        false_negatives=10,
        true_negatives=50,
    )

    assert metrics.precision == 1.0  # 40 / 40
    assert metrics.recall == 0.8  # 40 / 50
    assert metrics.false_positive_rate == 0.0  # 0 / 50
    assert metrics.f1_score > 0.88

    as_dict = metrics.to_dict()
    assert as_dict["precision"] == 1.0
    assert as_dict["false_positives"] == 0


def test_benchmark_evaluator_execution():
    """Verify that BenchmarkEvaluator runs over the security_corpus and yields valid metrics."""
    evaluator = BenchmarkEvaluator()
    results = evaluator.evaluate()

    assert results.total_samples > 0
    assert results.precision >= 0.90  # Precision target (>90%)
    assert results.recall >= 0.90  # Recall target (>90%)
    assert results.false_positives <= 2
