"""Unit test suite for Batch C3 Path Traversal Reasoning Engine including quality metrics breakdown."""

from karsasec.analysis.file_security.path_engine import (
    PathAccessNode,
    PathTraversalReasoningEngine,
    PathVulnerabilityType,
)


def test_path_traversal_engine_unit() -> None:
    """Verifies core path traversal engine unit functions."""
    engine = PathTraversalReasoningEngine()
    node = PathAccessNode(path_input="../../etc/passwd", is_containment_checked=False)
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.PATH_TRAVERSAL
    assert "source" in ev.to_dict()
    assert "sink" in ev.to_dict()


def test_quality_metrics_calculation() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = PathTraversalReasoningEngine()

    positives = [
        PathAccessNode(path_input=f"../../etc/passwd_{i}", is_containment_checked=False) for i in range(50)
    ]
    negatives = [
        PathAccessNode(path_input=f"file_{i}.txt", is_containment_checked=True, is_canonicalized=True) for i in range(50)
    ]

    tp = sum(1 for node in positives if engine.evaluate_path_access(node) is not None)
    fn = len(positives) - tp

    fp = sum(1 for node in negatives if engine.evaluate_path_access(node) is not None)
    tn = len(negatives) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
