"""Unit tests for RegressionReport model and deterministic report_id in tests/unit/analysis/test_regression_report.py."""

from __future__ import annotations

from karsasec.analysis.regression_report import (
    RegressionReport,
    RegressionStatus,
    compute_regression_report_id,
)


def test_regression_report_deterministic_id() -> None:
    """Verifies deterministic report_id computation."""
    rid1 = compute_regression_report_id(["fp1"], ["fp2"], [], [], [])
    rid2 = compute_regression_report_id(["fp1"], ["fp2"], [], [], [])

    assert rid1 == rid2
    assert len(rid1) == 64


def test_regression_report_creation() -> None:
    """Verifies RegressionReport factory creation."""
    report = RegressionReport.create(
        status=RegressionStatus.FAIL,
        new_fingerprints=["fp1"],
        persistent_fingerprints=["fp2"],
        resolved_fingerprints=[],
        changed_fingerprints=[],
        unknown_fingerprints=[],
        explanations=["NEW vulnerability detected"],
    )

    assert report.report_id is not None
    assert report.status == RegressionStatus.FAIL
    assert report.regressions_detected is True
