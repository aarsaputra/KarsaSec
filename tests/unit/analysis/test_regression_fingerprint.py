"""Unit tests for RegressionFingerprint model, path normalization, and line independence."""

from __future__ import annotations

from karsasec.analysis.regression_fingerprint import (
    RegressionFingerprint,
    compute_regression_fingerprint,
    normalize_path,
)


def test_normalize_path_line_and_dot_stripping() -> None:
    """Verifies line number stripping and path normalization."""
    assert normalize_path("foo/../foo/app.py:42:10") == "foo/app.py"
    assert normalize_path("./foo/app.py") == "foo/app.py"
    assert normalize_path("C:\\foo\\bar\\app.py:100") == "c:/foo/bar/app.py"


def test_regression_fingerprint_line_independence() -> None:
    """INV-E14-PRIO-15 & Case AE: Changing line numbers MUST NOT alter regression fingerprint."""
    fp1 = compute_regression_fingerprint("SQL_INJECTION", "sf1", "SQL", "app.py:10", "SQL-001")
    fp2 = compute_regression_fingerprint("SQL_INJECTION", "sf1", "SQL", "app.py:1000", "SQL-001")

    assert fp1 == fp2
    assert len(fp1) == 64


def test_regression_fingerprint_creation() -> None:
    """Verifies factory creation of RegressionFingerprint."""
    fp = RegressionFingerprint.create(
        vulnerability_class="SQL_INJECTION",
        source_kind="sf1",
        sink_category="SQL",
        file_path="foo/app.py:50",
        rule_key="SQL-001",
        cluster_id="c1",
    )

    assert fp.fingerprint_id is not None
    assert fp.normalized_path == "foo/app.py"
