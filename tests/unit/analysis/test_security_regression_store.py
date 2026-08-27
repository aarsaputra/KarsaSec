"""Unit tests for SecurityRegressionStore thread-safety and insert-if-absent logic."""

from __future__ import annotations

import concurrent.futures

from karsasec.analysis.regression_fingerprint import RegressionFingerprint
from karsasec.analysis.security_regression_store import SecurityRegressionStore


def test_security_regression_store_deduplication() -> None:
    """INV-E14-PRIO-17: Store MUST NOT create duplicate records for identical fingerprints."""
    fp1 = RegressionFingerprint.create("SQL_INJECTION", "sf1", "SQL", "app.py", "SQL-001", "c1")
    fp2 = RegressionFingerprint.create("SQL_INJECTION", "sf1", "SQL", "app.py", "SQL-001", "c1")

    store = SecurityRegressionStore()
    res1 = store.add(fp1)
    res2 = store.add(fp2)

    assert res1 is True
    assert res2 is False
    assert len(store) == 1


def test_security_regression_store_concurrent_insert() -> None:
    """Case AH: 100 concurrent identical insertions MUST produce exactly one record."""
    fp = RegressionFingerprint.create("SQL_INJECTION", "sf1", "SQL", "app.py", "SQL-001", "c1")
    store = SecurityRegressionStore()

    def _insert() -> bool:
        return store.add(fp)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_insert) for _ in range(100)]
        results = [f.result() for f in futures]

    assert sum(1 for r in results if r is True) == 1
    assert len(store) == 1
