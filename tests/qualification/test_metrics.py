"""Tests for karsasec.qualification.metrics (E12-1)."""

from __future__ import annotations

import pytest

from karsasec.qualification.metrics import (
    build_rule_result,
    calculate_duplicate_rate,
    calculate_f1,
    calculate_precision,
    calculate_recall,
)


class TestPrecision:
    def test_perfect_precision(self) -> None:
        assert calculate_precision(10, 0) == 1.0

    def test_zero_tp(self) -> None:
        assert calculate_precision(0, 5) == 0.0

    def test_mixed(self) -> None:
        assert calculate_precision(8, 2) == pytest.approx(0.8)

    def test_zero_tp_zero_fp(self) -> None:
        # Documented: TP+FP==0 -> 0.0
        assert calculate_precision(0, 0) == 0.0

    def test_negative_counts_not_raised(self) -> None:
        # Defensive: negative counts should not crash
        assert calculate_precision(0, 0) == 0.0


class TestRecall:
    def test_perfect_recall(self) -> None:
        assert calculate_recall(10, 0) == 1.0

    def test_zero_tp(self) -> None:
        assert calculate_recall(0, 5) == 0.0

    def test_mixed(self) -> None:
        assert calculate_recall(8, 2) == pytest.approx(0.8)

    def test_zero_tp_zero_fn(self) -> None:
        # Documented: TP+FN==0 -> 0.0
        assert calculate_recall(0, 0) == 0.0


class TestF1:
    def test_perfect_f1(self) -> None:
        assert calculate_f1(1.0, 1.0) == pytest.approx(1.0)

    def test_zero_both(self) -> None:
        # Documented: P+R==0 -> 0.0
        assert calculate_f1(0.0, 0.0) == 0.0

    def test_asymmetric(self) -> None:
        p = calculate_precision(8, 2)  # 0.8
        r = calculate_recall(8, 2)  # 0.8
        f = calculate_f1(p, r)
        assert f == pytest.approx(0.8)

    def test_zero_recall(self) -> None:
        assert calculate_f1(1.0, 0.0) == 0.0

    def test_zero_precision(self) -> None:
        assert calculate_f1(0.0, 1.0) == 0.0


class TestDuplicateRate:
    def test_no_duplicates(self) -> None:
        assert calculate_duplicate_rate(10, 10) == 0.0

    def test_some_duplicates(self) -> None:
        rate = calculate_duplicate_rate(100, 90)
        assert rate == pytest.approx(0.10)

    def test_zero_raw(self) -> None:
        # Documented: raw==0 -> 0.0
        assert calculate_duplicate_rate(0, 0) == 0.0

    def test_final_greater_than_raw_clamped(self) -> None:
        # final > raw should not return negative rate
        assert calculate_duplicate_rate(10, 15) == 0.0

    def test_all_duplicates(self) -> None:
        assert calculate_duplicate_rate(10, 0) == pytest.approx(1.0)


class TestBuildRuleResult:
    def test_perfect(self) -> None:
        rr = build_rule_result("KS-PHP-0002", tp=5, fp=0, fn=0, unknown=0, cases=5)
        assert rr.precision == pytest.approx(1.0)
        assert rr.recall == pytest.approx(1.0)
        assert rr.f1 == pytest.approx(1.0)

    def test_zero_detections(self) -> None:
        rr = build_rule_result("KS-PHP-0002", tp=0, fp=0, fn=5, unknown=0, cases=5)
        assert rr.precision == 0.0
        assert rr.recall == 0.0

    def test_rule_id_preserved(self) -> None:
        rr = build_rule_result("KS-PHP-0099", tp=1, fp=1, fn=1, unknown=2, cases=3)
        assert rr.rule_id == "KS-PHP-0099"
        assert rr.unknown == 2
