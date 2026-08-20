"""Unit tests for qualification metrics calculation and category aggregation (E12-2)."""

from __future__ import annotations

import pytest

from karsasec.qualification.metrics import (
    CategoryQualificationResult,
    build_category_result,
    calculate_cross_rule_overlap_rate,
    calculate_duplicate_rate,
    calculate_f1,
    calculate_precision,
    calculate_recall,
    calculate_unknown_rate,
)


class TestMetricsCalculation:
    def test_precision_standard(self) -> None:
        assert calculate_precision(8, 2) == 0.8
        assert calculate_precision(10, 0) == 1.0
        assert calculate_precision(0, 5) == 0.0

    def test_precision_zero_division(self) -> None:
        assert calculate_precision(0, 0) == 0.0

    def test_recall_standard(self) -> None:
        assert calculate_recall(8, 2) == 0.8
        assert calculate_recall(10, 0) == 1.0
        assert calculate_recall(0, 5) == 0.0

    def test_recall_zero_division(self) -> None:
        assert calculate_recall(0, 0) == 0.0

    def test_f1_standard(self) -> None:
        p = 0.8
        r = 0.8
        assert pytest.approx(calculate_f1(p, r), 0.0001) == 0.8

    def test_f1_zero_division(self) -> None:
        assert calculate_f1(0.0, 0.0) == 0.0
        assert calculate_f1(0.0, 0.5) == 0.0

    def test_duplicate_rate(self) -> None:
        assert calculate_duplicate_rate(10, 8) == 0.2
        assert calculate_duplicate_rate(5, 5) == 0.0
        assert calculate_duplicate_rate(0, 0) == 0.0

    def test_cross_rule_overlap_rate(self) -> None:
        assert calculate_cross_rule_overlap_rate(2, 10) == 0.2
        assert calculate_cross_rule_overlap_rate(0, 5) == 0.0
        assert calculate_cross_rule_overlap_rate(0, 0) == 0.0

    def test_unknown_rate(self) -> None:
        assert calculate_unknown_rate(3, 10) == 0.3
        assert calculate_unknown_rate(0, 5) == 0.0
        assert calculate_unknown_rate(0, 0) == 0.0

    def test_build_category_result(self) -> None:
        res = build_category_result(
            category="SQL_INJECTION",
            tp=6,
            fp=2,
            fn=0,
            tn=2,
            unknown=0,
            cases=10,
        )
        assert isinstance(res, CategoryQualificationResult)
        assert res.category == "SQL_INJECTION"
        assert res.tp == 6
        assert res.fp == 2
        assert res.precision == 0.75
        assert res.recall == 1.0
        assert pytest.approx(res.f1, 0.001) == 0.8571
