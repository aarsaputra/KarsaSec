"""Metric calculations for the Qualification System (E12-1).

All functions are pure and deterministic.
Zero-division is handled explicitly and documented — never raises ZeroDivisionError.

Definitions:
    Precision  = TP / (TP + FP)   — what fraction of detections are real?
    Recall     = TP / (TP + FN)   — what fraction of real vulns are detected?
    F1         = 2 * P * R / (P + R) — harmonic mean
    Duplicate Rate = duplicates / raw_findings

Zero-division policy (documented invariant):
    TP + FP == 0  → precision = 0.0  (no detections made; precision undefined)
    TP + FN == 0  → recall    = 0.0  (no positive cases; recall undefined)
    P + R   == 0  → f1        = 0.0  (both undefined)
    raw == 0      → dup_rate  = 0.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleQualificationResult:
    """Per-rule qualification metrics."""

    rule_id: str
    tp: int
    fp: int
    fn: int
    unknown: int
    precision: float
    recall: float
    f1: float
    cases_evaluated: int


@dataclass(frozen=True, slots=True)
class CategoryQualificationResult:
    """Per-category qualification metrics."""

    category: str
    tp: int
    fp: int
    fn: int
    tn: int
    unknown: int
    precision: float
    recall: float
    f1: float
    cases_evaluated: int


def calculate_precision(tp: int, fp: int) -> float:
    """Precision = TP / (TP + FP).

    Returns 0.0 when TP + FP == 0 (no detections — precision is undefined).
    """
    denom = tp + fp
    return tp / denom if denom > 0 else 0.0


def calculate_recall(tp: int, fn: int) -> float:
    """Recall = TP / (TP + FN).

    Returns 0.0 when TP + FN == 0 (no positive cases — recall is undefined).
    """
    denom = tp + fn
    return tp / denom if denom > 0 else 0.0


def calculate_f1(precision: float, recall: float) -> float:
    """F1 = 2 * P * R / (P + R).

    Returns 0.0 when P + R == 0.
    """
    denom = precision + recall
    return 2.0 * precision * recall / denom if denom > 0.0 else 0.0


def calculate_duplicate_rate(raw_count: int, final_count: int) -> float:
    """Duplicate rate = duplicates / raw_count.

    Returns 0.0 when raw_count == 0.
    Duplicates = raw_count - final_count. Clamped to 0 (never negative).
    """
    if raw_count <= 0:
        return 0.0
    duplicates = max(0, raw_count - final_count)
    return duplicates / raw_count


def calculate_cross_rule_overlap_rate(overlap_locations_count: int, total_locations_count: int) -> float:
    """Cross-rule overlap rate = overlap_locations / total_locations.

    Returns 0.0 when total_locations_count == 0.
    """
    if total_locations_count <= 0:
        return 0.0
    return max(0, overlap_locations_count) / total_locations_count


def calculate_unknown_rate(unknown_count: int, total_findings_count: int) -> float:
    """UNKNOWN rate = unknown_count / total_findings_count.

    Returns 0.0 when total_findings_count == 0.
    """
    if total_findings_count <= 0:
        return 0.0
    return max(0, unknown_count) / total_findings_count


def build_rule_result(rule_id: str, tp: int, fp: int, fn: int, unknown: int, cases: int) -> RuleQualificationResult:
    """Compute a complete RuleQualificationResult from raw counts."""
    p = calculate_precision(tp, fp)
    r = calculate_recall(tp, fn)
    f = calculate_f1(p, r)
    return RuleQualificationResult(
        rule_id=rule_id,
        tp=tp,
        fp=fp,
        fn=fn,
        unknown=unknown,
        precision=p,
        recall=r,
        f1=f,
        cases_evaluated=cases,
    )


def build_category_result(
    category: str, tp: int, fp: int, fn: int, tn: int, unknown: int, cases: int
) -> CategoryQualificationResult:
    """Compute a complete CategoryQualificationResult from raw counts."""
    p = calculate_precision(tp, fp)
    r = calculate_recall(tp, fn)
    f = calculate_f1(p, r)
    return CategoryQualificationResult(
        category=category,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        unknown=unknown,
        precision=p,
        recall=r,
        f1=f,
        cases_evaluated=cases,
    )
