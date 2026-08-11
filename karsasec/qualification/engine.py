"""Qualification Engine: orchestrates ground-truth comparison and metric calculation (E12-2).

Pipeline:
    GroundTruthBenchmark + Final Findings + Raw Findings
              ↓
    QualificationClassifier   (TP/FP/FN/TN/UNKNOWN)
              ↓
    MetricCalculator          (precision/recall/F1/duplicate_rate/overlap_rate/unknown_rate)
              ↓
    QualificationResult       (per-benchmark, per-rule, per-category, quality metrics)

Performance target: qualification overhead < 10% of scan runtime.
The engine is pure: it receives pre-scanned findings, does not re-run the parser.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from karsasec.core.finding.model import Finding
from karsasec.qualification.classifier import ClassificationReport, QualificationClassifier
from karsasec.qualification.identity import FindingIdentity
from karsasec.qualification.metrics import (
    CategoryQualificationResult,
    RuleQualificationResult,
    build_category_result,
    build_rule_result,
    calculate_cross_rule_overlap_rate,
    calculate_duplicate_rate,
    calculate_f1,
    calculate_precision,
    calculate_recall,
    calculate_unknown_rate,
)
from karsasec.qualification.model import GroundTruthBenchmark


@dataclass(frozen=True)
class QualificationResult:
    """Complete qualification result for one benchmark run.

    Attributes:
        benchmark_id:            Benchmark name.
        version:                 Benchmark version.
        total_cases:             Total ground-truth cases evaluated.
        true_positives:          TP count.
        false_positives:         FP count (FP-from-TN + unmatched findings).
        false_negatives:         FN count.
        true_negatives:          TN count (TN cases with no matching finding).
        unknown_findings:        Findings with UNKNOWN confidence (tracked, not TP/FP).
        precision:               Benchmark-wide precision.
        recall:                  Benchmark-wide recall.
        f1:                      Benchmark-wide F1.
        raw_findings:            Finding count BEFORE deduplication.
        final_findings:          Finding count AFTER deduplication (what was qualified).
        duplicate_findings:      raw - final (clamp ≥ 0).
        duplicate_rate:          duplicate_findings / raw_findings.
        exact_duplicates:        Count of identical (file, line, rule_id) before deduplication.
        exact_duplicate_rate:    exact_duplicates / raw_findings.
        cross_rule_overlaps:     Locations (file, line) reported by >1 distinct rule.
        cross_rule_overlap_rate: cross_rule_overlaps / total_finding_locations.
        unknown_rate:            unknown_findings / final_findings.
        per_rule:                Per-rule breakdown keyed by rule_id.
        per_category:            Per-category breakdown keyed by category.
        classification_report:   Full case-by-case classification detail.
    """
    benchmark_id: str
    version: str
    total_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    unknown_findings: int
    precision: float
    recall: float
    f1: float
    raw_findings: int
    final_findings: int
    duplicate_findings: int
    duplicate_rate: float
    exact_duplicates: int
    exact_duplicate_rate: float
    cross_rule_overlaps: int
    cross_rule_overlap_rate: float
    unknown_rate: float
    per_rule: dict[str, RuleQualificationResult]
    per_category: dict[str, CategoryQualificationResult]
    classification_report: ClassificationReport


class QualificationEngine:
    """Orchestrates the qualification pipeline for a given benchmark and scan result."""

    def __init__(self) -> None:
        self._classifier = QualificationClassifier()

    def qualify(
        self,
        benchmark: GroundTruthBenchmark,
        final_findings: tuple[Finding, ...] | list[Finding],
        scan_root: Path,
        raw_finding_count: int = 0,
        raw_findings: tuple[Finding, ...] | list[Finding] | None = None,
    ) -> QualificationResult:
        """Run full qualification pipeline.

        Args:
            benchmark:          Ground-truth benchmark.
            final_findings:     Correlated findings from FindingCorrelator.
            scan_root:          Absolute path used to normalize finding file paths.
            raw_finding_count:  Count of findings before deduplication (for duplicate_rate).
            raw_findings:       Optional tuple/list of raw findings before deduplication.

        Returns:
            QualificationResult with all metrics, per-rule and per-category breakdowns.
        """
        report = self._classifier.classify(benchmark, final_findings, scan_root)

        tp = report.tp
        fp = report.fp
        fn = report.fn
        tn = report.tn
        unknown = report.unknown

        precision = calculate_precision(tp, fp)
        recall = calculate_recall(tp, fn)
        f1 = calculate_f1(precision, recall)

        final_count = len(final_findings)
        raw_count = max(raw_finding_count, final_count)
        dup_count = max(0, raw_count - final_count)
        dup_rate = calculate_duplicate_rate(raw_count, final_count)

        # --- Compute Exact Duplicates ---
        exact_dups = 0
        if raw_findings:
            identities = [FindingIdentity.from_finding(f, scan_root) for f in raw_findings]
            unique_identities = set(identities)
            exact_dups = max(0, len(identities) - len(unique_identities))
        else:
            exact_dups = dup_count
        exact_dup_rate = exact_dups / raw_count if raw_count > 0 else 0.0

        # --- Compute Cross-Rule Overlaps ---
        location_rules: dict[tuple[str, int | None], set[str]] = defaultdict(set)
        for f in final_findings:
            fi = FindingIdentity.from_finding(f, scan_root)
            location_rules[(fi.normalized_file, fi.line)].add(fi.rule_id)

        total_locations = len(location_rules)
        cross_rule_overlaps = sum(1 for rules in location_rules.values() if len(rules) > 1)
        cross_rule_overlap_rate = calculate_cross_rule_overlap_rate(cross_rule_overlaps, total_locations)

        # --- Compute UNKNOWN Rate ---
        unknown_rate = calculate_unknown_rate(unknown, final_count)

        # --- Aggregations ---
        per_rule = self._build_per_rule(report)
        per_category = self._build_per_category(report)

        return QualificationResult(
            benchmark_id=benchmark.benchmark_id,
            version=benchmark.version,
            total_cases=len(benchmark.cases),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            unknown_findings=unknown,
            precision=precision,
            recall=recall,
            f1=f1,
            raw_findings=raw_count,
            final_findings=final_count,
            duplicate_findings=dup_count,
            duplicate_rate=dup_rate,
            exact_duplicates=exact_dups,
            exact_duplicate_rate=exact_dup_rate,
            cross_rule_overlaps=cross_rule_overlaps,
            cross_rule_overlap_rate=cross_rule_overlap_rate,
            unknown_rate=unknown_rate,
            per_rule=per_rule,
            per_category=per_category,
            classification_report=report,
        )

    @staticmethod
    def _build_per_rule(report: ClassificationReport) -> dict[str, RuleQualificationResult]:
        """Build per-rule TP/FP/FN/UNKNOWN breakdown."""
        rule_tp: dict[str, int] = defaultdict(int)
        rule_fp: dict[str, int] = defaultdict(int)
        rule_fn: dict[str, int] = defaultdict(int)
        rule_cases: dict[str, int] = defaultdict(int)

        for cr in report.results:
            rid = cr.case.rule_id or "_no_rule"
            rule_cases[rid] += 1
            if cr.outcome == "TP":
                rule_tp[rid] += 1
            elif cr.outcome == "FP":
                rule_fp[rid] += 1
            elif cr.outcome == "FN":
                rule_fn[rid] += 1

        for f in report.unmatched_findings:
            rule_fp[f.rule_id] += 1

        all_rules: set[str] = set(rule_tp) | set(rule_fp) | set(rule_fn)

        rule_unknown: dict[str, int] = defaultdict(int)
        for f in report.unknown_findings:
            rule_unknown[f.rule_id] += 1
        all_rules |= set(rule_unknown)

        result: dict[str, RuleQualificationResult] = {}
        for rid in sorted(all_rules):
            result[rid] = build_rule_result(
                rule_id=rid,
                tp=rule_tp[rid],
                fp=rule_fp[rid],
                fn=rule_fn[rid],
                unknown=rule_unknown[rid],
                cases=rule_cases[rid],
            )

        return result

    @staticmethod
    def _build_per_category(report: ClassificationReport) -> dict[str, CategoryQualificationResult]:
        """Build per-category TP/FP/FN/TN/UNKNOWN breakdown."""
        cat_tp: dict[str, int] = defaultdict(int)
        cat_fp: dict[str, int] = defaultdict(int)
        cat_fn: dict[str, int] = defaultdict(int)
        cat_tn: dict[str, int] = defaultdict(int)
        cat_cases: dict[str, int] = defaultdict(int)

        for cr in report.results:
            cat = cr.case.category or "OTHER"
            cat_cases[cat] += 1
            if cr.outcome == "TP":
                cat_tp[cat] += 1
            elif cr.outcome == "FP":
                cat_fp[cat] += 1
            elif cr.outcome == "FN":
                cat_fn[cat] += 1
            elif cr.outcome == "TN":
                cat_tn[cat] += 1

        # Unmatched findings (FPs with no case) map to OTHER or finding category
        for f in report.unmatched_findings:
            cat_fp["OTHER"] += 1

        cat_unknown: dict[str, int] = defaultdict(int)
        for f in report.unknown_findings:
            cat_unknown["OTHER"] += 1

        all_cats = set(cat_tp) | set(cat_fp) | set(cat_fn) | set(cat_tn) | set(cat_unknown)

        result: dict[str, CategoryQualificationResult] = {}
        for cat in sorted(all_cats):
            result[cat] = build_category_result(
                category=cat,
                tp=cat_tp[cat],
                fp=cat_fp[cat],
                fn=cat_fn[cat],
                tn=cat_tn[cat],
                unknown=cat_unknown[cat],
                cases=cat_cases[cat],
            )

        return result
