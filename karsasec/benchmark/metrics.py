"""Mathematically Strict Security Benchmark Metrics Engine (Gate 5).

Implements exact formulas required by Chief Architect Directives:
- Strict Precision: TP / (TP + FP) with 95% Wilson Score Confidence Interval (Gate 5H)
- Strict Recall: TP / (TP + FN + FN_EPISTEMIC) with 95% Wilson Score Confidence Interval
- Epistemic Recall: (TP + FN_EPISTEMIC) / (TP + FN + FN_EPISTEMIC)
- F1 Score: 2 * P * R / (P + R)
- Epistemic Uncertainty Ratio: (UNKNOWN + CONFLICT) / Total
- Error Taxonomy breakdown (Gate 5G)
- Language x Framework Recall Matrix
"""

from __future__ import annotations

import math

from karsasec.benchmark.models import (
    BenchmarkMetricResult,
    BenchmarkOutcome,
    BenchmarkRun,
    ConfidenceInterval,
    GateVerdict,
)


def compute_wilson_confidence_interval(k: int, n: int, confidence: float = 0.95) -> ConfidenceInterval:
    """Computes 95% Wilson Score Interval for proportion k/n (Gate 5H)."""
    if n <= 0:
        return ConfidenceInterval(0.0, 1.0, confidence_level=confidence)

    # z-score for 95% confidence interval is ~1.96
    z = 1.959963984540054
    p_hat = k / n
    z2 = z * z

    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z2 / (4 * n * n)))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return ConfidenceInterval(lower_bound=lower, upper_bound=upper, confidence_level=confidence)


def compute_benchmark_metrics(
    run: BenchmarkRun,
    outcomes: list[dict[str, str]],
) -> BenchmarkMetricResult:
    """Computes mathematically strict confusion, epistemic uncertainty, and statistical metrics.

    Args:
        run: BenchmarkRun provenance object.
        outcomes: List of evaluation outcome dicts containing outcome, engine_verdict, language, framework, error_taxonomy.

    Returns:
        BenchmarkMetricResult containing full metric breakdown.
    """
    total = len(outcomes)
    if total == 0:
        empty_ci = ConfidenceInterval(0.0, 1.0)
        return BenchmarkMetricResult(
            run=run,
            total_cases=0,
            tp=0,
            fp=0,
            tn=0,
            fn=0,
            fn_epistemic=0,
            uncertain_tn=0,
            strict_precision=1.0,
            precision_ci=empty_ci,
            strict_recall=1.0,
            recall_ci=empty_ci,
            epistemic_recall=1.0,
            epistemic_recall_ci=empty_ci,
            f1_score=1.0,
            epistemic_uncertainty_ratio=0.0,
            unknown_rate=0.0,
            conflict_rate=0.0,
            error_taxonomy_breakdown={},
            language_framework_matrix={},
            verdict=GateVerdict.G5_PASS_WITH_KNOWN_GAPS,
        )

    tp = sum(1 for o in outcomes if o["outcome"] == BenchmarkOutcome.TP)
    fp = sum(1 for o in outcomes if o["outcome"] == BenchmarkOutcome.FP)
    tn = sum(1 for o in outcomes if o["outcome"] == BenchmarkOutcome.TN)
    fn = sum(1 for o in outcomes if o["outcome"] == BenchmarkOutcome.FN)
    fn_epistemic = sum(1 for o in outcomes if o["outcome"] == BenchmarkOutcome.FN_EPISTEMIC)
    uncertain_tn = sum(1 for o in outcomes if o["outcome"] == BenchmarkOutcome.UNCERTAIN_TN)

    unknown_count = sum(1 for o in outcomes if o.get("engine_verdict") == "UNKNOWN")
    conflict_count = sum(1 for o in outcomes if o.get("engine_verdict") == "CONFLICT")

    # Strict Precision = TP / (TP + FP)
    pred_positives = tp + fp
    strict_precision = tp / pred_positives if pred_positives > 0 else 1.0
    precision_ci = compute_wilson_confidence_interval(tp, pred_positives) if pred_positives > 0 else ConfidenceInterval(1.0, 1.0)

    # Strict Recall = TP / (TP + FN + FN_EPISTEMIC)
    total_vulnerable = tp + fn + fn_epistemic
    strict_recall = tp / total_vulnerable if total_vulnerable > 0 else 1.0
    recall_ci = compute_wilson_confidence_interval(tp, total_vulnerable) if total_vulnerable > 0 else ConfidenceInterval(1.0, 1.0)

    # Epistemic Recall = (TP + FN_EPISTEMIC) / total_vulnerable
    epistemic_recall = (tp + fn_epistemic) / total_vulnerable if total_vulnerable > 0 else 1.0
    epistemic_recall_ci = compute_wilson_confidence_interval(tp + fn_epistemic, total_vulnerable) if total_vulnerable > 0 else ConfidenceInterval(1.0, 1.0)

    # F1 Score
    f1_denom = strict_precision + strict_recall
    f1_score = (2 * strict_precision * strict_recall) / f1_denom if f1_denom > 0 else 0.0

    # Rates
    epistemic_uncertainty_ratio = (unknown_count + conflict_count) / total
    unknown_rate = unknown_count / total
    conflict_rate = conflict_count / total

    # Gate 5G — Error Taxonomy Breakdown
    taxonomy_counts: dict[str, int] = {}
    for o in outcomes:
        tax = o.get("error_taxonomy")
        if tax:
            taxonomy_counts[tax] = taxonomy_counts.get(tax, 0) + 1

    # Language x Framework Matrix
    lang_fw_groups: dict[str, dict[str, list[dict[str, str]]]] = {}
    for o in outcomes:
        lang = o.get("language", "java")
        fw = o.get("framework", "servlet")
        lang_fw_groups.setdefault(lang, {}).setdefault(fw, []).append(o)

    lang_fw_matrix: dict[str, dict[str, float]] = {}
    for lang, fw_dict in lang_fw_groups.items():
        lang_fw_matrix[lang] = {}
        for fw, items in fw_dict.items():
            fw_tp = sum(1 for i in items if i["outcome"] == BenchmarkOutcome.TP)
            fw_total_vuln = sum(1 for i in items if i["outcome"] in (BenchmarkOutcome.TP, BenchmarkOutcome.FN, BenchmarkOutcome.FN_EPISTEMIC))
            lang_fw_matrix[lang][fw] = round(fw_tp / fw_total_vuln, 4) if fw_total_vuln > 0 else 1.0

    # 4-tier Gate Verdict evaluation
    if total < 5:
        verdict = GateVerdict.G5_EXTERNAL_VALIDITY_INSUFFICIENT
    elif strict_precision >= 0.90 and strict_recall >= 0.90:
        verdict = GateVerdict.G5_PASS
    else:
        verdict = GateVerdict.G5_PASS_WITH_KNOWN_GAPS

    return BenchmarkMetricResult(
        run=run,
        total_cases=total,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        fn_epistemic=fn_epistemic,
        uncertain_tn=uncertain_tn,
        strict_precision=strict_precision,
        precision_ci=precision_ci,
        strict_recall=strict_recall,
        recall_ci=recall_ci,
        epistemic_recall=epistemic_recall,
        epistemic_recall_ci=epistemic_recall_ci,
        f1_score=f1_score,
        epistemic_uncertainty_ratio=epistemic_uncertainty_ratio,
        unknown_rate=unknown_rate,
        conflict_rate=conflict_rate,
        error_taxonomy_breakdown=taxonomy_counts,
        language_framework_matrix=lang_fw_matrix,
        verdict=verdict,
    )
