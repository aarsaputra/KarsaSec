"""Independent Oracle & Metric Evaluator enforcing INVARIANT G5.1-01, G5.1-07, G5.1-08.

Strictly separates detector predictions from ground truth manifest evaluation.
Computes:
- Strict Precision & Recall
- FPR, FNR, Specificity
- Epistemic Decision Correctness (EDC)
- 95% Wilson Confidence Intervals
"""

from typing import Any

from karsasec.benchmark.statistics import wilson_interval


class IndependentEvaluator:
    """Independent oracle for evaluating raw predictions against ground truth manifest."""

    CWE_PROPERTY_MAP: dict[str, str] = {
        "CWE-89": "SQL_INJECTION",
        "CWE-79": "CROSS_SITE_SCRIPTING",
        "CWE-78": "COMMAND_INJECTION",
        "CWE-918": "SSRF",
        "CWE-22": "PATH_TRAVERSAL",
        "CWE-862": "AUTHORIZATION",
        "CWE-285": "AUTHORIZATION",
        "CWE-639": "AUTHORIZATION",
    }

    def evaluate_manifest(self, raw_predictions: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
        """Evaluates raw predictions against ground-truth manifest.

        Args:
            raw_predictions: List of dicts with 'case_id' and 'findings' (by property).
            manifest: Frozen manifest containing 'cases' list with expected statuses.

        Returns:
            dict containing evaluation metrics and Wilson CIs.
        """
        cases_by_id = {c["vulnerability_id"]: c for c in manifest.get("cases", [])}

        tp = tn = fp = fn = correct_unk = correct_conf = 0
        evaluated_cases = 0

        for pred in raw_predictions:
            cid = pred.get("case_id")
            if cid not in cases_by_id:
                continue

            gt_case = cases_by_id[cid]
            expected_status = gt_case.get("expected_status")
            cwe = gt_case.get("CWE", "")
            target_prop = self.CWE_PROPERTY_MAP.get(cwe, "SQL_INJECTION")

            findings = pred.get("findings", {})
            predicted_verdict = findings.get(target_prop, "UNKNOWN")

            evaluated_cases += 1

            if predicted_verdict == expected_status:
                if expected_status == "VULNERABLE":
                    tp += 1
                elif expected_status == "SAFE":
                    tn += 1
                elif expected_status == "UNKNOWN":
                    correct_unk += 1
                elif expected_status == "CONFLICT":
                    correct_conf += 1
            else:
                if expected_status == "VULNERABLE" and predicted_verdict == "SAFE":
                    fn += 1
                elif expected_status == "SAFE" and predicted_verdict == "VULNERABLE":
                    fp += 1
                elif expected_status == "VULNERABLE" and predicted_verdict == "UNKNOWN":
                    fn += 1

        strict_prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        strict_rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 1.0

        correct_decisions = tp + tn + correct_unk + correct_conf
        edc = correct_decisions / evaluated_cases if evaluated_cases > 0 else 0.0

        # Compute 95% Wilson Confidence Intervals
        prec_point, prec_low, prec_high = wilson_interval(tp, tp + fp)
        rec_point, rec_low, rec_high = wilson_interval(tp, tp + fn)
        edc_point, edc_low, edc_high = wilson_interval(correct_decisions, evaluated_cases)

        return {
            "total_evaluated_cases": evaluated_cases,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "correct_unknown": correct_unk,
            "correct_conflict": correct_conf,
            "strict_precision": strict_prec,
            "strict_recall": strict_rec,
            "fpr": fpr,
            "fnr": fnr,
            "specificity": specificity,
            "epistemic_decision_correctness": edc,
            "wilson_95_ci": {
                "precision": {"point": prec_point, "lower": prec_low, "upper": prec_high},
                "recall": {"point": rec_point, "lower": rec_low, "upper": rec_high},
                "edc": {"point": edc_point, "lower": edc_low, "upper": edc_high},
            },
        }
