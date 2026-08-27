"""Validation KPI & Scorecard Engine for Phase V0 Real-World Validation."""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.validation.v0_models import ValidationRunResult, ValidationScorecard


class ScorecardEngine:
    """Computes Phase V0 real-world validation scorecard and evaluates gate pass/fail status against PRD KPIs."""

    @staticmethod
    def generate_scorecard(
        results: Sequence[ValidationRunResult],
        mutation_sensitivity_score: float = 100.0,
    ) -> ValidationScorecard:
        """Generates an immutable ValidationScorecard from run results."""
        if not results:
            return ValidationScorecard.create(
                total_samples=0,
                true_positives=0,
                false_positives=0,
                false_negatives=0,
                tp_rate=100.0,
                fp_rate=0.0,
                mutation_sensitivity_score=mutation_sensitivity_score,
                gate_status="PASS",
            )

        total = len(results)
        tp = sum(1 for r in results if r.is_true_positive)
        fp = sum(1 for r in results if r.is_false_positive)
        fn = sum(1 for r in results if r.is_false_negative)

        tp_rate = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
        fp_rate = (fp / total) * 100.0 if total > 0 else 0.0

        # KPI Gate Criteria: 100% TP, 0 False Negatives, FP < 5%, 100% Mutation Sensitivity
        is_pass = (tp_rate == 100.0) and (fn == 0) and (fp_rate < 5.0) and (mutation_sensitivity_score == 100.0)
        gate_status = "PASS" if is_pass else "FAIL"

        return ValidationScorecard.create(
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            tp_rate=tp_rate,
            fp_rate=fp_rate,
            mutation_sensitivity_score=mutation_sensitivity_score,
            gate_status=gate_status,
        )
