"""Differential Regression Framework (Gate 5F).

Tracks benchmark deltas across engine commits/versions to ensure no detection
regression occurs on existing detectors when new knowledge packs are added.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from karsasec.benchmark.models import BenchmarkMetricResult


@dataclass(frozen=True)
class DifferentialRegressionReport:
    """Report comparing baseline benchmark run against a new benchmark run."""

    baseline_run_id: str
    new_run_id: str
    precision_delta: float
    recall_delta: float
    epistemic_recall_delta: float
    f1_delta: float
    epistemic_uncertainty_delta: float
    has_precision_regression: bool
    has_recall_regression: bool
    is_acceptable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_run_id": self.baseline_run_id,
            "new_run_id": self.new_run_id,
            "deltas": {
                "precision_delta": round(self.precision_delta, 4),
                "recall_delta": round(self.recall_delta, 4),
                "epistemic_recall_delta": round(self.epistemic_recall_delta, 4),
                "f1_delta": round(self.f1_delta, 4),
                "epistemic_uncertainty_delta": round(self.epistemic_uncertainty_delta, 4),
            },
            "has_precision_regression": self.has_precision_regression,
            "has_recall_regression": self.has_recall_regression,
            "is_acceptable": self.is_acceptable,
        }


class DifferentialRegressionEngine:
    """Evaluates differential regression between baseline and candidate benchmark runs."""

    def compare_runs(
        self,
        baseline: BenchmarkMetricResult,
        candidate: BenchmarkMetricResult,
        max_allowed_precision_drop: float = 0.0,
        max_allowed_recall_drop: float = 0.0,
    ) -> DifferentialRegressionReport:
        """Compares candidate run metrics against baseline.

        Returns DifferentialRegressionReport detailing metric deltas and regression flags.
        """
        precision_delta = candidate.strict_precision - baseline.strict_precision
        recall_delta = candidate.strict_recall - baseline.strict_recall
        epistemic_recall_delta = candidate.epistemic_recall - baseline.epistemic_recall
        f1_delta = candidate.f1_score - baseline.f1_score
        epistemic_uncertainty_delta = candidate.epistemic_uncertainty_ratio - baseline.epistemic_uncertainty_ratio

        has_precision_reg = precision_delta < -max_allowed_precision_drop
        has_recall_reg = recall_delta < -max_allowed_recall_drop

        is_acceptable = not (has_precision_reg or has_recall_reg)

        return DifferentialRegressionReport(
            baseline_run_id=baseline.run.run_id,
            new_run_id=candidate.run.run_id,
            precision_delta=precision_delta,
            recall_delta=recall_delta,
            epistemic_recall_delta=epistemic_recall_delta,
            f1_delta=f1_delta,
            epistemic_uncertainty_delta=epistemic_uncertainty_delta,
            has_precision_regression=has_precision_reg,
            has_recall_regression=has_recall_reg,
            is_acceptable=is_acceptable,
        )
