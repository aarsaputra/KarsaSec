"""BenchmarkHarness evaluating KarsaSec engine predictions against independent GroundTruthProvider (Gate 5)."""

from __future__ import annotations

from datetime import UTC, datetime

from karsasec.benchmark.metrics import compute_benchmark_metrics
from karsasec.benchmark.models import (
    BenchmarkMetricResult,
    BenchmarkOutcome,
    BenchmarkRun,
    GroundTruthStatus,
)
from karsasec.benchmark.provider import GroundTruthProvider


class BenchmarkHarness:
    """Benchmark evaluation harness for external security validation."""

    def __init__(
        self,
        provider: GroundTruthProvider,
        commit_sha: str = "cbbb7fe4d088cd55212e97fe7928847103892d97",
        engine_version: str = "v1.0.0",
    ) -> None:
        self.provider = provider
        self.commit_sha = commit_sha
        self.engine_version = engine_version

    def evaluate_predictions(
        self,
        predictions: dict[str, str],  # test_case_id -> prediction ("VULNERABLE", "SAFE", "UNKNOWN", "CONFLICT")
        dataset_name: str = "OWASP_BENCHMARK",
        dataset_version: str = "v1.2",
    ) -> BenchmarkMetricResult:
        """Evaluates prediction dictionary against ground truth provider manifests."""
        outcomes: list[dict[str, str]] = []

        for manifest in self.provider.list_manifests():
            tc_id = manifest.test_case_id
            gt_status = manifest.expected_status
            pred = predictions.get(tc_id, "UNKNOWN")

            outcome = self._classify_outcome(gt_status, pred)
            outcomes.append({
                "test_case_id": tc_id,
                "ground_truth": gt_status.value,
                "engine_verdict": pred,
                "outcome": outcome.value,
            })

        now_utc = datetime.now(UTC)
        run = BenchmarkRun(
            run_id=f"RUN_{dataset_name}_{now_utc.strftime('%Y%m%d_%H%M%S')}",
            commit_sha=self.commit_sha,
            dataset_name=dataset_name,
            dataset_version=dataset_version,
            adapter_version="1.0.0",
            oracle_version="1.0.0",
            engine_version=self.engine_version,
            timestamp=now_utc.isoformat(),
            configuration_hash="CONFIG_FREEZE_V1",
        )

        return compute_benchmark_metrics(run=run, outcomes=outcomes)

    @staticmethod
    def _classify_outcome(gt_status: GroundTruthStatus, engine_verdict: str) -> BenchmarkOutcome:
        """Classifies prediction vs ground truth into canonical 6-tuple outcome.

        Ground Truth     Prediction       Classification
        -------------------------------------------------
        VULNERABLE       VULNERABLE       TP
        VULNERABLE       SAFE             FN
        VULNERABLE       UNKNOWN          FN_EPISTEMIC
        VULNERABLE       CONFLICT         FN_EPISTEMIC

        SAFE             VULNERABLE       FP
        SAFE             SAFE             TN
        SAFE             UNKNOWN          UNCERTAIN_TN
        SAFE             CONFLICT         UNCERTAIN_TN
        """
        if gt_status == GroundTruthStatus.VULNERABLE:
            if engine_verdict == "VULNERABLE":
                return BenchmarkOutcome.TP
            elif engine_verdict == "SAFE":
                return BenchmarkOutcome.FN
            else:  # UNKNOWN, CONFLICT
                return BenchmarkOutcome.FN_EPISTEMIC
        elif gt_status == GroundTruthStatus.SAFE:
            if engine_verdict == "VULNERABLE":
                return BenchmarkOutcome.FP
            elif engine_verdict == "SAFE":
                return BenchmarkOutcome.TN
            else:  # UNKNOWN, CONFLICT
                return BenchmarkOutcome.UNCERTAIN_TN
        else:  # GroundTruthStatus.UNKNOWN
            if engine_verdict == "VULNERABLE":
                return BenchmarkOutcome.FP
            elif engine_verdict == "SAFE":
                return BenchmarkOutcome.TN
            else:
                return BenchmarkOutcome.UNCERTAIN_TN
