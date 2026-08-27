"""Continuous Verification Engine for Sprint E18."""

from __future__ import annotations

from karsasec.continuous.drift_evaluator import SecurityDriftEvaluator
from karsasec.continuous.models import DriftReport, VerificationSnapshot


class ContinuousVerificationEngine:
    """Orchestrates real-time background security verification and baseline drift tracking."""

    def __init__(self, evaluator: SecurityDriftEvaluator | None = None) -> None:
        self.evaluator = evaluator or SecurityDriftEvaluator()
        self._baselines: dict[str, VerificationSnapshot] = {}

    def register_baseline(self, snapshot: VerificationSnapshot) -> str:
        """Registers a baseline snapshot for a target."""
        if not snapshot.target_id:
            raise ValueError("VerificationSnapshot must have a target_id")
        self._baselines[snapshot.target_id] = snapshot
        return snapshot.snapshot_id

    def verify_target(self, current_snapshot: VerificationSnapshot) -> DriftReport:
        """Verifies a current snapshot against stored baseline for the target."""
        if not current_snapshot or not current_snapshot.target_id:
            return DriftReport.create(
                baseline_snapshot_id="NULL",
                current_snapshot_id="NULL",
                has_drift=True,
                drift_type="INVALID_INPUT",
                reasons=("FAIL-CLOSED: Current snapshot or target_id is invalid",),
            )

        baseline = self._baselines.get(current_snapshot.target_id)
        if not baseline:
            return DriftReport.create(
                baseline_snapshot_id="MISSING",
                current_snapshot_id=current_snapshot.snapshot_id,
                has_drift=True,
                drift_type="MISSING_BASELINE",
                reasons=(f"FAIL-CLOSED: No registered baseline for target '{current_snapshot.target_id}'",),
            )

        return self.evaluator.compare(baseline=baseline, current=current_snapshot)
