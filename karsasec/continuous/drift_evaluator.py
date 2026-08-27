"""Security Drift Evaluator for Sprint E18."""

from __future__ import annotations

from karsasec.continuous.models import DriftReport, VerificationSnapshot


class SecurityDriftEvaluator:
    """Evaluates security posture drift between baseline and current snapshots."""

    def compare(
        self,
        baseline: VerificationSnapshot | None,
        current: VerificationSnapshot | None,
    ) -> DriftReport:
        """Compares baseline and current posture snapshots with fail-closed safeguards."""
        if baseline is None or current is None:
            return DriftReport.create(
                baseline_snapshot_id=baseline.snapshot_id if baseline else "NULL",
                current_snapshot_id=current.snapshot_id if current else "NULL",
                has_drift=True,
                drift_type="INVALID_SNAPSHOT_INPUT",
                reasons=("FAIL-CLOSED: Missing baseline or current snapshot input",),
            )

        reasons: list[str] = []
        has_drift = False

        if current.critical_count > baseline.critical_count:
            has_drift = True
            reasons.append(
                f"CRITICAL_DRIFT: Critical findings increased from {baseline.critical_count} to {current.critical_count}"
            )

        if current.high_count > baseline.high_count:
            has_drift = True
            reasons.append(
                f"HIGH_DRIFT: High findings increased from {baseline.high_count} to {current.high_count}"
            )

        if current.policy_hash != baseline.policy_hash:
            has_drift = True
            reasons.append("POLICY_DRIFT: Active policy hash changed without authorization")

        drift_type = "NO_DRIFT" if not has_drift else ("CRITICAL_DRIFT" if "CRITICAL_DRIFT" in str(reasons) else "POSTURE_DRIFT")

        if not reasons:
            reasons.append("Zero security drift detected")

        return DriftReport.create(
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current.snapshot_id,
            has_drift=has_drift,
            drift_type=drift_type,
            reasons=tuple(reasons),
        )
