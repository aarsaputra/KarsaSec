"""Immutable domain models for Sprint E18 Continuous Security Verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def compute_hash(prefix: str, payload: dict[str, Any]) -> str:
    """Computes canonical SHA-256 hash for verification artifacts."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prefix}:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class VerificationSnapshot:
    """Immutable baseline security posture snapshot for continuous tracking."""

    snapshot_id: str
    target_id: str
    cluster_count: int
    critical_count: int
    high_count: int
    policy_hash: str
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        target_id: str,
        cluster_count: int,
        critical_count: int,
        high_count: int,
        policy_hash: str,
    ) -> VerificationSnapshot:
        payload = {
            "target_id": target_id,
            "cluster_count": cluster_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "policy_hash": policy_hash,
            "schema_version": "1.0",
        }
        sid = compute_hash("VERIF-SNAP", payload)
        return cls(
            snapshot_id=sid,
            target_id=target_id,
            cluster_count=cluster_count,
            critical_count=critical_count,
            high_count=high_count,
            policy_hash=policy_hash,
        )


@dataclass(frozen=True)
class DriftReport:
    """Immutable report of security posture drift comparison."""

    report_id: str
    baseline_snapshot_id: str
    current_snapshot_id: str
    has_drift: bool
    drift_type: str
    reasons: tuple[str, ...]

    @classmethod
    def create(
        cls,
        baseline_snapshot_id: str,
        current_snapshot_id: str,
        has_drift: bool,
        drift_type: str,
        reasons: tuple[str, ...],
    ) -> DriftReport:
        sorted_reasons = tuple(sorted(reasons))
        payload = {
            "baseline_snapshot_id": baseline_snapshot_id,
            "current_snapshot_id": current_snapshot_id,
            "has_drift": has_drift,
            "drift_type": drift_type,
            "reasons": list(sorted_reasons),
        }
        rid = compute_hash("DRIFT-REP", payload)
        return cls(
            report_id=rid,
            baseline_snapshot_id=baseline_snapshot_id,
            current_snapshot_id=current_snapshot_id,
            has_drift=has_drift,
            drift_type=drift_type,
            reasons=sorted_reasons,
        )
