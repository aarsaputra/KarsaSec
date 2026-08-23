"""K1 Differential Validation Engine & Centralized Validation Gate (Task K1.6 & Task K1.6-LOCK).

Compairs current detector findings against independent baseline finding snapshots,
enforces a strict stop-on-failure state machine (RUNNING, PASS, BLOCKED),
and integrates release-boundary certification integrity preconditions.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from karsasec.analysis.taint.k1_integrated import K1IntegratedFinding
from karsasec.benchmark.k1_certification_integrity import (
    CertificationGateState,
    require_certification_integrity,
)


class ValidationState(StrEnum):
    RUNNING = "RUNNING"
    PASS = "PASS"
    BLOCKED = "BLOCKED"


@dataclass
class DifferentialResult:
    fixture_id: str
    baseline_findings: list[dict[str, str]]
    current_findings: list[dict[str, str]]
    added_findings: list[dict[str, str]] = field(default_factory=list)
    removed_findings: list[dict[str, str]] = field(default_factory=list)
    status: str = "EQUIVALENT"  # EQUIVALENT, MISMATCH, ADDED, REMOVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "baseline_findings": self.baseline_findings,
            "current_findings": self.current_findings,
            "added_findings": self.added_findings,
            "removed_findings": self.removed_findings,
            "status": self.status,
        }


class ValidationGate:
    """Centralized Validation Gate State Machine with Release Boundary Preconditions."""

    def __init__(self) -> None:
        self.state = ValidationState.RUNNING
        self.failure_reason: str | None = None

    def mark_failure(self, reason: str) -> None:
        self.state = ValidationState.BLOCKED
        self.failure_reason = reason

    def mark_pass(self) -> None:
        if self.state != ValidationState.BLOCKED:
            self.state = ValidationState.PASS

    def is_blocked(self) -> bool:
        return self.state == ValidationState.BLOCKED

    def verify_certification_precondition(
        self,
        manifest_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json",
        detached_sha_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256",
        repo_root: Path | str = ".",
        check_git: bool = False,
    ) -> bool:
        """Enforces INV-K1.6-L01 precondition integrity before validation execution."""
        gate_res = require_certification_integrity(manifest_path, detached_sha_path, repo_root, check_git)
        if gate_res.state != CertificationGateState.READY:
            self.mark_failure(f"Precondition release boundary failure [{gate_res.integrity_status}]: {gate_res.reason}")
            return False
        return True


def normalize_finding(finding: K1IntegratedFinding | dict[str, str]) -> dict[str, str]:
    if isinstance(finding, K1IntegratedFinding):
        return {
            "rule_id": finding.rule_id,
            "property_name": finding.property_name,
            "knowledge_pack": finding.knowledge_pack,
            "severity": finding.severity,
        }
    return {
        "rule_id": finding.get("rule_id", ""),
        "property_name": finding.get("property_name", ""),
        "knowledge_pack": finding.get("knowledge_pack", ""),
        "severity": finding.get("severity", ""),
    }


def compare_detectors(
    fixture_id: str,
    baseline_raw: Sequence[K1IntegratedFinding | dict[str, str]],
    current_raw: Sequence[K1IntegratedFinding | dict[str, str]],
) -> DifferentialResult:
    baseline_norm = [normalize_finding(f) for f in baseline_raw]
    current_norm = [normalize_finding(f) for f in current_raw]

    # Convert to set of tuples for differential calculation
    baseline_tuples = {
        (f["rule_id"], f["property_name"], f["knowledge_pack"], f["severity"])
        for f in baseline_norm
    }
    current_tuples = {
        (f["rule_id"], f["property_name"], f["knowledge_pack"], f["severity"])
        for f in current_norm
    }

    added_tuples = current_tuples - baseline_tuples
    removed_tuples = baseline_tuples - current_tuples

    added_findings = [
        {"rule_id": t[0], "property_name": t[1], "knowledge_pack": t[2], "severity": t[3]}
        for t in sorted(added_tuples)
    ]
    removed_findings = [
        {"rule_id": t[0], "property_name": t[1], "knowledge_pack": t[2], "severity": t[3]}
        for t in sorted(removed_tuples)
    ]

    status = "EQUIVALENT"
    if added_findings and removed_findings:
        status = "MISMATCH"
    elif added_findings:
        status = "ADDED"
    elif removed_findings:
        status = "REMOVED"

    return DifferentialResult(
        fixture_id=fixture_id,
        baseline_findings=baseline_norm,
        current_findings=current_norm,
        added_findings=added_findings,
        removed_findings=removed_findings,
        status=status,
    )


def evaluate_fixture_with_gate(
    gate: ValidationGate,
    fixture_id: str,
    baseline_norm: Sequence[dict[str, str]],
    detector_func: Callable[[str], Sequence[Any]],
    code: str,
) -> DifferentialResult | None:
    """Executes detector under gate protection, failing closed on any exception."""
    if gate.is_blocked():
        return None

    try:
        current_raw = detector_func(code)
    except Exception as e:
        gate.mark_failure(f"Detector exception in {fixture_id}: {e}")
        return None

    res = compare_detectors(fixture_id, baseline_norm, current_raw)
    if res.status != "EQUIVALENT":
        gate.mark_failure(f"Differential regression detected in {fixture_id}: {res.status}")
    return res
