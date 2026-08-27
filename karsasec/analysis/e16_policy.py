"""Policy-as-Code Engine with Total Fail-Closed Precedence for Sprint E16."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from karsasec.analysis.e16_models import AdmissionStatus, EnforcementPolicy

if TYPE_CHECKING:
    from karsasec.analysis.e15_models import SecurityDecision
    from karsasec.analysis.e16_models import ReleaseArtifact


def _is_invalid_score(score: float | int | None) -> bool:
    """Guards against None, NaN, Inf, negative, or >1.0 scores."""
    if score is None:
        return True
    try:
        val = float(score)
    except (TypeError, ValueError):
        return True
    if math.isnan(val) or math.isinf(val):
        return True
    return val < 0.0 or val > 1.0


class PolicyEngine:
    """Evaluates SecurityDecision and ReleaseArtifact against EnforcementPolicy with total fail-closed precedence."""

    def __init__(self, policy: EnforcementPolicy | None = None) -> None:
        self.policy = policy or EnforcementPolicy.create()

    def evaluate(
        self,
        artifact: ReleaseArtifact | None,
        decision: SecurityDecision | None,
        policy: EnforcementPolicy | None = None,
        remediation_plan: Any | None = None,
        regression_report: Any | None = None,
    ) -> tuple[AdmissionStatus, tuple[str, ...]]:
        """Evaluates release admission status adhering strictly to fail-closed total precedence hierarchy.

        Precedence Hierarchy:
        1. Rule 01 — Missing/None Input -> UNKNOWN
        2. Rule 02 — TOCTOU Identity / Decision Mismatch -> UNKNOWN
        3. Rule 03 — Score Laundering & Bounds Protection (NaN/Inf/<0/>1) -> UNKNOWN
        4. Rule 04 — Evidence & Exploitability Validity -> UNKNOWN
        5. Rule 05 — E15 UNKNOWN Decision -> UNKNOWN
        6. Rule 06 — E15 BLOCK Decision -> BLOCKED
        7. Rule 07 — Strict Regression Failure (FAIL -> BLOCKED, UNKNOWN -> UNKNOWN) -> BLOCKED / UNKNOWN
        8. Rule 08 — Blocked or Incomplete Remediation -> BLOCKED / REVIEW_REQUIRED
        9. Rule 09 — Explicit E15 REVIEW Decision -> REVIEW_REQUIRED
        10. Rule 10 — Policy Confidence / Determinism Threshold Violation -> BLOCKED
        11. Rule 11 — Explicit ALLOW + All Predicates Satisfied -> APPROVED
        """
        active_policy = policy or self.policy
        reasons: list[str] = []

        # Rule 01 — Missing Input Check
        if artifact is None or decision is None or active_policy is None:
            reasons.append("FAIL-CLOSED: Missing artifact, decision, or policy input")
            return AdmissionStatus.UNKNOWN, tuple(reasons)

        # Rule 02 — TOCTOU Identity Binding Check
        if getattr(artifact, "decision_id", "") != getattr(decision, "decision_id", ""):
            reasons.append("FAIL-CLOSED: Artifact decision_id mismatch (TOCTOU protection)")
            return AdmissionStatus.UNKNOWN, tuple(reasons)

        # Rule 03 — Score Bounds & NaN/Inf Protection
        confidence = getattr(decision, "confidence", None)
        if _is_invalid_score(confidence):
            reasons.append("FAIL-CLOSED: Invalid confidence score (NaN, Inf, negative, or >1.0)")
            return AdmissionStatus.UNKNOWN, tuple(reasons)

        # Rule 04 — Evidence & Exploitability Validity
        if not getattr(decision, "evidence_valid", False):
            reasons.append("FAIL-CLOSED: Evidence validation failed upstream")
            return AdmissionStatus.UNKNOWN, tuple(reasons)
        if not getattr(decision, "exploitability_valid", False):
            reasons.append("FAIL-CLOSED: Exploitability validation failed upstream")
            return AdmissionStatus.UNKNOWN, tuple(reasons)

        dec_status = str(getattr(getattr(decision, "decision", None), "value", getattr(decision, "decision", "UNKNOWN"))).upper()

        # Rule 05 — E15 UNKNOWN Decision
        if dec_status == "UNKNOWN":
            reasons.append("FAIL-CLOSED: Upstream E15 decision is UNKNOWN")
            return AdmissionStatus.UNKNOWN, tuple(reasons)

        # Rule 06 — E15 BLOCK Decision
        if dec_status == "BLOCK":
            reasons.append("ENFORCEMENT BLOCK: E15 security decision is BLOCK")
            return AdmissionStatus.BLOCKED, tuple(reasons)

        # Rule 07 — Regression State Enforcement
        reg_status = str(getattr(decision, "regression_status", "NOT_TESTED")).upper()
        if regression_report is not None:
            r_val = getattr(getattr(regression_report, "status", None), "value", getattr(regression_report, "status", "NOT_TESTED"))
            reg_status = str(r_val).upper()

        if reg_status == "FAIL":
            reasons.append("ENFORCEMENT BLOCK: Security regression detected (FAIL)")
            return AdmissionStatus.BLOCKED, tuple(reasons)
        if reg_status == "UNKNOWN":
            reasons.append("FAIL-CLOSED: Security regression evaluation is UNKNOWN")
            return AdmissionStatus.UNKNOWN, tuple(reasons)

        # Rule 08 — Remediation Plan State Enforcement
        if remediation_plan is not None:
            rem_status = str(getattr(getattr(remediation_plan, "status", None), "value", getattr(remediation_plan, "status", "UNKNOWN"))).upper()
            if rem_status == "BLOCKED":
                reasons.append("ENFORCEMENT BLOCK: Remediation plan is BLOCKED by barrier")
                return AdmissionStatus.BLOCKED, tuple(reasons)
            if rem_status == "UNKNOWN":
                reasons.append("FAIL-CLOSED: Remediation plan status is UNKNOWN")
                return AdmissionStatus.UNKNOWN, tuple(reasons)
            if rem_status == "REQUIRED":
                reasons.append("REMEDIATION PENDING: Confirmed vulnerability requires active remediation patch")

        # Rule 09 — Explicit E15 REVIEW Decision
        if dec_status == "REVIEW":
            reasons.append("REVIEW REQUIRED: E15 security decision requires human security review")
            return AdmissionStatus.REVIEW_REQUIRED, tuple(reasons)

        # Rule 10 — Policy Confidence & Determinism Threshold
        if float(confidence) < active_policy.minimum_confidence:
            reasons.append(
                f"POLICY VIOLATION: Decision confidence {confidence:.2f} is below policy minimum {active_policy.minimum_confidence:.2f}"
            )
            return AdmissionStatus.BLOCKED, tuple(reasons)

        if dec_status not in active_policy.allow_on:
            reasons.append(f"POLICY VIOLATION: E15 decision state '{dec_status}' not in policy allow_on {active_policy.allow_on}")
            return AdmissionStatus.BLOCKED, tuple(reasons)

        # Rule 11 — Explicit ALLOW + All Predicates Satisfied -> APPROVED
        if dec_status == "ALLOW":
            reasons.append("RELEASE APPROVED: E15 decision is ALLOW and all policy conditions satisfied")
            return AdmissionStatus.APPROVED, tuple(reasons)

        # Fail-closed default fallthrough
        reasons.append("FAIL-CLOSED: Fallthrough default policy protection")
        return AdmissionStatus.UNKNOWN, tuple(reasons)
