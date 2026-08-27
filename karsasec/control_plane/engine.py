"""Central Security Control Plane Engine Facade for Sprint E17."""

from __future__ import annotations

from typing import Any

from karsasec.analysis.e16_admission import ReleaseAdmissionEngine
from karsasec.analysis.e16_audit import ReleaseAuditLedger
from karsasec.analysis.e16_models import (
    AdmissionStatus,
    EnforcementPolicy,
    ReleaseAdmission,
    ReleaseArtifact,
)
from karsasec.control_plane.models import (
    ControlPlaneConfig,
    ControlPlaneEvaluationResult,
)
from karsasec.control_plane.policy_registry import PolicyRegistry


class SecurityControlPlane:
    """Central Control Plane coordinating admission, policy registration, audit ledger, and fail-closed governance."""

    def __init__(
        self,
        config: ControlPlaneConfig | None = None,
        registry: PolicyRegistry | None = None,
    ) -> None:
        self.config = config or ControlPlaneConfig.create()
        self.registry = registry or PolicyRegistry()
        self.admission_engine = ReleaseAdmissionEngine()
        self.audit_ledger = ReleaseAuditLedger()

    def evaluate_release(
        self,
        artifact: ReleaseArtifact | None,
        decision: Any,
        remediation_plan: Any = None,
        regression_report: Any = None,
        policy_id: str | None = None,
    ) -> ControlPlaneEvaluationResult:
        """Central entrypoint for evaluating a release through Control Plane.

        Enforces fail-closed posture on invalid inputs or configuration errors.
        """
        # Fail-closed check: None artifact or decision
        if artifact is None or decision is None:
            blocked_adm = ReleaseAdmission.create(
                status=AdmissionStatus.BLOCKED,
                artifact_id=artifact.artifact_id if artifact else "UNKNOWN",
                artifact_content_hash=artifact.content_hash if artifact else "UNKNOWN",
                decision_id=getattr(decision, "decision_id", "UNKNOWN"),
                policy_id=policy_id or "NONE",
                evaluation_id="EVAL-CP-NULL",
                reason_codes=("ERR_FAIL_CLOSED_NULL_INPUT",),
            )
            audit_rec = self.audit_ledger.append(blocked_adm)

            return ControlPlaneEvaluationResult.create(
                tenant_id=self.config.tenant_id,
                policy_id=policy_id or "NONE",
                status="REJECTED",
                reason="Fail-closed default: artifact or decision is None",
                admission_status="BLOCKED",
                audit_record_hash=audit_rec.audit_hash,
            )

        # Retrieve policy if policy_id provided
        active_policy = None
        if policy_id:
            active_policy = self.registry.get(policy_id)
            if not active_policy or not active_policy.is_active:
                rejected_adm = ReleaseAdmission.create(
                    status=AdmissionStatus.BLOCKED,
                    artifact_id=artifact.artifact_id,
                    artifact_content_hash=artifact.content_hash,
                    decision_id=getattr(decision, "decision_id", "UNKNOWN"),
                    policy_id=policy_id,
                    evaluation_id="EVAL-CP-INVALID-POLICY",
                    reason_codes=("ERR_POLICY_INACTIVE_OR_MISSING",),
                )
                audit_rec = self.audit_ledger.append(rejected_adm)

                return ControlPlaneEvaluationResult.create(
                    tenant_id=self.config.tenant_id,
                    policy_id=policy_id,
                    status="REJECTED",
                    reason=f"Fail-closed: policy '{policy_id}' is invalid or inactive",
                    admission_status="BLOCKED",
                    audit_record_hash=audit_rec.audit_hash,
                )

        # Delegate to E16 Release Admission Engine
        policy_to_use = active_policy or EnforcementPolicy.create()
        admission = self.admission_engine.evaluate(
            artifact=artifact,
            decision=decision,
            policy=policy_to_use,
            remediation_plan=remediation_plan,
            regression_report=regression_report,
        )

        status_str = str(admission.status).upper()
        cp_status = "APPROVED" if status_str == "APPROVED" else "REJECTED"

        audit_rec = self.audit_ledger.append(admission)
        reason_desc = ", ".join(admission.reason_codes) if admission.reason_codes else status_str

        return ControlPlaneEvaluationResult.create(
            tenant_id=self.config.tenant_id,
            policy_id=active_policy.policy_id if active_policy else "DEFAULT",
            status=cp_status,
            reason=reason_desc,
            admission_status=status_str,
            audit_record_hash=audit_rec.audit_hash,
        )
