"""Release Admission Engine for Sprint E16 — Pure Deterministic Evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from karsasec.analysis.e16_models import AdmissionStatus, EnforcementPolicy, ReleaseAdmission, ReleaseArtifact
from karsasec.analysis.e16_policy import PolicyEngine

if TYPE_CHECKING:
    from karsasec.analysis.e15_models import SecurityDecision


class ReleaseAdmissionEngine:
    """Pure, deterministic release admission decision engine with zero side effects.

    Binds artifact, decision, and policy into an immutable ReleaseAdmission record.
    """

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()

    def evaluate(
        self,
        artifact: ReleaseArtifact | None,
        decision: SecurityDecision | None,
        policy: EnforcementPolicy | None = None,
        remediation_plan: Any | None = None,
        regression_report: Any | None = None,
    ) -> ReleaseAdmission:
        """Evaluates release admission for an artifact and decision against policy.

        Returns an immutable ReleaseAdmission object bound by SHA-256 canonical identity.
        """
        active_policy = policy or self.policy_engine.policy

        if artifact is None or decision is None or active_policy is None:
            return ReleaseAdmission.create(
                status=AdmissionStatus.UNKNOWN,
                artifact_id=getattr(artifact, "artifact_id", "UNKNOWN_ARTIFACT"),
                artifact_content_hash=getattr(artifact, "content_hash", "UNKNOWN_HASH"),
                decision_id=getattr(decision, "decision_id", "UNKNOWN_DECISION"),
                policy_id=getattr(active_policy, "policy_id", "UNKNOWN_POLICY"),
                evaluation_id=getattr(artifact, "evaluation_id", "UNKNOWN_EVALUATION"),
                reason_codes=("FAIL-CLOSED: Missing artifact, decision, or policy input",),
            )

        status, reasons = self.policy_engine.evaluate(
            artifact=artifact,
            decision=decision,
            policy=active_policy,
            remediation_plan=remediation_plan,
            regression_report=regression_report,
        )

        return ReleaseAdmission.create(
            status=status,
            artifact_id=artifact.artifact_id,
            artifact_content_hash=artifact.content_hash,
            decision_id=decision.decision_id,
            policy_id=active_policy.policy_id,
            evaluation_id=artifact.evaluation_id,
            reason_codes=reasons,
        )
