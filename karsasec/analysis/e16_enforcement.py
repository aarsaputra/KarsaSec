"""Enforcement Engine enforcing Anti-Confused-Deputy release permissions for Sprint E16."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from karsasec.analysis.e16_models import AdmissionStatus, ReleaseAdmission, deterministic_id


@dataclass(frozen=True)
class EnforcementPermission:
    """Immutable representation of an operational release permission decision."""

    permission_id: str
    admission_id: str
    is_permitted: bool
    permission_status: str
    reason: str
    schema_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        """Serializes permission to dictionary."""
        return {
            "permission_id": self.permission_id,
            "admission_id": self.admission_id,
            "is_permitted": self.is_permitted,
            "permission_status": self.permission_status,
            "reason": self.reason,
            "schema_version": self.schema_version,
        }


class EnforcementEngine:
    """Anti-Confused-Deputy Release Permission Engine.

    REJECTS bare boolean input flags (e.g. approved=True).
    Permission MUST strictly derive from a valid, verified ReleaseAdmission object.
    """

    def authorize_permission(self, admission: ReleaseAdmission | None) -> EnforcementPermission:
        """Determines operational release permission strictly from a valid ReleaseAdmission object."""
        if admission is None or not isinstance(admission, ReleaseAdmission):
            p_id = deterministic_id(
                "E16-ENFORCEMENT:v1:",
                {
                    "admission_id": "NONE",
                    "is_permitted": False,
                    "permission_status": "PROHIBITED_INVALID_INPUT",
                    "reason": "ANTI-CONFUSED-DEPUTY: Admission object is None or invalid type",
                },
            )
            return EnforcementPermission(
                permission_id=p_id,
                admission_id="NONE",
                is_permitted=False,
                permission_status="PROHIBITED_INVALID_INPUT",
                reason="ANTI-CONFUSED-DEPUTY: Admission object is None or invalid type",
            )

        status_str = str(admission.status).upper()

        if status_str == AdmissionStatus.APPROVED.value:
            p_status = "PERMITTED"
            permitted = True
            reason = "PERMITTED: Release admission is APPROVED and verified"
        elif status_str == AdmissionStatus.BLOCKED.value:
            p_status = "PROHIBITED_BLOCKED"
            permitted = False
            reason = "PROHIBITED: Release admission is BLOCKED due to security violations"
        elif status_str == AdmissionStatus.REVIEW_REQUIRED.value:
            p_status = "PROHIBITED_REVIEW_REQUIRED"
            permitted = False
            reason = "PROHIBITED: Release admission requires manual human security review"
        elif status_str == AdmissionStatus.UNKNOWN.value:
            p_status = "PROHIBITED_UNKNOWN"
            permitted = False
            reason = "PROHIBITED: Release admission is UNKNOWN (fail-closed)"
        else:
            p_status = "PROHIBITED_INVALID_STATUS"
            permitted = False
            reason = f"PROHIBITED: Invalid admission status '{status_str}'"

        payload = {
            "admission_id": admission.admission_id,
            "is_permitted": permitted,
            "permission_status": p_status,
            "reason": reason,
        }
        p_id = deterministic_id("E16-ENFORCEMENT:v1:", payload)

        return EnforcementPermission(
            permission_id=p_id,
            admission_id=admission.admission_id,
            is_permitted=permitted,
            permission_status=p_status,
            reason=reason,
        )
