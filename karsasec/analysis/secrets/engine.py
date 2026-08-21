"""Secrets & Credential Exposure Reasoning Engine for Batch C12."""

from __future__ import annotations

from karsasec.analysis.secrets.models import (
    CredentialValidity,
    PrivilegeLevel,
    SecretContext,
    SecretEvidence,
    SecretExposureCategory,
    SecretType,
)


class SecretExposureReasoningEngine:
    """Deterministic reasoning engine for Secrets, Credential Exposure, Compromise, and Privilege Escalation Paths."""

    def evaluate_secret_exposure(self, ctx: SecretContext) -> SecretEvidence | None:
        """Evaluates secret context, trust boundaries, validity, privilege level, and exposure state."""
        # Step 1: Rule C12.6 & INV-C12-01 (Managed by SecretVault or In-code constant never crossing trust boundary -> SAFE)
        if ctx.is_vault_managed and ctx.exposure_boundary is None:
            return SecretEvidence(
                category=SecretExposureCategory.SECRET_PRESENT,
                secret_type=ctx.secret_type,
                source_boundary=ctx.source_boundary,
                exposure_boundary=None,
                credential_validity=ctx.validity,
                privilege_level=ctx.privilege_level,
                exposed=False,
                accessible_by_attacker=False,
                evidence_path=[ctx.source_boundary, "VAULT_MANAGED"],
                resolution="SAFE",
            )

        if not ctx.is_cross_boundary and ctx.exposure_boundary is None:
            return SecretEvidence(
                category=SecretExposureCategory.SECRET_PRESENT,
                secret_type=ctx.secret_type,
                source_boundary=ctx.source_boundary,
                exposure_boundary=None,
                credential_validity=ctx.validity,
                privilege_level=ctx.privilege_level,
                exposed=False,
                accessible_by_attacker=False,
                evidence_path=[ctx.source_boundary, "INTERNAL_TRUST_BOUNDARY"],
                resolution="SAFE",
            )

        # Step 2: INV-C12-05 (Ambiguous or Unresolved Validity with Unknown Boundary -> UNKNOWN)
        if ctx.validity == CredentialValidity.UNKNOWN and ctx.exposure_boundary == "AMBIGUOUS_BOUNDARY":
            return SecretEvidence(
                category=SecretExposureCategory.SECRET_EXPOSURE,
                secret_type=ctx.secret_type,
                source_boundary=ctx.source_boundary,
                exposure_boundary=ctx.exposure_boundary,
                credential_validity=CredentialValidity.UNKNOWN,
                privilege_level=ctx.privilege_level,
                exposed=True,
                accessible_by_attacker=False,
                evidence_path=[ctx.source_boundary, "AMBIGUOUS_BOUNDARY"],
                resolution="UNKNOWN",
            )

        # Step 3: Privilege Escalation Path (Admin/Root level key exposed/compromised)
        if ctx.privilege_level in (PrivilegeLevel.ADMIN, PrivilegeLevel.ROOT_SYSTEM) and ctx.exposure_boundary is not None:
            return SecretEvidence(
                category=SecretExposureCategory.PRIVILEGE_ESCALATION_PATH,
                secret_type=ctx.secret_type,
                source_boundary=ctx.source_boundary,
                exposure_boundary=ctx.exposure_boundary,
                credential_validity=ctx.validity,
                privilege_level=ctx.privilege_level,
                exposed=True,
                accessible_by_attacker=True,
                evidence_path=[ctx.source_boundary, str(ctx.secret_type), ctx.exposure_boundary, "PRIVILEGE_ESCALATION_PATH"],
                resolution="VULNERABLE",
            )

        # Step 4: Credential Compromise (SSRF -> Metadata / SSH key leak / Valid active key leak)
        sec_type_str = str(ctx.secret_type)
        if (
            ctx.exposure_boundary in ("METADATA_SERVICE", "SSRF_CALLBACK", "PUBLIC_API")
            or sec_type_str in (SecretType.SSH_PRIVATE_KEY.value, SecretType.GCP_SERVICE_ACCOUNT.value, SecretType.KUBERNETES_TOKEN.value)
            or ctx.validity == CredentialValidity.VALID
        ):
            return SecretEvidence(
                category=SecretExposureCategory.CREDENTIAL_COMPROMISE,
                secret_type=ctx.secret_type,
                source_boundary=ctx.source_boundary,
                exposure_boundary=ctx.exposure_boundary,
                credential_validity=ctx.validity,
                privilege_level=ctx.privilege_level,
                exposed=True,
                accessible_by_attacker=True,
                evidence_path=[ctx.source_boundary, sec_type_str, str(ctx.exposure_boundary), "CREDENTIAL_COMPROMISE"],
                resolution="VULNERABLE",
            )

        # Step 5: General Secret Exposure (HTTP Response, Logs, Git Repository)
        if ctx.exposure_boundary in ("HTTP_RESPONSE", "LOG_FILE", "GIT_REPOSITORY", "CI_CD_SYSTEM") or ctx.is_cross_boundary:
            return SecretEvidence(
                category=SecretExposureCategory.SECRET_EXPOSURE,
                secret_type=ctx.secret_type,
                source_boundary=ctx.source_boundary,
                exposure_boundary=ctx.exposure_boundary,
                credential_validity=ctx.validity,
                privilege_level=ctx.privilege_level,
                exposed=True,
                accessible_by_attacker=True,
                evidence_path=[ctx.source_boundary, sec_type_str, str(ctx.exposure_boundary)],
                resolution="VULNERABLE",
            )

        return SecretEvidence(
            category=SecretExposureCategory.SECRET_EXPOSURE,
            secret_type=ctx.secret_type,
            source_boundary=ctx.source_boundary,
            exposure_boundary=ctx.exposure_boundary,
            credential_validity=ctx.validity,
            privilege_level=ctx.privilege_level,
            exposed=True,
            accessible_by_attacker=True,
            evidence_path=[ctx.source_boundary, sec_type_str, "EXPOSED"],
            resolution="VULNERABLE",
        )
