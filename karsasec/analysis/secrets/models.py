"""Data models for KarsaSec Secrets & Credential Exposure Reasoning Engine (Batch C12)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SecretType(StrEnum):
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    GCP_SERVICE_ACCOUNT = "GCP_SERVICE_ACCOUNT"
    AZURE_STORAGE_KEY = "AZURE_STORAGE_KEY"
    DATABASE_PASSWORD = "DATABASE_PASSWORD"
    JWT_SIGNING_KEY = "JWT_SIGNING_KEY"
    API_TOKEN = "API_TOKEN"
    SSH_PRIVATE_KEY = "SSH_PRIVATE_KEY"
    TLS_PRIVATE_KEY = "TLS_PRIVATE_KEY"
    OAUTH_CLIENT_SECRET = "OAUTH_CLIENT_SECRET"
    KUBERNETES_TOKEN = "KUBERNETES_TOKEN"
    GENERIC_SECRET = "GENERIC_SECRET"


class SecretExposureCategory(StrEnum):
    SECRET_PRESENT = "SECRET_PRESENT"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    PRIVILEGE_ESCALATION_PATH = "PRIVILEGE_ESCALATION_PATH"


class CredentialValidity(StrEnum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class PrivilegeLevel(StrEnum):
    READ_ONLY = "READ_ONLY"
    LIMITED_USER = "LIMITED_USER"
    ADMIN = "ADMIN"
    ROOT_SYSTEM = "ROOT_SYSTEM"
    UNKNOWN = "UNKNOWN"


@dataclass
class SecretContext:
    """Context node passed into SecretExposureReasoningEngine."""

    secret_type: SecretType | str
    secret_value: str
    source_boundary: str  # SOURCE_CODE, ENVIRONMENT_VARIABLE, CONFIG_FILE, CI_CD_SYSTEM, SECRET_MANAGER, DATABASE
    exposure_boundary: str | None = None  # HTTP_RESPONSE, LOG_FILE, GIT_REPOSITORY, PUBLIC_API, METADATA_SERVICE
    validity: CredentialValidity = CredentialValidity.UNKNOWN
    privilege_level: PrivilegeLevel = PrivilegeLevel.UNKNOWN
    is_cross_boundary: bool = False
    is_vault_managed: bool = False
    language: str = "python"


@dataclass
class SecretEvidence:
    """Machine-readable evidence output for Secrets & Credential Exposure findings."""

    category: SecretExposureCategory
    secret_type: SecretType | str
    source_boundary: str
    exposure_boundary: str | None
    credential_validity: CredentialValidity
    privilege_level: PrivilegeLevel
    exposed: bool
    accessible_by_attacker: bool
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value if isinstance(self.category, SecretExposureCategory) else str(self.category),
            "secret_type": self.secret_type.value if isinstance(self.secret_type, SecretType) else str(self.secret_type),
            "source_boundary": self.source_boundary,
            "exposure_boundary": self.exposure_boundary,
            "credential_validity": self.credential_validity.value if isinstance(self.credential_validity, CredentialValidity) else str(self.credential_validity),
            "privilege_level": self.privilege_level.value if isinstance(self.privilege_level, PrivilegeLevel) else str(self.privilege_level),
            "accessible_by_attacker": self.accessible_by_attacker,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
