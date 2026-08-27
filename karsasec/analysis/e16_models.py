"""E16 Domain Models, AdmissionStatus Enum, and Canonical SHA-256 Identity Computation for Sprint E16."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AdmissionStatus(StrEnum):
    """Release admission decision status."""

    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


class ReleaseState(StrEnum):
    """Release state machine lifecycle status."""

    CREATED = "CREATED"
    SECURITY_EVALUATED = "SECURITY_EVALUATED"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


def deterministic_id(namespace: str, payload: dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hex digest for a given namespace and payload.

    Guarantees:
    - Exactly 64 hex characters
    - Sorted keys and canonical json formatting
    - UTF-8 encoding
    - Zero dependence on Python dict hash ordering or PYTHONHASHSEED
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{namespace}{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class ReleaseArtifact:
    """Immutable representation of a software artifact evaluated for release admission."""

    artifact_id: str
    version: str
    commit_sha: str
    decision_id: str
    evaluation_id: str
    content_hash: str
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        version: str,
        commit_sha: str,
        decision_id: str,
        evaluation_id: str,
        content_hash: str,
        schema_version: str = "1.0.0",
    ) -> ReleaseArtifact:
        """Factory creating immutable ReleaseArtifact with canonical SHA-256 ID."""
        payload = {
            "version": version,
            "commit_sha": commit_sha,
            "decision_id": decision_id,
            "evaluation_id": evaluation_id,
            "content_hash": content_hash,
            "schema_version": schema_version,
        }
        art_id = deterministic_id("E16-ARTIFACT:v1:", payload)
        return cls(
            artifact_id=art_id,
            version=version,
            commit_sha=commit_sha,
            decision_id=decision_id,
            evaluation_id=evaluation_id,
            content_hash=content_hash,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes artifact to dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "version": self.version,
            "commit_sha": self.commit_sha,
            "decision_id": self.decision_id,
            "evaluation_id": self.evaluation_id,
            "content_hash": self.content_hash,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class EnforcementPolicy:
    """Immutable representation of a Policy-as-Code release enforcement configuration."""

    policy_id: str
    allow_on: tuple[str, ...]
    require_review_for: tuple[str, ...]
    block_on: tuple[str, ...]
    minimum_confidence: float
    require_deterministic_decision: bool
    policy_version: str = "1.0.0"
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        allow_on: tuple[str, ...] = ("ALLOW",),
        require_review_for: tuple[str, ...] = ("REVIEW",),
        block_on: tuple[str, ...] = ("BLOCK", "UNKNOWN"),
        minimum_confidence: float = 0.80,
        require_deterministic_decision: bool = True,
        policy_version: str = "1.0.0",
        schema_version: str = "1.0.0",
    ) -> EnforcementPolicy:
        """Factory creating immutable EnforcementPolicy with canonical SHA-256 ID."""
        payload = {
            "allow_on": sorted(allow_on),
            "require_review_for": sorted(require_review_for),
            "block_on": sorted(block_on),
            "minimum_confidence": float(minimum_confidence),
            "require_deterministic_decision": bool(require_deterministic_decision),
            "policy_version": policy_version,
            "schema_version": schema_version,
        }
        pol_id = deterministic_id("E16-POLICY:v1:", payload)
        return cls(
            policy_id=pol_id,
            allow_on=tuple(sorted(allow_on)),
            require_review_for=tuple(sorted(require_review_for)),
            block_on=tuple(sorted(block_on)),
            minimum_confidence=float(minimum_confidence),
            require_deterministic_decision=bool(require_deterministic_decision),
            policy_version=policy_version,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes policy to dictionary."""
        return {
            "policy_id": self.policy_id,
            "allow_on": list(self.allow_on),
            "require_review_for": list(self.require_review_for),
            "block_on": list(self.block_on),
            "minimum_confidence": self.minimum_confidence,
            "require_deterministic_decision": self.require_deterministic_decision,
            "policy_version": self.policy_version,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class ReleaseAdmission:
    """Immutable representation of a Release Admission decision."""

    admission_id: str
    status: AdmissionStatus
    artifact_id: str
    artifact_content_hash: str
    decision_id: str
    policy_id: str
    evaluation_id: str
    reason_codes: tuple[str, ...]
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        status: AdmissionStatus,
        artifact_id: str,
        artifact_content_hash: str,
        decision_id: str,
        policy_id: str,
        evaluation_id: str,
        reason_codes: tuple[str, ...],
        schema_version: str = "1.0.0",
    ) -> ReleaseAdmission:
        """Factory creating immutable ReleaseAdmission with canonical SHA-256 ID."""
        sorted_reasons = tuple(sorted(reason_codes))
        payload = {
            "status": str(status),
            "artifact_id": artifact_id,
            "artifact_content_hash": artifact_content_hash,
            "decision_id": decision_id,
            "policy_id": policy_id,
            "evaluation_id": evaluation_id,
            "reason_codes": list(sorted_reasons),
            "schema_version": schema_version,
        }
        adm_id = deterministic_id("E16-ADMISSION:v1:", payload)
        return cls(
            admission_id=adm_id,
            status=status,
            artifact_id=artifact_id,
            artifact_content_hash=artifact_content_hash,
            decision_id=decision_id,
            policy_id=policy_id,
            evaluation_id=evaluation_id,
            reason_codes=sorted_reasons,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes release admission to dictionary."""
        return {
            "admission_id": self.admission_id,
            "status": str(self.status),
            "artifact_id": self.artifact_id,
            "artifact_content_hash": self.artifact_content_hash,
            "decision_id": self.decision_id,
            "policy_id": self.policy_id,
            "evaluation_id": self.evaluation_id,
            "reason_codes": list(self.reason_codes),
            "schema_version": self.schema_version,
        }
