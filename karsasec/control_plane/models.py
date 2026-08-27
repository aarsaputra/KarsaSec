"""Immutable domain models for Sprint E17 Security Control Plane."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def compute_hash(prefix: str, payload: dict[str, Any]) -> str:
    """Computes canonical SHA-256 hash for control plane artifacts."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prefix}:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class ControlPlaneConfig:
    """Configuration governing Security Control Plane behavior."""

    config_id: str
    tenant_id: str
    fail_closed: bool
    require_audit_logging: bool
    allow_emergency_override: bool
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        tenant_id: str = "DEFAULT",
        fail_closed: bool = True,
        require_audit_logging: bool = True,
        allow_emergency_override: bool = False,
    ) -> ControlPlaneConfig:
        payload = {
            "tenant_id": tenant_id,
            "fail_closed": fail_closed,
            "require_audit_logging": require_audit_logging,
            "allow_emergency_override": allow_emergency_override,
            "schema_version": "1.0",
        }
        cid = compute_hash("CP-CONFIG", payload)
        return cls(
            config_id=cid,
            tenant_id=tenant_id,
            fail_closed=fail_closed,
            require_audit_logging=require_audit_logging,
            allow_emergency_override=allow_emergency_override,
        )


@dataclass(frozen=True)
class PolicyVersion:
    """Immutable representation of a versioned policy registered in Control Plane."""

    policy_id: str
    name: str
    version: str
    content_hash: str
    rules: tuple[dict[str, Any], ...]
    is_active: bool

    @classmethod
    def create(
        cls,
        name: str,
        version: str,
        rules: tuple[dict[str, Any], ...],
        is_active: bool = True,
    ) -> PolicyVersion:
        payload = {
            "name": name,
            "version": version,
            "rules": sorted(rules, key=lambda x: str(x.get("id", ""))),
        }
        chash = compute_hash("POLICY-RULES", payload)
        pid = compute_hash("POLICY-VER", {"content_hash": chash, "version": version})
        return cls(
            policy_id=pid,
            name=name,
            version=version,
            content_hash=chash,
            rules=rules,
            is_active=is_active,
        )


@dataclass(frozen=True)
class ControlPlaneEvaluationResult:
    """Immutable evaluation result produced by Security Control Plane."""

    evaluation_id: str
    tenant_id: str
    policy_id: str
    status: str
    reason: str
    admission_status: str
    audit_record_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        tenant_id: str,
        policy_id: str,
        status: str,
        reason: str,
        admission_status: str,
        audit_record_hash: str,
        metadata: dict[str, Any] | None = None,
    ) -> ControlPlaneEvaluationResult:
        meta = metadata or {}
        payload = {
            "tenant_id": tenant_id,
            "policy_id": policy_id,
            "status": status,
            "reason": reason,
            "admission_status": admission_status,
            "audit_record_hash": audit_record_hash,
            "metadata": meta,
        }
        eid = compute_hash("CP-EVAL", payload)
        return cls(
            evaluation_id=eid,
            tenant_id=tenant_id,
            policy_id=policy_id,
            status=status,
            reason=reason,
            admission_status=admission_status,
            audit_record_hash=audit_record_hash,
            metadata=meta,
        )
