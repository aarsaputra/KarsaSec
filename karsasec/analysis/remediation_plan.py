"""RemediationPlan model and deterministic plan_id calculation for Sprint E14."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from karsasec.analysis.remediation_pattern import RemediationStatus


def compute_remediation_plan_id(
    cluster_id: str,
    pattern_id: str,
    status: RemediationStatus,
    primary_fix: str,
    schema_version: str = "1.0",
) -> str:
    """Computes deterministic SHA-256 remediation plan identity."""
    payload = {
        "schema_version": schema_version,
        "cluster_id": cluster_id,
        "pattern_id": pattern_id,
        "status": status.value,
        "primary_fix": primary_fix,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"E14-PLAN:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class RemediationPlan:
    """Immutable representation of a generated remediation plan."""

    plan_id: str
    cluster_id: str
    pattern_id: str
    status: RemediationStatus
    primary_fix: str
    alternative_fixes: tuple[str, ...]
    affected_nodes: tuple[str, ...]
    validation_steps: tuple[str, ...]
    rationale: tuple[str, ...]
    regression_required: bool
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        cluster_id: str,
        pattern_id: str,
        status: RemediationStatus,
        primary_fix: str,
        alternative_fixes: Sequence[str],
        affected_nodes: Sequence[str],
        validation_steps: Sequence[str],
        rationale: Sequence[str],
        regression_required: bool = True,
        schema_version: str = "1.0",
    ) -> RemediationPlan:
        """Factory creating immutable RemediationPlan with deterministic plan_id."""
        pid = compute_remediation_plan_id(
            cluster_id=cluster_id,
            pattern_id=pattern_id,
            status=status,
            primary_fix=primary_fix,
            schema_version=schema_version,
        )

        return cls(
            plan_id=pid,
            cluster_id=cluster_id,
            pattern_id=pattern_id,
            status=status,
            primary_fix=primary_fix,
            alternative_fixes=tuple(sorted(set(str(x) for x in alternative_fixes))),
            affected_nodes=tuple(sorted(set(str(x) for x in affected_nodes))),
            validation_steps=tuple(sorted(set(str(x) for x in validation_steps))),
            rationale=tuple(sorted(set(str(x) for x in rationale))),
            regression_required=regression_required,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes remediation plan to dictionary."""
        return {
            "plan_id": self.plan_id,
            "cluster_id": self.cluster_id,
            "pattern_id": self.pattern_id,
            "status": self.status.value,
            "primary_fix": self.primary_fix,
            "alternative_fixes": list(self.alternative_fixes),
            "affected_nodes": list(self.affected_nodes),
            "validation_steps": list(self.validation_steps),
            "rationale": list(self.rationale),
            "regression_required": self.regression_required,
            "schema_version": self.schema_version,
        }
