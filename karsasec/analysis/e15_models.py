"""Sprint E15 — Domain Models & Decision Enums.

Provides immutable dataclasses, StrEnum status representations, and deterministic
SHA-256 identity calculation for security decisions and gate results.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
from typing import Any


class StrEnum(str, Enum):
    """String Enum compatibility helper for Python < 3.11."""
    def __str__(self) -> str:
        return str(self.value)


class DecisionStatus(StrEnum):
    """Terminal security decision status for automated security gates."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    UNKNOWN = "UNKNOWN"


def _is_valid_bounded_float(val: Any) -> bool:
    """Returns True if val is a float in [0.0, 1.0] and not NaN/Inf."""
    if not isinstance(val, (int, float)):
        return False
    f_val = float(val)
    if math.isnan(f_val) or math.isinf(f_val):
        return False
    return 0.0 <= f_val <= 1.0


@dataclass(frozen=True)
class EvidenceValidation:
    """Validation report for evidence graph & finding completeness."""
    evidence_valid: bool
    completeness: float
    contradictions: int
    missing_dimensions: tuple[str, ...]
    validation_reason: str

    def __post_init__(self) -> None:
        if not _is_valid_bounded_float(self.completeness):
            object.__setattr__(self, "evidence_valid", False)


@dataclass(frozen=True)
class ExploitabilityAssessment:
    """Deterministic exploitability assessment metrics."""
    exploitability_score: float
    attack_surface: float
    controllability: float
    reachability: float
    privilege_requirement: float
    exploit_chain_complete: bool
    assessment_valid: bool
    rationale: str

    def __post_init__(self) -> None:
        metrics = (
            self.exploitability_score,
            self.attack_surface,
            self.controllability,
            self.reachability,
            self.privilege_requirement,
        )
        if any(not _is_valid_bounded_float(m) for m in metrics):
            object.__setattr__(self, "assessment_valid", False)


@dataclass(frozen=True)
class SecurityPolicy:
    """Configurable security gate policy rules."""
    policy_id: str
    policy_version: str
    minimum_priority: str
    minimum_confidence: float
    allowed_regression_states: tuple[str, ...]
    require_valid_evidence: bool
    require_valid_exploitability: bool
    block_unknown: bool
    require_remediation_for_confirmed: bool
    schema_version: str = "1.0.0"

    def is_valid(self) -> bool:
        """Returns True if policy fields and bounds are valid."""
        if not self.policy_id or not self.policy_version:
            return False
        if not _is_valid_bounded_float(self.minimum_confidence):
            return False
        return True


@dataclass(frozen=True)
class SecurityDecision:
    """Immutable terminal security decision record."""
    decision_id: str
    priority_id: str
    remediation_plan_id: str
    fingerprint_id: str
    decision: DecisionStatus
    confidence: float
    rationale: str
    policy_version: str
    evidence_valid: bool
    exploitability_valid: bool
    regression_status: str
    created_from_schema_version: str = "1.0.0"

    @staticmethod
    def compute_decision_id(
        priority_id: str,
        remediation_plan_id: str,
        fingerprint_id: str,
        decision: DecisionStatus | str,
        evidence_valid: bool,
        exploitability_valid: bool,
        regression_status: str,
        policy_version: str,
        schema_version: str = "1.0.0",
    ) -> str:
        """Computes a deterministic 64-character SHA-256 identity."""
        payload = {
            "priority_id": priority_id,
            "remediation_plan_id": remediation_plan_id,
            "fingerprint_id": fingerprint_id,
            "decision": str(decision),
            "evidence_valid": bool(evidence_valid),
            "exploitability_valid": bool(exploitability_valid),
            "regression_status": str(regression_status),
            "policy_version": str(policy_version),
            "schema_version": str(schema_version),
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        raw = f"E15-DECISION:{serialized}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SecurityGateResult:
    """Immutable aggregate security release gate execution result."""
    gate_id: str
    decision_id: str
    passed: bool
    blocked: bool
    requires_review: bool
    unknown: bool
    failed_rules: tuple[str, ...]
    evaluated_rules: tuple[str, ...]
    policy_version: str

    @staticmethod
    def compute_gate_id(
        decision_id: str,
        policy_id: str,
        evaluated_rules: tuple[str, ...] | list[str],
        failed_rules: tuple[str, ...] | list[str],
        schema_version: str = "1.0.0",
    ) -> str:
        """Computes a deterministic 64-character SHA-256 gate identity."""
        payload = {
            "decision_id": decision_id,
            "policy_id": policy_id,
            "evaluated_rules": sorted(evaluated_rules),
            "failed_rules": sorted(failed_rules),
            "schema_version": str(schema_version),
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        raw = f"E15-GATE:{serialized}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
