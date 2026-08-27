"""Immutable domain models for Sprint E20 Autonomous Security Operations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def compute_hash(prefix: str, payload: dict[str, Any]) -> str:
    """Computes canonical SHA-256 hash for autonomous ops artifacts."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prefix}:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class CircuitBreakerBudget:
    """Immutable circuit breaker operational budget parameters (§3.5)."""

    budget_id: str
    max_auto_block_per_window: int
    action_budget: int
    time_budget_seconds: int
    retry_budget: int
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        max_auto_block_per_window: int = 5,
        action_budget: int = 10,
        time_budget_seconds: int = 30,
        retry_budget: int = 2,
    ) -> CircuitBreakerBudget:
        payload = {
            "max_auto_block_per_window": max_auto_block_per_window,
            "action_budget": action_budget,
            "time_budget_seconds": time_budget_seconds,
            "retry_budget": retry_budget,
            "schema_version": "1.0",
        }
        bid = compute_hash("AUTO-BUDGET", payload)
        return cls(
            budget_id=bid,
            max_auto_block_per_window=max_auto_block_per_window,
            action_budget=action_budget,
            time_budget_seconds=time_budget_seconds,
            retry_budget=retry_budget,
        )


@dataclass(frozen=True)
class ActionProposal:
    """Immutable representation of an autonomous security action proposal."""

    proposal_id: str
    target_id: str
    action_type: str
    cluster_id: str
    requires_human_approval: bool
    status: str

    @classmethod
    def create(
        cls,
        target_id: str,
        action_type: str,
        cluster_id: str,
        requires_human_approval: bool = True,
        status: str = "PROPOSED",
    ) -> ActionProposal:
        payload = {
            "target_id": target_id,
            "action_type": action_type,
            "cluster_id": cluster_id,
            "requires_human_approval": requires_human_approval,
            "status": status,
        }
        pid = compute_hash("ACTION-PROP", payload)
        return cls(
            proposal_id=pid,
            target_id=target_id,
            action_type=action_type,
            cluster_id=cluster_id,
            requires_human_approval=requires_human_approval,
            status=status,
        )


@dataclass(frozen=True)
class ActionExecutionResult:
    """Immutable result of an autonomous action execution attempt."""

    result_id: str
    proposal_id: str
    executed: bool
    status: str
    reason: str

    @classmethod
    def create(
        cls,
        proposal_id: str,
        executed: bool,
        status: str,
        reason: str,
    ) -> ActionExecutionResult:
        payload = {
            "proposal_id": proposal_id,
            "executed": executed,
            "status": status,
            "reason": reason,
        }
        rid = compute_hash("ACTION-EXEC", payload)
        return cls(
            result_id=rid,
            proposal_id=proposal_id,
            executed=executed,
            status=status,
            reason=reason,
        )
