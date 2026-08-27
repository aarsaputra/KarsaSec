"""Autonomous Security Operations Engine for Sprint E20."""

from __future__ import annotations

from karsasec.autonomous.circuit_breaker import CircuitBreakerEngine
from karsasec.autonomous.models import (
    ActionExecutionResult,
    ActionProposal,
    CircuitBreakerBudget,
)


class AutonomousOpsEngine:
    """Coordinates shadow-mode proposals, circuit breaker checks, and action authorization."""

    def __init__(
        self,
        budget: CircuitBreakerBudget | None = None,
        is_shadow_mode: bool = True,
    ) -> None:
        self.circuit_breaker = CircuitBreakerEngine(budget=budget)
        self.is_shadow_mode = is_shadow_mode

    def propose_action(
        self,
        target_id: str,
        action_type: str,
        cluster_id: str,
    ) -> ActionProposal:
        """Emits an ActionProposal adhering to Shadow-Mode (§3.3) invariants."""
        return ActionProposal.create(
            target_id=target_id,
            action_type=action_type,
            cluster_id=cluster_id,
            requires_human_approval=self.is_shadow_mode,
            status="PROPOSED_SHADOW" if self.is_shadow_mode else "PROPOSED_ACTIVE",
        )

    def execute_proposal(self, proposal: ActionProposal) -> ActionExecutionResult:
        """Evaluates proposal against circuit breaker and shadow-mode status."""
        if not proposal:
            return ActionExecutionResult.create(
                proposal_id="NULL",
                executed=False,
                status="REJECTED",
                reason="FAIL-CLOSED: ActionProposal is None",
            )

        if proposal.requires_human_approval or self.is_shadow_mode:
            return ActionExecutionResult.create(
                proposal_id=proposal.proposal_id,
                executed=False,
                status="SHADOW_MODE_PROPOSAL",
                reason="SHADOW_MODE: Action recorded as proposal for human review per §3.3",
            )

        allowed, reason = self.circuit_breaker.check_and_consume(
            is_auto_block=(proposal.action_type.upper() == "AUTO_BLOCK")
        )

        if not allowed:
            return ActionExecutionResult.create(
                proposal_id=proposal.proposal_id,
                executed=False,
                status="CIRCUIT_BREAKER_BLOCKED",
                reason=reason,
            )

        return ActionExecutionResult.create(
            proposal_id=proposal.proposal_id,
            executed=True,
            status="EXECUTED",
            reason="Autonomous action executed within authorized budget limits",
        )
