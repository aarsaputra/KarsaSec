"""Sprint F10 Phase 2 — Atomic Token & Cost Budget Fencer (INV-F10-BUDGET-01, INV-F10-BUDGET-02, INV-F10-BUDGET-03).

Enforces atomic token reservation, commit, and release using single-statement conditional SQL updates.
All low-level operations are transactionally caller-controlled (zero internal session.commit calls).
"""

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from karsasec.ai.exceptions import (
    BudgetAccountingError,
    TokenBudgetExceededError,
)
from karsasec.persistence.models import AIBudgetModel


class AIBudgetService:
    """Authoritative service for atomic token & financial budget fencing."""

    @classmethod
    def reserve_tokens(
        cls,
        session: Session,
        budget_id: str,
        request_tokens: int,
    ) -> None:
        """Atomically reserves request_tokens on the specified budget (INV-F10-BUDGET-01).

        Uses a single atomic conditional UPDATE:
        UPDATE ai_budgets SET reserved_tokens = reserved_tokens + :request_tokens
        WHERE budget_id = :budget_id AND used_tokens + reserved_tokens + :request_tokens <= token_limit

        Raises:
            BudgetAccountingError: If request_tokens <= 0 or budget does not exist.
            TokenBudgetExceededError: If token_limit would be exceeded.
        """
        if request_tokens <= 0:
            raise BudgetAccountingError(f"Reservation token count must be positive (got {request_tokens}).")

        stmt = (
            update(AIBudgetModel)
            .where(
                AIBudgetModel.budget_id == budget_id,
                (AIBudgetModel.used_tokens + AIBudgetModel.reserved_tokens + request_tokens)
                <= AIBudgetModel.token_limit,
            )
            .values(reserved_tokens=AIBudgetModel.reserved_tokens + request_tokens)
        )

        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) == 1:
            return

        # Rowcount == 0 — analyze cause for explicit exception
        budget = session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == budget_id))
        if not budget:
            raise BudgetAccountingError(f"Budget '{budget_id}' not found.")

        raise TokenBudgetExceededError(
            f"Token budget limit exceeded for '{budget_id}'. "
            f"Limit={budget.token_limit}, Used={budget.used_tokens}, "
            f"Reserved={budget.reserved_tokens}, Requested={request_tokens}."
        )

    @classmethod
    def commit_tokens(
        cls,
        session: Session,
        budget_id: str,
        reserved_tokens: int,
        actual_tokens: int,
        actual_cost_micro_units: int,
    ) -> None:
        """Atomically commits actual token usage and micro-unit cost while releasing reserved tokens (INV-F10-BUDGET-09).

        Raises:
            BudgetAccountingError: If inputs are negative or reserved_tokens is insufficient.
            TokenBudgetExceededError: If cost_limit_micro_units would be exceeded.
        """
        if reserved_tokens < 0 or actual_tokens < 0 or actual_cost_micro_units < 0:
            raise BudgetAccountingError("Commit values must be non-negative integers.")

        stmt = (
            update(AIBudgetModel)
            .where(
                AIBudgetModel.budget_id == budget_id,
                AIBudgetModel.reserved_tokens >= reserved_tokens,
                (AIBudgetModel.used_cost_micro_units + actual_cost_micro_units) <= AIBudgetModel.cost_limit_micro_units,
            )
            .values(
                reserved_tokens=AIBudgetModel.reserved_tokens - reserved_tokens,
                used_tokens=AIBudgetModel.used_tokens + actual_tokens,
                used_cost_micro_units=AIBudgetModel.used_cost_micro_units + actual_cost_micro_units,
            )
        )

        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) == 1:
            return

        budget = session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == budget_id))
        if not budget:
            raise BudgetAccountingError(f"Budget '{budget_id}' not found.")
        if budget.reserved_tokens < reserved_tokens:
            raise BudgetAccountingError(
                f"Insufficient reserved tokens on budget '{budget_id}' "
                f"(active reserved={budget.reserved_tokens}, releasing={reserved_tokens})."
            )
        raise TokenBudgetExceededError(
            f"Cost limit exceeded on budget '{budget_id}'. "
            f"Limit={budget.cost_limit_micro_units}, Used={budget.used_cost_micro_units}, "
            f"Added={actual_cost_micro_units}."
        )

    @classmethod
    def release_tokens(
        cls,
        session: Session,
        budget_id: str,
        tokens_to_release: int,
    ) -> None:
        """Atomically releases reserved tokens back to the budget pool (INV-F10-BUDGET-10).

        Idempotent & non-negative: releasing 0 is a no-op.

        Raises:
            BudgetAccountingError: If tokens_to_release < 0 or reserved_tokens < tokens_to_release.
        """
        if tokens_to_release < 0:
            raise BudgetAccountingError(f"Tokens to release must be non-negative (got {tokens_to_release}).")

        if tokens_to_release == 0:
            return

        stmt = (
            update(AIBudgetModel)
            .where(
                AIBudgetModel.budget_id == budget_id,
                AIBudgetModel.reserved_tokens >= tokens_to_release,
            )
            .values(reserved_tokens=AIBudgetModel.reserved_tokens - tokens_to_release)
        )

        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) == 1:
            return

        budget = session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == budget_id))
        if not budget:
            raise BudgetAccountingError(f"Budget '{budget_id}' not found.")
        raise BudgetAccountingError(
            f"Cannot release {tokens_to_release} tokens from budget '{budget_id}' "
            f"(active reserved_tokens={budget.reserved_tokens})."
        )
