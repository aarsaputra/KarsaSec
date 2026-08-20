"""Sprint F10 Phase 2 — AI Request State & Idempotency Boundary Service (INV-F10-IDEMPOTENCY-04, INV-F10-STATE-06, INV-F10-STATE-07).

Provides database-authoritative request creation, reservation, transition, commit, and release operations.
All methods operate strictly within caller-controlled transactions (zero internal session.commit calls).
"""

from typing import Any
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from karsasec.ai.budget import AIBudgetService
from karsasec.ai.exceptions import (
    AIRequestIdempotencyConflictError,
    AIRequestNotFoundError,
    AIRequestStateConflictError,
    InvalidAIRequestStateTransitionError,
)
from karsasec.ai.state_machine import (
    STATE_CANCELLED,
    STATE_COMPLETED,
    STATE_CREATED,
    STATE_RESERVED,
    is_terminal_state,
    validate_state_transition,
)
from karsasec.persistence.models import AIRequestModel


class AIRequestStateService:
    """Authoritative service for AI request creation, idempotency, and atomic state transitions."""

    @classmethod
    def get_request(cls, session: Session, request_id: str) -> AIRequestModel | None:
        """Retrieves AIRequestModel by request_id."""
        return session.scalar(select(AIRequestModel).where(AIRequestModel.request_id == request_id))

    @classmethod
    def create_request(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        budget_id: str,
        prompt_hash: str,
        context_hash: str,
    ) -> AIRequestModel:
        """Creates a new AI request or idempotently verifies an existing request (INV-F10-IDEMPOTENCY-04, INV-F10-IDEMPOTENCY-05).

        If request_id already exists:
        - If (task_id, budget_id, prompt_hash, context_hash) match: returns existing record.
        - If any semantic metadata field mismatches: raises AIRequestIdempotencyConflictError.

        Raises:
            AIRequestIdempotencyConflictError: If request_id exists with conflicting metadata.
            ValueError: If SHA-256 hashes are invalid length (not 64 hex chars).
        """
        if len(prompt_hash) != 64 or len(context_hash) != 64:
            raise ValueError("prompt_hash and context_hash must be valid 64-character hex strings.")

        existing = cls.get_request(session, request_id)
        if existing:
            # Semantic identity validation
            if (
                existing.task_id == task_id
                and existing.budget_id == budget_id
                and existing.prompt_hash == prompt_hash
                and existing.context_hash == context_hash
            ):
                return existing

            raise AIRequestIdempotencyConflictError(
                f"Request '{request_id}' already exists with different payload metadata."
            )

        req = AIRequestModel(
            request_id=request_id,
            task_id=task_id,
            budget_id=budget_id,
            prompt_hash=prompt_hash,
            context_hash=context_hash,
            status=STATE_CREATED,
        )
        session.add(req)
        try:
            session.flush()
        except IntegrityError as exc:
            # Race condition handling for concurrent create_request calls
            session.rollback()
            existing_race = cls.get_request(session, request_id)
            if existing_race:
                if (
                    existing_race.task_id == task_id
                    and existing_race.budget_id == budget_id
                    and existing_race.prompt_hash == prompt_hash
                    and existing_race.context_hash == context_hash
                ):
                    return existing_race
                raise AIRequestIdempotencyConflictError(
                    f"Request '{request_id}' created concurrently with different metadata."
                ) from exc
            raise

        return req

    @classmethod
    def reserve_budget(
        cls,
        session: Session,
        request_id: str,
        request_tokens: int,
    ) -> AIRequestModel:
        """Atomically reserves budget and transitions AI request status CREATED -> RESERVED (INV-F10-BUDGET-08).

        Idempotency / Crash Recovery (INV-F10-CRASH-13):
        If the request is already in status RESERVED with identical reserved_tokens, returns without double-charging.

        Raises:
            AIRequestNotFoundError: If request_id does not exist.
            InvalidAIRequestStateTransitionError: If transition from active status to RESERVED is prohibited.
            AIRequestStateConflictError: If a concurrent status transition occurred.
        """
        request = cls.get_request(session, request_id)
        if not request:
            raise AIRequestNotFoundError(f"AI Request '{request_id}' not found.")

        # Idempotent retry check
        if request.status == STATE_RESERVED:
            if request.reserved_tokens == request_tokens:
                return request
            raise AIRequestIdempotencyConflictError(
                f"Request '{request_id}' already reserved with {request.reserved_tokens} tokens (requested {request_tokens})."
            )

        validate_state_transition(request.status, STATE_RESERVED)

        # 1. Reserve tokens on AIBudgetModel (atomic CAS UPDATE)
        AIBudgetService.reserve_tokens(session, request.budget_id, request_tokens)

        # 2. Update AIRequestModel state & reserved_tokens (atomic CAS UPDATE)
        stmt = (
            update(AIRequestModel)
            .where(
                AIRequestModel.request_id == request_id,
                AIRequestModel.status == request.status,
            )
            .values(status=STATE_RESERVED, reserved_tokens=request_tokens)
        )
        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) != 1:
            raise AIRequestStateConflictError(f"Concurrent status transition conflict for request '{request_id}'.")

        session.flush()
        return request

    @classmethod
    def transition_status(
        cls,
        session: Session,
        request_id: str,
        expected_status: str,
        new_status: str,
        selected_provider_id: str | None = None,
        selected_model_id: str | None = None,
    ) -> AIRequestModel:
        """Atomically transitions an AI request status (INV-F10-STATE-07).

        Raises:
            AIRequestNotFoundError: If request_id does not exist.
            InvalidAIRequestStateTransitionError: If the transition is prohibited by state machine rules.
            AIRequestStateConflictError: If expected_status does not match active DB status.
        """
        request = cls.get_request(session, request_id)
        if not request:
            raise AIRequestNotFoundError(f"AI Request '{request_id}' not found.")

        validate_state_transition(expected_status, new_status)
        if request.status != expected_status:
            raise AIRequestStateConflictError(
                f"State transition conflict for '{request_id}'. Expected status '{expected_status}', active status is '{request.status}'."
            )

        values: dict[str, Any] = {"status": new_status}
        if selected_provider_id is not None:
            values["selected_provider_id"] = selected_provider_id
        if selected_model_id is not None:
            values["selected_model_id"] = selected_model_id

        stmt = (
            update(AIRequestModel)
            .where(
                AIRequestModel.request_id == request_id,
                AIRequestModel.status == expected_status,
            )
            .values(**values)
        )
        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) != 1:
            raise AIRequestStateConflictError(
                f"State transition conflict for '{request_id}'. Expected status '{expected_status}'."
            )

        session.flush()
        return request

    @classmethod
    def commit_execution(
        cls,
        session: Session,
        request_id: str,
        actual_tokens: int,
        actual_cost_micro_units: int,
        selected_provider_id: str | None = None,
        selected_model_id: str | None = None,
    ) -> AIRequestModel:
        """Atomically commits actual token & financial usage and transitions to COMPLETED status (INV-F10-BUDGET-09).

        Idempotency: If request is already COMPLETED with matching committed values, returns existing record.
        """
        request = cls.get_request(session, request_id)
        if not request:
            raise AIRequestNotFoundError(f"AI Request '{request_id}' not found.")

        if request.status == STATE_COMPLETED:
            if request.committed_tokens == actual_tokens and request.actual_cost_micro_units == actual_cost_micro_units:
                return request
            raise AIRequestIdempotencyConflictError(
                f"Request '{request_id}' already completed with different token/cost figures."
            )

        validate_state_transition(request.status, STATE_COMPLETED)

        # 1. Commit token usage on AIBudgetModel
        AIBudgetService.commit_tokens(
            session,
            budget_id=request.budget_id,
            reserved_tokens=request.reserved_tokens,
            actual_tokens=actual_tokens,
            actual_cost_micro_units=actual_cost_micro_units,
        )

        # 2. Update AIRequestModel
        values: dict[str, Any] = {
            "status": STATE_COMPLETED,
            "committed_tokens": actual_tokens,
            "actual_cost_micro_units": actual_cost_micro_units,
            "reserved_tokens": 0,
        }
        if selected_provider_id is not None:
            values["selected_provider_id"] = selected_provider_id
        if selected_model_id is not None:
            values["selected_model_id"] = selected_model_id

        stmt = (
            update(AIRequestModel)
            .where(
                AIRequestModel.request_id == request_id,
                AIRequestModel.status == request.status,
            )
            .values(**values)
        )
        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) != 1:
            raise AIRequestStateConflictError(
                f"Concurrent status transition conflict during commit for request '{request_id}'."
            )

        session.flush()
        return request

    @classmethod
    def release_reservation(
        cls,
        session: Session,
        request_id: str,
        target_status: str = STATE_CANCELLED,
    ) -> AIRequestModel:
        """Atomically releases reserved tokens back to the budget pool and transitions to terminal CANCELLED or FAILED state (INV-F10-BUDGET-10).

        Idempotent: Re-releasing a CANCELLED or FAILED request returns the record without double releasing tokens.
        """
        request = cls.get_request(session, request_id)
        if not request:
            raise AIRequestNotFoundError(f"AI Request '{request_id}' not found.")

        if is_terminal_state(request.status):
            if request.status == target_status:
                return request
            raise InvalidAIRequestStateTransitionError(
                f"Cannot transition terminal request '{request_id}' from '{request.status}' to '{target_status}'."
            )

        validate_state_transition(request.status, target_status)

        reserved_tokens_to_release = request.reserved_tokens

        # 1. Release tokens on AIBudgetModel if reserved
        if reserved_tokens_to_release > 0:
            AIBudgetService.release_tokens(session, request.budget_id, reserved_tokens_to_release)

        # 2. Update AIRequestModel
        stmt = (
            update(AIRequestModel)
            .where(
                AIRequestModel.request_id == request_id,
                AIRequestModel.status == request.status,
            )
            .values(status=target_status, reserved_tokens=0)
        )
        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) != 1:
            raise AIRequestStateConflictError(
                f"Concurrent status transition conflict during release for request '{request_id}'."
            )

        session.flush()
        return request
