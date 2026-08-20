"""Sprint F10 Phase 4 — Transactional AI Event Staging Service (INV-F10-AUDIT-01 through INV-F10-AUDIT-14).

Integrates AI request lifecycle with the EXISTING TransactionalOutbox and TaskAuditLedger.

Security Boundaries (always enforced):
  - NEVER persists raw prompt, raw completion, API keys, bearer tokens, or credentials.
  - All event payloads are bounded: request_id, task_id, budget_id, provider_id, model_id,
    prompt_hash, context_hash, attempt_id, attempt_number, bounded status, bounded error_class,
    bounded token counts, bounded cost micro-units.
  - SHA-256 hashes only for content identification.
  - Canonical JSON serialization (sort_keys=True, separators=(',', ':')) for determinism.

Transaction Boundary (INV-F10-AUDIT-02):
  - Zero internal session.commit() calls.
  - Caller owns the transaction lifecycle.
  - All mutations (AI state, budget, outbox, audit) roll back atomically if caller raises.

Event Identity / Deduplication (INV-F10-AUDIT-09):
  - deduplication_key = SHA-256(f"{aggregate_type}:{aggregate_id}:{event_type}:{stable_identity}")
  - stable_identity is derived from request_id + attempt_id (if applicable) + event_type.
  - Reusing the same deduplication_key on retry returns the existing event (idempotent).

F9 Compatibility (INV-F10-AUDIT-14):
  - No modifications to karsasec/recovery/, karsasec/events/audit_ledger.py,
    karsasec/events/outbox.py, or karsasec/persistence/postgres_task_repository.py.
  - TaskAuditLedger receives AI lifecycle transitions using its existing record_transition() API.
  - ai_* state transitions use 'AI_*' prefixed state strings in the reason field, keeping
    task_id chain semantically consistent.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

from sqlalchemy.orm import Session

from karsasec.ai.exceptions import KarsaSecAIError
from karsasec.events.audit_ledger import TaskAuditLedger
from karsasec.events.outbox import TransactionalOutbox
from karsasec.persistence.models import OutboxEventModel


# ─── AI Aggregate Type ────────────────────────────────────────────────────────

AI_AGGREGATE_TYPE: Final[str] = "AI_REQUEST"

# ─── AI Event Type Vocabulary ─────────────────────────────────────────────────

EVT_BUDGET_RESERVED: Final[str] = "AI_BUDGET_RESERVED"
EVT_PROMPT_GENERATED: Final[str] = "AI_PROMPT_GENERATED"
EVT_PROVIDER_SELECTED: Final[str] = "AI_PROVIDER_SELECTED"
EVT_PROVIDER_FAILED: Final[str] = "AI_PROVIDER_FAILED"
EVT_RESPONSE_RECEIVED: Final[str] = "AI_RESPONSE_RECEIVED"
EVT_BUDGET_COMMITTED: Final[str] = "AI_BUDGET_COMMITTED"
EVT_BUDGET_RELEASED: Final[str] = "AI_BUDGET_RELEASED"
EVT_BUDGET_EXHAUSTED: Final[str] = "AI_BUDGET_EXHAUSTED"

ALL_AI_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        EVT_BUDGET_RESERVED,
        EVT_PROMPT_GENERATED,
        EVT_PROVIDER_SELECTED,
        EVT_PROVIDER_FAILED,
        EVT_RESPONSE_RECEIVED,
        EVT_BUDGET_COMMITTED,
        EVT_BUDGET_RELEASED,
        EVT_BUDGET_EXHAUSTED,
    }
)

# ─── Bounded Provider Error Taxonomy (re-used from router) ───────────────────
# Any error_class in AI events MUST come from this set.

BOUNDED_ERROR_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "TIMEOUT",
        "RATE_LIMIT",
        "AUTHENTICATION_FAILED",
        "PROVIDER_UNAVAILABLE",
        "INVALID_REQUEST",
        "NETWORK_ERROR",
        "UNKNOWN_PROVIDER_ERROR",
        "COST_LIMIT",
    }
)

# ─── Security Violation Exception ─────────────────────────────────────────────


class AIEventSecurityError(KarsaSecAIError):
    """Raised when an AI event staging attempt violates secret-isolation or payload contracts."""

    pass


# ─── Canonical Serialization ──────────────────────────────────────────────────


def _canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic JSON serialization for event payloads (INV-F10-AUDIT-13).

    Uses sort_keys=True and compact separators to guarantee identical output
    across Python versions and dict orderings.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _deduplication_key(aggregate_type: str, aggregate_id: str, event_type: str, stable_identity: str) -> str:
    """Derives a stable deduplication_key for TransactionalOutbox (INV-F10-AUDIT-09).

    Reusing this key on retry returns the existing event without creating a duplicate.
    The key is SHA-256(f"{aggregate_type}:{aggregate_id}:{event_type}:{stable_identity}").
    """
    raw = f"{aggregate_type}:{aggregate_id}:{event_type}:{stable_identity}"
    return _sha256(raw)


# ─── Secret/Raw-Content Validator ─────────────────────────────────────────────

# Patterns that, if detected in a string value, indicate a credential or raw content.
_FORBIDDEN_PREFIXES: Final[tuple[str, ...]] = ("sk-", "Bearer ", "Authorization:", "api_key=")
_MIN_HASH_LEN: Final[int] = 8  # Minimum expected hash/id field length sanity


def _assert_no_secret(field_name: str, value: str | None) -> None:
    """Raises AIEventSecurityError if value looks like a raw secret (INV-F10-AUDIT-04)."""
    if value is None:
        return
    for prefix in _FORBIDDEN_PREFIXES:
        if value.startswith(prefix):
            raise AIEventSecurityError(
                f"Field '{field_name}' appears to contain a credential prefix '{prefix}'. "
                f"Raw secrets must never appear in AI event payloads (INV-F10-AUDIT-04)."
            )


# ─── AIEventService ───────────────────────────────────────────────────────────


class AIEventService:
    """Transactional AI lifecycle event staging service (INV-F10-AUDIT-01 through INV-F10-AUDIT-14).

    Responsibility:
      - Validate bounded event metadata (INV-F10-AUDIT-05).
      - Reject any raw secrets or unbounded content (INV-F10-AUDIT-04).
      - Build canonical, deterministic JSON payloads (INV-F10-AUDIT-13).
      - Derive stable deduplication keys (INV-F10-AUDIT-09).
      - Delegate to TransactionalOutbox.stage_event() for event staging.
      - Delegate to TaskAuditLedger.record_transition() for audit chain entries.
      - NEVER call session.commit() (INV-F10-AUDIT-02).
      - NEVER mutate ai_budgets directly (INV-F10-AUDIT-11).

    All methods accept a SQLAlchemy Session that MUST already be inside an open transaction.
    """

    # ─── Budget Events ─────────────────────────────────────────────────────

    @classmethod
    def stage_budget_reserved(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        budget_id: str,
        reserved_tokens: int,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_BUDGET_RESERVED after a successful token reservation (INV-F10-AUDIT-01).

        Args:
            session: Active SQLAlchemy session (caller-controlled transaction).
            request_id: Durable AI request identity.
            task_id: Parent task identity.
            budget_id: Budget being reserved.
            reserved_tokens: Number of tokens reserved (non-negative integer).
            lease_version: Aggregate sequence for outbox ordering.

        Raises:
            AIEventSecurityError: If any field contains credential-like values.
            ValueError: If reserved_tokens is negative.
        """
        _assert_no_secret("request_id", request_id)
        _assert_no_secret("budget_id", budget_id)
        if reserved_tokens < 0:
            raise ValueError(f"reserved_tokens must be non-negative (got {reserved_tokens}).")

        payload = {
            "budget_id": budget_id,
            "request_id": request_id,
            "reserved_tokens": reserved_tokens,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_BUDGET_RESERVED, request_id)

        TaskAuditLedger.record_transition(
            session,
            task_id=task_id,
            previous_state="CREATED",
            new_state="RESERVED",
            reason=f"AI_BUDGET_RESERVED:request={request_id}:tokens={reserved_tokens}",
            lease_version=lease_version,
        )

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_BUDGET_RESERVED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    @classmethod
    def stage_prompt_generated(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        prompt_hash: str,
        context_hash: str,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_PROMPT_GENERATED after prompt preparation (INV-F10-AUDIT-04).

        Accepts SHA-256 hashes only — never raw prompt content.

        Raises:
            AIEventSecurityError: If hashes appear to be credentials.
            ValueError: If hash strings are not valid 64-char hex strings.
        """
        if len(prompt_hash) != 64 or len(context_hash) != 64:
            raise ValueError("prompt_hash and context_hash must be valid 64-character SHA-256 hex strings.")

        _assert_no_secret("prompt_hash", prompt_hash)
        _assert_no_secret("context_hash", context_hash)

        payload = {
            "context_hash": context_hash,
            "prompt_hash": prompt_hash,
            "request_id": request_id,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_PROMPT_GENERATED, request_id)

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_PROMPT_GENERATED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    # ─── Provider Events ───────────────────────────────────────────────────

    @classmethod
    def stage_provider_selected(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        attempt_id: str,
        attempt_number: int,
        provider_id: str,
        model_id: str,
        estimated_cost_micro_units: int,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_PROVIDER_SELECTED when router commits to a provider.

        Raises:
            AIEventSecurityError: If provider_id/model_id appear to contain credentials.
            ValueError: If attempt_number < 1 or estimated_cost_micro_units < 0.
        """
        _assert_no_secret("provider_id", provider_id)
        _assert_no_secret("model_id", model_id)
        _assert_no_secret("attempt_id", attempt_id)
        if attempt_number < 1:
            raise ValueError(f"attempt_number must be >= 1 (got {attempt_number}).")
        if estimated_cost_micro_units < 0:
            raise ValueError(f"estimated_cost_micro_units must be non-negative (got {estimated_cost_micro_units}).")

        payload = {
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "estimated_cost_micro_units": estimated_cost_micro_units,
            "model_id": model_id,
            "provider_id": provider_id,
            "request_id": request_id,
            "task_id": task_id,
        }
        # Attempt-scoped dedup: same attempt_id → same event (idempotent retry)
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_PROVIDER_SELECTED, attempt_id)

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_PROVIDER_SELECTED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    @classmethod
    def stage_provider_failed(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        attempt_id: str,
        attempt_number: int,
        provider_id: str,
        model_id: str,
        error_class: str,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_PROVIDER_FAILED with a bounded error taxonomy string (INV-F10-AUDIT-08).

        Raises:
            AIEventSecurityError: If error_class is not a known bounded taxonomy string,
                or if provider_id/model_id contain credential-like values.
            ValueError: If attempt_number < 1.
        """
        if error_class not in BOUNDED_ERROR_CLASSES:
            raise AIEventSecurityError(
                f"error_class '{error_class}' is not a bounded taxonomy string. "
                f"Must be one of {sorted(BOUNDED_ERROR_CLASSES)}. "
                f"Raw exception payloads are prohibited (INV-F10-AUDIT-08)."
            )
        _assert_no_secret("provider_id", provider_id)
        _assert_no_secret("model_id", model_id)
        if attempt_number < 1:
            raise ValueError(f"attempt_number must be >= 1 (got {attempt_number}).")

        payload = {
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "error_class": error_class,
            "model_id": model_id,
            "provider_id": provider_id,
            "request_id": request_id,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_PROVIDER_FAILED, attempt_id)

        TaskAuditLedger.record_transition(
            session,
            task_id=task_id,
            previous_state="ROUTED",
            new_state="PROVIDER_FAILED",
            reason=f"AI_PROVIDER_FAILED:attempt={attempt_number}:provider={provider_id}:error={error_class}",
            lease_version=lease_version,
        )

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_PROVIDER_FAILED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    @classmethod
    def stage_response_received(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        attempt_id: str,
        attempt_number: int,
        provider_id: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        actual_cost_micro_units: int,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_RESPONSE_RECEIVED after a successful provider response.

        Never persists raw response content — only bounded token counts and cost.

        Raises:
            AIEventSecurityError: If credential-like values detected.
            ValueError: If token counts or cost are negative.
        """
        _assert_no_secret("provider_id", provider_id)
        _assert_no_secret("model_id", model_id)
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("input_tokens and output_tokens must be non-negative.")
        if actual_cost_micro_units < 0:
            raise ValueError(f"actual_cost_micro_units must be non-negative (got {actual_cost_micro_units}).")

        payload = {
            "actual_cost_micro_units": actual_cost_micro_units,
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "input_tokens": input_tokens,
            "model_id": model_id,
            "output_tokens": output_tokens,
            "provider_id": provider_id,
            "request_id": request_id,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_RESPONSE_RECEIVED, attempt_id)

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_RESPONSE_RECEIVED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    @classmethod
    def stage_budget_committed(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        budget_id: str,
        actual_tokens: int,
        actual_cost_micro_units: int,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_BUDGET_COMMITTED after tokens and cost are committed to the budget.

        Raises:
            ValueError: If token counts or cost are negative.
        """
        if actual_tokens < 0 or actual_cost_micro_units < 0:
            raise ValueError("actual_tokens and actual_cost_micro_units must be non-negative.")

        payload = {
            "actual_cost_micro_units": actual_cost_micro_units,
            "actual_tokens": actual_tokens,
            "budget_id": budget_id,
            "request_id": request_id,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_BUDGET_COMMITTED, request_id)

        TaskAuditLedger.record_transition(
            session,
            task_id=task_id,
            previous_state="IN_FLIGHT",
            new_state="COMPLETED",
            reason=f"AI_BUDGET_COMMITTED:request={request_id}:tokens={actual_tokens}:cost={actual_cost_micro_units}",
            lease_version=lease_version,
        )

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_BUDGET_COMMITTED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    @classmethod
    def stage_budget_released(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        budget_id: str,
        released_tokens: int,
        reason: str = "CANCELLED",
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_BUDGET_RELEASED when reserved tokens are returned to the budget pool.

        Raises:
            ValueError: If released_tokens is negative.
            AIEventSecurityError: If reason looks like a credential or raw exception payload.
        """
        if released_tokens < 0:
            raise ValueError(f"released_tokens must be non-negative (got {released_tokens}).")
        _assert_no_secret("reason", reason)

        payload = {
            "budget_id": budget_id,
            "reason": reason,
            "released_tokens": released_tokens,
            "request_id": request_id,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_BUDGET_RELEASED, f"{request_id}:{reason}")

        TaskAuditLedger.record_transition(
            session,
            task_id=task_id,
            previous_state="RESERVED",
            new_state="CANCELLED",
            reason=f"AI_BUDGET_RELEASED:request={request_id}:tokens={released_tokens}:reason={reason}",
            lease_version=lease_version,
        )

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_BUDGET_RELEASED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )

    @classmethod
    def stage_budget_exhausted(
        cls,
        session: Session,
        request_id: str,
        task_id: str,
        budget_id: str,
        requested_tokens: int,
        current_available: int,
        lease_version: int = 1,
    ) -> OutboxEventModel | None:
        """Stages AI_BUDGET_EXHAUSTED when budget reservation or commit fails due to limits.

        MUST NOT be called if a budget commit succeeded for the same operation (INV-F10-AUDIT-10).

        Raises:
            ValueError: If requested_tokens or current_available are negative.
        """
        if requested_tokens < 0 or current_available < 0:
            raise ValueError("requested_tokens and current_available must be non-negative.")

        payload = {
            "budget_id": budget_id,
            "current_available": current_available,
            "request_id": request_id,
            "requested_tokens": requested_tokens,
            "task_id": task_id,
        }
        dedup = _deduplication_key(AI_AGGREGATE_TYPE, request_id, EVT_BUDGET_EXHAUSTED, request_id)

        return TransactionalOutbox.stage_event(
            session,
            aggregate_type=AI_AGGREGATE_TYPE,
            aggregate_id=request_id,
            event_type=EVT_BUDGET_EXHAUSTED,
            payload=_canonical_json(payload),
            lease_version=lease_version,
            deduplication_key=dedup,
        )
