"""Sprint F10 — AI Budget, Request State Machine & Provider Router Exceptions."""


class KarsaSecAIError(Exception):
    """Base exception for all KarsaSec AI gateway and budget operations."""

    pass


class TokenBudgetExceededError(KarsaSecAIError):
    """Raised when token or financial budget limit would be exceeded (INV-F10-BUDGET-01)."""

    pass


class BudgetAccountingError(KarsaSecAIError):
    """Raised when an invalid or negative budget accounting mutation is attempted (INV-F10-BUDGET-03)."""

    pass


class AIRequestStateConflictError(KarsaSecAIError):
    """Raised when a conditional SQL state transition fails due to concurrent mutation (INV-F10-STATE-07)."""

    pass


class InvalidAIRequestStateTransitionError(KarsaSecAIError):
    """Raised when an invalid state transition is requested in the AI request lifecycle (INV-F10-STATE-06)."""

    pass


class AIRequestNotFoundError(KarsaSecAIError):
    """Raised when an AI request is not found in the database."""

    pass


class AIRequestAlreadyExistsError(KarsaSecAIError):
    """Raised when an AI request with the same request_id already exists."""

    pass


class AIRequestIdempotencyConflictError(KarsaSecAIError):
    """Raised when a request retry with the same request_id has mismatched payload metadata (INV-F10-IDEMPOTENCY-05)."""

    pass


# ─── Phase 3: Router Exceptions ───────────────────────────────────────────────


class ProviderRoutingError(KarsaSecAIError):
    """Base class for provider routing and selection failures (Sprint F10 Phase 3)."""

    pass
