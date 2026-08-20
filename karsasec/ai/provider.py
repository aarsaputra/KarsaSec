"""Sprint F10 Phase 3 — AI Provider Descriptor Contract (INV-F10-ROUTER-01, INV-F10-ROUTER-06).

Defines the authoritative, immutable descriptor for a registered AI provider/model combination.
All financial values are stored as non-negative integers (micro-units: $1.00 = 1,000,000).
No API keys, bearer tokens, or credentials are permitted in this object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


# ─── Canonical Provider Health States ─────────────────────────────────────────
# Routing rules:
#   HEALTHY:     Always eligible for routing.
#   DEGRADED:    Eligible only when the active RoutingPolicy allows degraded providers.
#   UNAVAILABLE: Always rejected — fail-closed.
#   UNKNOWN:     Always rejected — fail-closed (INV-F10-ROUTER-05).

HEALTH_HEALTHY: Final[str] = "HEALTHY"
HEALTH_DEGRADED: Final[str] = "DEGRADED"
HEALTH_UNAVAILABLE: Final[str] = "UNAVAILABLE"
HEALTH_UNKNOWN: Final[str] = "UNKNOWN"

ELIGIBLE_HEALTH_STATES: Final[frozenset[str]] = frozenset({HEALTH_HEALTHY, HEALTH_DEGRADED})
KNOWN_HEALTH_STATES: Final[frozenset[str]] = frozenset({HEALTH_HEALTHY, HEALTH_DEGRADED, HEALTH_UNAVAILABLE})


# ─── Bounded Attempt Error Taxonomy ───────────────────────────────────────────
# Error strings stored in AIProviderAttemptModel.error_class.
# Never store raw exception payloads, API responses, or credential hints.

ATTEMPT_ERROR_TIMEOUT: Final[str] = "TIMEOUT"
ATTEMPT_ERROR_RATE_LIMIT: Final[str] = "RATE_LIMIT"
ATTEMPT_ERROR_AUTH_FAILED: Final[str] = "AUTHENTICATION_FAILED"
ATTEMPT_ERROR_UNAVAILABLE: Final[str] = "PROVIDER_UNAVAILABLE"
ATTEMPT_ERROR_INVALID_REQUEST: Final[str] = "INVALID_REQUEST"
ATTEMPT_ERROR_NETWORK: Final[str] = "NETWORK_ERROR"
ATTEMPT_ERROR_UNKNOWN: Final[str] = "UNKNOWN_PROVIDER_ERROR"

KNOWN_ERROR_CLASSES: Final[frozenset[str]] = frozenset(
    {
        ATTEMPT_ERROR_TIMEOUT,
        ATTEMPT_ERROR_RATE_LIMIT,
        ATTEMPT_ERROR_AUTH_FAILED,
        ATTEMPT_ERROR_UNAVAILABLE,
        ATTEMPT_ERROR_INVALID_REQUEST,
        ATTEMPT_ERROR_NETWORK,
        ATTEMPT_ERROR_UNKNOWN,
    }
)


# ─── ProviderDescriptor ────────────────────────────────────────────────────────


@dataclass(frozen=True, order=False)
class ProviderDescriptor:
    """Immutable, database-free descriptor for a registered AI provider/model combination.

    Ordering & tie-breaking are performed externally by the router (not via Python comparison).

    Constraints:
    - provider_id and model_id must be non-empty strings.
    - input_price_micro_units and output_price_micro_units must be non-negative integers.
    - priority must be a non-negative integer (lower value = higher priority in the router).
    - health must be one of KNOWN_HEALTH_STATES.
    - No API keys or raw credentials may be embedded in any field.
    """

    provider_id: str
    model_id: str
    capabilities: frozenset[str]
    priority: int
    input_price_micro_units: int
    output_price_micro_units: int
    health: str = HEALTH_HEALTHY

    def __post_init__(self) -> None:
        if not self.provider_id or not self.provider_id.strip():
            raise ValueError("provider_id must be a non-empty string.")
        if not self.model_id or not self.model_id.strip():
            raise ValueError("model_id must be a non-empty string.")
        if not isinstance(self.capabilities, frozenset):
            raise TypeError("capabilities must be a frozenset.")
        if self.priority < 0:
            raise ValueError(f"priority must be non-negative (got {self.priority}).")
        if self.input_price_micro_units < 0:
            raise ValueError(f"input_price_micro_units must be non-negative (got {self.input_price_micro_units}).")
        if self.output_price_micro_units < 0:
            raise ValueError(f"output_price_micro_units must be non-negative (got {self.output_price_micro_units}).")
        if self.health not in KNOWN_HEALTH_STATES:
            raise ValueError(
                f"health must be one of {sorted(KNOWN_HEALTH_STATES)} (got '{self.health}'). "
                f"UNKNOWN health is not a valid descriptor state — use HEALTH_UNAVAILABLE."
            )

    @property
    def sort_key(self) -> tuple[int, str, str]:
        """Deterministic sort key for provider selection: (priority ASC, provider_id ASC, model_id ASC).

        Lower priority value = higher selection preference.
        Stable lexical tie-breaking on provider_id, then model_id (INV-F10-ROUTER-07).
        """
        return (self.priority, self.provider_id, self.model_id)
