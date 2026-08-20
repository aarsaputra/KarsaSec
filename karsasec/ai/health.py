"""Sprint F10 Phase 3 — Provider Health Registry (INV-F10-ROUTER-05).

Provides an explicit, database-backed health state registry for AI providers.

Design Authority:
  - Health state is stored as a Python in-memory dict, which is intentionally
    NOT the authoritative financial/accounting source (that is PostgreSQL via AIBudgetModel).
  - Health state is authoritative for ROUTING ELIGIBILITY only within the same process lifetime.
  - If distributed, persistent health authority is required, the health backend must be replaced
    with a PostgreSQL-backed lease or a shared KV store with explicit staleness fencing.
  - Process-local health does NOT participate in token accounting or cost commit decisions.
  - Unknown providers always fail closed (HEALTH_UNKNOWN → rejected).

INV-F10-ROUTER-05: If provider health is unknown, reject the provider.
"""

from __future__ import annotations


from karsasec.ai.provider import (
    HEALTH_HEALTHY,
    HEALTH_UNKNOWN,
    KNOWN_HEALTH_STATES,
)


class ProviderHealthRegistry:
    """Process-local provider health state store for routing eligibility decisions.

    Authority scope: ROUTING ELIGIBILITY only.
    Financial authority: PostgreSQL (AIBudgetModel) — unchanged.

    Fail-closed contract (INV-F10-ROUTER-05):
      Querying a provider_id that was never registered returns HEALTH_UNKNOWN.
      HEALTH_UNKNOWN providers are always rejected by the router.
    """

    def __init__(self) -> None:
        self._health: dict[tuple[str, str], str] = {}

    def register(self, provider_id: str, model_id: str, health: str = HEALTH_HEALTHY) -> None:
        """Register or update the health status of a provider/model combination.

        Raises:
            ValueError: If health is not a KNOWN_HEALTH_STATES value.
        """
        if health not in KNOWN_HEALTH_STATES:
            raise ValueError(f"Invalid health state '{health}'. Must be one of {sorted(KNOWN_HEALTH_STATES)}.")
        self._health[(provider_id, model_id)] = health

    def get_health(self, provider_id: str, model_id: str) -> str:
        """Returns the health state for the given provider/model.

        Returns HEALTH_UNKNOWN if the provider was never registered (fail-closed).
        """
        return self._health.get((provider_id, model_id), HEALTH_UNKNOWN)

    def is_healthy(self, provider_id: str, model_id: str) -> bool:
        """Returns True only if health is HEALTHY or DEGRADED (routable states)."""
        from karsasec.ai.provider import ELIGIBLE_HEALTH_STATES

        return self.get_health(provider_id, model_id) in ELIGIBLE_HEALTH_STATES

    def set_unavailable(self, provider_id: str, model_id: str) -> None:
        """Marks a provider/model as UNAVAILABLE (fail-closed immediately)."""
        from karsasec.ai.provider import HEALTH_UNAVAILABLE

        self._health[(provider_id, model_id)] = HEALTH_UNAVAILABLE
