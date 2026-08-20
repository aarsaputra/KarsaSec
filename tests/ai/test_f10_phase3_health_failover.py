"""Sprint F10 Phase 3 — Health & Failover Tests (INV-F10-ROUTER-02, INV-F10-ROUTER-05, INV-F10-ROUTER-10).

Tests:
5.  Unknown health → provider rejected
6.  UNAVAILABLE provider → provider rejected
9.  Primary provider failure → deterministic fallback
10. Repeated failover → identical ordering
8.  Capability mismatch → provider rejected
"""

import pytest

from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import (
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_UNAVAILABLE,
    ProviderDescriptor,
)
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import NoEligibleProviderError, ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy


def _make_policy(**kwargs) -> RoutingPolicy:
    defaults = dict(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=1000,
        estimated_output_tokens=500,
        max_request_cost_micro_units=100_000_000,
        allow_degraded=False,
    )
    defaults.update(kwargs)
    return RoutingPolicy(**defaults)


def _build_router(descriptors: list[ProviderDescriptor], health_map: dict[tuple[str, str], str]) -> ProviderRouter:
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    for desc in descriptors:
        registry.register(desc)
    for (pid, mid), h in health_map.items():
        health_reg.register(pid, mid, h)
    return ProviderRouter(registry, health_reg)


def test_unknown_health_rejected():
    """5. Provider with UNKNOWN health is always rejected (fail-closed, INV-F10-ROUTER-05)."""
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()  # No health registered
    desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    registry.register(desc)
    # Intentionally NOT registering health → ProviderHealthRegistry returns HEALTH_UNKNOWN

    router = ProviderRouter(registry, health_reg)
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy())


def test_unavailable_provider_rejected():
    """6. UNAVAILABLE provider is always rejected (INV-F10-ROUTER-05)."""
    desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    router = _build_router([desc], {("openai", "gpt-4o"): HEALTH_UNAVAILABLE})
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy())


def test_degraded_rejected_when_policy_disallows():
    """DEGRADED provider is rejected when allow_degraded=False (default)."""
    desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    router = _build_router([desc], {("openai", "gpt-4o"): HEALTH_DEGRADED})
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy(allow_degraded=False))


def test_degraded_eligible_when_policy_allows():
    """DEGRADED provider is eligible when allow_degraded=True."""
    desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    router = _build_router([desc], {("openai", "gpt-4o"): HEALTH_DEGRADED})
    result = router.select_provider(_make_policy(allow_degraded=True))
    assert result.descriptor.provider_id == "openai"


def test_capability_mismatch_rejected():
    """8. Provider without required capability is rejected (INV-F10-ROUTER-06)."""
    desc = ProviderDescriptor(
        "embeddings-only",
        "embed-v3",
        frozenset({"embeddings"}),
        priority=5,
        input_price_micro_units=100,
        output_price_micro_units=0,
        health=HEALTH_HEALTHY,
    )
    router = _build_router([desc], {("embeddings-only", "embed-v3"): HEALTH_HEALTHY})
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy(required_capabilities=frozenset({"chat"})))


def test_primary_failure_deterministic_fallback():
    """9. Primary provider failure → deterministic fallback to next eligible provider."""
    providers = [
        ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY),
        ProviderDescriptor("anthropic", "claude-3-5", frozenset({"chat"}), 20, 800, 2500, HEALTH_HEALTHY),
    ]
    health_map = {
        ("openai", "gpt-4o"): HEALTH_HEALTHY,
        ("anthropic", "claude-3-5"): HEALTH_HEALTHY,
    }
    router = _build_router(providers, health_map)
    policy = _make_policy()

    # First pass: openai selected
    result1 = router.select_provider(policy)
    assert result1.descriptor.provider_id == "openai"
    assert result1.attempt_number == 1

    # Simulate failure → exclude openai, route to next
    excluded = frozenset({("openai", "gpt-4o")})
    result2 = router.select_provider(policy, excluded=excluded)
    assert result2.descriptor.provider_id == "anthropic"
    assert result2.attempt_number == 2


def test_repeated_failover_identical_ordering():
    """10. Repeated failover must produce the exact same fallback sequence (INV-F10-ROUTER-02)."""
    providers = [
        ProviderDescriptor("z-provider", "model-a", frozenset({"chat"}), 30, 100, 200, HEALTH_HEALTHY),
        ProviderDescriptor("a-provider", "model-b", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY),
        ProviderDescriptor("m-provider", "model-c", frozenset({"chat"}), 20, 500, 1000, HEALTH_HEALTHY),
    ]
    health_map = {(p.provider_id, p.model_id): HEALTH_HEALTHY for p in providers}
    router = _build_router(providers, health_map)
    policy = _make_policy()

    def run_failover_sequence():
        excluded = frozenset()
        sequence = []
        for _ in range(3):
            try:
                r = router.select_provider(policy, excluded=excluded)
                sequence.append((r.descriptor.provider_id, r.attempt_number))
                excluded = excluded | {(r.descriptor.provider_id, r.descriptor.model_id)}
            except NoEligibleProviderError:
                break
        return sequence

    seq1 = run_failover_sequence()
    seq2 = run_failover_sequence()
    seq3 = run_failover_sequence()

    assert seq1 == seq2 == seq3, "Failover sequence must be deterministic across all runs"
    # First should be "a-provider" (priority=10), then "m-provider" (20), then "z-provider" (30)
    assert seq1[0][0] == "a-provider"
    assert seq1[1][0] == "m-provider"
    assert seq1[2][0] == "z-provider"


def test_all_excluded_fails_closed():
    """Excluding all providers results in NoEligibleProviderError (fail-closed)."""
    desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    router = _build_router([desc], {("openai", "gpt-4o"): HEALTH_HEALTHY})
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy(), excluded=frozenset({("openai", "gpt-4o")}))
