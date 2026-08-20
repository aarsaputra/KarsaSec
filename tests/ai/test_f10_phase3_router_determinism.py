"""Sprint F10 Phase 3 — Router Determinism Tests (INV-F10-ROUTER-01, INV-F10-ROUTER-07).

Tests:
1.  Same input -> identical provider selection
2.  Different registration order -> identical selection
3.  Equal priority -> stable provider_id/model_id tie-break
19. Empty eligible provider set fails closed
"""

import pytest

from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import HEALTH_HEALTHY, HEALTH_UNAVAILABLE, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import NoEligibleProviderError, ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy


def _register_standard(registry: ProviderRegistry, health_reg: ProviderHealthRegistry) -> None:
    providers = [
        ProviderDescriptor(
            provider_id="openai",
            model_id="gpt-4o",
            capabilities=frozenset({"chat", "code"}),
            priority=10,
            input_price_micro_units=1000,
            output_price_micro_units=3000,
            health=HEALTH_HEALTHY,
        ),
        ProviderDescriptor(
            provider_id="anthropic",
            model_id="claude-3-5",
            capabilities=frozenset({"chat", "code"}),
            priority=20,
            input_price_micro_units=800,
            output_price_micro_units=2500,
            health=HEALTH_HEALTHY,
        ),
        ProviderDescriptor(
            provider_id="ollama",
            model_id="llama3",
            capabilities=frozenset({"chat", "code"}),
            priority=30,
            input_price_micro_units=100,
            output_price_micro_units=200,
            health=HEALTH_HEALTHY,
        ),
    ]
    for p in providers:
        registry.register(p)
        health_reg.register(p.provider_id, p.model_id, HEALTH_HEALTHY)


def _make_policy(**kwargs) -> RoutingPolicy:
    defaults = dict(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=1000,
        estimated_output_tokens=500,
        max_request_cost_micro_units=50_000_000,
        allow_degraded=False,
    )
    defaults.update(kwargs)
    return RoutingPolicy(**defaults)


def test_same_input_produces_identical_selection():
    """1. Same routing policy → identical ProviderDescriptor selected every time."""
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    _register_standard(registry, health_reg)
    router = ProviderRouter(registry, health_reg)
    policy = _make_policy()

    results = [router.select_provider(policy) for _ in range(100)]
    assert all(r.descriptor.provider_id == results[0].descriptor.provider_id for r in results)
    assert all(r.descriptor.model_id == results[0].descriptor.model_id for r in results)


def test_different_registration_order_identical_selection():
    """2. Registration order must never influence selection result."""
    policy = _make_policy()

    # Forward registration order
    reg1 = ProviderRegistry()
    h1 = ProviderHealthRegistry()
    providers = [
        ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY),
        ProviderDescriptor("anthropic", "claude-3-5", frozenset({"chat"}), 20, 800, 2500, HEALTH_HEALTHY),
        ProviderDescriptor("ollama", "llama3", frozenset({"chat"}), 30, 100, 200, HEALTH_HEALTHY),
    ]
    for p in providers:
        reg1.register(p)
        h1.register(p.provider_id, p.model_id, HEALTH_HEALTHY)
    result1 = ProviderRouter(reg1, h1).select_provider(policy)

    # Reverse registration order
    reg2 = ProviderRegistry()
    h2 = ProviderHealthRegistry()
    for p in reversed(providers):
        reg2.register(p)
        h2.register(p.provider_id, p.model_id, HEALTH_HEALTHY)
    result2 = ProviderRouter(reg2, h2).select_provider(policy)

    assert result1.descriptor.provider_id == result2.descriptor.provider_id
    assert result1.descriptor.model_id == result2.descriptor.model_id


def test_equal_priority_stable_lexical_tie_break():
    """3. Equal priority → stable (provider_id, model_id) lexical tie-break."""
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    providers = [
        ProviderDescriptor("z-provider", "model-a", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY),
        ProviderDescriptor("a-provider", "model-b", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY),
        ProviderDescriptor("m-provider", "model-c", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY),
    ]
    for p in providers:
        registry.register(p)
        health_reg.register(p.provider_id, p.model_id, HEALTH_HEALTHY)

    router = ProviderRouter(registry, health_reg)
    result = router.select_provider(_make_policy())
    # Lexically first: "a-provider"
    assert result.descriptor.provider_id == "a-provider"


def test_empty_eligible_provider_set_fails_closed():
    """19. Empty eligible set → NoEligibleProviderError (never silently succeeds)."""
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    # Register a provider but mark unavailable
    p = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    registry.register(p)
    health_reg.register("openai", "gpt-4o", HEALTH_UNAVAILABLE)
    router = ProviderRouter(registry, health_reg)

    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy())


def test_no_providers_registered_fails_closed():
    """Empty registry → NoEligibleProviderError."""
    router = ProviderRouter(ProviderRegistry())
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(_make_policy())


def test_repeated_routing_100x_deterministic():
    """Routing result must be identical across 100 repeated calls (INV-F10-ROUTER-01)."""
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    _register_standard(registry, health_reg)
    router = ProviderRouter(registry, health_reg)
    policy = _make_policy()

    first = router.select_provider(policy)
    for _ in range(99):
        result = router.select_provider(policy)
        assert result.descriptor == first.descriptor
        assert result.estimated_cost_micro_units == first.estimated_cost_micro_units
