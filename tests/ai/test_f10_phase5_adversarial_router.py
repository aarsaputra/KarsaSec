"""Sprint F10 Phase 5 — Adversarial Cost Router & Provider Selection Test Suite (INV-F10-ROUTER-01 through INV-F10-ROUTER-10)."""

import pytest

from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import HEALTH_HEALTHY, HEALTH_UNAVAILABLE, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import NoEligibleProviderError, ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy


def create_mock_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(
        ProviderDescriptor(
            provider_id="openai",
            model_id="gpt-4o",
            capabilities=frozenset({"CODE_REMEDIATION"}),
            priority=1,
            input_price_micro_units=5000,
            output_price_micro_units=15000,
        )
    )
    registry.register(
        ProviderDescriptor(
            provider_id="anthropic",
            model_id="claude-3-5",
            capabilities=frozenset({"CODE_REMEDIATION"}),
            priority=2,
            input_price_micro_units=3000,
            output_price_micro_units=12000,
        )
    )
    registry.register(
        ProviderDescriptor(
            provider_id="ollama",
            model_id="llama3",
            capabilities=frozenset({"CODE_REMEDIATION"}),
            priority=3,
            input_price_micro_units=0,
            output_price_micro_units=0,
        )
    )
    return registry


def create_healthy_registry(registry: ProviderRegistry) -> ProviderHealthRegistry:
    health = ProviderHealthRegistry()
    for p in registry.list_all():
        health.register(p.provider_id, p.model_id, HEALTH_HEALTHY)
    return health


def test_registry_order_invariance():
    """INV-F10-ROUTER-07: Permuted registry registration order MUST yield identical selection given same policy."""
    p1 = ProviderDescriptor(
        provider_id="p1",
        model_id="m1",
        capabilities=frozenset({"CODE_REMEDIATION"}),
        priority=1,
        input_price_micro_units=100,
        output_price_micro_units=200,
    )
    p2 = ProviderDescriptor(
        provider_id="p2",
        model_id="m2",
        capabilities=frozenset({"CODE_REMEDIATION"}),
        priority=2,
        input_price_micro_units=100,
        output_price_micro_units=200,
    )
    p3 = ProviderDescriptor(
        provider_id="p3",
        model_id="m3",
        capabilities=frozenset({"CODE_REMEDIATION"}),
        priority=3,
        input_price_micro_units=100,
        output_price_micro_units=200,
    )

    policy = RoutingPolicy(
        required_capabilities=frozenset({"CODE_REMEDIATION"}), estimated_input_tokens=100, estimated_output_tokens=100
    )

    # Order 1: p1, p2, p3
    r1 = ProviderRegistry()
    r1.register(p1)
    r1.register(p2)
    r1.register(p3)
    h1 = ProviderHealthRegistry()
    h1.register("p1", "m1", HEALTH_HEALTHY)
    h1.register("p2", "m2", HEALTH_HEALTHY)
    h1.register("p3", "m3", HEALTH_HEALTHY)

    sel1 = ProviderRouter(r1, h1).select_provider(policy)

    # Order 2: p3, p2, p1
    r2 = ProviderRegistry()
    r2.register(p3)
    r2.register(p2)
    r2.register(p1)
    h2 = ProviderHealthRegistry()
    h2.register("p1", "m1", HEALTH_HEALTHY)
    h2.register("p2", "m2", HEALTH_HEALTHY)
    h2.register("p3", "m3", HEALTH_HEALTHY)

    sel2 = ProviderRouter(r2, h2).select_provider(policy)

    # Order 3: p2, p1, p3
    r3 = ProviderRegistry()
    r3.register(p2)
    r3.register(p1)
    r3.register(p3)
    h3 = ProviderHealthRegistry()
    h3.register("p1", "m1", HEALTH_HEALTHY)
    h3.register("p2", "m2", HEALTH_HEALTHY)
    h3.register("p3", "m3", HEALTH_HEALTHY)

    sel3 = ProviderRouter(r3, h3).select_provider(policy)

    assert sel1.descriptor.provider_id == sel2.descriptor.provider_id == sel3.descriptor.provider_id == "p1"


def test_failover_sequence_excludes_failed_providers():
    """Sequential failure excludes attempted providers until exhausted -> NoEligibleProviderError."""
    registry = create_mock_registry()
    health = create_healthy_registry(registry)
    router = ProviderRouter(registry, health)
    policy = RoutingPolicy(
        required_capabilities=frozenset({"CODE_REMEDIATION"}), estimated_input_tokens=100, estimated_output_tokens=100
    )

    # Pass 1 -> openai (attempt 1)
    sel1 = router.select_provider(policy)
    assert sel1.descriptor.provider_id == "openai"
    assert sel1.attempt_number == 1

    # Pass 2 -> anthropic (attempt 2, exclude openai)
    sel2 = router.select_provider(policy, excluded=frozenset({("openai", "gpt-4o")}))
    assert sel2.descriptor.provider_id == "anthropic"
    assert sel2.attempt_number == 2

    # Pass 3 -> ollama (attempt 3, exclude openai & anthropic)
    sel3 = router.select_provider(policy, excluded=frozenset({("openai", "gpt-4o"), ("anthropic", "claude-3-5")}))
    assert sel3.descriptor.provider_id == "ollama"
    assert sel3.attempt_number == 3

    # Pass 4 -> Exclude all -> NoEligibleProviderError
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(
            policy, excluded=frozenset({("openai", "gpt-4o"), ("anthropic", "claude-3-5"), ("ollama", "llama3")})
        )


def test_unhealthy_and_unknown_providers_are_bypassed():
    """INV-F10-ROUTER-05: UNKNOWN and UNAVAILABLE health states are fail-closed excluded."""
    registry = create_mock_registry()
    health = ProviderHealthRegistry()
    health.register("openai", "gpt-4o", HEALTH_UNAVAILABLE)
    # anthropic is HEALTH_UNKNOWN (never registered)
    health.register("ollama", "llama3", HEALTH_HEALTHY)

    router = ProviderRouter(registry, health)
    policy = RoutingPolicy(
        required_capabilities=frozenset({"CODE_REMEDIATION"}), estimated_input_tokens=100, estimated_output_tokens=100
    )

    sel = router.select_provider(policy)
    assert sel.descriptor.provider_id == "ollama"


def test_cost_ceiling_filters_expensive_providers():
    """INV-F10-ROUTER-03: Cost ceiling filter excludes providers exceeding max_request_cost_micro_units."""
    registry = create_mock_registry()
    health = create_healthy_registry(registry)
    router = ProviderRouter(registry, health)

    # Cost ceiling = 0 micro-units -> only ollama (0 micro-units) qualifies
    policy = RoutingPolicy(
        required_capabilities=frozenset({"CODE_REMEDIATION"}),
        estimated_input_tokens=1000,
        estimated_output_tokens=1000,
        max_request_cost_micro_units=0,
    )
    sel = router.select_provider(policy)
    assert sel.descriptor.provider_id == "ollama"
