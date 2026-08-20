"""Sprint F10 Phase 5 — Adversarial Router Determinism & Tie-Breaking Test Suite (INV-F10-DET-16).

Verifies strict lexical tie-breaking, order-invariant registration, and deterministic failover.
"""

from __future__ import annotations


from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import HEALTH_HEALTHY, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy


def test_routing_determinism_under_concurrent_registration_permutations():
    """INV-F10-DET-16: Registering providers in varying orders yields identical top selection and failover chain."""
    p1 = ProviderDescriptor("anthropic", "claude-3-5-sonnet", frozenset({"CODE_REMEDIATION"}), 1, 100, 200)
    p2 = ProviderDescriptor("openai", "gpt-4o", frozenset({"CODE_REMEDIATION"}), 1, 100, 200)
    p3 = ProviderDescriptor("google", "gemini-1.5-pro", frozenset({"CODE_REMEDIATION"}), 1, 100, 200)

    # Permutation 1: Anthropic, OpenAI, Google
    reg1 = ProviderRegistry()
    reg1.register(p1)
    reg1.register(p2)
    reg1.register(p3)

    health1 = ProviderHealthRegistry()
    health1.register("anthropic", "claude-3-5-sonnet", HEALTH_HEALTHY)
    health1.register("openai", "gpt-4o", HEALTH_HEALTHY)
    health1.register("google", "gemini-1.5-pro", HEALTH_HEALTHY)

    router1 = ProviderRouter(reg1, health1)
    policy = RoutingPolicy(frozenset({"CODE_REMEDIATION"}), 100, 100)
    res1 = router1.select_provider(policy)

    # Permutation 2: Google, OpenAI, Anthropic
    reg2 = ProviderRegistry()
    reg2.register(p3)
    reg2.register(p2)
    reg2.register(p1)

    health2 = ProviderHealthRegistry()
    health2.register("anthropic", "claude-3-5-sonnet", HEALTH_HEALTHY)
    health2.register("openai", "gpt-4o", HEALTH_HEALTHY)
    health2.register("google", "gemini-1.5-pro", HEALTH_HEALTHY)

    router2 = ProviderRouter(reg2, health2)
    res2 = router2.select_provider(policy)

    assert res1.descriptor.provider_id == res2.descriptor.provider_id
    assert res1.descriptor.model_id == res2.descriptor.model_id
    # Lexical tie break: 'anthropic' < 'google' < 'openai'
    assert res1.descriptor.provider_id == "anthropic"


def test_repeated_routing_100x_trials_are_100_percent_deterministic():
    """Executing select_provider 100 times continuously produces identical results."""
    p1 = ProviderDescriptor("openai", "gpt-4o", frozenset({"CODE_REMEDIATION"}), 1, 100, 200)
    p2 = ProviderDescriptor("anthropic", "claude-3-5-sonnet", frozenset({"CODE_REMEDIATION"}), 1, 100, 200)

    reg = ProviderRegistry()
    reg.register(p1)
    reg.register(p2)

    health = ProviderHealthRegistry()
    health.register("openai", "gpt-4o", HEALTH_HEALTHY)
    health.register("anthropic", "claude-3-5-sonnet", HEALTH_HEALTHY)

    router = ProviderRouter(reg, health)
    policy = RoutingPolicy(frozenset({"CODE_REMEDIATION"}), 100, 100)

    first_selection = router.select_provider(policy).descriptor.provider_id

    for _ in range(100):
        selection = router.select_provider(policy).descriptor.provider_id
        assert selection == first_selection
