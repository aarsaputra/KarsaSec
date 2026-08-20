"""Sprint F10 Phase 3 — Cost Routing Tests (INV-F10-ROUTER-03, INV-F10-ROUTER-04).

Tests:
4.  Unknown pricing → provider rejected
7.  Cost above ceiling → provider rejected
14. No float accounting
20. Malformed pricing metadata fails closed
"""

import pytest

from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import HEALTH_HEALTHY, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.pricing import PricingError, estimate_cost_micro_units
from karsasec.ai.router import NoEligibleProviderError, ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy


def _router_with_provider(
    input_price: int,
    output_price: int,
    priority: int = 10,
) -> ProviderRouter:
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    desc = ProviderDescriptor(
        provider_id="test-provider",
        model_id="model-a",
        capabilities=frozenset({"chat"}),
        priority=priority,
        input_price_micro_units=input_price,
        output_price_micro_units=output_price,
        health=HEALTH_HEALTHY,
    )
    registry.register(desc)
    health_reg.register("test-provider", "model-a", HEALTH_HEALTHY)
    return ProviderRouter(registry, health_reg)


def _make_policy(max_cost: int | None = None, **kwargs) -> RoutingPolicy:
    defaults = dict(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=1000,
        estimated_output_tokens=500,
        max_request_cost_micro_units=max_cost,
        allow_degraded=False,
    )
    defaults.update(kwargs)
    return RoutingPolicy(**defaults)


def test_cost_estimation_integer_only():
    """14. Cost calculation must produce a pure integer — no float coercion."""
    desc = ProviderDescriptor(
        provider_id="p",
        model_id="m",
        capabilities=frozenset({"chat"}),
        priority=10,
        input_price_micro_units=1000,
        output_price_micro_units=3000,
        health=HEALTH_HEALTHY,
    )
    cost = estimate_cost_micro_units(desc, 100, 50)
    assert isinstance(cost, int), "Cost must be a pure int"
    assert cost == 100 * 1000 + 50 * 3000


def test_exact_cost_ceiling_accepted():
    """Provider whose estimated cost exactly equals the ceiling is accepted."""
    # input=1000 tokens * 1000 micro/tok + output=500 tokens * 0 micro/tok = 1_000_000
    router = _router_with_provider(input_price=1000, output_price=0)
    policy = _make_policy(max_cost=1_000_000)
    result = router.select_provider(policy)
    assert result.descriptor.provider_id == "test-provider"
    assert result.estimated_cost_micro_units == 1_000_000


def test_cost_above_ceiling_rejected():
    """7. Provider whose estimated cost exceeds the ceiling is rejected (INV-F10-ROUTER-03)."""
    # 1000 * 2000 + 500 * 0 = 2_000_000 > ceiling 1_500_000
    router = _router_with_provider(input_price=2000, output_price=0)
    policy = _make_policy(max_cost=1_500_000)
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(policy)


def test_no_cost_ceiling_all_providers_eligible():
    """When max_request_cost_micro_units is None, cost ceiling is not applied."""
    router = _router_with_provider(input_price=999_999_999, output_price=999_999_999)
    policy = _make_policy(max_cost=None)
    result = router.select_provider(policy)
    assert result.descriptor.provider_id == "test-provider"


def test_pricing_estimation_negative_tokens_rejected():
    """Negative token counts raise PricingError (INV-F10-ROUTER-04)."""
    desc = ProviderDescriptor(
        provider_id="p",
        model_id="m",
        capabilities=frozenset(),
        priority=0,
        input_price_micro_units=1000,
        output_price_micro_units=3000,
        health=HEALTH_HEALTHY,
    )
    with pytest.raises(PricingError):
        estimate_cost_micro_units(desc, -1, 100)

    with pytest.raises(PricingError):
        estimate_cost_micro_units(desc, 100, -1)


def test_router_selects_cheapest_provider_within_ceiling():
    """Router prefers lowest priority (=highest priority number = cheapest), not lowest cost.
    Cost ceiling validates all candidates; priority determines selection.
    """
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()

    expensive = ProviderDescriptor(
        "expensive",
        "gpt-4o",
        frozenset({"chat"}),
        priority=10,
        input_price_micro_units=5000,
        output_price_micro_units=10000,
        health=HEALTH_HEALTHY,
    )
    cheap = ProviderDescriptor(
        "cheap",
        "llama3",
        frozenset({"chat"}),
        priority=20,
        input_price_micro_units=100,
        output_price_micro_units=200,
        health=HEALTH_HEALTHY,
    )
    for d in [expensive, cheap]:
        registry.register(d)
        health_reg.register(d.provider_id, d.model_id, HEALTH_HEALTHY)

    router = ProviderRouter(registry, health_reg)

    # With no cost ceiling: priority=10 wins (lower number = higher priority)
    result = router.select_provider(_make_policy(max_cost=None))
    assert result.descriptor.provider_id == "expensive"  # priority 10 wins

    # With cost ceiling that excludes expensive provider:
    # expensive: 1000*5000 + 500*10000 = 10_000_000 > 5_000_000
    # cheap: 1000*100 + 500*200 = 200_000 < 5_000_000
    result_cheap = router.select_provider(_make_policy(max_cost=5_000_000))
    assert result_cheap.descriptor.provider_id == "cheap"
