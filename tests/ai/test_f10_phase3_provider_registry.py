"""Sprint F10 Phase 3 — Provider Registry Tests (INV-F10-ROUTER-01)."""

import pytest

from karsasec.ai.provider import HEALTH_HEALTHY, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry, ProviderRegistryConflictError


def _make_desc(provider_id: str, model_id: str = "model-a", priority: int = 10) -> ProviderDescriptor:
    return ProviderDescriptor(
        provider_id=provider_id,
        model_id=model_id,
        capabilities=frozenset({"chat", "code"}),
        priority=priority,
        input_price_micro_units=1000,
        output_price_micro_units=3000,
        health=HEALTH_HEALTHY,
    )


def test_register_and_get_provider():
    registry = ProviderRegistry()
    desc = _make_desc("openai")
    registry.register(desc)
    result = registry.get_provider("openai", "model-a")
    assert result == desc


def test_get_unregistered_returns_none():
    """Unregistered provider always returns None (router fails closed)."""
    registry = ProviderRegistry()
    assert registry.get_provider("ghost-provider", "ghost-model") is None


def test_idempotent_registration_same_metadata():
    """Re-registering the exact same descriptor is a no-op."""
    registry = ProviderRegistry()
    desc = _make_desc("openai")
    registry.register(desc)
    registry.register(desc)  # Must not raise
    assert len(registry) == 1


def test_conflict_on_metadata_mismatch():
    """Re-registering with conflicting metadata raises ProviderRegistryConflictError."""
    registry = ProviderRegistry()
    registry.register(_make_desc("openai"))
    conflicting = ProviderDescriptor(
        provider_id="openai",
        model_id="model-a",
        capabilities=frozenset({"chat"}),
        priority=99,  # Different priority
        input_price_micro_units=1000,
        output_price_micro_units=3000,
        health=HEALTH_HEALTHY,
    )
    with pytest.raises(ProviderRegistryConflictError):
        registry.register(conflicting)


def test_list_all_stable_lexical_order():
    """list_all() returns providers in stable lexical order by (provider_id, model_id)."""
    registry = ProviderRegistry()
    registry.register(_make_desc("openai", "gpt-4o"))
    registry.register(_make_desc("anthropic", "claude-3-5"))
    registry.register(_make_desc("ollama", "llama3"))
    registry.register(_make_desc("openai", "gpt-4-turbo"))

    all_providers = registry.list_all()
    ids = [(p.provider_id, p.model_id) for p in all_providers]
    assert ids == sorted(ids), "list_all() must return providers in stable (provider_id, model_id) order"


def test_list_all_independent_of_registration_order():
    """Providers registered in any order must always produce the same sorted list_all() result."""
    desc_a = _make_desc("openai", "gpt-4o")
    desc_b = _make_desc("anthropic", "claude-3-5")
    desc_c = _make_desc("ollama", "llama3")

    registry1 = ProviderRegistry()
    registry1.register(desc_a)
    registry1.register(desc_b)
    registry1.register(desc_c)

    registry2 = ProviderRegistry()
    registry2.register(desc_c)
    registry2.register(desc_a)
    registry2.register(desc_b)

    assert registry1.list_all() == registry2.list_all()


def test_deregister():
    registry = ProviderRegistry()
    registry.register(_make_desc("openai"))
    registry.deregister("openai", "model-a")
    assert registry.get_provider("openai", "model-a") is None
    assert len(registry) == 0


def test_list_by_capability():
    registry = ProviderRegistry()
    registry.register(
        ProviderDescriptor(
            provider_id="openai",
            model_id="gpt-4o",
            capabilities=frozenset({"chat", "code"}),
            priority=10,
            input_price_micro_units=1000,
            output_price_micro_units=3000,
            health=HEALTH_HEALTHY,
        )
    )
    registry.register(
        ProviderDescriptor(
            provider_id="embeddings-only",
            model_id="embed-v3",
            capabilities=frozenset({"embeddings"}),
            priority=5,
            input_price_micro_units=100,
            output_price_micro_units=0,
            health=HEALTH_HEALTHY,
        )
    )

    code_providers = registry.list_by_capability("code")
    assert len(code_providers) == 1
    assert code_providers[0].provider_id == "openai"

    embed_providers = registry.list_by_capability("embeddings")
    assert len(embed_providers) == 1
    assert embed_providers[0].provider_id == "embeddings-only"


def test_provider_descriptor_negative_price_rejected():
    """ProviderDescriptor rejects negative pricing at construction time."""
    with pytest.raises(ValueError):
        ProviderDescriptor(
            provider_id="bad-provider",
            model_id="model-x",
            capabilities=frozenset({"chat"}),
            priority=10,
            input_price_micro_units=-1,
            output_price_micro_units=3000,
            health=HEALTH_HEALTHY,
        )


def test_provider_descriptor_unknown_health_rejected():
    """ProviderDescriptor rejects unknown health strings (not a KNOWN_HEALTH_STATE)."""
    with pytest.raises(ValueError):
        ProviderDescriptor(
            provider_id="p",
            model_id="m",
            capabilities=frozenset(),
            priority=0,
            input_price_micro_units=0,
            output_price_micro_units=0,
            health="MAYBE",
        )
