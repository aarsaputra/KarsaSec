"""Sprint F10 Phase 3 — Provider Registry (INV-F10-ROUTER-01).

Central registry for AI provider descriptors.
Providers are registered by (provider_id, model_id) key.
Duplicate registration with differing metadata raises a conflict error.
Retrieval of an unregistered provider returns None (fail-closed in the router).
"""

from __future__ import annotations

from karsasec.ai.exceptions import KarsaSecAIError
from karsasec.ai.provider import ProviderDescriptor


class ProviderRegistryConflictError(KarsaSecAIError):
    """Raised when a provider/model is registered with conflicting metadata."""

    pass


class ProviderRegistry:
    """Registry of known AI provider descriptors.

    Registration rules:
    - (provider_id, model_id) must be unique.
    - Re-registering the exact same descriptor is idempotent (no-op).
    - Re-registering with conflicting metadata raises ProviderRegistryConflictError.

    Retrieval:
    - get_provider() returns None for unknown providers (router handles fail-closed behavior).
    - list_all() returns providers in stable lexical order by (provider_id, model_id).
    """

    def __init__(self) -> None:
        self._providers: dict[tuple[str, str], ProviderDescriptor] = {}

    def register(self, descriptor: ProviderDescriptor) -> None:
        """Register a provider descriptor.

        Raises:
            ProviderRegistryConflictError: If (provider_id, model_id) already exists with different metadata.
        """
        key = (descriptor.provider_id, descriptor.model_id)
        existing = self._providers.get(key)
        if existing is not None:
            if existing == descriptor:
                return  # Idempotent re-registration
            raise ProviderRegistryConflictError(
                f"Provider '{descriptor.provider_id}/{descriptor.model_id}' is already registered "
                f"with different metadata. De-register first."
            )
        self._providers[key] = descriptor

    def deregister(self, provider_id: str, model_id: str) -> None:
        """Remove a provider from the registry. No-op if not found."""
        self._providers.pop((provider_id, model_id), None)

    def get_provider(self, provider_id: str, model_id: str) -> ProviderDescriptor | None:
        """Returns the ProviderDescriptor or None if not registered."""
        return self._providers.get((provider_id, model_id))

    def list_all(self) -> list[ProviderDescriptor]:
        """Returns all registered providers in stable lexical order by (provider_id, model_id)."""
        return [self._providers[k] for k in sorted(self._providers)]

    def list_by_capability(self, capability: str) -> list[ProviderDescriptor]:
        """Returns providers supporting the given capability, in stable lexical order."""
        return [self._providers[k] for k in sorted(self._providers) if capability in self._providers[k].capabilities]

    def __len__(self) -> int:
        return len(self._providers)
