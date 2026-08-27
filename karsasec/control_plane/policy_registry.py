"""Centralized Policy Registry for Security Control Plane."""

from __future__ import annotations

from collections.abc import Sequence
from karsasec.control_plane.models import PolicyVersion


class PolicyRegistry:
    """Thread-safe, append-only registry storing registered policy versions."""

    def __init__(self) -> None:
        self._policies: dict[str, PolicyVersion] = {}

    def register(self, policy: PolicyVersion) -> str:
        """Registers a new PolicyVersion in the control plane."""
        if not policy.policy_id:
            raise ValueError("PolicyVersion must have a valid policy_id")
        self._policies[policy.policy_id] = policy
        return policy.policy_id

    def get(self, policy_id: str) -> PolicyVersion | None:
        """Retrieves a policy by ID."""
        return self._policies.get(policy_id)

    def list_all(self) -> Sequence[PolicyVersion]:
        """Returns all registered policies sorted by policy_id."""
        return tuple(sorted(self._policies.values(), key=lambda p: p.policy_id))
