"""Sprint F10 Phase 3 — Routing Policy Contract (INV-F10-ROUTER-01, INV-F10-ROUTER-06).

Defines the routing request specification for a single AI provider selection pass.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RoutingPolicy:
    """Specifies constraints and eligibility rules for a single provider routing pass.

    Attributes:
        required_capabilities: Set of capabilities the selected provider must support.
        max_request_cost_micro_units: Maximum allowed estimated cost in integer micro-units.
            If None, no cost ceiling is applied.
        allow_degraded: If True, DEGRADED providers are eligible for routing.
            If False, only HEALTHY providers are eligible.
        estimated_input_tokens: Estimated number of input/prompt tokens.
        estimated_output_tokens: Estimated number of output/completion tokens.
    """

    required_capabilities: frozenset[str]
    estimated_input_tokens: int
    estimated_output_tokens: int
    max_request_cost_micro_units: int | None = None
    allow_degraded: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.required_capabilities, frozenset):
            raise TypeError("required_capabilities must be a frozenset.")
        if self.estimated_input_tokens < 0:
            raise ValueError(f"estimated_input_tokens must be non-negative (got {self.estimated_input_tokens}).")
        if self.estimated_output_tokens < 0:
            raise ValueError(f"estimated_output_tokens must be non-negative (got {self.estimated_output_tokens}).")
        if self.max_request_cost_micro_units is not None and self.max_request_cost_micro_units < 0:
            raise ValueError(
                f"max_request_cost_micro_units must be non-negative or None (got {self.max_request_cost_micro_units})."
            )
