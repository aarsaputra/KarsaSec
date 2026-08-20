"""Sprint F10 Phase 3 — Integer-Only Cost Estimation Engine (INV-F10-ROUTER-03, INV-F10-ROUTER-04).

All cost calculations use integer micro-units exclusively.
$1.00 = 1,000,000 micro-units.
No float arithmetic is ever used in cost accounting.

Fail-closed contract (INV-F10-ROUTER-04):
  Unknown or missing pricing (price = None or < 0) always rejects the provider.
  Never silently assume zero pricing.
"""

from __future__ import annotations


from karsasec.ai.exceptions import KarsaSecAIError
from karsasec.ai.provider import ProviderDescriptor


class PricingError(KarsaSecAIError):
    """Raised when pricing data is missing, malformed, or fails a pricing check."""

    pass


def estimate_cost_micro_units(
    descriptor: ProviderDescriptor,
    estimated_input_tokens: int,
    estimated_output_tokens: int,
) -> int:
    """Calculates estimated cost as a strict integer micro-unit value (INV-F10-ROUTER-03).

    Formula (integer-only):
        estimated_cost = estimated_input_tokens * input_price_micro_units
                       + estimated_output_tokens * output_price_micro_units

    Fail-closed rules:
    - estimated_input_tokens or estimated_output_tokens < 0 raises PricingError.
    - input_price_micro_units or output_price_micro_units < 0 on the descriptor raises PricingError.
      (descriptor validation already enforces non-negative prices, but this is re-asserted here.)

    Returns:
        int: Total estimated cost in integer micro-units.

    Raises:
        PricingError: If inputs are invalid or pricing metadata is absent/invalid.
    """
    if estimated_input_tokens < 0:
        raise PricingError(f"estimated_input_tokens must be non-negative (got {estimated_input_tokens}).")
    if estimated_output_tokens < 0:
        raise PricingError(f"estimated_output_tokens must be non-negative (got {estimated_output_tokens}).")
    # Re-assert pricing sanity (descriptor constructor enforces, but belt-and-suspenders)
    if descriptor.input_price_micro_units < 0 or descriptor.output_price_micro_units < 0:
        raise PricingError(
            f"Provider '{descriptor.provider_id}/{descriptor.model_id}' has invalid pricing metadata. "
            f"Rejecting (INV-F10-ROUTER-04)."
        )

    cost = (
        estimated_input_tokens * descriptor.input_price_micro_units
        + estimated_output_tokens * descriptor.output_price_micro_units
    )
    # Sanity: result must be a pure int — assert no float coercion
    if not isinstance(cost, int):
        raise PricingError(
            f"Cost calculation produced a non-integer result for provider "
            f"'{descriptor.provider_id}/{descriptor.model_id}'. Float pricing is prohibited."
        )
    return cost


def is_within_cost_ceiling(
    descriptor: ProviderDescriptor,
    estimated_input_tokens: int,
    estimated_output_tokens: int,
    max_request_cost_micro_units: int,
) -> tuple[bool, int]:
    """Determines whether a provider's estimated cost is within the allowed ceiling.

    Args:
        descriptor: ProviderDescriptor with pricing.
        estimated_input_tokens: Estimated prompt token count.
        estimated_output_tokens: Estimated completion token count.
        max_request_cost_micro_units: Maximum allowed cost in micro-units.

    Returns:
        Tuple (eligible: bool, estimated_cost: int).
        If eligible is False, provider must be rejected.

    Raises:
        PricingError: If cost estimation fails due to invalid inputs.
    """
    estimated = estimate_cost_micro_units(descriptor, estimated_input_tokens, estimated_output_tokens)
    return estimated <= max_request_cost_micro_units, estimated
