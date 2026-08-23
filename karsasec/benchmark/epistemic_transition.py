"""Epistemic Transition Validator (INV-G5.4-05).

Enforces Epistemic Monotonicity, preventing conversion of UNKNOWN/CONFLICT states into
SAFE/VULNERABLE without explicit, independently validated evidence.
"""

from typing import Any


FORBIDDEN_UNSUPPORTED_TRANSITIONS = {
    ("UNKNOWN", "SAFE"),
    ("UNKNOWN", "VULNERABLE"),
    ("CONFLICT", "SAFE"),
    ("CONFLICT", "VULNERABLE"),
}


def validate_epistemic_transition(
    before: str, after: str, evidence: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Validates epistemic decision transitions.

    Forbidden unless explicit, independently validated evidence is provided:
    UNKNOWN -> SAFE
    UNKNOWN -> VULNERABLE
    CONFLICT -> SAFE
    CONFLICT -> VULNERABLE
    """
    pair = (before.upper(), after.upper())

    if pair in FORBIDDEN_UNSUPPORTED_TRANSITIONS:
        if evidence is None or not evidence.get("validated", False):
            return {
                "status": "INVALID_TRANSITION",
                "valid": False,
                "transition": f"{before} -> {after}",
                "rationale": f"Epistemic transition '{before} -> {after}' requires explicit validated evidence.",
            }

    return {
        "status": "PASS",
        "valid": True,
        "transition": f"{before} -> {after}",
        "rationale": f"Valid transition '{before} -> {after}'.",
    }
