"""Sprint F10 Phase 2 — AI Request State Machine (INV-F10-STATE-06).

Defines valid AI request states, allowed transitions, and validation rules.
"""

from typing import Final
from karsasec.ai.exceptions import InvalidAIRequestStateTransitionError

# Valid AI Request states
STATE_CREATED: Final[str] = "CREATED"
STATE_RESERVED: Final[str] = "RESERVED"
STATE_ROUTED: Final[str] = "ROUTED"
STATE_IN_FLIGHT: Final[str] = "IN_FLIGHT"
STATE_PROVIDER_FAILED: Final[str] = "PROVIDER_FAILED"
STATE_COMPLETED: Final[str] = "COMPLETED"
STATE_FAILED: Final[str] = "FAILED"
STATE_CANCELLED: Final[str] = "CANCELLED"

ALL_STATES: Final[set[str]] = {
    STATE_CREATED,
    STATE_RESERVED,
    STATE_ROUTED,
    STATE_IN_FLIGHT,
    STATE_PROVIDER_FAILED,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_CANCELLED,
}

TERMINAL_STATES: Final[set[str]] = {
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_CANCELLED,
}

ALLOWED_TRANSITIONS: Final[dict[str, set[str]]] = {
    STATE_CREATED: {STATE_RESERVED, STATE_CANCELLED, STATE_FAILED},
    STATE_RESERVED: {STATE_ROUTED, STATE_CANCELLED, STATE_FAILED},
    STATE_ROUTED: {STATE_IN_FLIGHT, STATE_PROVIDER_FAILED, STATE_FAILED, STATE_CANCELLED},
    STATE_IN_FLIGHT: {STATE_COMPLETED, STATE_PROVIDER_FAILED, STATE_FAILED, STATE_CANCELLED},
    STATE_PROVIDER_FAILED: {STATE_ROUTED, STATE_FAILED, STATE_CANCELLED},
    STATE_COMPLETED: set(),
    STATE_FAILED: set(),
    STATE_CANCELLED: set(),
}


def is_terminal_state(status: str) -> bool:
    """Returns True if the given status is a terminal state."""
    return status in TERMINAL_STATES


def validate_state_transition(current_status: str, new_status: str) -> None:
    """Validates that a transition from current_status to new_status is allowed.

    Raises:
        InvalidAIRequestStateTransitionError: If the transition is invalid or status is unknown.
    """
    if current_status not in ALL_STATES:
        raise InvalidAIRequestStateTransitionError(f"Unknown current status '{current_status}'.")
    if new_status not in ALL_STATES:
        raise InvalidAIRequestStateTransitionError(f"Unknown new target status '{new_status}'.")

    if current_status == new_status:
        # Self-transitions are not allowed
        raise InvalidAIRequestStateTransitionError(
            f"Invalid self-transition from '{current_status}' to '{new_status}'."
        )

    allowed_targets = ALLOWED_TRANSITIONS.get(current_status, set())
    if new_status not in allowed_targets:
        raise InvalidAIRequestStateTransitionError(
            f"Invalid state transition from '{current_status}' to '{new_status}'. Allowed targets: {sorted(allowed_targets)}"
        )
