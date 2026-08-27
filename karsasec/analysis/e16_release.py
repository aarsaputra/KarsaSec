"""Monotonic Release State Machine for Sprint E16."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from karsasec.analysis.e16_models import AdmissionStatus, ReleaseState

if TYPE_CHECKING:
    from karsasec.analysis.e16_models import ReleaseAdmission


class IllegalStateTransitionError(ValueError):
    """Raised when an illegal release state transition is attempted."""


class ReleaseStateMachine:
    """Monotonic Release State Machine.

    Lifecycle:
    CREATED -> SECURITY_EVALUATED -> (APPROVED | REVIEW_REQUIRED | BLOCKED | UNKNOWN)

    Guarantees:
    - Reject direct transition from BLOCKED -> APPROVED
    - Reject direct transition from UNKNOWN -> APPROVED
    - Reject direct transition from REVIEW_REQUIRED -> APPROVED
    - Requires a new evaluation_id to re-evaluate after a security failure.
    """

    def __init__(self, artifact_id: str, initial_state: ReleaseState = ReleaseState.CREATED) -> None:
        self.artifact_id = artifact_id
        self._current_state: ReleaseState = initial_state
        self._last_evaluation_id: str | None = None

    @property
    def current_state(self) -> ReleaseState:
        """Returns the current state of the release state machine."""
        return self._current_state

    @property
    def last_evaluation_id(self) -> str | None:
        """Returns the last evaluation ID processed by the state machine."""
        return self._last_evaluation_id

    def transition(self, target_state: ReleaseState, admission: ReleaseAdmission | None = None) -> ReleaseState:
        """Attempts a state transition given a target state and optional admission record."""
        current = self._current_state

        if target_state == ReleaseState.SECURITY_EVALUATED:
            if current != ReleaseState.CREATED:
                raise IllegalStateTransitionError(
                    f"MONOTONIC VIOLATION: Cannot transition to SECURITY_EVALUATED from '{current}'"
                )
            self._current_state = ReleaseState.SECURITY_EVALUATED
            if admission is not None:
                self._last_evaluation_id = admission.evaluation_id
            return self._current_state

        if current == ReleaseState.SECURITY_EVALUATED:
            if admission is None:
                raise IllegalStateTransitionError(
                    "MONOTONIC VIOLATION: Admission object required to transition out of SECURITY_EVALUATED"
                )

            # Replay protection: verify evaluation_id
            if self._last_evaluation_id and admission.evaluation_id != self._last_evaluation_id:
                raise IllegalStateTransitionError(
                    "REPLAY VIOLATION: Evaluation ID mismatch during state transition"
                )

            status_str = str(admission.status).upper()
            if target_state == ReleaseState.APPROVED and status_str != AdmissionStatus.APPROVED.value:
                raise IllegalStateTransitionError(
                    f"MONOTONIC VIOLATION: Cannot transition to APPROVED when admission status is '{status_str}'"
                )

            if target_state == ReleaseState.BLOCKED and status_str != AdmissionStatus.BLOCKED.value:
                raise IllegalStateTransitionError(
                    f"MONOTONIC VIOLATION: Cannot transition to BLOCKED when admission status is '{status_str}'"
                )

            if target_state == ReleaseState.REVIEW_REQUIRED and status_str != AdmissionStatus.REVIEW_REQUIRED.value:
                raise IllegalStateTransitionError(
                    f"MONOTONIC VIOLATION: Cannot transition to REVIEW_REQUIRED when admission status is '{status_str}'"
                )

            self._current_state = target_state
            return self._current_state

        # Prevent forbidden transitions from terminal / security-failed states
        if current in (ReleaseState.BLOCKED, ReleaseState.UNKNOWN, ReleaseState.REVIEW_REQUIRED):
            if target_state == ReleaseState.APPROVED:
                raise IllegalStateTransitionError(
                    f"MONOTONIC VIOLATION: Forbidden direct state transition '{current}' -> 'APPROVED'. Fresh evaluation required."
                )

        raise IllegalStateTransitionError(
            f"MONOTONIC VIOLATION: Forbidden state transition '{current}' -> '{target_state}'"
        )

    def reset_for_fresh_evaluation(self, new_evaluation_id: str) -> None:
        """Resets the state machine to CREATED for a fresh, independent security evaluation."""
        if not new_evaluation_id or new_evaluation_id == self._last_evaluation_id:
            raise IllegalStateTransitionError(
                "REPLAY PROTECTION: Fresh evaluation requires a new, distinct evaluation_id"
            )
        self._current_state = ReleaseState.CREATED
        self._last_evaluation_id = new_evaluation_id

    def to_dict(self) -> dict[str, Any]:
        """Serializes state machine to dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "current_state": str(self._current_state),
            "last_evaluation_id": self._last_evaluation_id,
        }
