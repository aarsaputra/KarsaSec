"""Append-Only Audit Ledger & Cryptographic Chain Engine for KarsaSec AI Engine (Sprint E13-5 Phase 3).

Defines an immutable, order-sensitive append-only ledger for historical remediation lifecycle events.

Enforces Security Invariants:
  - L11: Append-Only Audit (History cannot be modified, deleted, replaced, or reordered).
  - L21-L22: Predecessor & Chain Integrity (Strict cryptographic linkage event_i -> event_{i-1}).
  - L23-L24: Tamper Detection & Replay Prevention (Rejects tampered events or duplicate IDs/fingerprints).
  - L26: No Security Verdict Authority (Zero authority to grant VERIFIED_FIXED or transition states).
  - L28: No Execution / Subprocess Capabilities (Zero shell/git/subprocess/network calls).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from karsasec.ai.remediation.audit import LifecycleAuditEvent


@dataclass(frozen=True, slots=True)
class RemediationLedger:
    """Immutable, append-only historical audit ledger (L11, L21, L22)."""

    events: tuple[LifecycleAuditEvent, ...] = ()

    def __post_init__(self) -> None:
        self.validate_chain()

    @property
    def latest_event(self) -> LifecycleAuditEvent | None:
        """Returns the most recently appended audit event, or None if ledger is empty."""
        return self.events[-1] if self.events else None

    @property
    def ledger_fingerprint(self) -> str:
        """Computes deterministic, ORDER-SENSITIVE SHA-256 fingerprint over ordered event sequence.

        Unlike the provenance graph, the ledger preserves chronological sequence order.
        [E1, E2, E3] != [E2, E1, E3].
        """
        records: list[str] = []
        for e in self.events:
            p_id = e.predecessor_event_id or "NONE"
            p_fp = e.predecessor_event_fingerprint or "NONE"
            records.append(f"{e.event_id}:{e.event_type}:{e.event_fingerprint}:{p_id}:{p_fp}")
        raw = "||".join(records)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_event(self, event_id: str) -> LifecycleAuditEvent | None:
        """Retrieve audit event by event ID."""
        for e in self.events:
            if e.event_id == event_id:
                return e
        return None

    def get_events_for_finding(self, finding_id: str) -> tuple[LifecycleAuditEvent, ...]:
        """Retrieve all audit events corresponding to a finding ID."""
        return tuple(e for e in self.events if e.finding_id == finding_id)

    def get_events_by_state(self, lifecycle_state: str) -> tuple[LifecycleAuditEvent, ...]:
        """Retrieve all audit events corresponding to a given lifecycle state."""
        return tuple(e for e in self.events if e.lifecycle_state == lifecycle_state)

    def append(self, event: LifecycleAuditEvent) -> RemediationLedger:
        """Append an event and return a NEW immutable RemediationLedger instance (L11).

        Enforces duplicate ID check, fingerprint replay check, and predecessor chain linkage.
        """
        existing_ids = {e.event_id for e in self.events}
        if event.event_id in existing_ids:
            raise ValueError(f"Duplicate event_id '{event.event_id}' rejected (L24).")

        existing_fps = {e.event_fingerprint for e in self.events}
        if event.event_fingerprint in existing_fps:
            raise ValueError(
                f"Duplicate event_fingerprint for event '{event.event_id}' rejected (L24 Replay Prevention)."
            )

        # Validate Predecessor Linkage (L21, L22)
        if not self.events:
            if event.predecessor_event_id is not None or event.predecessor_event_fingerprint is not None:
                raise ValueError(f"First event '{event.event_id}' in ledger must have None for predecessor linkage.")
        else:
            last = self.events[-1]
            if event.predecessor_event_id != last.event_id:
                raise ValueError(
                    f"Broken predecessor link for event '{event.event_id}': "
                    f"predecessor_event_id '{event.predecessor_event_id}' != expected '{last.event_id}'."
                )
            if event.predecessor_event_fingerprint != last.event_fingerprint:
                raise ValueError(
                    f"Broken predecessor fingerprint for event '{event.event_id}': "
                    f"predecessor_event_fingerprint '{event.predecessor_event_fingerprint}' != expected '{last.event_fingerprint}'."
                )

        new_events = self.events + (event,)
        return RemediationLedger(events=new_events)

    def validate_chain(self) -> tuple[bool, str]:
        """Cryptographically validate predecessor linkage and fingerprints across all events (L22, L23)."""
        seen_ids: set[str] = set()
        seen_fps: set[str] = set()

        for idx, event in enumerate(self.events):
            if event.event_id in seen_ids:
                raise ValueError(f"Duplicate event_id '{event.event_id}' detected at index {idx}.")
            seen_ids.add(event.event_id)

            if event.event_fingerprint in seen_fps:
                raise ValueError(f"Duplicate event_fingerprint for '{event.event_id}' detected at index {idx}.")
            seen_fps.add(event.event_fingerprint)

            # Re-verify fingerprint computation
            expected_fp = LifecycleAuditEvent.compute_event_fingerprint(
                event_id=event.event_id,
                event_type=event.event_type,
                finding_id=event.finding_id,
                lifecycle_state=event.lifecycle_state,
                actor=event.actor,
                timestamp=event.timestamp,
                repository_identity=event.repository_identity,
                predecessor_event_id=event.predecessor_event_id,
                predecessor_event_fingerprint=event.predecessor_event_fingerprint,
                proposal_fingerprint=event.proposal_fingerprint,
                source_snapshot_hash=event.source_snapshot_hash,
                post_apply_snapshot_hash=event.post_apply_snapshot_hash,
                verification_run_id=event.verification_run_id,
                verification_fingerprint=event.verification_fingerprint,
                provenance_fingerprint=event.provenance_fingerprint,
                metadata=event.metadata,
            )
            if event.event_fingerprint != expected_fp:
                raise ValueError(f"Tampered event fingerprint for '{event.event_id}' at index {idx}.")

            # Verify predecessor linkage
            if idx == 0:
                if event.predecessor_event_id is not None or event.predecessor_event_fingerprint is not None:
                    raise ValueError(f"Initial event '{event.event_id}' must not have predecessor linkage.")
            else:
                prev_event = self.events[idx - 1]
                if event.predecessor_event_id != prev_event.event_id:
                    raise ValueError(
                        f"Predecessor ID mismatch at index {idx}: '{event.predecessor_event_id}' != '{prev_event.event_id}'."
                    )
                if event.predecessor_event_fingerprint != prev_event.event_fingerprint:
                    raise ValueError(
                        f"Predecessor fingerprint mismatch at index {idx}: '{event.predecessor_event_fingerprint}' != '{prev_event.event_fingerprint}'."
                    )

        return True, "VALID"

    def to_dict(self) -> dict[str, Any]:
        """Export canonical dictionary representation."""
        return {
            "ledger_fingerprint": self.ledger_fingerprint,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemediationLedger:
        """Reconstruct RemediationLedger by sequentially appending events to verify chain integrity."""
        events_data = data.get("events", [])
        ledger = cls()
        for ed in events_data:
            ev = LifecycleAuditEvent.from_dict(ed)
            ledger = ledger.append(ev)
        return ledger
