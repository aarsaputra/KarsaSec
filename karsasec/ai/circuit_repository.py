"""Sprint F11 Phase 6 — Persistent Circuit State Repository (INV-F11-CIRCUIT-06, INV-F11-CIRCUIT-07, INV-F11-CIRCUIT-14).

Provides database-authoritative persistence for Provider Circuit Breaker state:
  - Preserves circuit state (CLOSED, OPEN, HALF_OPEN) across process/pod/node restarts.
  - Persists rolling failure window, cooldown_until timestamp, and cooldown_reason.
  - Enforces UNIQUE(provider_id, model_id) constraint.
  - Enforces INV-F11-CIRCUIT-14: Non-mutating startup state recovery.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from karsasec.persistence.models import AICircuitStateModel


class CircuitStateConflictError(Exception):
    """Raised when a optimistic concurrency state_version mismatch occurs during circuit state save."""

    pass


@dataclass
class CircuitStateData:
    """Immutable data container representing a persistent circuit state snapshot."""

    provider_id: str
    model_id: str
    state: str = "CLOSED"
    state_version: int = 1
    failure_count: int = 0
    success_count: int = 0
    failures: list[bool] = field(default_factory=list)
    opened_at: float | None = None
    cooldown_until: float | None = None
    cooldown_reason: str | None = None
    probe_generation: int = 0


@runtime_checkable
class CircuitStateRepository(Protocol):
    """Protocol interface for circuit state persistence."""

    def load(self, session: Session, provider_id: str, model_id: str) -> CircuitStateData | None:
        """Loads a single provider circuit state from persistent store."""
        ...

    def save(self, session: Session, data: CircuitStateData, expected_version: int | None = None) -> None:
        """Saves or updates a provider circuit state in persistent store."""
        ...

    def list_all(self, session: Session) -> list[CircuitStateData]:
        """Lists all persisted provider circuit states."""
        ...


class PostgresCircuitStateRepository:
    """Database-authoritative PostgreSQL Circuit State Repository (INV-F11-CONSENSUS-18)."""

    def load(self, session: Session, provider_id: str, model_id: str) -> CircuitStateData | None:
        """Loads circuit state for (provider_id, model_id) without mutating state."""
        row = (
            session.query(AICircuitStateModel)
            .filter(
                AICircuitStateModel.provider_id == provider_id,
                AICircuitStateModel.model_id == model_id,
            )
            .one_or_none()
        )

        if row is None:
            return None

        failures: list[bool] = []
        if row.failures_json:
            try:
                failures = json.loads(row.failures_json)
            except (json.JSONDecodeError, TypeError):
                failures = []

        return CircuitStateData(
            provider_id=row.provider_id,
            model_id=row.model_id,
            state=row.state,
            state_version=row.state_version,
            failure_count=row.failure_count,
            success_count=row.success_count,
            failures=failures,
            opened_at=row.opened_at,
            cooldown_until=row.cooldown_until,
            cooldown_reason=row.cooldown_reason,
            probe_generation=row.probe_generation,
        )

    def save(self, session: Session, data: CircuitStateData, expected_version: int | None = None) -> None:
        """Atomically inserts or updates circuit state record in database using Compare-And-Swap.

        Enforces INV-F11-CONSENSUS-18:
        If expected_version is specified and does not match the database state_version,
        a CircuitStateConflictError is raised.
        """
        row = (
            session.query(AICircuitStateModel)
            .filter(
                AICircuitStateModel.provider_id == data.provider_id,
                AICircuitStateModel.model_id == data.model_id,
            )
            .one_or_none()
        )

        failures_json = json.dumps(data.failures)

        if row is None:
            row = AICircuitStateModel(
                provider_id=data.provider_id,
                model_id=data.model_id,
                state=data.state,
                state_version=1,
                failure_count=data.failure_count,
                success_count=data.success_count,
                failures_json=failures_json,
                opened_at=data.opened_at,
                cooldown_until=data.cooldown_until,
                cooldown_reason=data.cooldown_reason,
                probe_generation=data.probe_generation,
            )
            session.add(row)
        else:
            if expected_version is not None and row.state_version != expected_version:
                raise CircuitStateConflictError(
                    f"Circuit state version mismatch for provider '{data.provider_id}' model '{data.model_id}'. "
                    f"Expected version {expected_version}, but found {row.state_version} in database."
                )
            row.state = data.state
            row.state_version = row.state_version + 1
            row.failure_count = data.failure_count
            row.success_count = data.success_count
            row.failures_json = failures_json
            row.opened_at = data.opened_at
            row.cooldown_until = data.cooldown_until
            row.cooldown_reason = data.cooldown_reason
            row.probe_generation = data.probe_generation

        session.flush()

    def list_all(self, session: Session) -> list[CircuitStateData]:
        """Lists all persisted circuit states from database."""
        rows = session.query(AICircuitStateModel).all()
        results: list[CircuitStateData] = []
        for row in rows:
            failures: list[bool] = []
            if row.failures_json:
                try:
                    failures = json.loads(row.failures_json)
                except (json.JSONDecodeError, TypeError):
                    failures = []
            results.append(
                CircuitStateData(
                    provider_id=row.provider_id,
                    model_id=row.model_id,
                    state=row.state,
                    state_version=row.state_version,
                    failure_count=row.failure_count,
                    success_count=row.success_count,
                    failures=failures,
                    opened_at=row.opened_at,
                    cooldown_until=row.cooldown_until,
                    cooldown_reason=row.cooldown_reason,
                    probe_generation=row.probe_generation,
                )
            )
        return results
