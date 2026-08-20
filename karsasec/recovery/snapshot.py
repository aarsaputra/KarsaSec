"""KarsaSec Sprint F9 — Deterministic Snapshot Manager.

Handles canonical serialization, Merkle-lite root hash generation, schema versioning,
generation fencing, and snapshot payload verification (INV-F9-SNAP-01, INV-F9-HASH-05, INV-F9-VERSION-06, INV-F9-RECOVERY-11).
"""

import hashlib
import json
from typing import Any
from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from karsasec.persistence.models import (
    TaskModel,
    TaskAuditLogModel,
    OutboxEventModel,
    RecoveryCheckpointModel,
)
from karsasec.recovery import (
    SnapshotIntegrityError,
    SchemaMismatchError,
    SnapshotFencingError,
)

CURRENT_SCHEMA_VERSION = 1
CURRENT_SNAPSHOT_VERSION = 1


def canonical_json(data: Any) -> str:
    """Produces deterministic canonical JSON formatting (sorted keys, compact separators)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_sha256(content: str) -> str:
    """Computes SHA-256 hex digest of given string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class SnapshotManager:
    """Deterministic Manager for Task State Snapshots and Merkle-Lite Root Hash validation."""

    @classmethod
    def create_snapshot(cls, session: Session, generation: int = 1) -> dict[str, Any]:
        """Captures a deterministic snapshot of all TaskModel records and produces a Merkle-lite root hash.

        Merkle-Lite Root Hash = SHA256(snapshot_hash + ":" + audit_head_hash + ":" + outbox_head_hash)
        (INV-F9-SNAP-01, INV-F9-HASH-05, INV-F9-RECOVERY-10).
        """
        tasks = list(session.scalars(select(TaskModel).order_by(TaskModel.task_id.asc())).all())

        tasks_data = [
            {
                "task_id": t.task_id,
                "finding_id": t.finding_id,
                "approval_token_id": t.approval_token_id,
                "fingerprint": t.fingerprint,
                "state": t.state,
                "attempts": t.attempts,
                "max_attempts": t.max_attempts,
                "assigned_worker_id": t.assigned_worker_id,
                "assigned_worker_fencing_token": t.assigned_worker_fencing_token,
                "recovery_fencing_token": t.recovery_fencing_token,
                "lease_seconds": t.lease_seconds,
                "lease_version": t.lease_version,
                "error_message": t.error_message,
            }
            for t in tasks
        ]

        tasks_json = canonical_json(tasks_data)
        snapshot_hash = compute_sha256(tasks_json)

        # Audit Head Boundary
        last_audit = session.scalar(
            select(TaskAuditLogModel).order_by(TaskAuditLogModel.created_at.desc(), TaskAuditLogModel.id.desc())
        )
        audit_head_hash = last_audit.event_hash if last_audit else "GENESIS"

        # Outbox Head Boundary
        last_outbox = session.scalar(
            select(OutboxEventModel).order_by(
                OutboxEventModel.created_at.desc(), OutboxEventModel.aggregate_sequence.desc()
            )
        )
        outbox_head_hash = last_outbox.event_hash if (last_outbox and last_outbox.event_hash) else "GENESIS"
        max_outbox_sequence = last_outbox.aggregate_sequence if last_outbox else 0

        max_lease_version = max((t.lease_version for t in tasks), default=0)

        root_input = f"{snapshot_hash}:{audit_head_hash}:{outbox_head_hash}"
        root_hash = compute_sha256(root_input)

        return {
            "snapshot_generation": generation,
            "snapshot_version": CURRENT_SNAPSHOT_VERSION,
            "schema_version": CURRENT_SCHEMA_VERSION,
            "root_hash": root_hash,
            "snapshot_hash": snapshot_hash,
            "audit_head_hash": audit_head_hash,
            "outbox_head_hash": outbox_head_hash,
            "max_lease_version": max_lease_version,
            "max_outbox_sequence": max_outbox_sequence,
            "audit_chain_head": audit_head_hash,
            "tasks": tasks_data,
        }

    @classmethod
    def verify_snapshot(cls, snapshot_data: dict[str, Any]) -> bool:
        """Validates snapshot schema and Merkle-lite root hash integrity (INV-F9-HASH-05)."""
        required_keys = {
            "snapshot_generation",
            "snapshot_version",
            "schema_version",
            "root_hash",
            "snapshot_hash",
            "audit_head_hash",
            "outbox_head_hash",
            "max_lease_version",
            "max_outbox_sequence",
            "audit_chain_head",
            "tasks",
        }
        if not required_keys.issubset(snapshot_data.keys()):
            raise SnapshotIntegrityError("Snapshot is missing required fields.")

        # Re-compute tasks snapshot hash
        tasks_json = canonical_json(snapshot_data["tasks"])
        computed_snapshot_hash = compute_sha256(tasks_json)
        if computed_snapshot_hash != snapshot_data["snapshot_hash"]:
            raise SnapshotIntegrityError("Snapshot tasks data payload hash mismatch.")

        # Re-compute Merkle-lite root hash
        root_input = (
            f"{snapshot_data['snapshot_hash']}:{snapshot_data['audit_head_hash']}:{snapshot_data['outbox_head_hash']}"
        )
        computed_root_hash = compute_sha256(root_input)

        if computed_root_hash != snapshot_data["root_hash"]:
            raise SnapshotIntegrityError("Merkle-lite composite root hash verification failed.")

        return True

    @classmethod
    def load_snapshot(
        cls,
        session: Session,
        snapshot_data: dict[str, Any],
    ) -> None:
        """Restores TaskModel records from snapshot after passing verification & fencing checks.

        INV-F9-VERSION-06: Verifies schema version matching.
        INV-F9-RECOVERY-11: Enforces snapshot generation fencing.
        """
        cls.verify_snapshot(snapshot_data)

        if snapshot_data["schema_version"] != CURRENT_SCHEMA_VERSION:
            raise SchemaMismatchError(
                f"Snapshot schema version '{snapshot_data['schema_version']}' is incompatible with engine schema version '{CURRENT_SCHEMA_VERSION}'."
            )

        # Check generation fencing
        latest_checkpoint = session.scalar(
            select(RecoveryCheckpointModel).order_by(RecoveryCheckpointModel.snapshot_generation.desc())
        )
        if latest_checkpoint and snapshot_data["snapshot_generation"] < latest_checkpoint.snapshot_generation:
            raise SnapshotFencingError(
                f"Stale snapshot generation {snapshot_data['snapshot_generation']} rejected; latest generation is {latest_checkpoint.snapshot_generation}."
            )

        # Clear existing tasks and populate from snapshot
        session.execute(delete(TaskModel))
        session.flush()

        for t_dict in snapshot_data["tasks"]:
            task = TaskModel(
                task_id=t_dict["task_id"],
                finding_id=t_dict["finding_id"],
                approval_token_id=t_dict["approval_token_id"],
                fingerprint=t_dict["fingerprint"],
                state=t_dict["state"],
                attempts=t_dict["attempts"],
                max_attempts=t_dict["max_attempts"],
                assigned_worker_id=t_dict.get("assigned_worker_id"),
                assigned_worker_fencing_token=t_dict.get("assigned_worker_fencing_token"),
                recovery_fencing_token=t_dict.get("recovery_fencing_token"),
                lease_seconds=t_dict.get("lease_seconds", 300),
                lease_version=t_dict["lease_version"],
                error_message=t_dict.get("error_message"),
            )
            session.add(task)

        session.flush()
