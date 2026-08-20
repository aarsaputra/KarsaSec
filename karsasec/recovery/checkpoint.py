"""KarsaSec Sprint F9 — Recovery Checkpoint & Disaster Recovery Orchestrator.

Provides atomic recovery lease fencing, checkpoint persistence, PITR sequence markers,
and fail-closed disaster recovery restoration (INV-F9-FENCE-07, INV-F9-RECOVERY-10, INV-F9-RECOVERY-11).
"""

import json
from typing import Any
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from karsasec.persistence.models import RecoveryCheckpointModel
from karsasec.recovery import (
    RecoveryError,
    RecoveryFencingError,
)
from karsasec.recovery.snapshot import SnapshotManager, canonical_json
from karsasec.recovery.replay import AuditReplayEngine


class RecoveryCheckpoint:
    """Orchestrates Disaster Recovery Checkpoints, atomic lease fencing, and PITR restoration."""

    @classmethod
    def save_checkpoint(
        cls,
        session: Session,
        checkpoint_id: str,
        generation: int = 1,
        recovery_id: str = "system_recovery",
        recovery_lease_token: str = "token_default",
    ) -> RecoveryCheckpointModel:
        """Captures a state snapshot and persists a versioned RecoveryCheckpointModel entry."""
        snapshot_data = SnapshotManager.create_snapshot(session, generation=generation)

        checkpoint = session.scalar(
            select(RecoveryCheckpointModel).where(RecoveryCheckpointModel.checkpoint_id == checkpoint_id)
        )
        if not checkpoint:
            checkpoint = RecoveryCheckpointModel(
                checkpoint_id=checkpoint_id,
                snapshot_generation=generation,
                snapshot_version=snapshot_data["snapshot_version"],
                schema_version=snapshot_data["schema_version"],
                root_hash=snapshot_data["root_hash"],
                snapshot_hash=snapshot_data["snapshot_hash"],
                audit_head_hash=snapshot_data["audit_head_hash"],
                outbox_head_hash=snapshot_data["outbox_head_hash"],
                recovery_id=recovery_id,
                recovery_lease_token=recovery_lease_token,
                last_audit_id=0,
                max_lease_version=snapshot_data["max_lease_version"],
                max_outbox_sequence=snapshot_data["max_outbox_sequence"],
                audit_chain_head=snapshot_data["audit_chain_head"],
                snapshot_json=canonical_json(snapshot_data),
            )
            session.add(checkpoint)
        else:
            checkpoint.snapshot_generation = generation
            checkpoint.root_hash = snapshot_data["root_hash"]
            checkpoint.snapshot_hash = snapshot_data["snapshot_hash"]
            checkpoint.audit_head_hash = snapshot_data["audit_head_hash"]
            checkpoint.outbox_head_hash = snapshot_data["outbox_head_hash"]
            checkpoint.recovery_id = recovery_id
            checkpoint.recovery_lease_token = recovery_lease_token
            checkpoint.max_lease_version = snapshot_data["max_lease_version"]
            checkpoint.max_outbox_sequence = snapshot_data["max_outbox_sequence"]
            checkpoint.audit_chain_head = snapshot_data["audit_chain_head"]
            checkpoint.snapshot_json = canonical_json(snapshot_data)

        session.flush()
        return checkpoint

    @classmethod
    def restore_checkpoint(
        cls,
        session: Session,
        checkpoint_id: str,
        recovery_id: str,
        recovery_lease_token: str,
        pitr_sequence: int | None = None,
    ) -> dict[str, Any]:
        """Executes atomic recovery restoration sequence.

        Pre-mutation fail-closed order:
        1. Verify DB table presence
        2. Validate Checkpoint & Recovery Lease Fencing (INV-F9-FENCE-07)
        3. Validate Snapshot JSON & Merkle-lite root hash (INV-F9-HASH-05)
        4. Validate Audit Chain Integrity (INV-F9-RECOVERY-12)
        5. Restore Task Snapshot (INV-F9-SNAP-01)
        6. Pure Audit Log Replay (INV-F9-PURITY-08)
        7. Rebuild Outbox (INV-F9-RECOVERY-02)
        """
        # 1. Pre-flight integrity check
        AuditReplayEngine.verify_restore_integrity(session)

        # 2. Checkpoint lookup & Fencing validation
        checkpoint = session.scalar(
            select(RecoveryCheckpointModel).where(RecoveryCheckpointModel.checkpoint_id == checkpoint_id)
        )
        if not checkpoint:
            raise RecoveryError(f"Recovery checkpoint '{checkpoint_id}' not found.")

        if checkpoint.recovery_lease_token and checkpoint.recovery_lease_token != recovery_lease_token:
            raise RecoveryFencingError(
                f"Recovery node '{recovery_id}' with lease token '{recovery_lease_token}' rejected; "
                f"checkpoint owned by lease token '{checkpoint.recovery_lease_token}'."
            )

        # Atomic lease acquisition check
        stmt = (
            update(RecoveryCheckpointModel)
            .where(
                RecoveryCheckpointModel.checkpoint_id == checkpoint_id,
                (RecoveryCheckpointModel.recovery_lease_token == recovery_lease_token)
                | (RecoveryCheckpointModel.recovery_lease_token.is_(None)),
            )
            .values(recovery_id=recovery_id, recovery_lease_token=recovery_lease_token)
        )
        result = session.execute(stmt)
        if getattr(result, "rowcount", 0) == 0 and checkpoint.recovery_lease_token != recovery_lease_token:
            raise RecoveryFencingError("Atomic recovery lease acquisition failed.")

        # 3. Parse Snapshot Data & Verify
        snapshot_data = json.loads(checkpoint.snapshot_json)
        SnapshotManager.verify_snapshot(snapshot_data)

        # 4. Mandatory Pre-Replay Audit Verification
        AuditReplayEngine.verify_audit_chain(session)

        # 5. Restore Snapshot
        SnapshotManager.load_snapshot(session, snapshot_data)

        # 6. Replay Events
        replayed_count = AuditReplayEngine.replay_events(session, snapshot_data, target_sequence=pitr_sequence)

        # 7. Rebuild Outbox
        rebuilt_outbox_count = AuditReplayEngine.rebuild_outbox_from_audit(session)

        return {
            "checkpoint_id": checkpoint_id,
            "replayed_events_count": replayed_count,
            "rebuilt_outbox_count": rebuilt_outbox_count,
            "snapshot_generation": snapshot_data["snapshot_generation"],
            "root_hash": snapshot_data["root_hash"],
        }
