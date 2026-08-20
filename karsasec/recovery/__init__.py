"""KarsaSec Sprint F9 — Distributed Snapshot, Checkpoint & Disaster Recovery Engine.

Provides deterministic snapshot generation, Merkle-lite root validation, pure audit ledger replay,
PITR boundary markers, snapshot generation fencing, and outbox identity preservation.
"""


class RecoveryError(Exception):
    """Base exception for all recovery subsystem failures."""


class SnapshotIntegrityError(RecoveryError):
    """Raised when snapshot payload or Merkle-lite root hash verification fails (INV-F9-HASH-05)."""


class SchemaMismatchError(RecoveryError):
    """Raised when snapshot schema_version does not match engine schema version (INV-F9-VERSION-06)."""


class RecoveryFencingError(RecoveryError):
    """Raised when recovery lease fencing token check fails (INV-F9-FENCE-07)."""


class SnapshotFencingError(RecoveryError):
    """Raised when attempting to restore a stale snapshot generation (INV-F9-RECOVERY-11)."""


class PartialRecoveryError(RecoveryError):
    """Raised when required recovery tables or audit log streams are missing or incomplete (INV-F9-RECOVERY-09)."""


class AuditCorruptionError(RecoveryError):
    """Raised when pre-replay cryptographic audit chain verification fails (INV-F9-RECOVERY-12)."""


__all__ = [
    "RecoveryError",
    "SnapshotIntegrityError",
    "SchemaMismatchError",
    "RecoveryFencingError",
    "SnapshotFencingError",
    "PartialRecoveryError",
    "AuditCorruptionError",
]
