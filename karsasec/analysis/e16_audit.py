"""Tamper-Evident Hash-Chained Audit Ledger for Sprint E16."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any

from karsasec.analysis.e16_models import ReleaseAdmission, deterministic_id

GENESIS_HASH = "E16-AUDIT-GENESIS"


@dataclass(frozen=True)
class AuditRecord:
    """Immutable representation of a single tamper-evident audit ledger entry."""

    audit_id: str
    sequence: int
    previous_hash: str
    audit_hash: str
    artifact_id: str
    decision_id: str
    policy_id: str
    admission_id: str
    status: str
    reason_codes: tuple[str, ...]
    policy_version: str = "1.0.0"
    schema_version: str = "1.0.0"

    def canonical_payload(self) -> dict[str, Any]:
        """Returns the canonical dictionary payload for audit hashing."""
        return {
            "admission_id": self.admission_id,
            "artifact_id": self.artifact_id,
            "decision_id": self.decision_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "reason_codes": list(self.reason_codes),
            "sequence": self.sequence,
            "schema_version": self.schema_version,
            "status": str(self.status),
        }

    def compute_hash(self) -> str:
        """Computes the cryptographic SHA-256 hash chaining previous_hash + canonical record."""
        canonical = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(f"{self.previous_hash}{canonical}".encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serializes record to dictionary."""
        d = self.canonical_payload()
        d["audit_id"] = self.audit_id
        d["previous_hash"] = self.previous_hash
        d["audit_hash"] = self.audit_hash
        return d


class ReleaseAuditLedger:
    """Thread-safe, append-only, tamper-evident release audit ledger.

    Uses threading.RLock for concurrent thread safety.
    Maintains a SHA-256 hash chain anchored at E16-AUDIT-GENESIS.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: list[AuditRecord] = []

    @property
    def record_count(self) -> int:
        """Returns the total number of recorded audit entries."""
        with self._lock:
            return len(self._records)

    def append(self, admission: ReleaseAdmission, policy_version: str = "1.0.0") -> AuditRecord:
        """Appends an immutable audit record derived from a ReleaseAdmission object."""
        with self._lock:
            seq = len(self._records) + 1
            prev_hash = self._records[-1].audit_hash if self._records else GENESIS_HASH

            sorted_reasons = tuple(sorted(admission.reason_codes))
            payload = {
                "admission_id": admission.admission_id,
                "artifact_id": admission.artifact_id,
                "decision_id": admission.decision_id,
                "policy_id": admission.policy_id,
                "policy_version": policy_version,
                "reason_codes": list(sorted_reasons),
                "sequence": seq,
                "schema_version": admission.schema_version,
                "status": str(admission.status),
            }
            aud_id = deterministic_id("E16-AUDIT:v1:", payload)

            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            audit_h = hashlib.sha256(f"{prev_hash}{canonical}".encode()).hexdigest()

            record = AuditRecord(
                audit_id=aud_id,
                sequence=seq,
                previous_hash=prev_hash,
                audit_hash=audit_h,
                artifact_id=admission.artifact_id,
                decision_id=admission.decision_id,
                policy_id=admission.policy_id,
                admission_id=admission.admission_id,
                status=str(admission.status),
                reason_codes=sorted_reasons,
                policy_version=policy_version,
                schema_version=admission.schema_version,
            )
            self._records.append(record)
            return record

    def get_records(self) -> tuple[AuditRecord, ...]:
        """Returns an immutable snapshot of all audit records."""
        with self._lock:
            return tuple(self._records)

    def verify_integrity(self) -> bool:
        """Verifies total hash chain integrity of the ledger.

        Checks:
        - Sequence monotonicity (1, 2, 3...)
        - Genesis anchor parity
        - Previous hash linkage
        - Re-computed SHA-256 hash match
        """
        with self._lock:
            if not self._records:
                return True

            expected_prev = GENESIS_HASH
            for i, record in enumerate(self._records, start=1):
                if record.sequence != i:
                    return False
                if record.previous_hash != expected_prev:
                    return False
                if record.audit_hash != record.compute_hash():
                    return False
                expected_prev = record.audit_hash

            return True
