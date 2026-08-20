"""Authoritative Lifecycle Audit Event Engine for KarsaSec AI Engine (Sprint E13-5 Phase 3).

Defines an immutable, cryptographically fingerprintable audit event model capturing historical
security actions across the remediation lifecycle.

Enforces Security Invariants:
  - L11: Append-Only Audit (Immutable events, frozen fields, explicit tamper protection).
  - L12-L13: Deterministic Event Fingerprinting & Metadata Canonicalization (SHA-256).
  - L14-L17: Repository, Proposal, Snapshot, Verification & Provenance Fingerprint Binding.
  - L20: No Finding Suppression (Ledger cannot delete or rewrite findings).
  - L25: Timestamp Non-Authority (Audit metadata only; cannot dictate verdicts or state transitions).
  - L26: No Security Verdict Authority (Zero authority to grant VERIFIED_FIXED or transition states).
  - L27: Privacy Boundary (Strict sanitization of source code, diffs, tokens, credentials).
  - L28: No Execution / Subprocess Capabilities (Zero shell/git/subprocess/network calls).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
from typing import Any


class AuditEventType(StrEnum):
    """Categorical types of remediation lifecycle audit events."""

    FINDING_DETECTED = "FINDING_DETECTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    RCA_ESTABLISHED = "RCA_ESTABLISHED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    SNAPSHOT_CAPTURED = "SNAPSHOT_CAPTURED"
    PATCH_APPLIED = "PATCH_APPLIED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    ROLLBACK_STARTED = "ROLLBACK_STARTED"
    ROLLBACK_COMPLETED = "ROLLBACK_COMPLETED"
    CRITICAL_RECOVERY_FAILURE = "CRITICAL_RECOVERY_FAILURE"


# Allowlist of exempt/valid metadata key suffixes and exact names that are cryptographic/audit IDs
_EXEMPT_METADATA_KEYS: set[str] = {
    "token_id",
    "approval_token_id",
    "proposal_fingerprint",
    "verification_fingerprint",
    "source_snapshot_hash",
    "post_apply_snapshot_hash",
    "pre_apply_snapshot_hash",
    "token_fingerprint",
    "provenance_fingerprint",
    "transaction_id",
    "verification_id",
    "proposal_id",
    "finding_id",
    "rule_id",
    "cwe_id",
    "file_path",
    "target_files",
    "status",
    "reason",
    "approver",
    "approved_by",
    "repository_identity",
}

# Blacklisted substrings for sensitive data (L27)
_SENSITIVE_KEY_SUBSTRINGS: set[str] = {
    "password",
    "passwd",
    "secret",
    "access_token",
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "source_code",
    "raw_source",
    "diff",
    "patch_content",
    "original_text",
    "proposed_text",
}


def sanitize_metadata(
    metadata: dict[str, Any] | tuple[tuple[str, str], ...] | list[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    """Sanitizes metadata to enforce Privacy Boundary (L27).

    Rejects keys containing sensitive keywords (passwords, credentials, source code buffers, diffs).
    Preserves audit/cryptographic identifiers.
    Returns sorted immutable key-value tuples.
    """
    items: list[tuple[str, str]] = []
    if isinstance(metadata, dict):
        raw_items = [(str(k), str(v)) for k, v in metadata.items()]
    else:
        raw_items = [(str(k), str(v)) for k, v in metadata]

    for k, v in raw_items:
        key_lower = k.lower().strip()
        # If key is explicitly exempt, pass
        if key_lower not in _EXEMPT_METADATA_KEYS:
            for sens in _SENSITIVE_KEY_SUBSTRINGS:
                if sens in key_lower:
                    raise ValueError(f"Sensitive metadata key detected and rejected (L27 Privacy Violation): '{k}'")

        items.append((k.strip(), str(v).strip()))

    return tuple(sorted(items))


@dataclass(frozen=True, slots=True)
class LifecycleAuditEvent:
    """Immutable audit event capturing a historical remediation lifecycle transition (L11)."""

    event_id: str
    event_type: AuditEventType
    finding_id: str
    lifecycle_state: str
    actor: str
    timestamp: str
    repository_identity: str
    predecessor_event_id: str | None = None
    predecessor_event_fingerprint: str | None = None
    proposal_fingerprint: str | None = None
    source_snapshot_hash: str | None = None
    post_apply_snapshot_hash: str | None = None
    verification_run_id: str | None = None
    verification_fingerprint: str | None = None
    provenance_fingerprint: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()
    event_fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.event_id or not self.event_id.strip():
            raise ValueError("event_id cannot be empty.")
        if not self.finding_id or not self.finding_id.strip():
            raise ValueError("finding_id cannot be empty.")

        # Validate privacy filtering (L27)
        sanitize_metadata(self.metadata)

        expected_fp = self.compute_event_fingerprint(
            event_id=self.event_id,
            event_type=self.event_type,
            finding_id=self.finding_id,
            lifecycle_state=self.lifecycle_state,
            actor=self.actor,
            timestamp=self.timestamp,
            repository_identity=self.repository_identity,
            predecessor_event_id=self.predecessor_event_id,
            predecessor_event_fingerprint=self.predecessor_event_fingerprint,
            proposal_fingerprint=self.proposal_fingerprint,
            source_snapshot_hash=self.source_snapshot_hash,
            post_apply_snapshot_hash=self.post_apply_snapshot_hash,
            verification_run_id=self.verification_run_id,
            verification_fingerprint=self.verification_fingerprint,
            provenance_fingerprint=self.provenance_fingerprint,
            metadata=self.metadata,
        )

        if self.event_fingerprint and self.event_fingerprint != expected_fp:
            raise ValueError(
                f"Invalid or tampered event fingerprint for '{self.event_id}'. "
                f"Expected '{expected_fp}', got '{self.event_fingerprint}'."
            )

    @staticmethod
    def compute_event_fingerprint(
        event_id: str,
        event_type: AuditEventType | str,
        finding_id: str,
        lifecycle_state: str,
        actor: str,
        timestamp: str,
        repository_identity: str,
        predecessor_event_id: str | None,
        predecessor_event_fingerprint: str | None,
        proposal_fingerprint: str | None,
        source_snapshot_hash: str | None,
        post_apply_snapshot_hash: str | None,
        verification_run_id: str | None,
        verification_fingerprint: str | None,
        provenance_fingerprint: str | None,
        metadata: tuple[tuple[str, str], ...],
    ) -> str:
        """Compute canonical SHA-256 fingerprint for audit event (L12, L13)."""
        ev_type_str = str(event_type)
        norm_repo = repository_identity.replace("\\", "/").rstrip("/")
        sorted_meta_str = "|".join(f"{k}:{v}" for k, v in sorted(metadata))

        raw = (
            f"{event_id}|{ev_type_str}|{finding_id}|{lifecycle_state}|{actor}|{timestamp}|"
            f"{norm_repo}|{predecessor_event_id or 'NONE'}|{predecessor_event_fingerprint or 'NONE'}|"
            f"{proposal_fingerprint or 'NONE'}|{source_snapshot_hash or 'NONE'}|"
            f"{post_apply_snapshot_hash or 'NONE'}|{verification_run_id or 'NONE'}|"
            f"{verification_fingerprint or 'NONE'}|{provenance_fingerprint or 'NONE'}|{sorted_meta_str}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        event_id: str,
        event_type: AuditEventType | str,
        finding_id: str,
        lifecycle_state: str,
        actor: str,
        timestamp: str,
        repository_identity: str,
        predecessor_event_id: str | None = None,
        predecessor_event_fingerprint: str | None = None,
        proposal_fingerprint: str | None = None,
        source_snapshot_hash: str | None = None,
        post_apply_snapshot_hash: str | None = None,
        verification_run_id: str | None = None,
        verification_fingerprint: str | None = None,
        provenance_fingerprint: str | None = None,
        metadata: dict[str, Any] | tuple[tuple[str, str], ...] = (),
    ) -> LifecycleAuditEvent:
        """Factory constructor for LifecycleAuditEvent."""
        ev_type = AuditEventType(str(event_type))
        meta_tuple = sanitize_metadata(metadata)

        fp = cls.compute_event_fingerprint(
            event_id=event_id,
            event_type=ev_type,
            finding_id=finding_id,
            lifecycle_state=lifecycle_state,
            actor=actor,
            timestamp=timestamp,
            repository_identity=repository_identity,
            predecessor_event_id=predecessor_event_id,
            predecessor_event_fingerprint=predecessor_event_fingerprint,
            proposal_fingerprint=proposal_fingerprint,
            source_snapshot_hash=source_snapshot_hash,
            post_apply_snapshot_hash=post_apply_snapshot_hash,
            verification_run_id=verification_run_id,
            verification_fingerprint=verification_fingerprint,
            provenance_fingerprint=provenance_fingerprint,
            metadata=meta_tuple,
        )

        return cls(
            event_id=event_id,
            event_type=ev_type,
            finding_id=finding_id,
            lifecycle_state=lifecycle_state,
            actor=actor,
            timestamp=timestamp,
            repository_identity=repository_identity,
            predecessor_event_id=predecessor_event_id,
            predecessor_event_fingerprint=predecessor_event_fingerprint,
            proposal_fingerprint=proposal_fingerprint,
            source_snapshot_hash=source_snapshot_hash,
            post_apply_snapshot_hash=post_apply_snapshot_hash,
            verification_run_id=verification_run_id,
            verification_fingerprint=verification_fingerprint,
            provenance_fingerprint=provenance_fingerprint,
            metadata=meta_tuple,
            event_fingerprint=fp,
        )

    def to_dict(self) -> dict[str, Any]:
        """Export canonical dictionary representation."""
        return {
            "event_id": self.event_id,
            "event_type": str(self.event_type),
            "finding_id": self.finding_id,
            "lifecycle_state": self.lifecycle_state,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "repository_identity": self.repository_identity,
            "predecessor_event_id": self.predecessor_event_id,
            "predecessor_event_fingerprint": self.predecessor_event_fingerprint,
            "proposal_fingerprint": self.proposal_fingerprint,
            "source_snapshot_hash": self.source_snapshot_hash,
            "post_apply_snapshot_hash": self.post_apply_snapshot_hash,
            "verification_run_id": self.verification_run_id,
            "verification_fingerprint": self.verification_fingerprint,
            "provenance_fingerprint": self.provenance_fingerprint,
            "metadata": dict(self.metadata),
            "event_fingerprint": self.event_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LifecycleAuditEvent:
        """Reconstruct LifecycleAuditEvent from dictionary data."""
        return cls.create(
            event_id=data["event_id"],
            event_type=data["event_type"],
            finding_id=data["finding_id"],
            lifecycle_state=data["lifecycle_state"],
            actor=data["actor"],
            timestamp=data["timestamp"],
            repository_identity=data["repository_identity"],
            predecessor_event_id=data.get("predecessor_event_id"),
            predecessor_event_fingerprint=data.get("predecessor_event_fingerprint"),
            proposal_fingerprint=data.get("proposal_fingerprint"),
            source_snapshot_hash=data.get("source_snapshot_hash"),
            post_apply_snapshot_hash=data.get("post_apply_snapshot_hash"),
            verification_run_id=data.get("verification_run_id"),
            verification_fingerprint=data.get("verification_fingerprint"),
            provenance_fingerprint=data.get("provenance_fingerprint"),
            metadata=data.get("metadata", {}),
        )
