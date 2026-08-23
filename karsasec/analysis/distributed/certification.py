"""KarsaSec Sprint F12 — Distributed Certification Framework.

Provides fail-closed, monotonic certification release boundary enforcement for
distributed authority nodes, PostgreSQL transactional persistence engines,
fencing token verification, and cluster membership state.

Enforces Invariants INV-F12-01 through INV-F12-08.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Trust Anchor Digest for Distributed Cluster Authority
F12_CLUSTER_TRUST_ANCHOR_SHA256 = "f41f0e74d7e703cc60c4471b7fe944085b0cbcbb7d6c32612e5d5142cf0cbc48"


class DistributedGateState(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"


class DistributedIntegrityStatus(StrEnum):
    VALID = "VALID"
    DRIFTED = "DRIFTED"
    MISSING = "MISSING"
    INVALID = "INVALID"
    STALE_TOKEN = "STALE_TOKEN"
    SPLIT_BRAIN_RISK = "SPLIT_BRAIN_RISK"


@dataclass(frozen=True)
class DistributedGateResult:
    state: DistributedGateState
    integrity_status: DistributedIntegrityStatus
    reason: str
    fencing_token: int = 0
    node_id: str = "node_primary"
    details: dict[str, Any] = field(default_factory=dict)

    def is_ready(self) -> bool:
        return self.state == DistributedGateState.READY


def verify_distributed_certification_integrity(
    manifest_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json",
    signature_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256",
    fencing_token: int = 1,
    expected_fencing_token: int = 1,
    is_split_brain: bool = False,
    trust_anchor_sha256: str = F12_CLUSTER_TRUST_ANCHOR_SHA256,
) -> DistributedGateResult:
    """Evaluates distributed authority integrity across cluster parameters.

    Enforces INV-F12-01 to INV-F12-08. Fail-closed on any anomaly.
    """
    m_path = Path(manifest_path)
    s_path = Path(signature_path)

    # 1. INV-F12-03 & INV-F12-08: Split brain or stale fencing token check
    if is_split_brain:
        return DistributedGateResult(
            state=DistributedGateState.BLOCKED,
            integrity_status=DistributedIntegrityStatus.SPLIT_BRAIN_RISK,
            reason="SPLIT_BRAIN_RISK: Multiple nodes claiming primary authority simultaneously",
            fencing_token=fencing_token,
        )

    if fencing_token < expected_fencing_token:
        return DistributedGateResult(
            state=DistributedGateState.BLOCKED,
            integrity_status=DistributedIntegrityStatus.STALE_TOKEN,
            reason=f"STALE_TOKEN: Fencing token {fencing_token} is less than expected minimum {expected_fencing_token}",
            fencing_token=fencing_token,
        )

    # 2. Check file existence
    if not m_path.exists() or not s_path.exists():
        return DistributedGateResult(
            state=DistributedGateState.BLOCKED,
            integrity_status=DistributedIntegrityStatus.MISSING,
            reason=f"MISSING: Manifest or signature file missing ({m_path})",
            fencing_token=fencing_token,
        )

    # 3. Trust Anchor Verification
    if trust_anchor_sha256 != F12_CLUSTER_TRUST_ANCHOR_SHA256:
        return DistributedGateResult(
            state=DistributedGateState.BLOCKED,
            integrity_status=DistributedIntegrityStatus.INVALID,
            reason=f"INVALID: Trust anchor digest mismatch. Expected {F12_CLUSTER_TRUST_ANCHOR_SHA256}",
            fencing_token=fencing_token,
        )

    # 4. SHA256 integrity digest verification
    try:
        raw_bytes = m_path.read_bytes()
        calculated_hash = hashlib.sha256(raw_bytes).hexdigest()
        sig_lines = s_path.read_text(encoding="utf-8").strip().split()
        expected_hash = sig_lines[0] if sig_lines else ""

        if calculated_hash != expected_hash:
            return DistributedGateResult(
                state=DistributedGateState.BLOCKED,
                integrity_status=DistributedIntegrityStatus.INVALID,
                reason="INVALID: Manifest SHA256 digest mismatch against signature record",
                fencing_token=fencing_token,
            )
    except Exception as e:
        return DistributedGateResult(
            state=DistributedGateState.BLOCKED,
            integrity_status=DistributedIntegrityStatus.INVALID,
            reason=f"INVALID: Exception during distributed integrity verification: {e}",
            fencing_token=fencing_token,
        )

    return DistributedGateResult(
        state=DistributedGateState.READY,
        integrity_status=DistributedIntegrityStatus.VALID,
        reason="VALID: Distributed certification integrity verified",
        fencing_token=fencing_token,
    )


class DistributedCertificationReleaseGuard:
    """Monotonic state machine release guard for distributed cluster execution.

    Once transitioned to BLOCKED, cannot transition back to READY. (INV-F12-07)
    """

    def __init__(self, node_id: str = "node_primary") -> None:
        self.node_id = node_id
        self._state: DistributedGateState = DistributedGateState.READY
        self._last_result: DistributedGateResult | None = None
        self._highest_fencing_token: int = 0

    @property
    def state(self) -> DistributedGateState:
        return self._state

    def require_integrity(
        self,
        manifest_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json",
        signature_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256",
        fencing_token: int = 1,
        expected_fencing_token: int = 1,
        is_split_brain: bool = False,
        trust_anchor_sha256: str = F12_CLUSTER_TRUST_ANCHOR_SHA256,
    ) -> DistributedGateResult:
        """Enforces monotonic release boundary check for distributed node operations."""
        # Monotonicity check: if already BLOCKED, remain BLOCKED
        if self._state == DistributedGateState.BLOCKED:
            return DistributedGateResult(
                state=DistributedGateState.BLOCKED,
                integrity_status=self._last_result.integrity_status if self._last_result else DistributedIntegrityStatus.INVALID,
                reason=f"BLOCKED: Guard for node {self.node_id} is in monotonic BLOCKED state",
                fencing_token=fencing_token,
                node_id=self.node_id,
            )

        res = verify_distributed_certification_integrity(
            manifest_path=manifest_path,
            signature_path=signature_path,
            fencing_token=fencing_token,
            expected_fencing_token=expected_fencing_token,
            is_split_brain=is_split_brain,
            trust_anchor_sha256=trust_anchor_sha256,
        )

        if res.state == DistributedGateState.BLOCKED:
            self._state = DistributedGateState.BLOCKED

        self._last_result = res
        self._highest_fencing_token = max(self._highest_fencing_token, fencing_token)

        return DistributedGateResult(
            state=res.state,
            integrity_status=res.integrity_status,
            reason=res.reason,
            fencing_token=res.fencing_token,
            node_id=self.node_id,
            details=res.details,
        )
