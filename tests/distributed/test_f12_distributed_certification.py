"""Unit test suite for Sprint F12 — Distributed Certification Framework.

Verifies invariants INV-F12-01 through INV-F12-08 across cluster integrity, fencing token validation,
split-brain protection, and monotonic guard semantics.
"""

from pathlib import Path
from unittest.mock import patch

from karsasec.analysis.distributed.certification import (
    DistributedCertificationReleaseGuard,
    DistributedGateState,
    DistributedIntegrityStatus,
    verify_distributed_certification_integrity,
)


def test_f12_01_valid_cluster_integrity_returns_ready() -> None:
    """F12-01 — Valid manifest, valid trust anchor, and valid fencing token evaluate to READY."""
    res = verify_distributed_certification_integrity(fencing_token=10, expected_fencing_token=10)
    assert res.state == DistributedGateState.READY
    assert res.integrity_status == DistributedIntegrityStatus.VALID
    assert res.is_ready() is True


def test_f12_02_split_brain_returns_blocked() -> None:
    """F12-02 — Detected split-brain condition returns BLOCKED / SPLIT_BRAIN_RISK."""
    res = verify_distributed_certification_integrity(is_split_brain=True)
    assert res.state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.SPLIT_BRAIN_RISK
    assert "SPLIT_BRAIN_RISK" in res.reason


def test_f12_03_stale_fencing_token_returns_blocked() -> None:
    """F12-03 — Fencing token lower than expected minimum returns BLOCKED / STALE_TOKEN."""
    res = verify_distributed_certification_integrity(fencing_token=5, expected_fencing_token=10)
    assert res.state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.STALE_TOKEN
    assert "STALE_TOKEN" in res.reason


def test_f12_04_missing_manifest_returns_blocked(tmp_path: Path) -> None:
    """F12-04 — Non-existent manifest path returns BLOCKED / MISSING."""
    missing_m = tmp_path / "non_existent.json"
    res = verify_distributed_certification_integrity(manifest_path=missing_m)
    assert res.state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.MISSING


def test_f12_05_trust_anchor_mismatch_returns_blocked() -> None:
    """F12-05 — Invalid trust anchor SHA256 string returns BLOCKED / INVALID."""
    res = verify_distributed_certification_integrity(trust_anchor_sha256="corrupted_trust_anchor")
    assert res.state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.INVALID


def test_f12_06_manifest_tampered_returns_blocked(tmp_path: Path) -> None:
    """F12-06 — Manifest file content mismatch against signature file returns BLOCKED / INVALID."""
    m_file = tmp_path / "manifest.json"
    s_file = tmp_path / "manifest.sha256"
    m_file.write_text('{"tampered": true}', encoding="utf-8")
    s_file.write_text("0" * 64 + "  manifest.json\n", encoding="utf-8")

    res = verify_distributed_certification_integrity(manifest_path=m_file, signature_path=s_file)
    assert res.state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.INVALID


def test_f12_07_monotonic_guard_remains_blocked(tmp_path: Path) -> None:
    """F12-07 — DistributedCertificationReleaseGuard remains BLOCKED after first failure (Monotonicity)."""
    guard = DistributedCertificationReleaseGuard(node_id="node_worker_1")

    # 1. Trigger failure with stale token
    res1 = guard.require_integrity(fencing_token=1, expected_fencing_token=5)
    assert res1.state == DistributedGateState.BLOCKED

    # 2. Re-attempt with valid parameters
    res2 = guard.require_integrity(fencing_token=5, expected_fencing_token=5)
    assert res2.state == DistributedGateState.BLOCKED
    assert "monotonic BLOCKED state" in res2.reason


def test_f12_08_exception_handling_fails_closed() -> None:
    """F12-08 — Exception during file read fails closed to BLOCKED / INVALID."""
    with patch("pathlib.Path.read_bytes", side_effect=OSError("Read error")):
        res = verify_distributed_certification_integrity()
        assert res.state == DistributedGateState.BLOCKED
        assert res.integrity_status == DistributedIntegrityStatus.INVALID
