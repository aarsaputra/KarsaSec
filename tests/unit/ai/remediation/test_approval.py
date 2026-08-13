"""Unit tests for PatchApprovalToken and approval domain model (Sprint E13-4)."""

from __future__ import annotations

from datetime import datetime, timedelta, UTC

import pytest

from karsasec.ai.remediation.approval import ApprovalStatus, PatchApprovalToken


def test_01_create_and_verify_valid_token() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py", "db.py"),
        repository_identity="/repo/root",
        approved_by="alice",
    )

    assert token.status == ApprovalStatus.APPROVED
    assert len(token.token_fingerprint) == 64

    valid, err = token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is True
    assert err == "VALID"


def test_02_mark_used_single_use_enforcement() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
    )

    used_token = token.mark_used()
    assert used_token.status == ApprovalStatus.USED

    # Mark used again raises error
    with pytest.raises(ValueError, match="already USED"):
        used_token.mark_used()

    # Reusing token fails verification
    valid, err = used_token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "TOKEN_ALREADY_USED" in err


def test_03_finding_id_mismatch_rejection() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
    )

    valid, err = token.verify_valid(
        expected_finding_id="F-999",  # Mismatch
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "FINDING_MISMATCH" in err


def test_04_proposal_fingerprint_mismatch_rejection() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
    )

    valid, err = token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="tampered_proposal_fp",  # Mismatch
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "PROPOSAL_FINGERPRINT_MISMATCH" in err


def test_05_snapshot_hash_mismatch_rejection_toctou() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
    )

    valid, err = token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="modified_source_hash",  # TOCTOU change
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "SNAPSHOT_HASH_MISMATCH" in err


def test_06_repository_identity_mismatch_rejection() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/repoA",
    )

    valid, err = token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/repoB",  # Wrong repository
    )
    assert valid is False
    assert "REPOSITORY_MISMATCH" in err


def test_07_token_expiration_rejection() -> None:
    past_iso = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
        expires_at=past_iso,
    )

    valid, err = token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "TOKEN_EXPIRED" in err


def test_08_token_tampering_detection() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
    )

    # Tamper token attributes manually
    tampered = PatchApprovalToken(
        token_id=token.token_id,
        finding_id="F-TAMPERED",
        proposal_fingerprint=token.proposal_fingerprint,
        source_snapshot_hash=token.source_snapshot_hash,
        target_files=token.target_files,
        repository_identity=token.repository_identity,
        approved_by=token.approved_by,
        approved_at=token.approved_at,
        expires_at=token.expires_at,
        approval_context=token.approval_context,
        status=token.status,
        token_fingerprint=token.token_fingerprint,  # Old fingerprint
    )

    valid, err = tampered.verify_valid(
        expected_finding_id="F-TAMPERED",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "TOKEN_TAMPERED" in err


def test_09_to_dict_and_from_dict_roundtrip() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py", "utils.py"),
        repository_identity="/repo/root",
    )

    d = token.to_dict()
    restored = PatchApprovalToken.from_dict(d)

    assert restored == token
    assert restored.token_fingerprint == token.token_fingerprint


def test_10_invalid_status_rejection() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
    )
    rejected_token = PatchApprovalToken(
        token_id=token.token_id,
        finding_id=token.finding_id,
        proposal_fingerprint=token.proposal_fingerprint,
        source_snapshot_hash=token.source_snapshot_hash,
        target_files=token.target_files,
        repository_identity=token.repository_identity,
        approved_by=token.approved_by,
        approved_at=token.approved_at,
        expires_at=token.expires_at,
        approval_context=token.approval_context,
        status=ApprovalStatus.REJECTED,
        token_fingerprint=token.token_fingerprint,
    )

    valid, err = rejected_token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is False
    assert "INVALID_TOKEN_STATUS" in err


def test_11_target_files_order_invariance_in_fingerprint() -> None:
    fp1 = PatchApprovalToken.compute_fingerprint(
        token_id="tok1",
        finding_id="F1",
        proposal_fingerprint="p1",
        source_snapshot_hash="s1",
        target_files=("b.py", "a.py"),
        repository_identity="/repo",
        approved_by="user",
        approved_at="2026-08-13T00:00:00Z",
        expires_at=None,
        approval_context="ctx",
    )
    fp2 = PatchApprovalToken.compute_fingerprint(
        token_id="tok1",
        finding_id="F1",
        proposal_fingerprint="p1",
        source_snapshot_hash="s1",
        target_files=("a.py", "b.py"),
        repository_identity="/repo",
        approved_by="user",
        approved_at="2026-08-13T00:00:00Z",
        expires_at=None,
        approval_context="ctx",
    )
    assert fp1 == fp2


def test_12_windows_path_normalization_in_fingerprint() -> None:
    fp1 = PatchApprovalToken.compute_fingerprint(
        token_id="tok1",
        finding_id="F1",
        proposal_fingerprint="p1",
        source_snapshot_hash="s1",
        target_files=("foo\\bar.py",),
        repository_identity="C:\\repo\\root",
        approved_by="user",
        approved_at="2026-08-13T00:00:00Z",
        expires_at=None,
        approval_context="ctx",
    )
    fp2 = PatchApprovalToken.compute_fingerprint(
        token_id="tok1",
        finding_id="F1",
        proposal_fingerprint="p1",
        source_snapshot_hash="s1",
        target_files=("foo/bar.py",),
        repository_identity="C:/repo/root",
        approved_by="user",
        approved_at="2026-08-13T00:00:00Z",
        expires_at=None,
        approval_context="ctx",
    )
    assert fp1 == fp2


def test_13_future_expiration_token_valid() -> None:
    future_iso = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
        expires_at=future_iso,
    )

    valid, err = token.verify_valid(
        expected_finding_id="F-101",
        expected_proposal_fingerprint="prop_fp_123",
        expected_snapshot_hash="snap_hash_abc",
        expected_repository_identity="/repo/root",
    )
    assert valid is True
    assert err == "VALID"


def test_14_token_with_custom_context() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=("app.py",),
        repository_identity="/repo/root",
        approval_context="AUDITED_BY_SECOP",
    )
    assert token.approval_context == "AUDITED_BY_SECOP"


def test_15_empty_target_files_fingerprinting() -> None:
    token = PatchApprovalToken.create(
        finding_id="F-101",
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_abc",
        target_files=(),
        repository_identity="/repo/root",
    )
    assert len(token.token_fingerprint) == 64
