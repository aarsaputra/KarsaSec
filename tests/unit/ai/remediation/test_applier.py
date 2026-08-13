"""Unit tests for ControlledPatchApplier and Atomic Byte Rollback (Sprint E13-4)."""

from __future__ import annotations

from pathlib import Path


from karsasec.ai.remediation.applier import ApplicationStatus, ControlledPatchApplier
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.models import PatchHunk, PatchProposal, PatchValidationStatus
from karsasec.ai.remediation.snapshot import SourceSnapshot


def _create_test_proposal(
    finding_id: str = "F-201",
    target_files: tuple[str, ...] = ("app.py",),
    hunks: tuple[PatchHunk, ...] = (),
) -> PatchProposal:
    if not hunks:
        hunks = (
            PatchHunk(
                file_path=target_files[0],
                start_line=5,
                end_line=5,
                original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
                proposed_text="cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
                context="db query",
                evidence_reference=f"{target_files[0]}:5",
            ),
        )
    diff = f"--- a/{target_files[0]}\n+++ b/{target_files[0]}\n@@ -5,1 +5,1 @@\n-{hunks[0].original_text}\n+{hunks[0].proposed_text}\n"
    fp = PatchProposal.compute_fingerprint(finding_id, target_files, diff, PatchValidationStatus.VALID)

    return PatchProposal(
        proposal_id=f"prop_{finding_id}",
        finding_id=finding_id,
        target_files=target_files,
        hunks=hunks,
        unified_diff=diff,
        rationale="Parameterization fix",
        root_cause_reference="RCA-201",
        evidence_references=("app.py:5",),
        expected_effect="Eliminate SQLi",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=fp,
    )


def test_01_successful_controlled_patch_application(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    orig_code = "import sqlite3\n\ndef query(name):\n    conn = sqlite3.connect('db.sqlite')\n    cursor = conn.cursor()\n    cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
    src_file.write_text(orig_code, encoding="utf-8")

    proposal = _create_test_proposal()
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, updated_token = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.APPLIED
    assert updated_token.status.value == "USED"
    assert "cursor.execute('SELECT * FROM users WHERE name=?', (name,))" in src_file.read_text(encoding="utf-8")


def test_02_hunk_occurrence_zero_rejection(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("code without expected snippet\n", encoding="utf-8")

    proposal = _create_test_proposal()
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "EXACT_HUNK_MATCH_FAILED" in res.failure_reason


def test_03_hunk_occurrence_ambiguous_multiple_matches_rejection(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    dup_code = (
        "cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
        "cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
    )
    src_file.write_text(dup_code, encoding="utf-8")

    proposal = _create_test_proposal()
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "AMBIGUOUS_HUNK_MATCH" in res.failure_reason


def test_04_target_allowlist_violation_rejection(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("cursor.execute('SELECT * FROM users WHERE name=' + name)\n", encoding="utf-8")

    # Hunk file path 'unauthorized.py' not in target_files ('app.py',)
    bad_hunk = PatchHunk(
        file_path="unauthorized.py",
        start_line=1,
        end_line=1,
        original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
        proposed_text="safe()",
        context="",
        evidence_reference="",
    )
    proposal = _create_test_proposal(hunks=(bad_hunk,))
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "TARGET_ALLOWLIST_VIOLATION" in res.failure_reason


def test_05_path_traversal_attack_rejection(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("data", encoding="utf-8")

    proposal = _create_test_proposal(target_files=("../secret.py",))
    snap = SourceSnapshot(
        repository_root=str(tmp_path.resolve()),
        file_snapshots=(),
        aggregate_hash="fake_hash",
        created_at="now",
    )
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "PATH_TRAVERSAL_REJECTED" in res.failure_reason


def test_06_toctou_source_snapshot_hash_mismatch_rejection(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("cursor.execute('SELECT * FROM users WHERE name=' + name)\n", encoding="utf-8")

    proposal = _create_test_proposal()
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash="old_stale_hash",  # Stale snapshot hash
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token)

    assert res.status == ApplicationStatus.REJECTED
    assert "SNAPSHOT_HASH_MISMATCH" in res.failure_reason


def test_07_token_already_used_rejection(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("cursor.execute('SELECT * FROM users WHERE name=' + name)\n", encoding="utf-8")

    proposal = _create_test_proposal()
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )
    used_token = token.mark_used()

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, used_token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "TOKEN_ALREADY_USED" in res.failure_reason


def test_08_atomic_rollback_on_write_failure(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    orig_content = "cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
    src_file.write_text(orig_content, encoding="utf-8")

    proposal = _create_test_proposal()
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    # Make file read-only to trigger write permission error
    src_file.chmod(0o444)

    try:
        applier = ControlledPatchApplier(tmp_path)
        res, _ = applier.apply(proposal, token, snap)
        assert res.status in (ApplicationStatus.FAILED, ApplicationStatus.CRITICAL_RECOVERY_FAILURE)
        assert res.rollback_status in ("SUCCESS", "CRITICAL_RECOVERY_FAILURE")
    finally:
        src_file.chmod(0o644)


def test_09_multi_file_atomic_patch_application(tmp_path: Path) -> None:
    f1 = tmp_path / "app.py"
    f1.write_text("code1: cursor.execute('SELECT * FROM users WHERE name=' + name)\n", encoding="utf-8")
    f2 = tmp_path / "db.py"
    f2.write_text("code2: query = 'SELECT * FROM items WHERE id=' + id\n", encoding="utf-8")

    hunk1 = PatchHunk(
        file_path="app.py",
        start_line=1,
        end_line=1,
        original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
        proposed_text="cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
        context="",
        evidence_reference="app.py:1",
    )
    hunk2 = PatchHunk(
        file_path="db.py",
        start_line=1,
        end_line=1,
        original_text="query = 'SELECT * FROM items WHERE id=' + id",
        proposed_text="query = 'SELECT * FROM items WHERE id=?', (id,)",
        context="",
        evidence_reference="db.py:1",
    )
    proposal = _create_test_proposal(target_files=("app.py", "db.py"), hunks=(hunk1, hunk2))

    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.APPLIED
    assert "name=?" in f1.read_text(encoding="utf-8")
    assert "id=?" in f2.read_text(encoding="utf-8")


def test_10_atomic_preflight_prevents_partial_file_writes(tmp_path: Path) -> None:
    f1 = tmp_path / "app.py"
    f1.write_text("code1: cursor.execute('SELECT * FROM users WHERE name=' + name)\n", encoding="utf-8")
    f2 = tmp_path / "db.py"
    f2.write_text("code2 without match\n", encoding="utf-8")

    hunk1 = PatchHunk(
        file_path="app.py",
        start_line=1,
        end_line=1,
        original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
        proposed_text="safe()",
        context="",
        evidence_reference="",
    )
    hunk2 = PatchHunk(
        file_path="db.py",
        start_line=1,
        end_line=1,
        original_text="NON_EXISTENT_TEXT",  # Fails preflight
        proposed_text="safe()",
        context="",
        evidence_reference="",
    )
    proposal = _create_test_proposal(target_files=("app.py", "db.py"), hunks=(hunk1, hunk2))

    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    # Assert zero bytes were written to file 1 (app.py remains unmodified)
    assert "code1: cursor.execute('SELECT * FROM users WHERE name=' + name)" in f1.read_text(encoding="utf-8")


def test_11_binary_file_rejection(tmp_path: Path) -> None:
    bin_file = tmp_path / "app.py"
    bin_file.write_bytes(b"\x80\x81\x82\xff\xfe\xfd")

    proposal = _create_test_proposal()
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "BINARY_FILE_REJECTED" in res.failure_reason


def test_12_non_existent_target_file_rejection(tmp_path: Path) -> None:
    proposal = _create_test_proposal(target_files=("missing.py",))
    snap = SourceSnapshot(
        repository_root=str(tmp_path.resolve()),
        file_snapshots=(),
        aggregate_hash="hash",
        created_at="now",
    )
    token = PatchApprovalToken.create(
        finding_id=proposal.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    applier = ControlledPatchApplier(tmp_path)
    res, _ = applier.apply(proposal, token, snap)

    assert res.status == ApplicationStatus.REJECTED
    assert "TARGET_FILE_MISSING" in res.failure_reason
