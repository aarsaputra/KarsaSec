"""Controlled Patch Applier & Atomic Rollback Engine for KarsaSec AI Engine (Sprint E13-4).

Executes controlled, human-approved patch application using constrained Python I/O.

Enforces Security Invariants:
  - H1: Explicit Approval Token Validation.
  - H2: TOCTOU Source Snapshot Protection.
  - H3: Cryptographic Proposal Fingerprint Binding.
  - H5: Transactional Byte-Exact Rollback Engine (Raw bytes backup & SHA256 verification).
  - H6: Restricted Capability Boundary (Python file I/O ONLY; ZERO subprocess/shell/git execution).
  - H7: Target File Allowlist Preflight.
  - H8: Strict Exact Hunk Matching (Exact 1 match required; zero fuzzy/ambiguous replacements).
  - H9: Path Traversal & Symlink Escape Guards.
  - H20: Atomic Commit Across Targets (ALL preflights succeed BEFORE any file write).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
from pathlib import Path
from typing import Any
import uuid

from karsasec.ai.remediation.approval import ApprovalStatus, PatchApprovalToken
from karsasec.ai.remediation.models import PatchProposal
from karsasec.ai.remediation.snapshot import SourceSnapshot


class ApplicationStatus(StrEnum):
    """Execution status for a controlled patch application transaction."""

    READY = "READY"
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    CRITICAL_RECOVERY_FAILURE = "CRITICAL_RECOVERY_FAILURE"


@dataclass(frozen=True, slots=True)
class ApplicationResult:
    """Immutable record of a controlled patch application attempt."""

    transaction_id: str
    finding_id: str
    proposal_fingerprint: str
    token_id: str
    status: ApplicationStatus
    target_files: tuple[str, ...]
    pre_apply_snapshot_hash: str
    post_apply_snapshot_hash: str
    rollback_status: str
    failure_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "finding_id": self.finding_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "token_id": self.token_id,
            "status": str(self.status),
            "target_files": list(self.target_files),
            "pre_apply_snapshot_hash": self.pre_apply_snapshot_hash,
            "post_apply_snapshot_hash": self.post_apply_snapshot_hash,
            "rollback_status": self.rollback_status,
            "failure_reason": self.failure_reason,
        }


class ControlledPatchApplier:
    """Restricted patch application engine operating strictly within Python file I/O."""

    def __init__(self, repository_root: Path | str) -> None:
        self.repository_root = Path(repository_root).resolve()

    def _validate_path_safety(self, target_rel: str) -> Path:
        """Enforces H9: Path Traversal & Symlink Escape Guards."""
        norm_rel = target_rel.replace("\\", "/")
        target_path = (self.repository_root / norm_rel).resolve()
        try:
            if not target_path.is_relative_to(self.repository_root):
                raise ValueError(f"Path traversal blocked: '{target_rel}' escapes '{self.repository_root}'.")
        except AttributeError:
            if self.repository_root not in target_path.parents and target_path != self.repository_root:
                raise ValueError(f"Path traversal blocked: '{target_rel}' escapes '{self.repository_root}'.")

        if target_path.is_symlink():
            if not target_path.resolve().is_relative_to(self.repository_root):
                raise ValueError(f"Symlink escape blocked: '{target_rel}' points outside repository.")

        return target_path

    def _rollback_transaction(
        self,
        backup_buffers: dict[Path, bytes],
        initial_file_hashes: dict[Path, str],
    ) -> tuple[str, str | None]:
        """Enforces H5: Transactional Byte-Exact Rollback & Hash Verification."""
        recovery_errors: list[str] = []

        for target_path, raw_bytes in backup_buffers.items():
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(raw_bytes)
                # Verify restored byte hash
                restored_hash = hashlib.sha256(target_path.read_bytes()).hexdigest()
                expected_hash = initial_file_hashes.get(target_path)
                if expected_hash and restored_hash != expected_hash:
                    recovery_errors.append(
                        f"Rollback hash mismatch for {target_path.name}: restored {restored_hash[:8]} != expected {expected_hash[:8]}."
                    )
            except Exception as exc:
                recovery_errors.append(f"Failed to restore {target_path.name}: {exc}")

        if recovery_errors:
            err_msg = "; ".join(recovery_errors)
            return "CRITICAL_RECOVERY_FAILURE", err_msg
        return "SUCCESS", None

    def apply(
        self,
        proposal: PatchProposal,
        token: PatchApprovalToken,
        current_snapshot: SourceSnapshot | None = None,
        transaction_id: str | None = None,
    ) -> tuple[ApplicationResult, PatchApprovalToken]:
        """Executes a controlled, human-approved patch application transaction.

        PHASE 1: Preflight Validation (H1, H2, H3, H7, H8, H9, H20 - ALL must pass BEFORE any write).
        PHASE 2: In-Memory Raw-Byte Backup & Transactional Application (H5, H6, H20).
        """
        tx_id = transaction_id or f"tx_{uuid.uuid4().hex[:12]}"
        target_files = proposal.target_files
        repo_str = str(self.repository_root)

        # ---------------------------------------------------------------------
        # PHASE 1: PREFLIGHT VALIDATION (Zero file writes)
        # ---------------------------------------------------------------------

        # 1.1 Approval Token Status & Expiration Check (H1, H19)
        if token.status == ApprovalStatus.USED:
            res = ApplicationResult(
                transaction_id=tx_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=ApplicationStatus.REJECTED,
                target_files=target_files,
                pre_apply_snapshot_hash="N/A",
                post_apply_snapshot_hash="N/A",
                rollback_status="NOT_NEEDED",
                failure_reason="TOKEN_ALREADY_USED: Approval token has already been consumed.",
            )
            return res, token

        # Capture or verify current SourceSnapshot
        try:
            snap = current_snapshot or SourceSnapshot.capture(self.repository_root, target_files)
        except ValueError as p_err:
            res = ApplicationResult(
                transaction_id=tx_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=ApplicationStatus.REJECTED,
                target_files=target_files,
                pre_apply_snapshot_hash="N/A",
                post_apply_snapshot_hash="N/A",
                rollback_status="NOT_NEEDED",
                failure_reason=f"PATH_TRAVERSAL_REJECTED: {p_err}",
            )
            return res, token

        # Verify Approval Token cryptographic binding (H1, H3, H18)
        valid, token_err = token.verify_valid(
            expected_finding_id=proposal.finding_id,
            expected_proposal_fingerprint=proposal.proposal_fingerprint,
            expected_snapshot_hash=snap.aggregate_hash,
            expected_repository_identity=repo_str,
        )
        if not valid:
            res = ApplicationResult(
                transaction_id=tx_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=ApplicationStatus.REJECTED,
                target_files=target_files,
                pre_apply_snapshot_hash=snap.aggregate_hash,
                post_apply_snapshot_hash="N/A",
                rollback_status="NOT_NEEDED",
                failure_reason=f"APPROVAL_VERIFICATION_FAILED: {token_err}",
            )
            return res, token

        # 1.2 Target Allowlist Preflight (H7)
        for hunk in proposal.hunks:
            if hunk.file_path not in target_files:
                res = ApplicationResult(
                    transaction_id=tx_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    status=ApplicationStatus.REJECTED,
                    target_files=target_files,
                    pre_apply_snapshot_hash=snap.aggregate_hash,
                    post_apply_snapshot_hash="N/A",
                    rollback_status="NOT_NEEDED",
                    failure_reason=f"TARGET_ALLOWLIST_VIOLATION: Hunk file '{hunk.file_path}' not in proposal target_files.",
                )
                return res, token

        # 1.3 Path Traversal & Symlink Safety Preflight (H9)
        target_paths: dict[str, Path] = {}
        for rel_file in target_files:
            try:
                target_paths[rel_file] = self._validate_path_safety(rel_file)
            except ValueError as p_err:
                res = ApplicationResult(
                    transaction_id=tx_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    status=ApplicationStatus.REJECTED,
                    target_files=target_files,
                    pre_apply_snapshot_hash=snap.aggregate_hash,
                    post_apply_snapshot_hash="N/A",
                    rollback_status="NOT_NEEDED",
                    failure_reason=f"PATH_TRAVERSAL_REJECTED: {p_err}",
                )
                return res, token

        # 1.4 Hunk Occurrence Preflight (H8 Strict Hunk Matching - Exact 1 Match)
        # Prepare in-memory text & backup buffers
        file_contents: dict[str, str] = {}
        backup_bytes: dict[Path, bytes] = {}
        initial_hashes: dict[Path, str] = {}

        for rel_file, path_obj in target_paths.items():
            if not path_obj.exists() or not path_obj.is_file():
                res = ApplicationResult(
                    transaction_id=tx_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    status=ApplicationStatus.REJECTED,
                    target_files=target_files,
                    pre_apply_snapshot_hash=snap.aggregate_hash,
                    post_apply_snapshot_hash="N/A",
                    rollback_status="NOT_NEEDED",
                    failure_reason=f"TARGET_FILE_MISSING: File '{rel_file}' does not exist.",
                )
                return res, token

            raw_b = path_obj.read_bytes()
            backup_bytes[path_obj] = raw_b
            initial_hashes[path_obj] = hashlib.sha256(raw_b).hexdigest()
            try:
                file_contents[rel_file] = raw_b.decode("utf-8")
            except UnicodeDecodeError:
                res = ApplicationResult(
                    transaction_id=tx_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    status=ApplicationStatus.REJECTED,
                    target_files=target_files,
                    pre_apply_snapshot_hash=snap.aggregate_hash,
                    post_apply_snapshot_hash="N/A",
                    rollback_status="NOT_NEEDED",
                    failure_reason=f"BINARY_FILE_REJECTED: File '{rel_file}' is binary/non-UTF8.",
                )
                return res, token

        # Validate each hunk against file contents (H8)
        modified_contents: dict[str, str] = dict(file_contents)

        for idx, hunk in enumerate(proposal.hunks):
            content = modified_contents[hunk.file_path]
            orig_text = hunk.original_text

            match_count = content.count(orig_text)
            if match_count == 0:
                res = ApplicationResult(
                    transaction_id=tx_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    status=ApplicationStatus.REJECTED,
                    target_files=target_files,
                    pre_apply_snapshot_hash=snap.aggregate_hash,
                    post_apply_snapshot_hash="N/A",
                    rollback_status="NOT_NEEDED",
                    failure_reason=f"EXACT_HUNK_MATCH_FAILED: Hunk {idx+1} original_text not found in '{hunk.file_path}'.",
                )
                return res, token
            elif match_count > 1:
                res = ApplicationResult(
                    transaction_id=tx_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    status=ApplicationStatus.REJECTED,
                    target_files=target_files,
                    pre_apply_snapshot_hash=snap.aggregate_hash,
                    post_apply_snapshot_hash="N/A",
                    rollback_status="NOT_NEEDED",
                    failure_reason=f"AMBIGUOUS_HUNK_MATCH: Hunk {idx+1} matches {match_count} occurrences in '{hunk.file_path}'. Exact 1 match required.",
                )
                return res, token

            # Apply single replacement in-memory buffer
            modified_contents[hunk.file_path] = content.replace(orig_text, hunk.proposed_text, 1)

        # ---------------------------------------------------------------------
        # PHASE 2: ATOMIC MUTATION & ROLLBACK (H5, H6, H20)
        # ---------------------------------------------------------------------
        try:
            for rel_file, new_text in modified_contents.items():
                path_obj = target_paths[rel_file]
                path_obj.write_bytes(new_text.encode("utf-8"))

            # Post-write snapshot validation
            post_snap = SourceSnapshot.capture(self.repository_root, target_files)
            used_token = token.mark_used()

            res = ApplicationResult(
                transaction_id=tx_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=ApplicationStatus.APPLIED,
                target_files=target_files,
                pre_apply_snapshot_hash=snap.aggregate_hash,
                post_apply_snapshot_hash=post_snap.aggregate_hash,
                rollback_status="NOT_NEEDED",
                failure_reason=None,
            )
            return res, used_token

        except Exception as exc:
            # Trigger Atomic Rollback Engine (H5)
            rb_status, rb_err = self._rollback_transaction(backup_bytes, initial_hashes)
            final_status = (
                ApplicationStatus.CRITICAL_RECOVERY_FAILURE
                if rb_status == "CRITICAL_RECOVERY_FAILURE"
                else ApplicationStatus.FAILED
            )

            fail_msg = f"APPLICATION_WRITE_FAILED: {exc}"
            if rb_err:
                fail_msg += f" | ROLLBACK_ERROR: {rb_err}"

            res = ApplicationResult(
                transaction_id=tx_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=final_status,
                target_files=target_files,
                pre_apply_snapshot_hash=snap.aggregate_hash,
                post_apply_snapshot_hash="N/A",
                rollback_status=rb_status,
                failure_reason=fail_msg,
            )
            return res, token
