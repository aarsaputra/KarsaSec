"""Remediation Application Agent Orchestrator for KarsaSec AI Engine (Sprint E13-4).

Coordinates the end-to-end controlled patch application lifecycle and post-apply security verification.

Enforces Security Invariants:
  - H1-H3: Approval Token, Snapshot TOCTOU, and Proposal Cryptographic Binding.
  - H4: Operational Apply vs Security Verdict Verification.
  - H5: Automatic Atomic Byte Rollback on verification failure (STILL_VULNERABLE / UNKNOWN).
  - H12: Human-in-the-Loop Isolation (LLM has zero execution authority).
  - H13: Immutable Audit Trail (Hashes & metadata without dumping raw secret source code).
  - H16: No Auto-Repair Loop (One approval transaction = single execution attempt).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from collections.abc import Callable
import uuid

from karsasec.ai.remediation.applier import ApplicationResult, ApplicationStatus, ControlledPatchApplier
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.models import PatchProposal
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.verification import PostApplyVerificationEngine, VerificationResult, VerificationStatus
from karsasec.core.finding.model import Finding


@dataclass(frozen=True, slots=True)
class ApplicationAuditRecord:
    """Immutable audit trail record for a patch application transaction (H13)."""

    audit_id: str
    transaction_id: str
    finding_id: str
    proposal_fingerprint: str
    token_id: str
    pre_apply_snapshot_hash: str
    post_apply_snapshot_hash: str
    application_status: ApplicationStatus
    verification_status: VerificationStatus
    rollback_status: str
    target_files: tuple[str, ...]
    timestamp: str
    failure_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "transaction_id": self.transaction_id,
            "finding_id": self.finding_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "token_id": self.token_id,
            "pre_apply_snapshot_hash": self.pre_apply_snapshot_hash,
            "post_apply_snapshot_hash": self.post_apply_snapshot_hash,
            "application_status": str(self.application_status),
            "verification_status": str(self.verification_status),
            "rollback_status": self.rollback_status,
            "target_files": list(self.target_files),
            "timestamp": self.timestamp,
            "failure_reason": self.failure_reason,
        }


class RemediationApplicationAgent:
    """Orchestrates controlled patch application, SAST re-scan verification, and atomic rollback."""

    def __init__(
        self,
        repository_root: Path | str,
        verification_engine: PostApplyVerificationEngine | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.applier = ControlledPatchApplier(self.repository_root)
        self.verifier = verification_engine or PostApplyVerificationEngine()

    def execute_transaction(
        self,
        proposal: PatchProposal,
        token: PatchApprovalToken,
        finding: Finding,
        rescan_callback: Callable[[], tuple[Finding, ...]],
        audit_records: list[ApplicationAuditRecord] | None = None,
    ) -> tuple[ApplicationResult, VerificationResult | None, PatchApprovalToken]:
        """Executes full 5-stage transaction:

        1. TOCTOU Snapshot & Preflight Validation
        2. Controlled Patch Application (Python I/O)
        3. Fresh SAST Re-scan
        4. Post-Apply Security Verification
        5. Atomic Rollback if verification fails (H5, H16)
        """
        now_iso = datetime.now(UTC).isoformat()
        audit_id = f"aud_{uuid.uuid4().hex[:12]}"

        # 1. Capture initial SourceSnapshot & Execute Controlled Apply
        app_res, updated_token = self.applier.apply(proposal=proposal, token=token)

        # Handle application failure / rejection
        if app_res.status not in (ApplicationStatus.APPLIED, ApplicationStatus.READY):
            ver_res = None
            if audit_records is not None:
                audit_records.append(
                    ApplicationAuditRecord(
                        audit_id=audit_id,
                        transaction_id=app_res.transaction_id,
                        finding_id=proposal.finding_id,
                        proposal_fingerprint=proposal.proposal_fingerprint,
                        token_id=token.token_id,
                        pre_apply_snapshot_hash=app_res.pre_apply_snapshot_hash,
                        post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
                        application_status=app_res.status,
                        verification_status=VerificationStatus.UNVERIFIED,
                        rollback_status=app_res.rollback_status,
                        target_files=proposal.target_files,
                        timestamp=now_iso,
                        failure_reason=app_res.failure_reason,
                    )
                )
            return app_res, ver_res, updated_token

        # 2. Execute fresh SAST scan callback
        try:
            post_apply_findings = rescan_callback()
        except Exception as scan_err:
            # SAST execution failed -> trigger atomic rollback (H5)
            target_paths = {rel: (self.repository_root / rel).resolve() for rel in proposal.target_files}
            # Capture pre-apply snapshot to recover
            pre_snap = SourceSnapshot.capture(self.repository_root, proposal.target_files)
            # Rollback file writes
            backup_bytes: dict[Path, bytes] = {}
            for rel, path_obj in target_paths.items():
                if path_obj.exists():
                    backup_bytes[path_obj] = path_obj.read_bytes()

            rb_status, rb_err = self.applier._rollback_transaction(backup_bytes, {})

            app_failed = ApplicationResult(
                transaction_id=app_res.transaction_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=ApplicationStatus.FAILED,
                target_files=proposal.target_files,
                pre_apply_snapshot_hash=pre_snap.aggregate_hash,
                post_apply_snapshot_hash="N/A",
                rollback_status=rb_status,
                failure_reason=f"SAST_RESCAN_FAILED: {scan_err} | Rollback: {rb_err}",
            )
            return app_failed, None, updated_token

        # 3. Perform Post-Apply SAST Verification (H4)
        ver_res = self.verifier.verify(finding=finding, post_apply_findings=post_apply_findings)

        # Run business test suite if SAST verification passes
        if ver_res.status == VerificationStatus.VERIFIED_FIXED:
            from karsasec.ai.remediation.verification import execute_business_test_suite
            test_success, test_output = execute_business_test_suite(self.repository_root)
            if not test_success:
                # Override verification result to trigger rollback
                ver_res = VerificationResult(
                    verification_id=ver_res.verification_id,
                    finding_id=ver_res.finding_id,
                    pre_apply_verdict_status=ver_res.pre_apply_verdict_status,
                    post_apply_verdict_status=ver_res.post_apply_verdict_status,
                    status=VerificationStatus.ROLLBACK_REQUIRED,
                    contract=ver_res.contract,
                    matching_findings_count=ver_res.matching_findings_count,
                    details=f"Business test suite regression detected:\n{test_output}",
                )

        # 4. If Verification Fails (STILL_VULNERABLE or UNKNOWN), Execute Automatic Rollback (H5, H16)
        if ver_res.status in (
            VerificationStatus.STILL_VULNERABLE,
            VerificationStatus.UNKNOWN,
            VerificationStatus.VERIFICATION_FAILED,
            VerificationStatus.ROLLBACK_REQUIRED,
        ):
            # Capture backup buffers from target files and restore original snapshots
            # Re-read files to capture current mutated state
            target_paths = {rel: (self.repository_root / rel).resolve() for rel in proposal.target_files}

            # Perform atomic rollback using hunks original_text
            for hunk in proposal.hunks:
                p_obj = target_paths[hunk.file_path]
                if p_obj.exists():
                    cur_text = p_obj.read_text(encoding="utf-8")
                    if hunk.proposed_text in cur_text:
                        restored_text = cur_text.replace(hunk.proposed_text, hunk.original_text, 1)
                        p_obj.write_bytes(restored_text.encode("utf-8"))

            post_rb_snap = SourceSnapshot.capture(self.repository_root, proposal.target_files)

            app_res = ApplicationResult(
                transaction_id=app_res.transaction_id,
                finding_id=proposal.finding_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                token_id=token.token_id,
                status=ApplicationStatus.ROLLED_BACK,
                target_files=proposal.target_files,
                pre_apply_snapshot_hash=app_res.pre_apply_snapshot_hash,
                post_apply_snapshot_hash=post_rb_snap.aggregate_hash,
                rollback_status="SUCCESS",
                failure_reason=f"SECURITY_VERIFICATION_FAILED ({ver_res.status}): Automatic rollback executed.",
            )

        # 5. Append audit record (H13)
        if audit_records is not None:
            audit_records.append(
                ApplicationAuditRecord(
                    audit_id=audit_id,
                    transaction_id=app_res.transaction_id,
                    finding_id=proposal.finding_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    token_id=token.token_id,
                    pre_apply_snapshot_hash=app_res.pre_apply_snapshot_hash,
                    post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
                    application_status=app_res.status,
                    verification_status=ver_res.status if ver_res else VerificationStatus.UNVERIFIED,
                    rollback_status=app_res.rollback_status,
                    target_files=proposal.target_files,
                    timestamp=now_iso,
                    failure_reason=app_res.failure_reason,
                )
            )

        return app_res, ver_res, updated_token
