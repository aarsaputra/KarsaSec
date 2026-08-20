"""Side-Effect-Free RTP Builder Adapter (Sprint F0).

Extracts evidence commitments from RemediationLifecycleResult and constructs an immutable
RemediationTransactionPackage (RTP).

Enforces Security Invariants:
  - R7-R9: Privacy Boundary (Zero raw source code, zero raw diff text, zero credentials).
  - R24-R28: Observational & Side-Effect Free (Zero file mutations, zero subprocess/git execution).
"""

from __future__ import annotations

import datetime
from typing import Any
import uuid

from karsasec.ai.remediation.lifecycle import RemediationLifecycleResult
from karsasec.ai.remediation.rtp.errors import RTPPrivacyError
from karsasec.ai.remediation.rtp.models import (
    ApprovalCommitment,
    ApplicationCommitment,
    AuditCommitment,
    EvidenceCommitment,
    FindingCommitment,
    ProposalCommitment,
    ProvenanceCommitment,
    RTP_SCHEMA_NAME,
    RTP_SCHEMA_VERSION,
    RemediationTransactionPackage,
    RootCauseCommitment,
    StrategyCommitment,
    VerificationCommitment,
)

# Prohibited key substrings for privacy validation
_PROHIBITED_METADATA_KEYS = {
    "source_code",
    "raw_source",
    "diff",
    "patch_content",
    "original_text",
    "proposed_text",
    "password",
    "secret",
    "api_key",
    "access_token",
}


def _verify_privacy_safety(data: dict[str, Any] | list[Any] | str) -> None:
    """Verifies that no prohibited sensitive fields or keys exist in payload."""
    if isinstance(data, dict):
        for k, v in data.items():
            key_lower = str(k).lower().strip()
            for prohib in _PROHIBITED_METADATA_KEYS:
                if prohib in key_lower:
                    raise RTPPrivacyError(f"Privacy violation: prohibited key detected '{k}'")
            _verify_privacy_safety(v)
    elif isinstance(data, list):
        for item in data:
            _verify_privacy_safety(item)


class RemediationTransactionPackageBuilder:
    """Observational, side-effect-free builder producing immutable RTP objects."""

    @classmethod
    def build(
        cls,
        lifecycle_result: RemediationLifecycleResult,
        transaction_id: str | None = None,
        created_at: str | None = None,
    ) -> RemediationTransactionPackage:
        """Extracts commitments from RemediationLifecycleResult to construct an immutable RTP.

        READ ONLY. Zero state machine or filesystem mutation.
        """
        tx_id = transaction_id or f"RTP-{uuid.uuid4().hex[:12]}"
        timestamp = created_at or datetime.datetime.now(datetime.UTC).isoformat()
        norm_repo = lifecycle_result.repository_identity.replace("\\", "/").rstrip("/")

        f = lifecycle_result.finding
        file_p = str(f.file_path).replace("\\", "/")
        line_no = f.evidence.line if f.evidence else (f.verdict.line_number if f.verdict else 0)
        cwe_id = f.cwe_id or "UNKNOWN"

        finding_commit = FindingCommitment(
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            severity=str(f.severity),
            cwe=cwe_id,
            file_path=file_p,
            line_number=line_no,
            finding_fingerprint=f.fingerprint,
        )

        # Evidence Commitment
        ev_commit: EvidenceCommitment | None = None
        verdict = getattr(f, "verdict", None)
        df_path = getattr(verdict, "dataflow_path", None) if verdict else None
        if df_path:
            ev_count = len(df_path)
            ev_commit = EvidenceCommitment(
                evidence_count=ev_count,
                evidence_fingerprint=str(verdict.evidence_fingerprint),
            )

        # RCA Commitment
        rca_commit: RootCauseCommitment | None = None
        if lifecycle_result.rca:
            rca = lifecycle_result.rca
            rca_commit = RootCauseCommitment(
                rca_category=str(getattr(rca, "root_cause_category", rca)),
                confidence=float(getattr(rca, "confidence", 1.0)),
                rca_fingerprint=str(getattr(rca, "rca_fingerprint", "")),
            )

        # Strategy Commitment
        strat_commit: StrategyCommitment | None = None
        if lifecycle_result.strategy:
            st = lifecycle_result.strategy
            strat_commit = StrategyCommitment(
                strategy_type=str(getattr(st, "strategy_type", st)),
                target_file=str(getattr(st, "target_file", "")).replace("\\", "/"),
                strategy_fingerprint=str(getattr(st, "strategy_fingerprint", "")),
            )

        # Proposal Commitment (Privacy-safe: zero raw diff text)
        prop_commit: ProposalCommitment | None = None
        if lifecycle_result.proposal:
            p = lifecycle_result.proposal
            prop_commit = ProposalCommitment(
                proposal_id=str(getattr(p, "proposal_id", "")),
                risk_level=str(getattr(p, "risk_level", "")),
                target_files=tuple(str(tf).replace("\\", "/") for tf in getattr(p, "target_files", ())),
                proposal_fingerprint=str(getattr(p, "proposal_fingerprint", "")),
            )

        # Approval Commitment
        appr_commit: ApprovalCommitment | None = None
        if lifecycle_result.approval_token:
            tok = lifecycle_result.approval_token
            appr_commit = ApprovalCommitment(
                approval_token_id=str(getattr(tok, "token_id", "")),
                approver=str(getattr(tok, "approved_by", "")),
                approval_status=str(getattr(tok, "status", "")),
                approval_fingerprint=str(getattr(tok, "token_fingerprint", "")),
            )

        # Application Commitment
        app_commit: ApplicationCommitment | None = None
        if lifecycle_result.source_snapshot and lifecycle_result.application_result:
            src_snap = getattr(
                lifecycle_result.source_snapshot,
                "aggregate_hash",
                getattr(lifecycle_result.source_snapshot, "snapshot_hash", ""),
            )
            app_res = lifecycle_result.application_result
            post_snap = getattr(
                app_res,
                "post_apply_snapshot_hash",
                getattr(getattr(app_res, "post_apply_snapshot", None), "aggregate_hash", src_snap),
            )
            app_commit = ApplicationCommitment(
                source_snapshot_hash=str(src_snap),
                post_apply_snapshot_hash=str(post_snap),
                application_status=str(getattr(app_res, "status", "")),
            )

        # Verification Commitment
        ver_commit: VerificationCommitment | None = None
        if lifecycle_result.verification_result:
            v_res = lifecycle_result.verification_result
            ver_commit = VerificationCommitment(
                verification_run_id=str(getattr(v_res, "verification_id", "")),
                status=str(getattr(v_res, "status", "")),
                matching_findings_count=int(getattr(v_res, "matching_findings_count", 0)),
                verification_fingerprint=str(getattr(v_res, "verification_fingerprint", "")),
            )

        # Provenance Commitment
        prov_commit = ProvenanceCommitment(
            graph_fingerprint=str(getattr(lifecycle_result.provenance_graph, "graph_fingerprint", ""))
        )

        # Audit Commitment
        audit_commit = AuditCommitment(
            ledger_fingerprint=str(getattr(lifecycle_result.ledger, "ledger_fingerprint", ""))
        )

        # Compute overarching receipt fingerprint
        pkg_fp = RemediationTransactionPackage.compute_package_fingerprint(
            schema_name=RTP_SCHEMA_NAME,
            schema_version=RTP_SCHEMA_VERSION,
            transaction_id=tx_id,
            repository_identity=norm_repo,
            created_at=timestamp,
            status=str(lifecycle_result.current_state),
            finding=finding_commit,
            evidence=ev_commit,
            root_cause=rca_commit,
            strategy=strat_commit,
            proposal=prop_commit,
            approval=appr_commit,
            application=app_commit,
            verification=ver_commit,
            provenance=prov_commit,
            audit=audit_commit,
        )

        rtp = RemediationTransactionPackage(
            schema_name=RTP_SCHEMA_NAME,
            schema_version=RTP_SCHEMA_VERSION,
            transaction_id=tx_id,
            repository_identity=norm_repo,
            created_at=timestamp,
            status=str(lifecycle_result.current_state),
            finding=finding_commit,
            evidence=ev_commit,
            root_cause=rca_commit,
            strategy=strat_commit,
            proposal=prop_commit,
            approval=appr_commit,
            application=app_commit,
            verification=ver_commit,
            provenance=prov_commit,
            audit=audit_commit,
            receipt_fingerprint=pkg_fp,
        )

        # Validate privacy safety
        _verify_privacy_safety(rtp.to_dict())

        return rtp
