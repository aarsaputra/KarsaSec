"""Post-Apply Security Verification Engine for KarsaSec AI Engine (Sprint E13-4).

Evaluates fresh post-apply SAST scan results against a semantic vulnerability contract.

Enforces Security Invariants:
  - H4: Apply DOES NOT Equal Fixed (Operational state vs Security verdict).
  - H10: Finding & Verdict Immutability (Historical verdicts remain untouched; separate VerificationResult created).
  - H15: Historical Evidence Preservation (Append-only lifecycle verification).
  - H21: SAST Verification is Security Correctness Authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
import uuid

from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import VerdictStatus


class VerificationStatus(StrEnum):
    """Lifecycle verification state for an applied patch."""

    UNVERIFIED = "UNVERIFIED"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    UNKNOWN = "UNKNOWN"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"


@dataclass(frozen=True, slots=True)
class VerificationContract:
    """Semantic vulnerability contract capturing pre-apply security properties."""

    finding_id: str
    rule_id: str
    cwe_id: str
    sink_category: str
    file_path: str
    line_number: int
    affected_symbol: str
    evidence_fingerprint: str

    @classmethod
    def from_finding(cls, finding: Finding) -> VerificationContract:
        v = finding.verdict
        file_p = str(finding.file_path).replace("\\", "/")
        rule_id = finding.rule_id
        cwe_id = finding.cwe_id or "UNKNOWN"
        sink_cat = v.sink_category if v else "UNKNOWN"
        line_no = finding.evidence.line if finding.evidence else (v.line_number if v else 0)
        symbol = v.variable_version if v else "UNKNOWN"
        ev_fp = v.evidence_fingerprint if v else finding.fingerprint

        return cls(
            finding_id=finding.finding_id,
            rule_id=rule_id,
            cwe_id=cwe_id,
            sink_category=sink_cat,
            file_path=file_p,
            line_number=line_no,
            affected_symbol=symbol,
            evidence_fingerprint=ev_fp,
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Immutable record of post-apply security verification."""

    verification_id: str
    finding_id: str
    pre_apply_verdict_status: str
    post_apply_verdict_status: str
    status: VerificationStatus
    contract: VerificationContract
    matching_findings_count: int
    details: str

    @property
    def verification_fingerprint(self) -> str:
        """Compute deterministic SHA-256 fingerprint for verification result."""
        import hashlib

        raw = f"{self.verification_id}|{self.finding_id}|{self.status}|{self.pre_apply_verdict_status}|{self.post_apply_verdict_status}|{self.matching_findings_count}|{self.contract.evidence_fingerprint if self.contract else ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "finding_id": self.finding_id,
            "pre_apply_verdict_status": self.pre_apply_verdict_status,
            "post_apply_verdict_status": self.post_apply_verdict_status,
            "status": str(self.status),
            "matching_findings_count": self.matching_findings_count,
            "verification_fingerprint": self.verification_fingerprint,
            "details": self.details,
        }


class PostApplyVerificationEngine:
    """Deterministic verifier comparing post-apply SAST scan findings against pre-apply contract."""

    def verify(
        self,
        finding: Finding,
        post_apply_findings: tuple[Finding, ...],
        verification_id: str | None = None,
    ) -> VerificationResult:
        """Evaluates fresh post-apply SAST scan findings against pre-apply contract (H4).

        Does NOT rely solely on finding_id presence; performs semantic contract matching.
        Does NOT mutate finding.verdict (H10 Immutability).
        """
        vid = verification_id or f"ver_{uuid.uuid4().hex[:12]}"
        contract = VerificationContract.from_finding(finding)
        pre_status = str(finding.verdict.status) if finding.verdict else "VULNERABLE"

        # Semantic contract matching against fresh scan findings
        semantic_matches: list[Finding] = []
        for post_f in post_apply_findings:
            post_v = post_f.verdict
            post_file = str(post_f.file_path).replace("\\", "/")
            post_rule = post_f.rule_id
            post_cwe = post_f.cwe_id or "UNKNOWN"
            post_sink_cat = post_v.sink_category if post_v else "UNKNOWN"

            # Match criteria: same file + (same rule or CWE) + same sink category
            if post_file == contract.file_path:
                if post_rule == contract.rule_id or (contract.cwe_id != "UNKNOWN" and post_cwe == contract.cwe_id):
                    if post_sink_cat == contract.sink_category or contract.sink_category == "UNKNOWN":
                        # Verify if verdict is active VULNERABLE
                        if post_v is None or post_v.status == VerdictStatus.VULNERABLE:
                            semantic_matches.append(post_f)

        match_count = len(semantic_matches)

        if match_count == 0:
            status = VerificationStatus.VERIFIED_FIXED
            post_verdict_str = "SAFE"
            details = (
                f"Vulnerability {contract.rule_id} ({contract.cwe_id}) successfully eliminated in {contract.file_path}."
            )
        else:
            status = VerificationStatus.STILL_VULNERABLE
            post_verdict_str = "VULNERABLE"
            details = f"Vulnerability persists post-patch: {match_count} matching SAST findings detected in {contract.file_path}."

        return VerificationResult(
            verification_id=vid,
            finding_id=finding.finding_id,
            pre_apply_verdict_status=pre_status,
            post_apply_verdict_status=post_verdict_str,
            status=status,
            contract=contract,
            matching_findings_count=match_count,
            details=details,
        )
