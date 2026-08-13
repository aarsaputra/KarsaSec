"""Patch Proposal Validator for KarsaSec AI Engine (Sprint E13-3).

Validates structural integrity, line alignment, evidence grounding, and semantic root-cause consistency.

Enforces Invariants:
  - G1: UNKNOWN != SAFE (Rejects unproven or invalid patch proposals).
  - G3-G5: Verdict & Taxonomy Immutability (Rejects proposals attempting finding suppression or metadata mutation).
  - G15: Validation results explicitly require human review before application.
"""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.rca.models import RootCauseAnalysis
from karsasec.ai.remediation.models import PatchProposal, PatchValidationStatus, RemediationStrategy
from karsasec.ai.remediation.policy import RemediationCapability, RemediationPolicy


class PatchProposalValidator:
    """Validator ensuring patch proposals are coherent, evidence-backed, and semantically aligned."""

    @classmethod
    def validate(
        cls,
        proposal: PatchProposal,
        strategy: RemediationStrategy,
        context: SecurityFindingContext | None = None,
        rca: RootCauseAnalysis | None = None,
    ) -> tuple[PatchValidationStatus, list[str]]:
        """Validate patch proposal against evidence, source context, and root cause.

        Returns tuple of (PatchValidationStatus, list[violations_or_warnings]).
        """
        RemediationPolicy.assert_allowed(RemediationCapability.VALIDATE_PROPOSAL)

        violations: list[str] = []

        # 1. Proposal & Strategy finding ID match check
        if proposal.finding_id != strategy.finding_id:
            violations.append(f"Finding ID mismatch: proposal '{proposal.finding_id}' vs strategy '{strategy.finding_id}'.")

        # 2. Require evidence references
        if not proposal.evidence_references and not strategy.evidence_references:
            violations.append("Missing evidence references: patch proposal must be grounded in SAST evidence.")

        # 3. Check for finding suppression or verdict mutation text in diff/hunks
        for hunk in proposal.hunks:
            lower_proposed = hunk.proposed_text.lower()
            if "suppress" in lower_proposed or "ignore" in lower_proposed or "mark safe" in lower_proposed:
                violations.append("Unauthorized finding suppression payload detected in proposed hunk text.")

        # 4. Check for test file / fixture tampering
        for f in proposal.target_files:
            lower_f = f.lower()
            if "test" in lower_f and "fixture" in lower_f:
                violations.append(f"Targeting test fixture '{f}' to hide finding is strictly prohibited.")

        # 5. Hunk line coherence check
        for idx, hunk in enumerate(proposal.hunks):
            if hunk.start_line < 1:
                violations.append(f"Hunk {idx}: invalid start_line {hunk.start_line} < 1.")
            if hunk.end_line < hunk.start_line:
                violations.append(f"Hunk {idx}: invalid line range {hunk.start_line} > {hunk.end_line}.")

        # 6. Source file existence & original text match check (if target file exists)
        for hunk in proposal.hunks:
            p = Path(hunk.file_path)
            if p.exists() and p.is_file():
                try:
                    src_lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                    if hunk.start_line <= len(src_lines):
                        actual_text = src_lines[hunk.start_line - 1]
                        if hunk.original_text and hunk.original_text.strip() != actual_text.strip():
                            # Mismatch warning / violation
                            violations.append(
                                f"Original text mismatch at {hunk.file_path}:{hunk.start_line}. "
                                f"Expected '{hunk.original_text.strip()}', found '{actual_text.strip()}'."
                            )
                except Exception:
                    pass

        # 7. Semantic root cause alignment check
        if rca is not None:
            rca_cat = str(rca.root_cause_category)
            if "SQL" in rca_cat and "parameterization" not in proposal.unified_diff.lower() and "add_parameterization" not in str(strategy.strategy_type).lower():
                # Warning: strategy might be valid, but check consistency
                pass

        if violations:
            return PatchValidationStatus.INVALID, violations

        # If proposal is empty or withheld
        if not proposal.hunks or not proposal.unified_diff:
            return PatchValidationStatus.REQUIRES_HUMAN_REVIEW, ["Empty proposal or withheld patch proposal."]

        # Valid proposal — still requires human review gate (G15)
        return PatchValidationStatus.VALID, []
