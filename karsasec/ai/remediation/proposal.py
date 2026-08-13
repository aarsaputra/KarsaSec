"""Patch Proposal Engine for KarsaSec AI Engine (Sprint E13-3).

Builds immutable, data-only PatchProposal models with canonical unified diffs.

Enforces Invariants:
  - G12-G14: Pure computation (DATA ONLY, no file writing/git/subprocess APIs).
  - G15: Defaults to REQUIRES_HUMAN_REVIEW validation status; patch proposal is NOT applied.
"""

from __future__ import annotations

import difflib
from pathlib import Path

from karsasec.ai.remediation.models import (
    PatchHunk,
    PatchProposal,
    PatchValidationStatus,
    RemediationStrategy,
    RemediationStrategyType,
)
from karsasec.ai.remediation.policy import RemediationCapability, RemediationPolicy
from karsasec.ai.remediation.provider import PatchGenerationProviderProtocol, TemplatePatchProvider


class PatchProposalEngine:
    """Engine responsible for synthesizing safe patch proposals as data objects."""

    def __init__(self, provider: PatchGenerationProviderProtocol | None = None) -> None:
        self.provider = provider or TemplatePatchProvider()

    def propose(
        self,
        strategy: RemediationStrategy,
        source_code: str | None = None,
        start_line: int = 1,
    ) -> PatchProposal:
        """Construct a data-only PatchProposal with canonical unified diff."""
        # 1. Enforce safety policy
        RemediationPolicy.assert_allowed(RemediationCapability.GENERATE_PROPOSAL)

        # 2. Acquire original source code strictly read-only
        original_source = source_code
        if original_source is None:
            target_p = Path(strategy.target_file)
            if target_p.exists() and target_p.is_file():
                try:
                    original_source = target_p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    original_source = ""
            else:
                original_source = ""

        # 3. Handle MANUAL_REVIEW_REQUIRED or UNKNOWN_REMEDIATION strategies
        if strategy.strategy_type in (RemediationStrategyType.MANUAL_REVIEW_REQUIRED, RemediationStrategyType.UNKNOWN_REMEDIATION):
            proposal_id = f"proposal_{strategy.finding_id}"
            fp = PatchProposal.compute_fingerprint(
                finding_id=strategy.finding_id,
                target_files=(strategy.target_file,),
                unified_diff="",
                status=PatchValidationStatus.REQUIRES_HUMAN_REVIEW,
            )
            return PatchProposal(
                proposal_id=proposal_id,
                finding_id=strategy.finding_id,
                target_files=(strategy.target_file,),
                hunks=(),
                unified_diff="",
                rationale="Automated patch proposal withheld due to incomplete or unproven evidence.",
                root_cause_reference=str(strategy.root_cause_category),
                evidence_references=strategy.evidence_references,
                expected_effect="Manual security review required.",
                risk_level="HIGH_RISK",
                assumptions=strategy.assumptions,
                validation_status=PatchValidationStatus.REQUIRES_HUMAN_REVIEW,
                proposal_fingerprint=fp,
            )

        # 4. Generate hunks via provider
        hunks = self.provider.generate_hunks(strategy, original_source, start_line=start_line)

        # 5. Build canonical unified diff string
        unified_diff = self._build_canonical_unified_diff(strategy.target_file, original_source, hunks)

        proposal_id = f"proposal_{strategy.finding_id}"
        fp = PatchProposal.compute_fingerprint(
            finding_id=strategy.finding_id,
            target_files=(strategy.target_file,),
            unified_diff=unified_diff,
            status=PatchValidationStatus.REQUIRES_HUMAN_REVIEW,
        )

        return PatchProposal(
            proposal_id=proposal_id,
            finding_id=strategy.finding_id,
            target_files=(strategy.target_file,),
            hunks=tuple(hunks),
            unified_diff=unified_diff,
            rationale=strategy.rationale,
            root_cause_reference=str(strategy.root_cause_category),
            evidence_references=strategy.evidence_references,
            expected_effect=f"Addresses root cause '{strategy.root_cause_category}' via strategy '{strategy.strategy_type.value}'.",
            risk_level="MEDIUM_RISK",
            assumptions=strategy.assumptions,
            validation_status=PatchValidationStatus.REQUIRES_HUMAN_REVIEW,
            proposal_fingerprint=fp,
        )

    @staticmethod
    def _build_canonical_unified_diff(
        target_file: str,
        original_source: str,
        hunks: list[PatchHunk],
    ) -> str:
        """Construct deterministic, byte-for-byte stable unified diff output."""
        norm_file = target_file.replace("\\", "/")
        if not hunks:
            return ""

        orig_lines = original_source.splitlines(keepends=True)
        if not orig_lines and original_source:
            orig_lines = [original_source + "\n"]

        # Build modified source in-memory
        mod_lines = list(orig_lines)
        for h in hunks:
            idx = max(0, min(h.start_line - 1, len(mod_lines)))
            proposed = h.proposed_text if h.proposed_text.endswith("\n") else h.proposed_text + "\n"
            if idx < len(mod_lines):
                mod_lines[idx] = proposed
            else:
                mod_lines.append(proposed)

        diff_gen = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{norm_file}",
            tofile=f"b/{norm_file}",
            lineterm="\n",
        )
        return "".join(diff_gen)
