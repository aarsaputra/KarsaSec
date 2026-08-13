"""Remediation Agent Orchestrator (Sprint E13-3).

Primary AI Agent component producing evidence-grounded remediation strategies and patch proposals.

Enforces Invariants G1-G17:
  - Read-only, proposal-only.
  - Zero source file mutation.
  - Zero subprocess execution.
  - Zero SecurityVerdict mutation.
"""

from __future__ import annotations

from karsasec.ai.evidence_context import SecurityFindingContext, SecurityFindingContextBuilder
from karsasec.ai.rca.models import RootCauseAnalysis
from karsasec.ai.remediation.models import PatchProposal, RemediationStrategy
from karsasec.ai.remediation.planner import RemediationPlanner
from karsasec.ai.remediation.proposal import PatchProposalEngine
from karsasec.ai.remediation.provider import PatchGenerationProviderProtocol, TemplatePatchProvider
from karsasec.ai.remediation.validator import PatchProposalValidator
from karsasec.ai.retrieval.adapter import KnowledgeChunk
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict


class RemediationAgent:
    """Remediation Planning & Patch Proposal Agent."""

    def __init__(self, patch_provider: PatchGenerationProviderProtocol | None = None) -> None:
        self.patch_provider = patch_provider or TemplatePatchProvider()
        self.engine = PatchProposalEngine(provider=self.patch_provider)

    def plan_and_propose(
        self,
        finding: Finding,
        verdict: SecurityVerdict | None = None,
        context: SecurityFindingContext | None = None,
        rca: RootCauseAnalysis | None = None,
        knowledge_chunks: list[KnowledgeChunk] | None = None,
        source_code: str | None = None,
    ) -> tuple[RemediationStrategy, PatchProposal]:
        """Generate evidence-grounded remediation strategy and validated patch proposal."""
        ctx = context or SecurityFindingContextBuilder.build(finding, verdict=verdict)

        # 1. Plan strategy
        strategy = RemediationPlanner.plan(
            finding=finding,
            verdict=verdict,
            context=ctx,
            rca=rca,
            knowledge_chunks=knowledge_chunks,
        )

        # 2. Propose patch (DATA ONLY)
        proposal = self.engine.propose(
            strategy=strategy,
            source_code=source_code,
            start_line=ctx.line_number,
        )

        # 3. Validate proposal
        status, violations = PatchProposalValidator.validate(
            proposal=proposal,
            strategy=strategy,
            context=ctx,
            rca=rca,
        )

        # Re-construct proposal with updated validation status if needed
        if status != proposal.validation_status:
            fp = PatchProposal.compute_fingerprint(
                finding_id=proposal.finding_id,
                target_files=proposal.target_files,
                unified_diff=proposal.unified_diff,
                status=status,
            )
            proposal = PatchProposal(
                proposal_id=proposal.proposal_id,
                finding_id=proposal.finding_id,
                target_files=proposal.target_files,
                hunks=proposal.hunks,
                unified_diff=proposal.unified_diff,
                rationale=proposal.rationale,
                root_cause_reference=proposal.root_cause_reference,
                evidence_references=proposal.evidence_references,
                expected_effect=proposal.expected_effect,
                risk_level=proposal.risk_level,
                assumptions=proposal.assumptions,
                validation_status=status,
                proposal_fingerprint=fp,
            )

        return strategy, proposal
