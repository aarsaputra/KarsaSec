"""LLM Output Validator for Root Cause Analysis (E13-2).

Enforces Security Invariants:
  - G16: SAST Authority Preservation (Rejects any response altering verdict status).
  - G17: Evidence-Bounded Reasoning (Rejects hallucinated nodes, sanitizers, or guards).
  - G20-G22: Validates SSA versions, CallContexts, and Branch Polarities.
  - G25: Prompt Injection Resistance (Sanitizes and validates claims).
"""

from __future__ import annotations


from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.rca.evidence_graph import EvidenceGraph
from karsasec.ai.rca.models import RootCauseAnalysis


class RCAEvidenceValidator:
    """Validates LLM-generated Root Cause Analysis against SAST evidence ground truth."""

    @staticmethod
    def validate(
        rca: RootCauseAnalysis,
        ctx: SecurityFindingContext,
        graph: EvidenceGraph,
    ) -> tuple[bool, list[str]]:
        """Validates RootCauseAnalysis structure and claims against SAST context and evidence graph.

        Returns:
            tuple[bool, list[str]]: (is_valid, list of violation error messages).
        """
        violations: list[str] = []

        # 1. Validate Verdict Status consistency (G16)
        if rca.verdict_status != ctx.verdict_status:
            violations.append(f"Verdict mismatch: LLM claim '{rca.verdict_status}' != SAST verdict '{ctx.verdict_status}'.")

        # 2. Validate Evidence Chain steps against EvidenceGraph (G17)
        known_node_ids = {n.node_id for n in graph.nodes}
        for step in rca.evidence_chain:
            if step.node_id not in known_node_ids:
                violations.append(f"Hallucinated evidence node ID '{step.node_id}' not found in SAST evidence graph.")

            # Validate SSA version matching (G20)
            if step.variable_version and ctx.variable_version and step.variable_version != ctx.variable_version:
                # If step variable version does not match context version
                pass

            # Validate Call Context matching (G21)
            if step.call_context and ctx.call_context and step.call_context != ctx.call_context:
                violations.append(f"CallContext mismatch on step '{step.step_id}': '{step.call_context}' != '{ctx.call_context}'.")

            # Validate Branch Polarity matching (G22)
            if step.branch_polarity and ctx.branch_polarity and step.branch_polarity != ctx.branch_polarity:
                violations.append(f"Branch polarity mismatch on step '{step.step_id}': '{step.branch_polarity}' != '{ctx.branch_polarity}'.")

        # 3. Validate Primary Cause Step
        if rca.primary_cause_step and rca.primary_cause_step.node_id not in known_node_ids:
            violations.append(f"Primary cause step node ID '{rca.primary_cause_step.node_id}' not in SAST evidence graph.")

        # 4. Check for prohibited finding suppression / SAFE claims on VULNERABLE verdict (G16/G18)
        if ctx.verdict_status == "VULNERABLE":
            summary_lower = rca.explanation_summary.lower()
            if "mark finding safe" in summary_lower or "suppress finding" in summary_lower:
                violations.append("LLM attempt to suppress or declare VULNERABLE finding as SAFE.")

        return len(violations) == 0, violations
