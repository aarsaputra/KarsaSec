"""Central AI Agent Skill Registry for KarsaSec.

Unifies Daytona, Agent Skills, Claude Secure Rules, and CodeGuard Guardrails
into an atomic pipeline for AI patch generation & security audits.
"""

from typing import Dict, Any, Optional
from .daytona_sandbox import DaytonaSandboxSkill
from .agent_skills_budget import AgentSkillsBudgetSkill
from .claude_secure_rules import ClaudeSecureCodingSkill
from .codeguard_verifier import CodeGuardVerifierSkill


class AISkillRegistry:
    """Unified Skill Registry providing Daytona, Agent Skills, Claude Rules, and CodeGuard capabilities."""

    def __init__(self, workspace_path: str = "."):
        self.daytona = DaytonaSandboxSkill(workspace_path=workspace_path)
        self.budget = AgentSkillsBudgetSkill()
        self.secure_rules = ClaudeSecureCodingSkill()
        self.codeguard = CodeGuardVerifierSkill()

    def execute_pre_patch_validation(
        self,
        file_path: str,
        target_line: int,
        patch_code: str,
        language: str = "python"
    ) -> Dict[str, Any]:
        """Runs pre-patch security validation across all 4 skill pillars before submitting for SAST rescan."""
        # 1. Prune context window using Agent Skills budget
        prune_res = self.budget.prune_file_context(file_path, target_line)

        # 2. Audit against Claude Secure Coding rules
        rule_res = self.secure_rules.audit_proposed_patch(patch_code)

        # 3. Verify safety & anti-hallucination using CodeGuard
        guard_res = self.codeguard.verify_patch_safety(patch_code, language=language)

        is_passed = (rule_res["passed"] and guard_res["is_safe"])

        return {
            "passed": is_passed,
            "fail_closed": not is_passed,
            "pruned_context": prune_res,
            "secure_coding_audit": rule_res,
            "codeguard_review": guard_res
        }
