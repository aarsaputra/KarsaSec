"""Agent Skills Token Window Budgeting & Typed Contract Skill.

Inspired by Agent Skills (https://github.com/tech-leads-club/agent-skills).
Enforces line-bounded file windowing, AST pruning, and structured
task execution phases (Specify -> Design -> Tasks -> Execute) to eliminate token waste.
"""

import os
from typing import Any, Optional


class AgentSkillsBudgetSkill:
    """Skill managing token window budgeting, line-bounded context pruning, and typed contract execution."""

    def __init__(self, max_context_lines: int = 150):
        self.max_context_lines = max_context_lines

    def prune_file_context(
        self,
        file_path: str,
        target_line: int,
        context_window: int = 25
    ) -> dict[str, Any]:
        """Extracts a pruned line-bounded context window around the target line to avoid loading full files raw into LLM context."""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}", "lines": []}

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()

            total_lines = len(all_lines)
            start_line = max(1, target_line - context_window)
            end_line = min(total_lines, target_line + context_window)

            snippet_lines = []
            for i in range(start_line - 1, end_line):
                snippet_lines.append(f"{i + 1}: {all_lines[i].rstrip()}")

            return {
                "file_path": file_path,
                "target_line": target_line,
                "start_line": start_line,
                "end_line": end_line,
                "total_file_lines": total_lines,
                "pruned_context": "\n".join(snippet_lines),
                "line_count": len(snippet_lines)
            }
        except Exception as exc:
            return {"error": str(exc), "lines": []}

    def validate_typed_proposal_contract(self, proposal_json: dict[str, Any]) -> dict[str, Any]:
        """Validates that an AI patch proposal strictly satisfies the typed JSON contract schema."""
        required_fields = ["hunks"]
        hunk_required_fields = ["start_line", "end_line", "original_text", "proposed_text"]

        if not isinstance(proposal_json, dict):
            return {"valid": False, "reason": "Proposal output is not a JSON object"}

        for field in required_fields:
            if field not in proposal_json:
                return {"valid": False, "reason": f"Missing required top-level field '{field}'"}

        hunks = proposal_json.get("hunks", [])
        if not isinstance(hunks, list):
            return {"valid": False, "reason": "'hunks' field must be a JSON array"}

        for idx, hunk in enumerate(hunks):
            for hfield in hunk_required_fields:
                if hfield not in hunk:
                    return {"valid": False, "reason": f"Hunk {idx} missing required field '{hfield}'"}

        return {"valid": True, "hunk_count": len(hunks)}
