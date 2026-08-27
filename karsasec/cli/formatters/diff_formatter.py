"""GitHub-Style Visual Diff Console Formatter for KarsaSec Remediation Proposals."""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.ai.remediation.models import PatchHunk


class DiffConsoleFormatter:
    """Formats patch hunks into colorized GitHub-style unified diffs for terminal display."""

    @staticmethod
    def format_hunk(
        hunk: PatchHunk,
        rule_id: str = "KS-VULN-0001",
        vuln_title: str = "Vulnerability Remediation",
        use_color: bool = True,
    ) -> str:
        """Renders a single PatchHunk as a GitHub-style unified diff block."""
        orig_lines = hunk.original_text.splitlines(keepends=True)
        if not orig_lines and hunk.original_text:
            orig_lines = [hunk.original_text + "\n"]

        prop_lines = hunk.proposed_text.splitlines(keepends=True)
        if not prop_lines and hunk.proposed_text:
            prop_lines = [hunk.proposed_text + "\n"]

        diff_gen = difflib.unified_diff(
            orig_lines,
            prop_lines,
            fromfile=f"a/{hunk.file_path}",
            tofile=f"b/{hunk.file_path}",
            fromfiledate="",
            tofiledate="",
            n=2,
        )
        diff_body_lines = list(diff_gen)

        header_sep = "=" * 68
        header = (
            f"{header_sep}\n"
            f"FILE: {hunk.file_path} (Line {hunk.start_line})\n"
            f"RULE: {rule_id} | {vuln_title}\n"
            f"{header_sep}"
        )

        if not diff_body_lines:
            # Fallback if text replacement is exact single line
            diff_body_lines = [
                f"--- a/{hunk.file_path}\n",
                f"+++ b/{hunk.file_path}\n",
                f"@@ -{hunk.start_line},1 +{hunk.start_line},1 @@\n",
                f"-{hunk.original_text}\n",
                f"+{hunk.proposed_text}\n",
            ]

        formatted_lines = [header]
        for line in diff_body_lines:
            clean_line = line.rstrip("\n")
            if not use_color:
                formatted_lines.append(clean_line)
                continue

            if clean_line.startswith("---") or clean_line.startswith("+++"):
                formatted_lines.append(f"\033[1m{clean_line}\033[0m")
            elif clean_line.startswith("@@"):
                formatted_lines.append(f"\033[36m{clean_line}\033[0m")
            elif clean_line.startswith("-"):
                formatted_lines.append(f"\033[31m{clean_line}\033[0m")  # Red for deleted/vulnerable code
            elif clean_line.startswith("+"):
                formatted_lines.append(f"\033[32m{clean_line}\033[0m")  # Green for added/remediated code
            else:
                formatted_lines.append(clean_line)

        return "\n".join(formatted_lines)
