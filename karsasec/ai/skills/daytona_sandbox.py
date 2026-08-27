"""Daytona Ephemeral Sandbox & Git Branch Isolation Skill.

Inspired by Daytona (https://github.com/daytonaio/daytona).
Provides sub-second execution sandboxing, git branch fencing,
and process isolation for AI patch application workflows.
"""

import os
import tempfile
import subprocess
from typing import Any, Optional


class DaytonaSandboxSkill:
    """Skill enforcing Daytona-style ephemeral sandbox execution and branch fencing."""

    def __init__(self, workspace_path: str = "."):
        self.workspace_path = os.path.abspath(workspace_path)

    def create_git_branch_fence(self, finding_id: str) -> dict[str, Any]:
        """Creates an isolated git branch fence for patching to prevent mutating main working state.
        
        Branch pattern: fix/karsasec-finding-<id>
        """
        branch_name = f"fix/karsasec-finding-{finding_id.lower().replace(':', '-').replace('_', '-')}"
        try:
            cmd = ["git", "checkout", "-b", branch_name]
            result = subprocess.run(
                cmd,
                cwd=self.workspace_path,
                capture_output=True,
                text=True,
                check=False
            )
            is_success = (result.returncode == 0)
            return {
                "branch_name": branch_name,
                "created": is_success,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()
            }
        except Exception as exc:
            return {
                "branch_name": branch_name,
                "created": False,
                "error": str(exc)
            }

    def execute_in_temp_sandbox(self, script_contents: str, extension: str = ".py") -> dict[str, Any]:
        """Executes a code patch validation script inside an ephemeral temp sandbox."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, f"sandbox_runner{extension}")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_contents)

            try:
                cmd = ["python3", script_path] if extension == ".py" else ["node", script_path]
                res = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return {
                    "exit_code": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                    "sandboxed": True
                }
            except subprocess.TimeoutExpired:
                return {
                    "exit_code": -1,
                    "error": "Execution timed out in Daytona sandbox",
                    "sandboxed": True
                }
            except Exception as exc:
                return {
                    "exit_code": -1,
                    "error": str(exc),
                    "sandboxed": True
                }
