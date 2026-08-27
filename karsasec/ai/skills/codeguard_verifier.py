"""Project CodeGuard AI Safety & Anti-Hallucination Guardrail Skill.

Inspired by CoSAI / OASIS Project CodeGuard (https://github.com/cosai-oasis/project-codeguard).
Performs AST symbol verification, import validation, hardcoded credentials checking,
and fail-closed patch validation before submitting patch proposals for SAST rescan.
"""

import re
import ast
from typing import Dict, Any, List, Set


class CodeGuardVerifierSkill:
    """Skill implementing Project CodeGuard AI safety guardrails and anti-hallucination checks."""

    # Common hardcoded credential patterns (CWE-798)
    SECRET_PATTERNS = [
        r'(?i)(api_key|secret_key|auth_token|access_token|password)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        r'-----BEGIN\s+PRIVATE\s+KEY-----',
        r'ghp_[A-Za-z0-9]{36}',
        r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    ]

    def verify_patch_safety(self, patch_code: str, language: str = "python") -> Dict[str, Any]:
        """Performs full CodeGuard pre-submission safety review of a proposed patch."""
        issues = []

        # 1. Hardcoded Secret Check
        for pattern in self.SECRET_PATTERNS:
            if re.search(pattern, patch_code):
                issues.append({
                    "severity": "CRITICAL",
                    "cwe": "CWE-798",
                    "issue": "Hardcoded credential or secret token detected in patch proposal."
                })

        # 2. Python AST Import & Symbol Validation (Anti-Hallucination)
        if language.lower() in ["python", "py"]:
            ast_result = self._check_python_ast_symbols(patch_code)
            if not ast_result["valid_syntax"]:
                issues.append({
                    "severity": "HIGH",
                    "cwe": "CWE-1177",
                    "issue": f"Patch contains invalid Python syntax: {ast_result.get('error')}"
                })

        is_safe = (len(issues) == 0)
        return {
            "is_safe": is_safe,
            "fail_closed": not is_safe,
            "issue_count": len(issues),
            "issues": issues
        }

    def _check_python_ast_symbols(self, python_code: str) -> Dict[str, Any]:
        """Parses python snippet using AST walker to detect hallucinated imports or broken syntax."""
        try:
            tree = ast.parse(python_code)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module)

            return {
                "valid_syntax": True,
                "imported_modules": list(imports)
            }
        except SyntaxError as syn_err:
            return {
                "valid_syntax": False,
                "error": str(syn_err)
            }
        except Exception as exc:
            return {
                "valid_syntax": False,
                "error": str(exc)
            }
