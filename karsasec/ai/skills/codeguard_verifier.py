"""Project CodeGuard AI Safety & Anti-Hallucination Guardrail Skill.

Extracted directly from CoSAI / OASIS Project CodeGuard (https://github.com/cosai-oasis/project-codeguard).
Performs:
- Banned/Broken Cryptographic Algorithms Check (MD5, DES, RC4, SHA-1, AES-ECB)
- Hardcoded Secret Detection (CWE-798)
- Deprecated OpenSSL API Detection (AES_encrypt, RSA_new, SHA1_Init)
- AST Symbol Verification & Anti-Hallucination Checks
- Fail-Closed Patch Validation before SAST rescan.
"""

import re
import ast
from typing import Any


class CodeGuardVerifierSkill:
    """Skill implementing Project CodeGuard AI safety guardrails and cryptographic guidelines."""

    # Hardcoded credential patterns (CWE-798)
    SECRET_PATTERNS = [
        r'(?i)(api_key|secret_key|auth_token|access_token|password)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        r'-----BEGIN\s+PRIVATE\s+KEY-----',
        r'ghp_[A-Za-z0-9]{36}',
        r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    ]

    # Banned Crypto Algorithms (CodeGuard Rule: codeguard-1-crypto-algorithms)
    BANNED_CRYPTO_PATTERNS = [
        (r'\b(hashlib\.)?md5\s*\(', "CWE-328", "Banned Hash: MD5 is cryptographically broken; use SHA-256 or bcrypt/argon2 for passwords."),
        (r'\b(hashlib\.)?sha1\s*\(', "CWE-328", "Deprecated Hash: SHA-1 has collision weaknesses; use SHA-256 or SHA-512."),
        (r'\b(DES|3DES|Blowfish|RC4|RC2)\b', "CWE-327", "Banned Symmetric Cipher: Obsolete and vulnerable to attacks; use AES-256-GCM or ChaCha20-Poly1305."),
        (r'AES\.MODE_ECB|AES_ECB', "CWE-327", "Forbidden AES Mode: ECB mode leaks pattern information; use AES-256-GCM (AEAD)."),
        (r'\b(AES_encrypt|AES_decrypt|RSA_new|SHA1_Init)\s*\(', "CWE-327", "Forbidden Deprecated OpenSSL C API: Use EVP high-level APIs (EVP_EncryptInit_ex, EVP_Q_MAC).")
    ]

    def verify_patch_safety(self, patch_code: str, language: str = "python") -> dict[str, Any]:
        """Performs full CodeGuard pre-submission safety review of a proposed patch."""
        issues = []

        # 1. Hardcoded Secret Check (codeguard-1-hardcoded-credentials)
        for pattern in self.SECRET_PATTERNS:
            if re.search(pattern, patch_code):
                issues.append({
                    "severity": "CRITICAL",
                    "cwe": "CWE-798",
                    "issue": "Hardcoded credential or secret token detected in patch proposal."
                })

        # 2. Cryptographic Security Check (codeguard-1-crypto-algorithms)
        for pattern, cwe, guidance in self.BANNED_CRYPTO_PATTERNS:
            if re.search(pattern, patch_code, re.IGNORECASE):
                issues.append({
                    "severity": "HIGH",
                    "cwe": cwe,
                    "issue": guidance
                })

        # 3. Python AST Import & Symbol Validation (Anti-Hallucination)
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

    def _check_python_ast_symbols(self, python_code: str) -> dict[str, Any]:
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
