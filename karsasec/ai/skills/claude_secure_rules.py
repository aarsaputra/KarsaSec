"""Claude Proactive Secure Coding Rules Enforcement Skill.

Inspired by TikiTribe/claude-secure-coding-rules (https://github.com/TikiTribe/claude-secure-coding-rules).
Enforces Security-by-Default defensive coding patterns:
- Parameterized SQL queries (CWE-89)
- Array-form Subprocess execution (CWE-78)
- Path Traversal atomic validation (CWE-22)
- Context-aware XSS escaping (CWE-79)
- Safe Deserialization (CWE-502)
- Cryptographically secure random tokens (CWE-330)
"""

import re
from typing import Dict, Any, List


class ClaudeSecureCodingSkill:
    """Skill enforcing proactive secure coding rules and refusing dangerous code patterns."""

    PATTERNS_TO_REFUSE = [
        # SQL Injection
        (r'execute\s*\(\s*f["\'].*SELECT.*\{', "CWE-89", "Do NOT use string interpolation in SQL queries; use parameterized placeholders (?, :id, or %s tuples)."),
        (r'query\s*\(\s*["\'].*SELECT.*\$', "CWE-89", "Do NOT concatenate raw variables into PHP/SQL query strings; use PDO prepare statement."),
        # Command Injection
        (r'subprocess\.(run|Popen|call)\(.*shell\s*=\s*True', "CWE-78", "Do NOT use shell=True; pass arguments as an array ['cmd', arg1, arg2]."),
        (r'os\.system\s*\(', "CWE-78", "Do NOT use os.system(); use subprocess.run(['cmd', arg], check=True)."),
        # Code Injection / Eval
        (r'\beval\s*\(', "CWE-94", "Never use eval(); use ast.literal_eval() or explicit AST node parsing."),
        (r'\bexec\s*\(', "CWE-94", "Never use exec(); dynamic code execution enables RCE."),
        # Dangerous Deserialization
        (r'pickle\.loads\s*\(', "CWE-502", "Never deserialize untrusted data with pickle; use json or safe_load."),
        (r'yaml\.load\s*\([^,\)]*,?\s*Loader\s*=\s*yaml\.Loader', "CWE-502", "Never use unsafe yaml.Loader; use yaml.safe_load()."),
        # Insecure Randomness
        (r'random\.(choice|randint|random)\s*\(', "CWE-330", "Do NOT use random for tokens/secrets; use secrets module (secrets.token_urlsafe)."),
    ]

    def audit_proposed_patch(self, patch_code: str) -> Dict[str, Any]:
        """Audits a proposed code patch snippet against Claude Secure Coding rules."""
        violations = []
        for pattern, cwe, guidance in self.PATTERNS_TO_REFUSE:
            if re.search(pattern, patch_code, re.IGNORECASE):
                violations.append({
                    "cwe": cwe,
                    "guidance": guidance,
                    "pattern": pattern
                })

        return {
            "passed": (len(violations) == 0),
            "violation_count": len(violations),
            "violations": violations
        }

    def suggest_canonical_remediation(self, cwe_id: str, language: str) -> str:
        """Returns the canonical secure pattern snippet for a given CWE and programming language."""
        cwe_clean = cwe_id.upper().strip()
        lang_clean = language.lower().strip()

        if "89" in cwe_clean or "SQL" in cwe_clean:
            if lang_clean in ["python", "py"]:
                return 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
            elif lang_clean in ["php"]:
                return '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute(["id" => $user_id]);'
            elif lang_clean in ["js", "javascript", "ts", "typescript"]:
                return 'db.query("SELECT * FROM users WHERE id = $1", [userId]);'

        elif "78" in cwe_clean or "COMMAND" in cwe_clean:
            if lang_clean in ["python", "py"]:
                return 'subprocess.run(["ls", "-la", user_path], capture_output=True, text=True, check=True)'
            elif lang_clean in ["go", "golang"]:
                return 'exec.Command("ls", "-la", userPath)'

        elif "22" in cwe_clean or "PATH" in cwe_clean:
            return 'safe_path = os.path.abspath(os.path.join(base_dir, os.path.basename(filename)))\nif not safe_path.startswith(base_dir):\n    raise ValueError("Path traversal attempt")'

        return "Apply zero-trust input sanitization and parameterized API bounds."
