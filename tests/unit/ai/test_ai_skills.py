"""Unit tests for KarsaSec AI Agent Skills System."""

import pytest
from karsasec.ai.skills import (
    DaytonaSandboxSkill,
    AgentSkillsBudgetSkill,
    ClaudeSecureCodingSkill,
    CodeGuardVerifierSkill,
    AISkillRegistry,
)


def test_daytona_sandbox_skill_git_fence(tmp_path):
    sandbox = DaytonaSandboxSkill(workspace_path=str(tmp_path))
    fence_info = sandbox.create_git_branch_fence("KS-PY-0001")
    assert "branch_name" in fence_info
    assert "fix/karsasec-finding-ks-py-0001" in fence_info["branch_name"]


def test_daytona_sandbox_temp_execution():
    sandbox = DaytonaSandboxSkill()
    res = sandbox.execute_in_temp_sandbox("print('Hello Daytona')")
    assert res["exit_code"] == 0
    assert "Hello Daytona" in res["stdout"]


def test_agent_skills_budget_context_pruning(tmp_path):
    dummy_file = tmp_path / "vulnerable.py"
    lines = [f"line_{i} = {i}\n" for i in range(1, 100)]
    dummy_file.write_text("".join(lines))

    budget = AgentSkillsBudgetSkill()
    pruned = budget.prune_file_context(str(dummy_file), target_line=50, context_window=5)

    assert pruned["start_line"] == 45
    assert pruned["end_line"] == 55
    assert "50: line_50 = 50" in pruned["pruned_context"]


def test_agent_skills_budget_contract_validation():
    budget = AgentSkillsBudgetSkill()
    valid_proposal = {
        "hunks": [
            {
                "start_line": 10,
                "end_line": 12,
                "original_text": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                "proposed_text": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            }
        ]
    }
    val_res = budget.validate_typed_proposal_contract(valid_proposal)
    assert val_res["valid"] is True


def test_claude_secure_coding_rules_detection():
    rules = ClaudeSecureCodingSkill()

    # Command Injection
    vulnerable_cmd = 'subprocess.run(f"ls {user_input}", shell=True)'
    audit_res = rules.audit_proposed_patch(vulnerable_cmd)
    assert audit_res["passed"] is False
    assert any(v["cwe"] == "CWE-78" for v in audit_res["violations"])

    # JWT None algorithm confusion
    vulnerable_jwt = 'payload = jwt.decode(token, key, algorithms=["HS256", "none"])'
    audit_jwt = rules.audit_proposed_patch(vulnerable_jwt)
    assert audit_jwt["passed"] is False
    assert any(v["cwe"] == "CWE-347" for v in audit_jwt["violations"])

    # AI Model Loading Safety
    vulnerable_llm = 'AutoModel.from_pretrained("org/repo", trust_remote_code=True)'
    audit_llm = rules.audit_proposed_patch(vulnerable_llm)
    assert audit_llm["passed"] is False
    assert any(v["cwe"] == "OWASP-LLM05" for v in audit_llm["violations"])

    # Safe snippet
    safe_snippet = 'subprocess.run(["ls", "-la", user_input], capture_output=True, check=True)'
    safe_res = rules.audit_proposed_patch(safe_snippet)
    assert safe_res["passed"] is True


def test_codeguard_verifier_hardcoded_secrets_and_banned_crypto():
    verifier = CodeGuardVerifierSkill()

    # Hardcoded Secret Check
    vuln_code = 'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEKEY"'
    review = verifier.verify_patch_safety(vuln_code)
    assert review["is_safe"] is False
    assert review["fail_closed"] is True
    assert any(issue["cwe"] == "CWE-798" for issue in review["issues"])

    # Banned Hash MD5 Check
    vuln_md5 = 'hash_val = hashlib.md5(password.encode()).hexdigest()'
    review_md5 = verifier.verify_patch_safety(vuln_md5)
    assert review_md5["is_safe"] is False
    assert any(issue["cwe"] == "CWE-328" for issue in review_md5["issues"])

    # Banned AES-ECB Mode Check
    vuln_ecb = 'cipher = AES.new(key, AES.MODE_ECB)'
    review_ecb = verifier.verify_patch_safety(vuln_ecb)
    assert review_ecb["is_safe"] is False
    assert any(issue["cwe"] == "CWE-327" for issue in review_ecb["issues"])


def test_ai_skill_registry_integration(tmp_path):
    dummy_file = tmp_path / "app.py"
    dummy_file.write_text("import os\n\ndef main():\n    pass\n")

    registry = AISkillRegistry(workspace_path=str(tmp_path))
    val_res = registry.execute_pre_patch_validation(
        file_path=str(dummy_file),
        target_line=2,
        patch_code='subprocess.run(["ls", "-la"], check=True)',
        language="python"
    )

    assert val_res["passed"] is True
    assert val_res["fail_closed"] is False
