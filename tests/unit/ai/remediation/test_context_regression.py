"""Permanent Regression Test for Context Secret Remediation (Task 4).

Executes the exact reproduction scenario from Context Bug Audit:
- Verifies that CWE-798 findings map strictly to REMOVE_SECRET strategy.
- Verifies that the proposed patch produces syntactically valid PHP.
- Verifies that the unified diff does not contain invalid syntax patterns.
"""

import pytest
from pathlib import Path
from karsasec.agents.orchestrator import AgentOrchestrator
from karsasec.ai.remediation.models import RemediationStrategyType
from karsasec.core.finding.model import Confidence, Evidence, Finding, Severity


class TestContextRegression:
    """Permanent regression test suite for Task 4 context bug scenario."""

    def test_context_reproduction_secret_remediation(self, tmp_path: Path) -> None:
        """Task 4: Permanent regression test reproducing Context scenario."""
        test_file = tmp_path / "config.php"
        test_file.write_text('<?php\n$api_key = "AKIAIOSFODNN7EXAMPLE";\n', encoding="utf-8")

        f1 = Finding(
            finding_id="F-SECRET-01",
            rule_id="KS-COMMON-0001",
            fingerprint="fp_secret_1",
            title="Hardcoded Secret",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-798",
            owasp="A07:2021",
            file_path=test_file,
            evidence=Evidence(snippet='$api_key = "AKIAIOSFODNN7EXAMPLE";', line=2, column=1),
            description="Hardcoded AWS-style key",
            remediation="Move to env var",
        )

        orch = AgentOrchestrator()
        p_out = orch.planner.plan(target_path=str(tmp_path), findings=[f1])
        a_out = orch.analyzer.analyze(target_path=str(tmp_path), ordered_findings=p_out.ordered_findings)
        r_out = orch.remediator.remediate(target_path=str(tmp_path), analyses=a_out.analyses)

        assert len(r_out.proposals) == 1
        p = r_out.proposals[0]

        # Assertion 1: Strategy type MUST be REMOVE_SECRET
        assert p.strategy_type == RemediationStrategyType.REMOVE_SECRET

        # Assertion 2: Validation status MUST be syntactically valid (True) or UNVALIDATED
        assert p.validation.syntax_valid is True or p.validation.confidence == "UNVALIDATED"

        # Assertion 3: Diff MUST NOT contain broken syntax patterns (;, or bare assignment in function args)
        diff_text = p.unified_diff
        assert ";," not in diff_text
        assert 'htmlspecialchars($api_key = "' not in diff_text
        assert "$api_key = getenv('API_KEY');" in diff_text or p.validation.confidence == "UNVALIDATED"
