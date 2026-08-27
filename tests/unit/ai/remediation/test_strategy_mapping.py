"""Unit tests for RemediationPlanner strategy mapping & TemplatePatchProvider guardrails (Tasks 2 & 3).

Verifies:
1. CWE-798 and secret findings correctly map to REMOVE_SECRET.
2. Unvalidated strategies without native templates return None and result in UNVALIDATED confidence.
"""

import pytest
from pathlib import Path
from karsasec.ai.remediation.planner import RemediationPlanner
from karsasec.ai.remediation.models import RemediationStrategyType, RemediationStrategy
from karsasec.ai.remediation.provider import TemplatePatchProvider
from karsasec.core.finding.model import Finding, Severity, Confidence, Evidence


class TestStrategyMapping:
    """Test suite for CWE-798 and strategy resolution."""

    def test_cwe_798_maps_to_remove_secret(self) -> None:
        """Task 2: Finding with CWE-798 must map to REMOVE_SECRET."""
        f_secret = Finding(
            finding_id="F-SECRET-798",
            rule_id="KS-COMMON-0001",
            fingerprint="fp_sec_798",
            title="Hardcoded AWS API Key",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-798",
            owasp="A07:2021",
            file_path=Path("config.php"),
            evidence=Evidence(snippet='$api_key = "AKIAIOSFODNN7EXAMPLE";', line=1, column=1),
            description="Hardcoded AWS key",
            remediation="Use env var",
        )
        strategy = RemediationPlanner.plan(finding=f_secret)
        assert strategy.strategy_type == RemediationStrategyType.REMOVE_SECRET

    def test_sqli_cwe_89_maps_to_add_parameterization(self) -> None:
        """Task 1: SQL Injection must map to ADD_PARAMETERIZATION."""
        f_sqli = Finding(
            finding_id="F-SQLI-89",
            rule_id="CWE-89-SQLI",
            fingerprint="fp_sqli_89",
            title="SQL Injection",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-89",
            owasp="A03:2021",
            file_path=Path("vulnerable.php"),
            evidence=Evidence(snippet='$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);', line=1, column=1),
            description="SQLi vulnerability",
            remediation="Use parameterized query",
        )
        strategy = RemediationPlanner.plan(finding=f_sqli)
        assert strategy.strategy_type == RemediationStrategyType.ADD_PARAMETERIZATION


class TestTemplatePatchProviderGuardrails:
    """Task 3 Opsi B: Test template generation guardrails."""

    def test_remove_secret_php_template(self) -> None:
        """Task 3 Opsi A: REMOVE_SECRET for PHP must generate valid getenv patch."""
        provider = TemplatePatchProvider()
        strat = RemediationStrategy(
            finding_id="F-1",
            root_cause_category="UNSAFE_ASSIGNMENT",
            strategy_type=RemediationStrategyType.REMOVE_SECRET,
            rationale="Test",
            target_file="config.php",
            target_locations=("config.php:1",),
            affected_symbols=("api_key",),
            evidence_references=("config.php:1",),
            knowledge_references=(),
            confidence=1.0,
            assumptions=(),
            limitations=(),
            strategy_fingerprint="fp1",
        )
        hunks = provider.generate_hunks(strat, "$api_key = 'AKIA...';")
        assert len(hunks) == 1
        assert "$api_key = getenv('API_KEY');" in hunks[0].proposed_text

    def test_unsupported_strategy_returns_empty_hunks(self) -> None:
        """Task 3 Opsi B: Strategies without native templates return empty hunks list."""
        provider = TemplatePatchProvider()
        strat = RemediationStrategy(
            finding_id="F-2",
            root_cause_category="MISSING_SANITIZATION",
            strategy_type=RemediationStrategyType.ADD_CSRF_PROTECTION,
            rationale="Test",
            target_file="form.php",
            target_locations=("form.php:1",),
            affected_symbols=(),
            evidence_references=("form.php:1",),
            knowledge_references=(),
            confidence=1.0,
            assumptions=(),
            limitations=(),
            strategy_fingerprint="fp2",
        )
        hunks = provider.generate_hunks(strat, "<form action='submit.php'>")
        assert hunks == []
