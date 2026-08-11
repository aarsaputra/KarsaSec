"""Unit tests for CandidateFinding model (E12-3)."""

from pathlib import Path

from karsasec.core.finding.candidate import CandidateFinding
from karsasec.rules.enums import Confidence, LanguageEnum, Severity
from karsasec.rules.schema import (
    Rule,
    RuleCondition,
    RuleMatch,
    RuleMetadataV2,
    RuleOutput,
)


def test_candidate_finding_instantiation() -> None:
    rule = Rule(
        id="KS-TEST-0001",
        metadata=RuleMetadataV2(name="Test Rule", author="Test", version="1.0"),
        match=RuleMatch(language=LanguageEnum.PHP),
        condition=RuleCondition(),
        output=RuleOutput(
            severity=Severity.HIGH,
            confidence=Confidence.CONFIDENT,
            message="Test finding",
            remediation="Fix it",
        ),
    )
    cand = CandidateFinding(
        candidate_id="cand-123",
        rule=rule,
        rule_id="KS-TEST-0001",
        file_path=Path("/tmp/test.php"),
        line=10,
        column=5,
        matched_text="shell_exec",
        snippet="shell_exec($_GET['cmd']);",
        source_text="$cmd = $_GET['cmd']; shell_exec($cmd);",
    )
    assert cand.candidate_id == "cand-123"
    assert cand.rule_id == "KS-TEST-0001"
    assert cand.line == 10
    assert cand.matched_text == "shell_exec"
