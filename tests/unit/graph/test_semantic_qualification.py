"""Unit tests for SemanticFindingQualifier state machine (E12-3)."""

from pathlib import Path
from karsasec.core.finding.candidate import CandidateFinding
from karsasec.core.finding.model import QualificationState
from karsasec.core.finding.qualifier import SemanticFindingQualifier
from karsasec.qualification.fp_taxonomy import FPTaxonomyReason
from karsasec.rules.enums import Confidence, LanguageEnum, Severity
from karsasec.rules.schema import (
    EvidenceSpec,
    Rule,
    RuleCondition,
    RuleMatch,
    RuleMetadataV2,
    RuleOutput,
)


def test_qualifier_rejects_comment_match() -> None:
    rule = Rule(
        id="KS-TEST-0001",
        metadata=RuleMetadataV2(name="Test Command Injection", author="Test", version="1.0"),
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
        candidate_id="c1",
        rule=rule,
        rule_id="KS-TEST-0001",
        file_path=Path("test.php"),
        line=5,
        column=0,
        matched_text="shell_exec",
        snippet="// shell_exec('ping ' . $_GET['ip']);",
        source_text="// shell_exec('ping ' . $_GET['ip']);",
    )
    qualifier = SemanticFindingQualifier()
    res = qualifier.qualify_candidate(cand)
    assert res.qualification_state == QualificationState.REJECTED
    assert res.rejection_reason == FPTaxonomyReason.COMMENT_OR_STRING_MATCH


def test_qualifier_confirms_tainted_command_injection() -> None:
    rule = Rule(
        id="KS-OWASP-0003",
        metadata=RuleMetadataV2(
            name="Command Injection",
            author="Test",
            version="1.0",
            cwe="CWE-78",
            tags=["command_injection"],
        ),
        match=RuleMatch(language=LanguageEnum.PHP),
        condition=RuleCondition(),
        evidence=EvidenceSpec(require=["user_input"]),
        output=RuleOutput(
            severity=Severity.HIGH,
            confidence=Confidence.CONFIDENT,
            message="Command injection",
            remediation="Sanitize input",
        ),
    )
    source_text = """<?php
    $target = $_REQUEST['ip'];
    shell_exec("ping " . $target);
    """
    cand = CandidateFinding(
        candidate_id="c2",
        rule=rule,
        rule_id="KS-OWASP-0003",
        file_path=Path("exec.php"),
        line=3,
        column=0,
        matched_text="shell_exec",
        snippet='shell_exec("ping " . $target);',
        source_text=source_text,
    )
    qualifier = SemanticFindingQualifier()
    res = qualifier.qualify_candidate(cand)
    assert res.qualification_state == QualificationState.CONFIRMED
    assert res.enriched_evidence is not None
    assert res.enriched_evidence.sink_category == "COMMAND_EXECUTION"
