"""Unit tests for Sprint E12-11 Contextual Dataflow Qualification & FP Attribution."""

from __future__ import annotations

import pytest
from pathlib import Path

from karsasec.core.finding.candidate import CandidateFinding
from karsasec.core.finding.evidence import OperationSemantics, SourceCategory
from karsasec.core.finding.model import QualificationState
from karsasec.core.finding.qualifier import SemanticFindingQualifier
from karsasec.graph.dataflow.model import TaintState
from karsasec.graph.taint_verifier import TaintVerifier
from karsasec.rules.enums import Confidence, LanguageEnum, Severity
from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadataV2, RuleOutput


@pytest.fixture
def dummy_rule() -> Rule:
    return Rule(
        id="KS-PHP-0004",
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


class TestContextualQualificationE1211:
    """Validates structural evidence qualification for Sprint E12-11."""

    def test_static_sql_argument_detection(self) -> None:
        from karsasec.parser.ast_nodes import ASTNode
        verifier = TaintVerifier()
        node = ASTNode(node_id="n1", node_type="call", start=None, end=None)
        source = '<?php mysqli_query($db, "SHOW COLUMNS FROM users"); ?>'
        res = verifier.verify_sink(
            node=node,
            snippet='mysqli_query($db, "SHOW COLUMNS FROM users")',
            context_text="mysqli_query",
            source_text=source,
        )
        assert res.is_hardcoded_static is True
        assert res.has_taint_source is False

    def test_escapeshellarg_sanitizer_guard(self) -> None:
        from karsasec.parser.ast_nodes import ASTNode
        verifier = TaintVerifier()
        node = ASTNode(node_id="n1", node_type="call", start=None, end=None)
        source = '<?php $cmd = escapeshellarg($_GET["cmd"]); exec($cmd); ?>'
        res = verifier.verify_sink(
            node=node,
            snippet="exec($cmd)",
            context_text="exec",
            source_text=source,
        )
        assert res.is_whitelisted_guard is True
        assert res.dataflow_evidence is not None
        assert res.dataflow_evidence.state == TaintState.SANITIZED

    def test_numeric_guard_sanitizer(self) -> None:
        from karsasec.parser.ast_nodes import ASTNode
        verifier = TaintVerifier()
        node = ASTNode(node_id="n1", node_type="call", start=None, end=None)
        source = '<?php $id = intval($_GET["id"]); mysqli_query($db, "SELECT * FROM users WHERE id = $id"); ?>'
        res = verifier.verify_sink(
            node=node,
            snippet="mysqli_query($db, $id)",
            context_text="mysqli_query",
            source_text=source,
        )
        assert res.is_whitelisted_guard is True
        assert res.dataflow_evidence is not None
        assert res.dataflow_evidence.state == TaintState.SANITIZED

    def test_secure_cookie_qualification(self) -> None:
        qualifier = SemanticFindingQualifier()
        op_sem = qualifier._classify_operation_semantics(
            candidate=None,  # type: ignore
            sink_category="COOKIE_CONFIG",
            snippet="setcookie('session_id', $val, time() + 3600, '/', '', true, true)",
        )
        assert op_sem == OperationSemantics.SECURE_CONFIGURATION

    def test_local_resource_provenance(self) -> None:
        qualifier = SemanticFindingQualifier()
        dummy_res = type("DummyRes", (), {"is_hardcoded_static": False, "has_taint_source": False})()
        src_cat = qualifier._classify_source_category(
            verifier_res=dummy_res,
            snippet="require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php'",
        )
        assert src_cat == SourceCategory.LOCAL_RESOURCE

    def test_sink_category_disambiguation_echo(self, dummy_rule: Rule) -> None:
        qualifier = SemanticFindingQualifier()
        candidate = CandidateFinding(
            candidate_id="cand-1",
            rule=dummy_rule,
            rule_id="KS-PHP-0004",
            file_path=Path("test.php"),
            line=10,
            column=1,
            matched_text="echo",
            snippet="if (!preg_match('/^\\d+$/', $_GET['user_id'])) {",
            source_text="if (!preg_match('/^\\d+$/', $_GET['user_id'])) {",
            language="PHP",
        )
        qualified = qualifier.qualify_candidate(candidate)
        assert qualified.qualification_state == QualificationState.REJECTED
