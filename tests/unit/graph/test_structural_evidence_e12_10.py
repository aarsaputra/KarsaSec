"""Sprint E12-10 Structural Evidence Attribution & Deterministic Qualification Tests.

Verifies:
1. Evidence model extensions: SourceCategory, OperationSemantics, QualificationEvidence, and JSON serialization.
2. Sink category extensions: SQL_PREPARATION and PARAMETER_BINDING in SinkCategory registry.
3. Expanded FP taxonomy reasons: PARAMETER_BINDING, SAFE_PREPARATION, NON_EXECUTING_OPERATION.
4. Universal qualification matrix behavior (rejecting non-executing statements, parameter bindings, static streams without benchmark-specific rules).
5. 100% Recall retention lock on the DVWA ground-truth benchmark (20/20 TP, 0 FN).
6. False positive volume lock (FP <= 110).
"""

from __future__ import annotations

from pathlib import Path
import pytest

from karsasec.core.execution.context import ScanContext
from karsasec.core.execution.executor import rule_executor
from karsasec.core.finding.candidate import CandidateFinding
from karsasec.core.finding.correlator import FindingCorrelator
from karsasec.core.finding.evidence import (
    OperationSemantics,
    QualificationEvidence,
    SourceCategory,
)
from karsasec.core.finding.model import QualificationState
from karsasec.core.finding.qualifier import SemanticFindingQualifier
from karsasec.graph.dataflow.sinks import SinkCategory, sink_registry
from karsasec.qualification.classifier import QualificationClassifier
from karsasec.qualification.fp_taxonomy import FPTaxonomyReason
from karsasec.qualification.model import ManifestLoader
from karsasec.parser.generic_parser import php_parser
from karsasec.rules.enums import Confidence, LanguageEnum, Severity
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadataV2, RuleOutput


def test_e12_10_evidence_models_serialization():
    """Verify structural evidence models and their JSON serialization dictionary structure."""
    ev = QualificationEvidence(
        decision=str(QualificationState.CONFIRMED),
        source_category=SourceCategory.USER_CONTROLLED,
        taint_evidence={"path": ["$_GET['id']", "mysqli_query"]},
        sanitizer_capability="NONE",
        sink_category=str(SinkCategory.SQL_EXECUTION),
        operation_semantics=OperationSemantics.STATEMENT_EXECUTION,
        rejection_reason=None,
        explanation="Tainted input reaches executable SQL sink.",
    )
    d = ev.to_dict()
    assert d["decision"] == "CONFIRMED"
    assert d["source_category"] == "USER_CONTROLLED"
    assert d["sink_category"] == "SQL_EXECUTION"
    assert d["operation_semantics"] == "STATEMENT_EXECUTION"
    assert d["rejection_reason"] is None


def test_e12_10_sink_registry_extensions():
    """Verify that SinkCategory includes SQL_PREPARATION and PARAMETER_BINDING."""
    assert SinkCategory.SQL_PREPARATION.value == "SQL_PREPARATION"
    assert SinkCategory.PARAMETER_BINDING.value == "PARAMETER_BINDING"

    cat_prepare = sink_registry.classify_sink("prepare", "$db->prepare('SELECT 1')", "php")
    assert cat_prepare == SinkCategory.SQL_PREPARATION

    cat_bind = sink_registry.classify_sink("bindParam", "$stmt->bindParam(':id', $id)", "php")
    assert cat_bind == SinkCategory.PARAMETER_BINDING


def test_e12_10_parameter_binding_rejection():
    """Verify deterministic rejection of parameter binding operations."""
    rule = Rule(
        id="KS-PHP-0002",
        metadata=RuleMetadataV2(name="SQLi Test", author="Test", version="1.0"),
        match=RuleMatch(language=LanguageEnum.PHP),
        condition=RuleCondition(),
        output=RuleOutput(severity=Severity.HIGH, confidence=Confidence.CONFIDENT, message="SQLi", remediation="Fix"),
    )
    qualifier = SemanticFindingQualifier()

    cand = CandidateFinding(
        candidate_id="cand-bind-001",
        rule=rule,
        rule_id="KS-PHP-0002",
        file_path=Path("vulnerabilities/sqli/source/impossible.php"),
        line=17,
        column=0,
        snippet="$data->bindParam( ':id', $id, PDO::PARAM_INT );",
        source_text="$data->bindParam( ':id', $id, PDO::PARAM_INT );",
        matched_text="bindParam",
        language="PHP",
    )
    res = qualifier.qualify_candidate(cand)
    assert res.qualification_state == QualificationState.REJECTED
    assert res.rejection_reason == FPTaxonomyReason.PARAMETER_BINDING


def test_e12_10_safe_preparation_rejection():
    """Verify deterministic rejection of query preparation statements."""
    rule = Rule(
        id="KS-PHP-0002",
        metadata=RuleMetadataV2(name="SQLi Test", author="Test", version="1.0"),
        match=RuleMatch(language=LanguageEnum.PHP),
        condition=RuleCondition(),
        output=RuleOutput(severity=Severity.HIGH, confidence=Confidence.CONFIDENT, message="SQLi", remediation="Fix"),
    )
    qualifier = SemanticFindingQualifier()

    cand = CandidateFinding(
        candidate_id="cand-prep-001",
        rule=rule,
        rule_id="KS-PHP-0002",
        file_path=Path("vulnerabilities/sqli/source/impossible.php"),
        line=16,
        column=0,
        snippet="$data = $db->prepare( 'SELECT first_name FROM users WHERE user_id = (:id);' );",
        source_text="$data = $db->prepare( 'SELECT first_name FROM users WHERE user_id = (:id);' );",
        matched_text="prepare",
        language="PHP",
    )
    res = qualifier.qualify_candidate(cand)
    assert res.qualification_state == QualificationState.REJECTED
    assert res.rejection_reason == FPTaxonomyReason.SAFE_PREPARATION


@pytest.fixture
def dvwa_e12_10_scan_results():
    repo_root = Path(__file__).resolve().parents[3]
    root = Path("/home/lota1337/pentest/DVWA/vulnerabilities")
    rules = YAMLRuleLoader().load_directory(repo_root / "karsasec" / "rules" / "patterns")

    all_findings = []
    if root.exists():
        for f in sorted(list(root.glob("**/*.php"))):
            res = php_parser.parse_file(f)
            ctx = ScanContext(
                file_node=res.root,
                symbol_table=res.symbol_table,
                language="PHP",
                file_path=f,
                source_bytes=f.read_bytes(),
            )
            exec_res = rule_executor.execute_scan(ctx, rules)
            all_findings.extend(exec_res.findings)

    correlator = FindingCorrelator()
    canon = correlator.correlate(all_findings)
    final_findings = correlator.to_findings(canon)

    active_findings = [
        f for f in final_findings if getattr(f, "qualification_state", None) != QualificationState.REJECTED
    ]

    bm = ManifestLoader().load(repo_root / "benchmarks" / "dvwa" / "manifest.yaml")
    classifier = QualificationClassifier()
    report = classifier.classify(bm, active_findings, root)
    return report, final_findings


def test_e12_10_recall_lock_100_percent(dvwa_e12_10_scan_results):
    """Invariant: Sprint E12-10 MUST maintain 100% recall (20/20 TP, 0 FN)."""
    report, _ = dvwa_e12_10_scan_results
    assert report.tp == 20, f"Expected 20 TPs, got {report.tp}"
    assert report.fn == 0, f"Expected 0 FNs, got {report.fn}"


def test_e12_10_fp_volume_lock(dvwa_e12_10_scan_results):
    """Invariant: Sprint E12-10 FP volume MUST be <= 110 (reduced from 140 in E12-9)."""
    report, _ = dvwa_e12_10_scan_results
    assert report.fp <= 110, f"Expected FP <= 110, got {report.fp}"
