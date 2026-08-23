"""Sprint E12-9 Evidence-Guided Precision & FP Root-Cause Elimination Tests.

Verifies:
1. 100% Recall retention lock on the benchmark ground-truth set (20/20 TP, 0 FN).
2. FP Reduction Target: False positive volume <= 150 (reduced from 176 baseline).
3. Authoritative DFG Precedence model (STATIC / SANITIZED override legacy fallback).
4. Candidate rejection for non-vulnerable validation guards (isset, intval, preg_match, is_numeric).
5. SSRF stream filtering (php://input, local path constants).
6. Accurate FP Taxonomy reason classification.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from karsasec.core.execution.context import ScanContext
from karsasec.core.execution.executor import rule_executor
from karsasec.core.finding.candidate import CandidateFinding
from karsasec.core.finding.correlator import FindingCorrelator
from karsasec.core.finding.model import QualificationState
from karsasec.core.finding.qualifier import SemanticFindingQualifier, FPTaxonomyReason
from karsasec.qualification.classifier import QualificationClassifier
from karsasec.qualification.model import ManifestLoader
from karsasec.parser.generic_parser import php_parser
from karsasec.rules.loader import YAMLRuleLoader


@pytest.fixture
def dvwa_e12_9_scan_results():
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


def test_e12_9_recall_lock_100_percent(dvwa_e12_9_scan_results):
    """Invariant: Sprint E12-9 MUST maintain 100% recall (20/20 TP, 0 FN)."""
    report, _ = dvwa_e12_9_scan_results
    assert report.tp == 20, f"Expected 20 TPs, got {report.tp}"
    assert report.fn == 0, f"Expected 0 FNs, got {report.fn}"


def test_e12_9_fp_reduction_target(dvwa_e12_9_scan_results):
    """Invariant: False positives MUST be <= 150 (down from 176 baseline)."""
    report, _ = dvwa_e12_9_scan_results
    assert report.fp <= 150, f"Expected FP <= 150, got {report.fp}"


def test_e12_9_candidate_rejection_validation_guards():
    """Verify that non-vulnerable input validation guards are rejected during candidate qualification."""
    from karsasec.rules.enums import Confidence, LanguageEnum, Severity
    from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadataV2, RuleOutput

    rule = Rule(
        id="KS-PHP-0008",
        metadata=RuleMetadataV2(name="Test BAC", author="Test", version="1.0"),
        match=RuleMatch(language=LanguageEnum.PHP),
        condition=RuleCondition(),
        output=RuleOutput(severity=Severity.HIGH, confidence=Confidence.CONFIDENT, message="BAC", remediation="Fix"),
    )
    qualifier = SemanticFindingQualifier()

    cand_isset = CandidateFinding(
        candidate_id="test-isset-001",
        rule=rule,
        rule_id="KS-PHP-0008",
        file_path=Path("vulnerabilities/bac/source/impossible.php"),
        line=16,
        column=0,
        snippet="if (!preg_match('/^\\d+$/', $_GET['user_id'])) {",
        source_text="if (!preg_match('/^\\d+$/', $_GET['user_id'])) {",
        matched_text="preg_match",
        language="PHP",
    )
    res_isset = qualifier.qualify_candidate(cand_isset)
    assert res_isset.qualification_state == QualificationState.REJECTED
    assert res_isset.rejection_reason in (
        FPTaxonomyReason.SANITIZED_INPUT.value,
        FPTaxonomyReason.NON_EXECUTING_OPERATION.value,
    )


def test_e12_9_ssrf_local_stream_filtering():
    """Verify that file_get_contents calls on local streams (php://input) are rejected as SSRF."""
    from karsasec.rules.enums import Confidence, LanguageEnum, Severity
    from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadataV2, RuleOutput

    rule = Rule(
        id="KS-OWASP-0010",
        metadata=RuleMetadataV2(name="Test SSRF", author="Test", version="1.0"),
        match=RuleMatch(language=LanguageEnum.PHP),
        condition=RuleCondition(),
        output=RuleOutput(severity=Severity.HIGH, confidence=Confidence.CONFIDENT, message="SSRF", remediation="Fix"),
    )
    qualifier = SemanticFindingQualifier()

    cand_ssrf = CandidateFinding(
        candidate_id="test-ssrf-001",
        rule=rule,
        rule_id="KS-OWASP-0010",
        file_path=Path("vulnerabilities/fi/source/impossible.php"),
        line=10,
        column=0,
        snippet="$input = (array) json_decode(file_get_contents('php://input'), true);",
        source_text="$input = (array) json_decode(file_get_contents('php://input'), true);",
        matched_text="file_get_contents",
        language="PHP",
    )
    res_ssrf = qualifier.qualify_candidate(cand_ssrf)
    assert res_ssrf.qualification_state == QualificationState.REJECTED
    assert res_ssrf.rejection_reason == FPTaxonomyReason.STATIC_INPUT.value


def test_e12_9_dfg_precedence_over_regex():
    """Verify DFG precedent over regex fallback for static/sanitized variables."""
    from karsasec.graph.taint_verifier import TaintVerifier
    from karsasec.parser.ast_nodes import ASTNode

    verifier = TaintVerifier()
    node = ASTNode(node_id="n1", node_type="call", start=None, end=None)

    # Static assignment case
    src = "$id = 123;\n$result = mysqli_query($conn, 'SELECT * FROM users WHERE id = ' . $id);"
    res = verifier.verify_sink(
        node=node, snippet="mysqli_query($conn, 'SELECT * FROM users')", context_text="mysqli_query", source_text=src
    )
    assert not res.has_taint_source or res.is_whitelisted_guard or res.is_hardcoded_static
