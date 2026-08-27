"""Unit & Integration Tests for Track Z: Multi-Agent Orchestration & RAG Remediation."""

from pathlib import Path

from karsasec.agents.analyzer import AnalyzerAgent
from karsasec.agents.models import AgentInput, AnalyzerOutput, FindingAnalysis
from karsasec.agents.orchestrator import AgentOrchestrator
from karsasec.agents.planner import PlannerAgent
from karsasec.agents.remediator import RemediatorAgent
from karsasec.agents.reporter import ReporterAgent
from karsasec.agents.validation.syntax_check import SyntaxValidator
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.rag.service import RAGDocument, RAGService
from karsasec.rules.enums import Confidence, Severity


def _make_finding(
    finding_id: str = "F-TEST",
    rule_id: str = "KS-PHP-SQLI-001",
    cwe: str = "CWE-89",
    file_path: str = "db.php",
    line: int = 10,
    severity: Severity = Severity.CRITICAL,
    snippet: str = "$conn->query('SELECT * FROM users WHERE id = ' . $_GET['id']);",
    owasp: str = "A03:2021-Injection",
) -> Finding:
    """Helper to create an authentic Finding object for tests."""
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        fingerprint=f"sha256-test-{finding_id}",
        title=f"Test finding {finding_id}",
        severity=severity,
        confidence=Confidence.CONFIDENT,
        cwe_id=cwe,
        owasp=owasp,
        file_path=Path(file_path),
        evidence=Evidence(line=line, column=1, snippet=snippet),
        description=snippet,
        remediation="Use parameterized queries.",
    )


def test_task_z1_planner_agent_with_dicts() -> None:
    """Task Z-1: Planner sorts dict-based findings by severity and confidence."""
    planner = PlannerAgent()
    findings = [
        {"id": "F-01", "severity": "LOW", "confidence": 0.5, "cwe": "CWE-20"},
        {"id": "F-02", "severity": "CRITICAL", "confidence": 0.9, "cwe": "CWE-89"},
        {"id": "F-03", "severity": "HIGH", "confidence": 0.8, "cwe": "CWE-78"},
    ]
    out = planner.plan("/tmp/test", findings)
    assert out.total_findings == 3
    assert out.ordered_findings[0]["id"] == "F-02"
    assert out.ordered_findings[1]["id"] == "F-03"
    assert out.ordered_findings[2]["id"] == "F-01"


def test_task_z1_planner_agent_with_finding_objects() -> None:
    """Task Z-1: Planner sorts authentic Finding objects and preserves them in ordered_findings_raw."""
    planner = PlannerAgent()
    f_low = _make_finding(finding_id="F-LOW", severity=Severity.LOW)
    f_crit = _make_finding(finding_id="F-CRIT", severity=Severity.CRITICAL)
    f_high = _make_finding(finding_id="F-HIGH", severity=Severity.HIGH)

    out = planner.plan("/tmp/test", [f_low, f_crit, f_high])
    assert out.total_findings == 3
    assert out.ordered_findings[0]["id"] == "F-CRIT"
    assert out.ordered_findings_raw is not None
    assert isinstance(out.ordered_findings_raw[0], Finding)
    assert out.ordered_findings_raw[0].finding_id == "F-CRIT"


def test_task_z1_analyzer_preserves_authentic_finding() -> None:
    """B1 fix: Analyzer uses authentic Finding objects instead of reconstructing synthetic ones."""
    analyzer = AnalyzerAgent()
    f = _make_finding(
        finding_id="F-AUTH",
        owasp="A10:2021-Server-Side Request Forgery",
        cwe="CWE-918",
    )
    planner = PlannerAgent()
    plan = planner.plan("test.php", [f])

    out = analyzer.analyze(
        target_path="test.php",
        ordered_findings=plan.ordered_findings,
        ordered_findings_raw=plan.ordered_findings_raw,
    )
    assert len(out.analyses) == 1
    analysis = out.analyses[0]

    # Verify authentic metadata was preserved
    assert analysis.cwe == "CWE-918"
    assert analysis.finding_id == "F-AUTH"
    assert analysis.finding_obj is not None
    assert analysis.finding_obj.owasp == "A10:2021-Server-Side Request Forgery"
    assert analysis.root_cause_category != ""


def test_task_z1_analyzer_agent_fallback_dict() -> None:
    """Task Z-1: Analyzer still works with dict-only input (legacy path)."""
    analyzer = AnalyzerAgent()
    findings = [
        {
            "id": "F-SQLI",
            "rule_id": "KS-PHP-SQLI-001",
            "cwe": "CWE-89",
            "file_path": "db.php",
            "line_number": 10,
            "severity": "CRITICAL",
            "snippet": "$conn->query('SELECT * FROM users WHERE id = ' . $_GET['id']);",
        }
    ]
    out = analyzer.analyze("db.php", findings)
    assert len(out.analyses) == 1
    assert out.analyses[0].finding_id == "F-SQLI"
    assert out.analyses[0].cwe == "CWE-89"


def test_task_z2_rag_grounding_success_and_missing() -> None:
    """Task Z-2: RAG grounding attaches snippets when found, marks NO_GROUNDING_FOUND when empty."""
    doc = RAGDocument(
        document_id="CWE-89-DOC",
        text="CWE-89 SQL Injection Remediation Guide: Use PDO prepared statements or parameterized queries.",
        metadata={"source_path": "docs/sqli.md", "source_file": "sqli.md", "chunk_index": "1"},
    )
    rag_service = RAGService([doc])
    remediator = RemediatorAgent(rag_service=rag_service)

    analysis_grounded = FindingAnalysis(
        finding_id="F-RAG-1",
        cwe="CWE-89",
        rule_id="KS-PHP-SQLI-001",
        file_path="app/db.py",
        line_number=5,
        severity="HIGH",
        root_cause_category="UNPARSED_INPUT",
        explanation="SQL Injection via $_GET",
        evidence_references=[],
    )

    out_grounded = remediator.remediate("app/db.py", [analysis_grounded])
    prop_g = out_grounded.proposals[0]
    assert prop_g.validation.rag_grounded is True
    assert prop_g.validation.grounding_status == "RAG_GROUNDED"
    assert len(prop_g.rag_snippets) > 0

    # Empty RAG service -> NO_GROUNDING_FOUND
    analysis_missing = FindingAnalysis(
        finding_id="F-RAG-2",
        cwe="CWE-UNKNOWN-9999",
        rule_id="UNKNOWN-RULE-X",
        file_path="app/unknown.py",
        line_number=1,
        severity="LOW",
        root_cause_category="UNKNOWN",
        explanation="Unknown vulnerability",
        evidence_references=[],
    )
    empty_rag = RAGService([])
    remediator_empty = RemediatorAgent(rag_service=empty_rag)
    out_missing = remediator_empty.remediate("app/unknown.py", [analysis_missing])
    prop_m = out_missing.proposals[0]
    assert prop_m.validation.rag_grounded is False
    assert prop_m.validation.grounding_status == "NO_GROUNDING_FOUND"


def test_task_z3_native_syntax_validation() -> None:
    """Task Z-3: Native syntax validator detects syntax errors without subprocess execution."""
    valid_python = "def foo():\n    return 42\n"
    invalid_python = "def foo():\n    return 42 +\n"

    val_good, err_good = SyntaxValidator.validate_source(valid_python, "script.py")
    assert val_good is True
    assert err_good is None

    val_bad, err_bad = SyntaxValidator.validate_source(invalid_python, "script.py")
    assert val_bad is False
    assert "SyntaxError" in str(err_bad)


def test_task_z1_end_to_end_orchestration() -> None:
    """Task Z-1: End-to-end 4-agent orchestration producing formatted report."""
    orchestrator = AgentOrchestrator()
    agent_input = AgentInput(
        target_path="/tmp/test_project",
        findings=[
            {
                "id": "F-E2E-1",
                "rule_id": "KS-PY-SQLI-001",
                "cwe": "CWE-89",
                "file_path": "main.py",
                "line_number": 12,
                "severity": "HIGH",
                "description": "SQL Injection vulnerability",
            }
        ],
    )
    report = orchestrator.run_review(agent_input, output_format="console")
    assert "KARSASEC MULTI-AGENT REVIEW REPORT" in report.formatted_report
    assert report.summary["total_findings"] == 1
    assert report.summary["total_proposals"] == 1


def test_task_z1_e2e_with_finding_objects() -> None:
    """B3 fix: End-to-end orchestration with authentic Finding objects."""
    f = _make_finding(
        finding_id="F-E2E-AUTH",
        owasp="A03:2021-Injection",
        cwe="CWE-89",
    )
    orchestrator = AgentOrchestrator()
    agent_input = AgentInput(
        target_path="/tmp/test_project",
        findings_raw=[f],
    )
    report = orchestrator.run_review(agent_input, output_format="console")
    assert "KARSASEC MULTI-AGENT REVIEW REPORT" in report.formatted_report
    assert "Root Cause:" in report.formatted_report
    assert "Explanation:" in report.formatted_report
    assert report.summary["total_findings"] == 1


def test_reporter_includes_analysis_output() -> None:
    """B7 fix: ReporterAgent includes RCA explanation in console output."""
    from karsasec.agents.models import (
        FixValidationInfo,
        PlannerOutput,
        RemediationProposalResult,
        RemediatorOutput,
    )

    planner_out = PlannerOutput(target_path="/test", total_findings=1, ordered_findings=[])
    analyzer_out = AnalyzerOutput(
        analyses=[
            FindingAnalysis(
                finding_id="F-RPT",
                cwe="CWE-78",
                rule_id="KS-PY-CMD-001",
                file_path="cmd.py",
                line_number=5,
                severity="HIGH",
                root_cause_category="MISSING_SANITIZATION",
                explanation="OS command injection via user input",
                evidence_references=[],
            )
        ]
    )
    remediator_out = RemediatorOutput(
        proposals=[
            RemediationProposalResult(
                finding_id="F-RPT",
                file_path="cmd.py",
                start_line=5,
                unified_diff="",
                rationale="Sanitize input",
                strategy_type="REPLACE_UNSAFE_API",
                validation=FixValidationInfo(syntax_valid=True, confidence="SYNTAX_ONLY"),
            )
        ]
    )

    reporter = ReporterAgent()
    result = reporter.report(planner_out, analyzer_out, remediator_out, output_format="console")
    assert "Root Cause: MISSING_SANITIZATION" in result.formatted_report
    assert "OS command injection" in result.formatted_report


def test_sqli_and_rce_produce_concrete_strategy_and_non_empty_diff() -> None:
    """Verifies SQLi and RCE findings transition from MANUAL_REVIEW_REQUIRED to concrete strategies producing non-empty diffs."""
    f_sqli = _make_finding(
        finding_id="F-SQLI-TEST",
        rule_id="KS-PHP-SQLI-001",
        cwe="CWE-89",
        file_path="app.php",
        line=3,
        snippet="$res = mysqli_query($conn, 'SELECT * FROM users WHERE id = ' . $_GET['id']);",
    )
    f_rce = _make_finding(
        finding_id="F-RCE-TEST",
        rule_id="KS-PHP-RCE-001",
        cwe="CWE-78",
        file_path="exec.php",
        line=4,
        snippet="system($_GET['cmd']);",
    )

    orchestrator = AgentOrchestrator()
    agent_input = AgentInput(
        target_path="/tmp/test_project",
        findings_raw=[f_sqli, f_rce],
    )
    report = orchestrator.run_review(agent_input, output_format="console")

    assert "ADD_PARAMETERIZATION" in report.formatted_report
    assert "REPLACE_UNSAFE_API" in report.formatted_report
    assert "Proposed Diff" in report.formatted_report
    assert "--- a/" in report.formatted_report or "--- " in report.formatted_report

