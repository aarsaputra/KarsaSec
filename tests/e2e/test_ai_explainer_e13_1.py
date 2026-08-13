"""End-to-End integration test suite for Sprint E13-1 RAG Explainer Agent."""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.evidence_context import SecurityFindingContextBuilder
from karsasec.ai.explainer.agent import ExplainerAgent, MockLLMProvider
from karsasec.core.finding.evidence import Evidence, FindingEvidence
from karsasec.core.finding.model import Finding, QualifiedFinding, QualificationState
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _make_verdict(
    verdict_id: str,
    status: VerdictStatus,
    rule_id: str,
    sink_cat: str,
    file_path: str,
    var_ver: str,
    call_ctx: str = "GLOBAL",
    branch_pol: str = "UNKNOWN",
) -> SecurityVerdict:
    return SecurityVerdict.create(
        status=status,
        confidence=VerdictConfidence.HIGH,
        rule_id=rule_id,
        sink_id="sink_01",
        sink_category=sink_cat,
        file_path=file_path,
        function_name="target_fn",
        line_number=20,
        variable_version=var_ver,
        call_context=call_ctx,
        branch_polarity=branch_pol,
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=(f"{file_path}:5", f"{file_path}:20"),
    )


def test_e13_1_01_sqli_finding() -> None:
    verdict = _make_verdict("V-01", VerdictStatus.VULNERABLE, "RULE-SQLI", "SQL_EXECUTION", "db.py", "$sql#1")
    finding = Finding(
        finding_id="F-E2E-01",
        rule_id="RULE-SQLI",
        fingerprint="fp_e2e_01",
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("db.py"),
        evidence=Evidence(snippet="exec(sql)", line=20, column=1),
        description="SQL Injection",
        remediation="Parameterize",
        verdict=verdict,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding)

    assert explanation.finding_id == "F-E2E-01"
    assert verdict.status == VerdictStatus.VULNERABLE  # SAST verdict unmodified
    assert explanation.provenance.verdict_fingerprint == verdict.canonical_fingerprint


def test_e13_1_02_xss_compatible_sanitizer() -> None:
    verdict = _make_verdict("V-02", VerdictStatus.SAFE, "RULE-XSS", "XSS_SINK", "view.php", "$html#1")
    ee = FindingEvidence(
        snippet="echo htmlspecialchars($input);",
        line=20,
        column=1,
        sanitizer_symbol="htmlspecialchars",
        sink_category="XSS_SINK",
    )
    finding = QualifiedFinding(
        finding_id="F-E2E-02",
        rule_id="RULE-XSS",
        fingerprint="fp_e2e_02",
        title="Reflected XSS",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        cwe_id="CWE-79",
        owasp="A03:2021",
        file_path=Path("view.php"),
        evidence=Evidence(snippet="echo htmlspecialchars($input);", line=20, column=1),
        description="XSS Sanitized",
        remediation="None needed",
        qualification_state=QualificationState.REJECTED,
        enriched_evidence=ee,
        verdict=verdict,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding)

    assert explanation.finding_id == "F-E2E-02"
    assert verdict.status == VerdictStatus.SAFE


def test_e13_1_03_xss_incompatible_sanitizer() -> None:
    verdict = _make_verdict("V-03", VerdictStatus.VULNERABLE, "RULE-XSS", "XSS_SINK", "render.php", "$raw#1")
    ee = FindingEvidence(
        snippet="echo addslashes($raw);",
        line=20,
        column=1,
        sanitizer_symbol="addslashes",
        sink_category="XSS_SINK",
    )
    finding = QualifiedFinding(
        finding_id="F-E2E-03",
        rule_id="RULE-XSS",
        fingerprint="fp_e2e_03",
        title="Reflected XSS Incompatible Sanitizer",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-79",
        owasp="A03:2021",
        file_path=Path("render.php"),
        evidence=Evidence(snippet="echo addslashes($raw);", line=20, column=1),
        description="Incompatible sanitizer on XSS sink",
        remediation="Use htmlspecialchars",
        qualification_state=QualificationState.CONFIRMED,
        enriched_evidence=ee,
        verdict=verdict,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding)

    assert explanation.finding_id == "F-E2E-03"
    assert verdict.status == VerdictStatus.VULNERABLE


def test_e13_1_04_interprocedural_finding() -> None:
    verdict = _make_verdict("V-04", VerdictStatus.VULNERABLE, "RULE-CMDI", "COMMAND_EXECUTION", "service.py", "$cmd#2")
    finding = Finding(
        finding_id="F-E2E-04",
        rule_id="RULE-CMDI",
        fingerprint="fp_e2e_04",
        title="Command Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe_id="CWE-78",
        owasp="A03:2021",
        file_path=Path("service.py"),
        evidence=Evidence(snippet="os.system(cmd)", line=20, column=1),
        description="Command injection interprocedural",
        remediation="Use subprocess with list",
        verdict=verdict,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding)
    assert explanation.finding_id == "F-E2E-04"


def test_e13_1_05_cross_file_finding() -> None:
    verdict = _make_verdict("V-05", VerdictStatus.VULNERABLE, "RULE-SQLI", "SQL_EXECUTION", "repo.py", "$q#1")
    ee = FindingEvidence(
        snippet="repo.query(q)",
        line=20,
        column=1,
        source_symbol="web/routes.py:12",
        sink_symbol="repo.py:20",
        sink_category="SQL_EXECUTION",
    )
    finding = QualifiedFinding(
        finding_id="F-E2E-05",
        rule_id="RULE-SQLI",
        fingerprint="fp_e2e_05",
        title="Cross File SQLi",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("repo.py"),
        evidence=Evidence(snippet="repo.query(q)", line=20, column=1),
        description="Cross file taint",
        remediation="Fix it",
        qualification_state=QualificationState.CONFIRMED,
        enriched_evidence=ee,
        verdict=verdict,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding)
    assert explanation.finding_id == "F-E2E-05"


def test_e13_1_06_multiple_call_contexts() -> None:
    verdict = _make_verdict("V-06", VerdictStatus.VULNERABLE, "RULE-XSS", "XSS_SINK", "app.py", "$p#1", call_ctx="call_ctx_admin")
    finding = Finding(
        finding_id="F-E2E-06",
        rule_id="RULE-XSS",
        fingerprint="fp_e2e_06",
        title="Context Isolated XSS",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-79",
        owasp="A03:2021",
        file_path=Path("app.py"),
        evidence=Evidence(snippet="render(p)", line=20, column=1),
        description="Call context isolated finding",
        remediation="Sanitize",
        verdict=verdict,
    )

    ctx = SecurityFindingContextBuilder.build(finding, verdict)
    assert ctx.call_context == "call_ctx_admin"


def test_e13_1_07_ssa_reassignment() -> None:
    verdict = _make_verdict("V-07", VerdictStatus.VULNERABLE, "RULE-SQLI", "SQL_EXECUTION", "db.py", "$var#2")
    finding = Finding(
        finding_id="F-E2E-07",
        rule_id="RULE-SQLI",
        fingerprint="fp_e2e_07",
        title="SSA Reassigned SQLi",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("db.py"),
        evidence=Evidence(snippet="query(var_2)", line=20, column=1),
        description="SSA version 2 taint",
        remediation="Fix it",
        verdict=verdict,
    )

    ctx = SecurityFindingContextBuilder.build(finding, verdict)
    assert ctx.variable_version == "$var#2"


def test_e13_1_08_unknown_evidence() -> None:
    finding = Finding(
        finding_id="F-E2E-08",
        rule_id="RULE-UNKNOWN",
        fingerprint="fp_e2e_08",
        title="Unknown Evidence Finding",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe_id="CWE-20",
        owasp="A04:2021",
        file_path=Path("unknown.py"),
        evidence=Evidence(snippet="check()", line=1, column=1),
        description="Unknown evidence",
        remediation="Review code",
        verdict=None,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding)
    assert explanation.finding_id == "F-E2E-08"


def test_e13_1_09_missing_knowledge() -> None:
    verdict = _make_verdict("V-09", VerdictStatus.VULNERABLE, "RULE-SQLI", "SQL_EXECUTION", "main.py", "$x#1")
    finding = Finding(
        finding_id="F-E2E-09",
        rule_id="RULE-SQLI",
        fingerprint="fp_e2e_09",
        title="Missing Knowledge Finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("main.py"),
        evidence=Evidence(snippet="exec()", line=1, column=1),
        description="Finding without RAG knowledge",
        remediation="Fix it",
        verdict=verdict,
    )

    agent = ExplainerAgent(provider=MockLLMProvider())
    explanation = agent.explain(finding, knowledge_chunks=[])
    assert explanation.finding_id == "F-E2E-09"
    assert explanation.knowledge_references == []


def test_e13_1_10_llm_unavailable_fallback() -> None:
    verdict = _make_verdict("V-10", VerdictStatus.VULNERABLE, "RULE-SQLI", "SQL_EXECUTION", "main.py", "$x#1")
    finding = Finding(
        finding_id="F-E2E-10",
        rule_id="RULE-SQLI",
        fingerprint="fp_e2e_10",
        title="Fallback Finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("main.py"),
        evidence=Evidence(snippet="exec()", line=1, column=1),
        description="Fallback mode test",
        remediation="Fix it",
        verdict=verdict,
    )

    failing_provider = MockLLMProvider(should_fail=True)
    agent = ExplainerAgent(provider=failing_provider)
    explanation = agent.explain(finding)

    assert explanation.finding_id == "F-E2E-10"
    assert explanation.provenance.provider == "template-fallback"
    assert verdict.status == VerdictStatus.VULNERABLE  # SAST verdict remains unchanged!
