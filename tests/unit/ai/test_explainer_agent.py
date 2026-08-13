"""Unit tests for ExplainerAgent and Offline Fallback (E13-1)."""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.explainer.agent import ExplainerAgent, MockLLMProvider
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _create_sample_finding() -> Finding:
    verdict = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-SQLI",
        sink_id="sink_exec",
        sink_category="SQL_EXECUTION",
        file_path="app/query.py",
        function_name="execute",
        line_number=20,
        variable_version="$raw_id#1",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=("app/main.py:5", "app/query.py:20"),
    )

    return Finding(
        finding_id="F-401",
        rule_id="RULE-SQLI",
        fingerprint="fp_401",
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("app/query.py"),
        evidence=Evidence(snippet="cursor.execute(sql)", line=20, column=1),
        description="Unsanitized query execution.",
        remediation="Use parameterized queries.",
        verdict=verdict,
    )


def test_explainer_agent_with_mock_provider() -> None:
    finding = _create_sample_finding()
    agent = ExplainerAgent(provider=MockLLMProvider())

    explanation = agent.explain(finding)
    assert explanation.finding_id == "F-401"
    assert explanation.vulnerability_type == "CWE-89"
    assert explanation.explanation_fingerprint != ""
    assert "F-401" in explanation.provenance.finding_id


def test_explainer_agent_offline_fallback() -> None:
    finding = _create_sample_finding()
    failing_provider = MockLLMProvider(should_fail=True)
    agent = ExplainerAgent(provider=failing_provider)

    explanation = agent.explain(finding)
    assert explanation.finding_id == "F-401"
    assert "Fallback" in explanation.limitations or "Deterministic SAST Verdict" in explanation.summary
    assert explanation.provenance.provider == "template-fallback"


def test_explainer_agent_canonical_fingerprint_determinism() -> None:
    finding = _create_sample_finding()
    agent = ExplainerAgent(provider=MockLLMProvider())

    exp1 = agent.explain(finding)
    exp2 = agent.explain(finding)

    assert exp1.explanation_fingerprint == exp2.explanation_fingerprint
    assert exp1.provenance.compute_fingerprint() == exp2.provenance.compute_fingerprint()
