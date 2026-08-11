"""Unit tests for FindingCorrelator 4-case correlation logic (E12-4)."""

from pathlib import Path

from karsasec.core.finding.correlator import FindingCorrelator
from karsasec.core.finding.evidence import Evidence, FindingEvidence
from karsasec.core.finding.model import QualificationState, QualifiedFinding
from karsasec.graph.dataflow.model import TaintState
from karsasec.rules.enums import Confidence, Severity


def _make_qualified_finding(
    rule_id: str,
    file_path: str = "vulnerabilities/exec/source/low.php",
    line: int = 15,
    snippet: str = "shell_exec($cmd)",
    sink_cat: str = "COMMAND_EXECUTION",
    taint_state: TaintState = TaintState.TAINTED,
    q_state: QualificationState = QualificationState.CONFIRMED,
) -> QualifiedFinding:
    ev = Evidence(snippet=snippet, line=line, column=1)
    enriched = FindingEvidence(
        snippet=snippet,
        line=line,
        column=1,
        rule_id=rule_id,
        sink_category=sink_cat,
        sink_symbol=snippet.split("(")[0],
        taint_state=taint_state,
        qualification_state=q_state.value,
    )
    return QualifiedFinding(
        finding_id=f"f-{rule_id}-{line}",
        rule_id=rule_id,
        fingerprint=f"fp-{rule_id}",
        title=f"Finding {rule_id}",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-78",
        owasp="A03:2021",
        file_path=Path(file_path),
        evidence=ev,
        description="Desc",
        remediation="Rem",
        qualification_state=q_state,
        enriched_evidence=enriched,
    )


def test_correlation_case_a_exact_duplicate() -> None:
    correlator = FindingCorrelator()
    f1 = _make_qualified_finding("KS-OWASP-0010", line=15)
    f2 = _make_qualified_finding("KS-OWASP-0010", line=15)

    canonical = correlator.correlate([f1, f2])
    assert len(canonical) == 1
    assert correlator.exact_duplicate_count == 1
    assert correlator.semantic_duplicate_count == 0


def test_correlation_case_b_semantic_duplicate() -> None:
    correlator = FindingCorrelator()
    f1 = _make_qualified_finding("KS-OWASP-0010", line=15)
    f2 = _make_qualified_finding("KS-PHP-EXEC-0001", line=15)

    canonical = correlator.correlate([f1, f2])
    assert len(canonical) == 1
    assert correlator.exact_duplicate_count == 0
    assert correlator.semantic_duplicate_count == 1
    assert set(canonical[0].correlated_rule_ids) == {"KS-OWASP-0010", "KS-PHP-EXEC-0001"}


def test_correlation_case_c_different_vulnerabilities() -> None:
    correlator = FindingCorrelator()
    f1 = _make_qualified_finding("KS-OWASP-0010", line=15, sink_cat="COMMAND_EXECUTION")
    f2 = _make_qualified_finding("KS-OWASP-0001", line=15, sink_cat="SQL_EXECUTION")

    canonical = correlator.correlate([f1, f2])
    assert len(canonical) == 2
    assert correlator.exact_duplicate_count == 0
    assert correlator.semantic_duplicate_count == 0


def test_correlation_to_findings_preserves_qualified_findings() -> None:
    correlator = FindingCorrelator()
    f1 = _make_qualified_finding("KS-OWASP-0010", line=15)
    f2 = _make_qualified_finding("KS-PHP-EXEC-0001", line=15)

    canonical = correlator.correlate([f1, f2])
    final = correlator.to_findings(canonical)
    assert len(final) == 1
    assert isinstance(final[0], QualifiedFinding)
    assert final[0].metadata["correlated_rules"] == ["KS-OWASP-0010", "KS-PHP-EXEC-0001"]
