"""Unit tests for EvidenceConflict model and conflict resolution (E12-4)."""

from pathlib import Path

from karsasec.core.finding.conflict import ConflictCategory, detect_evidence_conflict
from karsasec.core.finding.correlator import FindingCorrelator
from karsasec.core.finding.evidence import Evidence, FindingEvidence
from karsasec.core.finding.model import QualificationState, QualifiedFinding
from karsasec.graph.dataflow.model import TaintState
from karsasec.rules.enums import Confidence, Severity


def test_detect_evidence_conflict_taint_state() -> None:
    ev_a = FindingEvidence(snippet="exec($x)", line=5, column=1, taint_state=TaintState.TAINTED, qualification_state="CONFIRMED")
    ev_b = FindingEvidence(snippet="exec($x)", line=5, column=1, taint_state=TaintState.SANITIZED, qualification_state="CONFIRMED")

    conflict = detect_evidence_conflict(ev_a, ev_b, "RULE-A", "RULE-B")
    assert conflict is not None
    assert conflict.conflict_type == ConflictCategory.TAINT_STATE_CONFLICT
    assert conflict.resolution == "UNRESOLVED"


def test_detect_evidence_conflict_qualification_disagreement() -> None:
    ev_a = FindingEvidence(snippet="exec($x)", line=5, column=1, qualification_state="CONFIRMED")
    ev_b = FindingEvidence(snippet="exec($x)", line=5, column=1, qualification_state="REJECTED")

    conflict = detect_evidence_conflict(ev_a, ev_b, "RULE-A", "RULE-B")
    assert conflict is not None
    assert conflict.conflict_type == ConflictCategory.QUALIFICATION_CONFLICT
    assert conflict.resolution == "UNRESOLVED"


def test_correlator_case_d_conflict_to_unresolved() -> None:
    correlator = FindingCorrelator()

    f1 = QualifiedFinding(
        finding_id="f1",
        rule_id="RULE-A",
        fingerprint="fp1",
        title="Test A",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-78",
        owasp="A03",
        file_path=Path("app.php"),
        evidence=Evidence(snippet="system($x)", line=10, column=1),
        description="",
        remediation="",
        qualification_state=QualificationState.CONFIRMED,
        enriched_evidence=FindingEvidence(
            snippet="system($x)", line=10, column=1, rule_id="RULE-A", sink_category="COMMAND_EXECUTION", taint_state=TaintState.TAINTED, qualification_state="CONFIRMED"
        ),
    )

    f2 = QualifiedFinding(
        finding_id="f2",
        rule_id="RULE-B",
        fingerprint="fp2",
        title="Test B",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-78",
        owasp="A03",
        file_path=Path("app.php"),
        evidence=Evidence(snippet="system($x)", line=10, column=1),
        description="",
        remediation="",
        qualification_state=QualificationState.REJECTED,
        enriched_evidence=FindingEvidence(
            snippet="system($x)", line=10, column=1, rule_id="RULE-B", sink_category="COMMAND_EXECUTION", taint_state=TaintState.SANITIZED, qualification_state="REJECTED"
        ),
    )

    canonical = correlator.correlate([f1, f2])
    assert len(canonical) == 1
    assert correlator.conflict_count == 1
    primary = canonical[0].primary
    assert primary.qualification_state == QualificationState.UNRESOLVED
