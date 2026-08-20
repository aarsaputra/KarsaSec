"""Unit tests for evidence provenance, FindingEvidence model, and EvidenceCompleteness validation (E12-4)."""

from karsasec.core.finding.evidence import EvidenceCompleteness, FindingEvidence, ProvenanceStatus
from karsasec.graph.dataflow.model import TaintState


def test_finding_evidence_full_provenance() -> None:
    ev = FindingEvidence(
        snippet="shell_exec($_GET['cmd']);",
        line=15,
        column=4,
        rule_id="KS-OWASP-0010",
        node_type="sink",
        matched_text="shell_exec",
        sink_symbol="shell_exec",
        sink_category="COMMAND_EXECUTION",
        source_symbol="$_GET['cmd']",
        source_category="USER_INPUT",
        taint_state=TaintState.TAINTED,
        constant_resolution="DYNAMIC",
        sanitizer_symbol="",
        sanitizer_capability="NONE",
        ast_match=True,
        semantic_match=True,
        qualification_state="CONFIRMED",
        rejection_reason="",
    )
    assert ev.rule_id == "KS-OWASP-0010"
    assert ev.sink_category == "COMMAND_EXECUTION"
    assert ev.taint_state == TaintState.TAINTED

    d = ev.to_dict()
    assert d["rule_id"] == "KS-OWASP-0010"
    assert d["sink_category"] == "COMMAND_EXECUTION"
    assert d["taint_state"] == "TAINTED"


def test_evidence_completeness_validation() -> None:
    # 1. Complete evidence for CONFIRMED state
    complete_ev = FindingEvidence(
        snippet="eval($code);",
        line=10,
        column=1,
        sink_category="CODE_EVALUATION",
        sink_symbol="eval",
    )
    res = EvidenceCompleteness.evaluate(complete_ev, "CONFIRMED")
    assert res.is_complete is True
    assert res.status == ProvenanceStatus.KNOWN

    # 2. Incomplete evidence for CONFIRMED state (missing sink category/symbol)
    incomplete_ev = FindingEvidence(
        snippet="",
        line=0,
        column=0,
        sink_category="UNKNOWN",
        sink_symbol="",
    )
    res_inc = EvidenceCompleteness.evaluate(incomplete_ev, "CONFIRMED")
    assert res_inc.is_complete is False
    assert "snippet" in res_inc.missing_fields
    assert "line" in res_inc.missing_fields

    # 3. None evidence
    res_none = EvidenceCompleteness.evaluate(None, "CONFIRMED")
    assert res_none.is_complete is False
    assert "evidence" in res_none.missing_fields
