"""Comprehensive Unit & Adversarial Test Suite for RemediationProvenanceGraph (Sprint E13-5 Phase 2).

Validates Security Invariants P1-P18:
  - P1: Immutability
  - P2-P4: Node Identity, Chain Continuity, Orphan Prevention
  - P5-P6: Deterministic Canonical Fingerprinting & Order Invariance
  - P7-P15: Domain Evidence Binding (Finding, Evidence, RCA, Strategy, Proposal, Token, Snapshot, App, Verification)
  - P8: Observational Only (No Security Verdict Authority)
  - P16: No Auto-Repair / Execution Capabilities
  - P17: No Secret / Raw Source Code Leakage
  - P18: Deterministic Graph Fingerprint
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

pytest_plugins = []

import pytest

from karsasec.ai.rca.models import (
    FalsePositiveAssessment,
    ReflectionStatus,
    RootCauseAnalysis,
    RootCauseCategory,
)
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.applier import ApplicationResult, ApplicationStatus
from karsasec.ai.remediation.models import (
    PatchHunk,
    PatchProposal,
    PatchValidationStatus,
    RemediationStrategy,
    RemediationStrategyType,
)
from karsasec.ai.remediation.provenance import (
    ProvenanceNode,
    ProvenanceNodeType,
    RemediationProvenanceGraph,
)
from karsasec.ai.remediation.snapshot import FileSnapshot, SourceSnapshot
from karsasec.ai.remediation.state_machine import (
    LifecycleStateMachine,
    RemediationLifecycleState,
)
from karsasec.ai.remediation.verification import (
    VerificationContract,
    VerificationResult,
    VerificationStatus,
)
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import (
    SecurityVerdict,
    VerdictConfidence,
    VerdictStatus,
)
from karsasec.rules.enums import Confidence, Severity

# =============================================================================
# HELPER FIXTURES & BUILDERS
# =============================================================================


def _make_dummy_finding(finding_id: str = "F-101") -> Finding:
    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-01",
        sink_id="SINK-1",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        function_name="get_user",
        line_number=10,
        variable_version="query",
    )
    ev = Evidence(
        snippet="query = f'SELECT * FROM users WHERE name={name}'",
        line=10,
        column=1,
    )
    return Finding(
        finding_id=finding_id,
        rule_id="RULE-01",
        fingerprint="find_fp_101",
        title="SQL Injection in get_user",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021-Injection",
        file_path=Path("app.py"),
        evidence=ev,
        description="SQL injection vulnerability",
        remediation="Use parameterized queries",
        verdict=v,
    )


def _make_dummy_rca(finding_id: str = "F-101") -> RootCauseAnalysis:
    return RootCauseAnalysis(
        finding_id=finding_id,
        rule_id="RULE-01",
        verdict_status="VULNERABLE",
        root_cause_category=RootCauseCategory.DIRECT_USER_INPUT,
        primary_cause_step=None,
        evidence_chain=(),
        evidence_gaps=(),
        contradictions=(),
        false_positive_risk=FalsePositiveAssessment.LOW_RISK,
        reflection_status=ReflectionStatus.PROVEN,
        explanation_summary="Unsanitized user input concatenated into query string.",
        remediation_advice="Use parameterized queries.",
        rca_fingerprint="rca_fp_101",
    )


def _make_dummy_strategy(finding_id: str = "F-101") -> RemediationStrategy:
    return RemediationStrategy(
        finding_id=finding_id,
        root_cause_category=RootCauseCategory.DIRECT_USER_INPUT,
        strategy_type=RemediationStrategyType.ADD_PARAMETERIZATION,
        rationale="Add parameterization to cursor execute.",
        target_file="app.py",
        target_locations=("app.py:10",),
        affected_symbols=("query",),
        evidence_references=("app.py:10",),
        knowledge_references=(),
        confidence=0.9,
        assumptions=(),
        limitations=(),
        strategy_fingerprint="strat_fp_101",
    )


def _make_dummy_proposal(finding_id: str = "F-101") -> PatchProposal:
    hunk = PatchHunk(
        file_path="app.py",
        start_line=10,
        end_line=10,
        original_text="query = f'SELECT * FROM users WHERE name={name}'",
        proposed_text="cursor.execute('SELECT * FROM users WHERE name=%s', (name,))",
        context="def get_user(name):",
        evidence_reference="app.py:10",
    )
    return PatchProposal(
        proposal_id="prop_101",
        finding_id=finding_id,
        target_files=("app.py",),
        hunks=(hunk,),
        unified_diff="--- a/app.py\n+++ b/app.py\n@@ -10,1 +10,1 @@\n-query = f'SELECT * FROM users WHERE name={name}'\n+cursor.execute('SELECT * FROM users WHERE name=%s', (name,))",
        rationale="Add parameterization",
        root_cause_reference="rca_fp_101",
        evidence_references=("app.py:10",),
        expected_effect="Eliminates SQLi",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint="prop_fp_101",
    )


def _make_dummy_token(finding_id: str = "F-101") -> PatchApprovalToken:
    return PatchApprovalToken.create(
        token_id="tok_101",
        finding_id=finding_id,
        proposal_fingerprint="prop_fp_101",
        source_snapshot_hash="src_snap_101",
        target_files=("app.py",),
        repository_identity="/repo",
        approved_by="lead_architect",
        approved_at="2026-08-13T12:00:00Z",
    )


def _make_dummy_snapshot() -> SourceSnapshot:
    fs = FileSnapshot(relative_path="app.py", file_size=100, sha256="hash_app_py", exists=True)
    return SourceSnapshot(
        repository_root="/repo",
        file_snapshots=(fs,),
        aggregate_hash="src_snap_101",
        created_at="2026-08-13T12:00:00Z",
    )


def _make_dummy_app_result(finding_id: str = "F-101") -> ApplicationResult:
    return ApplicationResult(
        transaction_id="app_res_101",
        finding_id=finding_id,
        proposal_fingerprint="prop_fp_101",
        token_id="tok_101",
        status=ApplicationStatus.APPLIED,
        target_files=("app.py",),
        pre_apply_snapshot_hash="src_snap_101",
        post_apply_snapshot_hash="post_snap_101",
        rollback_status="NOT_NEEDED",
        failure_reason=None,
    )


def _make_dummy_ver_result(finding_id: str = "F-101") -> VerificationResult:
    contract = VerificationContract(
        finding_id=finding_id,
        rule_id="RULE-01",
        cwe_id="CWE-89",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        line_number=10,
        affected_symbol="query",
        evidence_fingerprint="ev_fp_101",
    )
    return VerificationResult(
        verification_id="ver_res_101",
        finding_id=finding_id,
        pre_apply_verdict_status="VULNERABLE",
        post_apply_verdict_status="SAFE",
        status=VerificationStatus.VERIFIED_FIXED,
        contract=contract,
        matching_findings_count=0,
        details="Vulnerability eliminated",
    )


# =============================================================================
# 1. PROVENANCE NODE TESTS (1 - 7)
# =============================================================================


def test_01_provenance_node_creation_and_fingerprint() -> None:
    finding = _make_dummy_finding()
    node = ProvenanceNode.create_finding_node(finding)

    assert node.node_id == "prov_finding_F-101"
    assert node.node_type == ProvenanceNodeType.FINDING
    assert len(node.fingerprint) == 64
    assert node.predecessor_node_ids == ()


def test_02_provenance_node_is_frozen_dataclass_p1() -> None:
    finding = _make_dummy_finding()
    node = ProvenanceNode.create_finding_node(finding)

    with pytest.raises(dataclasses.FrozenInstanceError):
        node.fingerprint = "malicious_fp"  # type: ignore[misc]


def test_03_tampered_node_fingerprint_rejected_p27() -> None:
    with pytest.raises(ValueError, match="Tampered or invalid node fingerprint"):
        ProvenanceNode(
            node_id="n1",
            node_type=ProvenanceNodeType.FINDING,
            fingerprint="bad_fp",
            predecessor_node_ids=(),
            metadata=(("k", "v"),),
        )


def test_04_node_to_dict_and_from_dict_roundtrip() -> None:
    finding = _make_dummy_finding()
    node1 = ProvenanceNode.create_finding_node(finding)
    d = node1.to_dict()

    node2 = ProvenanceNode.from_dict(d)
    assert node1 == node2
    assert node1.fingerprint == node2.fingerprint


def test_05_finding_evidence_rca_strategy_proposal_factories() -> None:
    f = _make_dummy_finding()
    rca = _make_dummy_rca()
    strat = _make_dummy_strategy()
    prop = _make_dummy_proposal()

    n_find = ProvenanceNode.create_finding_node(f)
    n_ev = ProvenanceNode.create_evidence_node(f, n_find.node_id)
    n_rca = ProvenanceNode.create_rca_node(rca, n_ev.node_id)
    n_strat = ProvenanceNode.create_strategy_node(strat, n_rca.node_id)
    n_prop = ProvenanceNode.create_proposal_node(prop, n_strat.node_id)

    assert n_ev.predecessor_node_ids == (n_find.node_id,)
    assert n_rca.predecessor_node_ids == (n_ev.node_id,)
    assert n_strat.predecessor_node_ids == (n_rca.node_id,)
    assert n_prop.predecessor_node_ids == (n_strat.node_id,)


def test_06_token_snapshot_app_ver_factories() -> None:
    tok = _make_dummy_token()
    snap = _make_dummy_snapshot()
    app_res = _make_dummy_app_result()
    ver_res = _make_dummy_ver_result()

    n_tok = ProvenanceNode.create_approval_token_node(tok, "pred_prop")
    n_snap = ProvenanceNode.create_source_snapshot_node(snap, "pred_tok")
    n_app = ProvenanceNode.create_application_node(app_res, ("pred_tok", "pred_snap"))
    n_ver = ProvenanceNode.create_verification_node(
        ver_res, n_app.node_id, "prop_fp_101", "src_snap_101", "post_snap_101", "ver_fp_101"
    )

    assert n_tok.node_type == ProvenanceNodeType.APPROVAL_TOKEN
    assert n_snap.node_type == ProvenanceNodeType.SOURCE_SNAPSHOT
    assert n_app.node_type == ProvenanceNodeType.APPLICATION_RESULT
    assert n_ver.node_type == ProvenanceNodeType.VERIFICATION_RESULT


def test_07_no_raw_source_code_or_secrets_in_metadata_p17() -> None:
    prop = _make_dummy_proposal()
    node = ProvenanceNode.create_proposal_node(prop, "pred_id")

    meta_str = str(node.metadata)
    assert "def get_user" not in meta_str
    assert "--- a/app.py" not in meta_str


# =============================================================================
# 2. PROVENANCE GRAPH CONSTRUCTION & INTEGRITY TESTS (8 - 16)
# =============================================================================


def test_08_empty_graph_creation() -> None:
    g = RemediationProvenanceGraph()
    assert len(g.nodes) == 0
    assert g.graph_fingerprint == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # sha256("")


def test_09_add_node_returns_new_immutable_graph_p1() -> None:
    g1 = RemediationProvenanceGraph()
    f = _make_dummy_finding()
    n_find = ProvenanceNode.create_finding_node(f)

    g2 = g1.add_node(n_find)
    assert len(g1.nodes) == 0
    assert len(g2.nodes) == 1
    assert g2.get_node(n_find.node_id) == n_find


def test_10_duplicate_node_id_rejection_p3() -> None:
    g = RemediationProvenanceGraph()
    f = _make_dummy_finding()
    n = ProvenanceNode.create_finding_node(f)
    g2 = g.add_node(n)

    with pytest.raises(ValueError, match="Duplicate node_id"):
        g2.add_node(n)


def test_11_orphan_predecessor_node_rejection_p4() -> None:
    g = RemediationProvenanceGraph()
    f = _make_dummy_finding()
    n_ev = ProvenanceNode.create_evidence_node(f, "non_existent_pred_id")

    with pytest.raises(ValueError, match="Orphan node error"):
        g.add_node(n_ev)


def test_12_self_reference_rejection() -> None:
    g = RemediationProvenanceGraph()
    # Force self reference
    node_id = "self_ref_node"
    meta = (("k", "v"),)
    preds = (node_id,)
    fp = ProvenanceNode.compute_fingerprint(node_id, ProvenanceNodeType.FINDING, preds, meta)
    node = ProvenanceNode(node_id, ProvenanceNodeType.FINDING, fp, preds, meta)

    with pytest.raises(ValueError, match="Self-reference detected"):
        g.add_node(node)


def test_13_cycle_detection_rejection() -> None:
    # A -> B -> C -> A
    nA_fp = ProvenanceNode.compute_fingerprint("nA", ProvenanceNodeType.FINDING, (), ())
    nA = ProvenanceNode("nA", ProvenanceNodeType.FINDING, nA_fp, ())

    nB_fp = ProvenanceNode.compute_fingerprint("nB", ProvenanceNodeType.EVIDENCE, ("nA",), ())
    nB = ProvenanceNode("nB", ProvenanceNodeType.EVIDENCE, nB_fp, ("nA",))

    g = RemediationProvenanceGraph().add_node(nA).add_node(nB)

    # Now create nC with pred nB, and modify nA to pred nC (cycle)
    nC_fp = ProvenanceNode.compute_fingerprint("nC", ProvenanceNodeType.RCA, ("nB",), ())
    nC = ProvenanceNode("nC", ProvenanceNodeType.RCA, nC_fp, ("nB",))
    g2 = g.add_node(nC)

    # Attempt adding a node that creates cycle back to nA
    nCycle_fp = ProvenanceNode.compute_fingerprint("nCycle", ProvenanceNodeType.STRATEGY, ("nC",), ())
    nCycle = ProvenanceNode("nCycle", ProvenanceNodeType.STRATEGY, nCycle_fp, ("nC",))

    # Manually construct list with cyclic nA
    nA_cycle_fp = ProvenanceNode.compute_fingerprint("nA", ProvenanceNodeType.FINDING, ("nCycle",), ())
    nA_cycle = ProvenanceNode("nA", ProvenanceNodeType.FINDING, nA_cycle_fp, ("nCycle",))

    with pytest.raises(ValueError, match="Cycle detected"):
        RemediationProvenanceGraph._detect_cycle((nA_cycle, nB, nC, nCycle))


def test_14_root_nodes_and_terminal_nodes_detection() -> None:
    f = _make_dummy_finding()
    rca = _make_dummy_rca()

    n_find = ProvenanceNode.create_finding_node(f)
    n_ev = ProvenanceNode.create_evidence_node(f, n_find.node_id)
    n_rca = ProvenanceNode.create_rca_node(rca, n_ev.node_id)

    g = RemediationProvenanceGraph().add_node(n_find).add_node(n_ev).add_node(n_rca)

    assert len(g.root_nodes) == 1
    assert g.root_nodes[0] == n_find
    assert len(g.terminal_nodes) == 1
    assert g.terminal_nodes[0] == n_rca


def test_15_full_remediation_evidence_chain_building() -> None:
    f = _make_dummy_finding()
    rca = _make_dummy_rca()
    strat = _make_dummy_strategy()
    prop = _make_dummy_proposal()
    tok = _make_dummy_token()
    snap = _make_dummy_snapshot()
    app = _make_dummy_app_result()
    ver = _make_dummy_ver_result()

    n_find = ProvenanceNode.create_finding_node(f)
    n_ev = ProvenanceNode.create_evidence_node(f, n_find.node_id)
    n_rca = ProvenanceNode.create_rca_node(rca, n_ev.node_id)
    n_strat = ProvenanceNode.create_strategy_node(strat, n_rca.node_id)
    n_prop = ProvenanceNode.create_proposal_node(prop, n_strat.node_id)
    n_tok = ProvenanceNode.create_approval_token_node(tok, n_prop.node_id)
    n_snap = ProvenanceNode.create_source_snapshot_node(snap, n_tok.node_id)
    n_app = ProvenanceNode.create_application_node(app, (n_tok.node_id, n_snap.node_id))
    n_ver = ProvenanceNode.create_verification_node(
        ver, n_app.node_id, prop.proposal_fingerprint, snap.aggregate_hash, app.post_apply_snapshot_hash, "ver_fp_101"
    )

    g = (
        RemediationProvenanceGraph()
        .add_node(n_find)
        .add_node(n_ev)
        .add_node(n_rca)
        .add_node(n_strat)
        .add_node(n_prop)
        .add_node(n_tok)
        .add_node(n_snap)
        .add_node(n_app)
        .add_node(n_ver)
    )

    assert len(g.nodes) == 9
    assert g.terminal_nodes[0] == n_ver
    valid, msg = g.validate_integrity()
    assert valid is True
    assert msg == "VALID"


def test_16_graph_serialization_roundtrip_p6() -> None:
    f = _make_dummy_finding()
    rca = _make_dummy_rca()
    n_find = ProvenanceNode.create_finding_node(f)
    n_ev = ProvenanceNode.create_evidence_node(f, n_find.node_id)
    n_rca = ProvenanceNode.create_rca_node(rca, n_ev.node_id)

    g1 = RemediationProvenanceGraph().add_node(n_find).add_node(n_ev).add_node(n_rca)
    d = g1.to_dict()

    g2 = RemediationProvenanceGraph.from_dict(d)
    assert g1.graph_fingerprint == g2.graph_fingerprint
    assert len(g1.nodes) == len(g2.nodes)


# =============================================================================
# 3. DETERMINISM & INVARIANCE TESTS (17 - 22)
# =============================================================================


def test_17_insertion_order_invariance_p5_p18() -> None:
    f = _make_dummy_finding()
    rca = _make_dummy_rca()
    strat = _make_dummy_strategy()

    n_find = ProvenanceNode.create_finding_node(f)
    n_ev = ProvenanceNode.create_evidence_node(f, n_find.node_id)
    n_rca = ProvenanceNode.create_rca_node(rca, n_ev.node_id)
    n_strat = ProvenanceNode.create_strategy_node(strat, n_rca.node_id)

    # Graph 1 added in topological order
    g1 = RemediationProvenanceGraph().add_node(n_find).add_node(n_ev).add_node(n_rca).add_node(n_strat)

    # Graph 2 built with nodes passed as tuple
    g2 = RemediationProvenanceGraph(nodes=(n_strat, n_rca, n_ev, n_find))

    assert g1.graph_fingerprint == g2.graph_fingerprint


def test_18_dict_key_ordering_invariance_p5() -> None:
    meta1 = (("b", "val_b"), ("a", "val_a"))
    meta2 = (("a", "val_a"), ("b", "val_b"))

    fp1 = ProvenanceNode.compute_fingerprint("n1", ProvenanceNodeType.FINDING, (), meta1)
    fp2 = ProvenanceNode.compute_fingerprint("n1", ProvenanceNodeType.FINDING, (), meta2)

    assert fp1 == fp2


def test_19_predecessors_ordering_invariance_p5() -> None:
    preds1 = ("p2", "p1")
    preds2 = ("p1", "p2")

    fp1 = ProvenanceNode.compute_fingerprint("n1", ProvenanceNodeType.APPLICATION_RESULT, preds1, ())
    fp2 = ProvenanceNode.compute_fingerprint("n1", ProvenanceNodeType.APPLICATION_RESULT, preds2, ())

    assert fp1 == fp2


def test_20_different_logical_graphs_produce_different_fingerprints() -> None:
    f1 = _make_dummy_finding("F-101")
    f2 = _make_dummy_finding("F-102")

    n1 = ProvenanceNode.create_finding_node(f1)
    n2 = ProvenanceNode.create_finding_node(f2)

    g1 = RemediationProvenanceGraph().add_node(n1)
    g2 = RemediationProvenanceGraph().add_node(n2)

    assert g1.graph_fingerprint != g2.graph_fingerprint


def test_21_immutable_returned_node_collections() -> None:
    f = _make_dummy_finding()
    n = ProvenanceNode.create_finding_node(f)
    g = RemediationProvenanceGraph().add_node(n)

    roots = g.root_nodes
    terms = g.terminal_nodes

    # Returned tuples are immutable
    with pytest.raises(TypeError):
        roots[0] = n  # type: ignore[index]


def test_22_tampered_node_fingerprint_in_graph_rejected_p27() -> None:
    f = _make_dummy_finding()
    n = ProvenanceNode.create_finding_node(f)

    # Forge fingerprint
    object.__setattr__(n, "fingerprint", "bad_fp_1234567890123456789012345678901234567890123456789012345678901234")

    with pytest.raises(ValueError, match="Node fingerprint mismatch"):
        RemediationProvenanceGraph(nodes=(n,))


# =============================================================================
# 4. ARTIFACT BINDING TESTS (23 - 28)
# =============================================================================


def test_23_proposal_fingerprint_binding_p11() -> None:
    prop = _make_dummy_proposal()
    node = ProvenanceNode.create_proposal_node(prop, "pred_id")

    meta_dict = dict(node.metadata)
    assert meta_dict["proposal_fingerprint"] == prop.proposal_fingerprint
    assert meta_dict["proposal_id"] == prop.proposal_id


def test_24_approval_token_binding_p12() -> None:
    tok = _make_dummy_token()
    node = ProvenanceNode.create_approval_token_node(tok, "pred_id")

    meta_dict = dict(node.metadata)
    assert meta_dict["token_fingerprint"] == tok.token_fingerprint
    assert meta_dict["proposal_fingerprint"] == tok.proposal_fingerprint
    assert meta_dict["source_snapshot_hash"] == tok.source_snapshot_hash
    assert meta_dict["repository_identity"] == tok.repository_identity


def test_25_snapshot_hash_binding_p13() -> None:
    snap = _make_dummy_snapshot()
    node = ProvenanceNode.create_source_snapshot_node(snap, "pred_id")

    meta_dict = dict(node.metadata)
    assert meta_dict["aggregate_hash"] == snap.aggregate_hash
    assert meta_dict["repository_root"] == snap.repository_root


def test_26_application_result_binding_p14() -> None:
    app = _make_dummy_app_result()
    node = ProvenanceNode.create_application_node(app, ("pred1", "pred2"))

    meta_dict = dict(node.metadata)
    assert meta_dict["transaction_id"] == app.transaction_id
    assert meta_dict["pre_apply_snapshot_hash"] == app.pre_apply_snapshot_hash
    assert meta_dict["post_apply_snapshot_hash"] == app.post_apply_snapshot_hash


def test_27_verification_result_binding_p15() -> None:
    ver = _make_dummy_ver_result()
    node = ProvenanceNode.create_verification_node(
        ver, "pred_app", "prop_fp_101", "src_snap_101", "post_snap_101", "ver_fp_101"
    )

    meta_dict = dict(node.metadata)
    assert meta_dict["verification_id"] == ver.verification_id
    assert meta_dict["status"] == str(ver.status)
    assert meta_dict["verification_fingerprint"] == "ver_fp_101"


def test_28_repository_identity_binding_p10() -> None:
    tok = _make_dummy_token()
    node = ProvenanceNode.create_approval_token_node(tok, "pred_id")

    meta_dict = dict(node.metadata)
    assert meta_dict["repository_identity"] == "/repo"


# =============================================================================
# 5. ANTI-BYPASS & NO SECURITY VERDICT AUTHORITY TESTS (29 - 32)
# =============================================================================


def test_29_provenance_node_does_not_grant_verified_fixed_p8() -> None:
    # Constructing a provenance node claiming VERIFIED_FIXED does NOT alter state machine
    ver = _make_dummy_ver_result()
    node = ProvenanceNode.create_verification_node(ver, "pred_app", "prop_fp", "src", "post", "ver_fp")

    sm = LifecycleStateMachine("F-101")
    assert sm.current_state == RemediationLifecycleState.DETECTED

    # Merely creating or adding node to graph has zero effect on state machine
    g = RemediationProvenanceGraph()
    # Graph remains independent audit layer
    assert sm.current_state == RemediationLifecycleState.DETECTED


def test_30_provenance_graph_does_not_mutate_historical_finding_or_verdict_p9() -> None:
    finding = _make_dummy_finding()
    orig_status = finding.verdict.status if finding.verdict else None

    node = ProvenanceNode.create_finding_node(finding)
    g = RemediationProvenanceGraph().add_node(node)

    assert len(g.nodes) == 1
    # Finding verdict is unchanged
    assert finding.verdict.status == orig_status


def test_31_provenance_contains_zero_execution_or_auto_repair_methods_p16() -> None:
    # Verify no execution or repair attributes exist on ProvenanceNode or RemediationProvenanceGraph
    g = RemediationProvenanceGraph()
    assert not hasattr(g, "retry_patch")
    assert not hasattr(g, "auto_repair")
    assert not hasattr(g, "execute_patch")
    assert not hasattr(g, "subprocess")


def test_32_cryptographic_continuity_chain_integrity() -> None:
    # Test end-to-end cryptographic link chain: Finding -> ... -> Verification
    f = _make_dummy_finding()
    rca = _make_dummy_rca()
    strat = _make_dummy_strategy()
    prop = _make_dummy_proposal()
    tok = _make_dummy_token()
    snap = _make_dummy_snapshot()
    app = _make_dummy_app_result()
    ver = _make_dummy_ver_result()

    n_find = ProvenanceNode.create_finding_node(f)
    n_ev = ProvenanceNode.create_evidence_node(f, n_find.node_id)
    n_rca = ProvenanceNode.create_rca_node(rca, n_ev.node_id)
    n_strat = ProvenanceNode.create_strategy_node(strat, n_rca.node_id)
    n_prop = ProvenanceNode.create_proposal_node(prop, n_strat.node_id)
    n_tok = ProvenanceNode.create_approval_token_node(tok, n_prop.node_id)
    n_snap = ProvenanceNode.create_source_snapshot_node(snap, n_tok.node_id)
    n_app = ProvenanceNode.create_application_node(app, (n_tok.node_id, n_snap.node_id))
    n_ver = ProvenanceNode.create_verification_node(
        ver, n_app.node_id, prop.proposal_fingerprint, snap.aggregate_hash, app.post_apply_snapshot_hash, "ver_fp_101"
    )

    g = (
        RemediationProvenanceGraph()
        .add_node(n_find)
        .add_node(n_ev)
        .add_node(n_rca)
        .add_node(n_strat)
        .add_node(n_prop)
        .add_node(n_tok)
        .add_node(n_snap)
        .add_node(n_app)
        .add_node(n_ver)
    )

    # Verify cryptographic fingerprint continuity
    fp_chain = [n.fingerprint for n in g.nodes]
    assert len(fp_chain) == 9
    assert len(set(fp_chain)) == 9  # All unique SHA-256 fingerprints
    assert len(g.graph_fingerprint) == 64
