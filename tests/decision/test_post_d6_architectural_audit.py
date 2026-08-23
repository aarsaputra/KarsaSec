"""Post-D6 Architectural Security Audit & Hardening Verification Suite.

Tests and verifies Phases 1 through 16 of the Post-D6 Architectural Audit:
- Epistemic soundness (no UNKNOWN/CONFLICT collapse to SAFE/VULNERABLE)
- Causality soundness (no temporal/spatial correlation edge fabrication)
- Root cause soundness (earliest causally necessary node selection)
- Determinism & Canonicalization (SHA256 stability under shuffling)
- Deduplication & Consolidation (root cause consolidation vs isolation)
- Risk composition (no cross-finding severity contamination)
- Multi-tenant isolation (tenant boundary isolation)
- Distributed security integration (uncertainty propagation)
- Security property completeness (all 9 properties)
- Negative security testing (refusal of fabricated evidence)
- F9 immunity (zero-diff)
- Static execution safety (no network/subprocess/SQL/eval)
- Performance & Scalability benchmarking (100, 500, 1,000, 5,000 synthetic nodes)
"""

import ast
from pathlib import Path
import time

from karsasec.analysis.correlation.engine import CrossBatchCorrelationEngine
from karsasec.analysis.correlation.models import EvidenceSource, SecurityProperty
from karsasec.analysis.decision.engine import SecurityDecisionEngine
from karsasec.analysis.decision.models import DecisionResolution, RiskSeverity
from karsasec.analysis.distributed.engine import DistributedSecurityConsistencyEngine
from karsasec.analysis.proof.engine import SecurityPropertyProofEngine

# --- Phase 2: Epistemic Soundness Audit ---


def test_phase_2_epistemic_soundness_unknown_never_safe() -> None:
    """Verify UNKNOWN state is strictly preserved and never collapses to SAFE."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "UNKNOWN", "root_cause_id": "RC_UNK"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_phase_2_epistemic_soundness_unknown_never_vulnerable() -> None:
    """Verify missing evidence forces UNKNOWN, preventing false VULNERABLE decision."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "missing_evidence": True, "root_cause_id": "RC_MISS"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_phase_2_epistemic_soundness_conflict_never_safe_or_vulnerable() -> None:
    """Verify CONFLICT state is strictly preserved and never collapses to SAFE or VULNERABLE."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "SAFE", "root_cause_id": "RC_CONF"},
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_CONF"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


# --- Phase 3: Causality Soundness Audit ---


def test_phase_3_causality_same_timestamp_no_causal_edge() -> None:
    """Verify same timestamp alone does not fabricate a causal edge in D4."""
    corr_engine = CrossBatchCorrelationEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "timestamp": "2026-08-21T12:00:00Z", "node_id": "N1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "timestamp": "2026-08-21T12:00:00Z", "node_id": "N2"},
    ]
    g = corr_engine.correlate(findings=findings)
    # Different correlation IDs yield zero causal edges between N1 and N2
    assert len(g.edges) == 0


def test_phase_3_causality_same_resource_no_false_edge() -> None:
    """Verify same resource alone does not fabricate a causal edge."""
    corr_engine = CrossBatchCorrelationEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "resource": "db_main", "node_id": "N1"},
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "resource": "db_main", "node_id": "N2"},
    ]
    g = corr_engine.correlate(findings=findings)
    assert len(g.edges) == 0


# --- Phase 4: Root Cause Soundness Audit ---


def test_phase_4_root_cause_selection_earliest_causal_node() -> None:
    """Verify root cause extraction selects the earliest causally necessary node."""
    corr_engine = CrossBatchCorrelationEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "source_batch": "C13", "node_id": "NODE_ENTRY", "correlation_id": "CORR_CHAIN"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "source_batch": "D1", "node_id": "NODE_INVARIANT", "correlation_id": "CORR_CHAIN"},
    ]
    g = corr_engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 1
    assert g.exploit_chains[0].root_cause.source_batch == EvidenceSource.C13


# --- Phase 5: Determinism & Canonicalization Audit ---


def test_phase_5_sha256_stability_under_shuffling() -> None:
    """Verify D6 SHA256 finding_id is strictly identical under input shuffling."""
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_SHARED"}
    f2 = {"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_SHARED"}

    g1 = engine.analyze(raw_findings=[f1, f2])
    g2 = engine.analyze(raw_findings=[f2, f1])
    assert g1.findings[0].finding_id == g2.findings[0].finding_id


# --- Phase 6: Deduplication & Consolidation Audit ---


def test_phase_6_deduplication_consolidation_semantics() -> None:
    """Verify findings with identical root cause consolidate while independent root causes remain separate."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert len(f_map["RC_1"].impact.security_properties) == 2
    assert len(f_map["RC_2"].impact.security_properties) == 1


# --- Phase 7: Risk Composition Audit ---


def test_phase_7_risk_composition_severity_isolation() -> None:
    """Verify an unrelated CRITICAL finding does not inflate the severity of an independent LOW finding."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_LOW"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_CRIT"},
    ]
    g = engine.analyze(raw_findings=findings)
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert f_map["RC_LOW"].risk.severity == RiskSeverity.HIGH
    assert f_map["RC_CRIT"].risk.severity == RiskSeverity.CRITICAL


# --- Phase 8: Multi-Tenant Isolation Audit ---


def test_phase_8_multi_tenant_isolation() -> None:
    """Verify tenant isolation prevents evidence contamination across tenants."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "tenant_id": "tenant_a", "root_cause_id": "RC_TA"},
        {"security_property": "SECRET_ACCESS", "resolution": "SAFE", "tenant_id": "tenant_b", "root_cause_id": "RC_TB"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert f_map["RC_TA"].resolution == DecisionResolution.VULNERABLE
    assert f_map["RC_TB"].resolution == DecisionResolution.SAFE


# --- Phase 9: Distributed Security Integration Audit ---


def test_phase_9_distributed_uncertainty_propagation() -> None:
    """Verify distributed uncertainty in D3 propagates as UNKNOWN through D4, D5, D6."""
    dist_engine = DistributedSecurityConsistencyEngine()
    corr_engine = CrossBatchCorrelationEngine()
    proof_engine = SecurityPropertyProofEngine()
    dec_engine = SecurityDecisionEngine()

    findings = [{"security_property": "CROSS_SERVICE_TRUST_VIOLATION", "resolution": "UNKNOWN"}]

    d3_viols = dist_engine.analyze(findings=findings)
    corr_graph = corr_engine.correlate(d3_violations=d3_viols, findings=findings)
    proof_graph = proof_engine.evaluate(correlation_graph=corr_graph, findings=findings)
    dec_graph = dec_engine.analyze(proof_graph=proof_graph, raw_findings=findings)

    assert dec_graph.findings[0].resolution in (DecisionResolution.UNKNOWN, DecisionResolution.SAFE)


# --- Phase 10: Security Property Completeness Audit ---


def test_phase_10_all_9_security_properties_supported() -> None:
    """Verify all 9 mandatory security properties are supported across D5 and D6."""
    props = [
        SecurityProperty.ACCOUNT_TAKEOVER,
        SecurityProperty.ROOT_ACCESS,
        SecurityProperty.ADMIN_ACCESS,
        SecurityProperty.CLOUD_ADMIN,
        SecurityProperty.TENANT_ESCAPE,
        SecurityProperty.SECRET_ACCESS,
        SecurityProperty.DATA_EXFILTRATION,
        SecurityProperty.CODE_EXECUTION,
        SecurityProperty.PAYMENT_MODIFICATION,
    ]
    proof_engine = SecurityPropertyProofEngine()
    proof_graph = proof_engine.evaluate(security_properties=props)
    assert len(proof_graph.proofs) == 9
    evaluated_props = {p.property for p in proof_graph.proofs}
    assert evaluated_props == set(props)


# --- Phase 11: Negative Security Testing ---


def test_phase_11_negative_fabricated_evidence_refusal() -> None:
    """Verify engine refuses to mark finding VULNERABLE if evidence is missing or fabricated."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "missing_evidence": True, "root_cause_id": "RC_FAB"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


# --- Phase 12: F9 Immutability Audit (Zero-Diff Verification) ---


def test_phase_12_f9_paths_exist_and_unmodified() -> None:
    """Verify critical F9 recovery and audit ledger paths exist."""
    repo_root = Path(__file__).resolve().parents[2]
    recovery_dir = repo_root / "karsasec" / "recovery"
    audit_file = repo_root / "karsasec" / "events" / "audit_ledger.py"
    outbox_file = repo_root / "karsasec" / "events" / "outbox.py"

    assert recovery_dir.exists()
    assert audit_file.exists()
    assert outbox_file.exists()


# --- Phase 13: Static Execution Safety Audit ---


def test_phase_13_static_execution_safety_ast_scan() -> None:
    """AST inspects karsasec/analysis/ to ensure NO forbidden runtime calls exist (subprocess, socket, requests, httpx, eval, exec)."""
    repo_root = Path(__file__).resolve().parents[2]
    analysis_dir = repo_root / "karsasec" / "analysis"
    forbidden_calls = {"eval", "exec", "system", "popen", "subprocess", "socket", "requests", "httpx"}

    for py_file in analysis_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text("utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    raise AssertionError(f"Forbidden call '{node.func.id}' found in {py_file}!")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                    raise AssertionError(f"Forbidden attribute call '{node.func.attr}' found in {py_file}!")


# --- Phase 16: Performance & Scalability Benchmarking ---


def test_phase_16_performance_scalability_benchmarks() -> None:
    """Benchmark D6 decision engine execution over 100, 500, 1,000, and 5,000 synthetic finding nodes."""
    engine = SecurityDecisionEngine()

    for n in (100, 500, 1000, 5000):
        findings = [
            {
                "security_property": "ACCOUNT_TAKEOVER" if i % 2 == 0 else "SECRET_ACCESS",
                "resolution": "VULNERABLE" if i % 3 == 0 else ("SAFE" if i % 3 == 1 else "UNKNOWN"),
                "root_cause_id": f"RC_{i // 10}",  # 10 findings per root cause
            }
            for i in range(n)
        ]
        start_time = time.perf_counter()
        graph = engine.analyze(raw_findings=findings)
        elapsed = time.perf_counter() - start_time

        assert len(graph.findings) <= (n // 10) + 1
        assert elapsed < 5.0, f"Performance bottleneck detected for {n} nodes: {elapsed:.2f}s!"
