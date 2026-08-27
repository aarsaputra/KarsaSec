"""Unit test suite verifying fixes for VULN-002, VULN-003, and VULN-005."""

import threading
from types import SimpleNamespace
from karsasec.analysis.rule_registry import SecurityRuleRegistry, SecurityRule
from karsasec.analysis.e15_security_gate import SecurityGate
from karsasec.analysis.e15_models import DecisionStatus, EvidenceValidation, ExploitabilityAssessment
from karsasec.framework.detector import FrameworkDetector


def test_vuln_002_atomic_index_rebuild_concurrency():
    """Verifies VULN-002: Concurrent unregister does not expose empty index during rebuilding."""
    registry = SecurityRuleRegistry()
    rule1 = SecurityRule.create(
        rule_key="TEST-001",
        name="Test Rule 1",
        version="1.0",
        vulnerability_class="Test",
        source_kinds=["http_input"],
        sink_categories=["sql"],
        blocked_by_sanitizers=[],
        minimum_confidence=0.6,
        severity="HIGH",
    )
    rule2 = SecurityRule.create(
        rule_key="TEST-002",
        name="Test Rule 2",
        version="1.0",
        vulnerability_class="Test",
        source_kinds=["http_input"],
        sink_categories=["command_execution"],
        blocked_by_sanitizers=[],
        minimum_confidence=0.6,
        severity="CRITICAL",
    )
    registry.register(rule1)
    registry.register(rule2)

    empty_reads = 0

    def reader():
        nonlocal empty_reads
        for _ in range(100):
            matches = registry.match("http_input", "sql")
            # If match returns 0 candidates while rule1 is registered, empty index bug hit
            if len(matches) == 0 and registry.get("TEST-001") is not None:
                empty_reads += 1

    def writer():
        for _ in range(50):
            registry.unregister("TEST-002")
            registry.register(rule2)

    t1 = threading.Thread(target=reader)
    t2 = threading.Thread(target=writer)

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert empty_reads == 0, "Transient empty index state detected during unregister"


def test_vuln_003_manifest_prioritization(tmp_path):
    """Verifies VULN-003: Manifest files are prioritized over naive file limits."""
    proj_dir = tmp_path / "test_proj"
    proj_dir.mkdir()

    # Create dummy source files
    for i in range(25):
        (proj_dir / f"file_{i:02d}.py").write_text("# Dummy Python file\n")

    # Write requirements.txt with flask import code
    (proj_dir / "requirements.txt").write_text("from flask import Flask\napp = Flask(__name__)\n")

    detector = FrameworkDetector()
    result = detector.detect_framework(proj_dir)

    assert result.framework == "FLASK"
    assert result.confidence >= 0.90


def test_vuln_005_gate_status_injection_fail_closed():
    """Verifies VULN-005: Injected invalid status string causes fail-closed UNKNOWN decision."""
    gate = SecurityGate()
    
    # Mock priority with unrecognized status string "BYPASS"
    fake_priority = SimpleNamespace(priority_status="BYPASS", confidence=0.99)
    fake_remediation = SimpleNamespace(status="REQUIRED")

    valid_evidence = EvidenceValidation(
        evidence_valid=True,
        completeness=1.0,
        contradictions=0,
        missing_dimensions=(),
        validation_reason="Valid",
    )
    valid_exploitability = ExploitabilityAssessment(
        exploitability_score=0.9,
        attack_surface=0.8,
        controllability=0.9,
        reachability=1.0,
        privilege_requirement=0.2,
        exploit_chain_complete=True,
        assessment_valid=True,
        rationale="Valid",
    )

    decision, gate_res = gate.evaluate(
        priority=fake_priority,
        remediation_plan=fake_remediation,
        evidence=valid_evidence,
        exploitability=valid_exploitability,
    )

    assert decision.decision == DecisionStatus.UNKNOWN
    assert gate_res.unknown is True
    assert "Unrecognized upstream status injection detected" in decision.rationale
