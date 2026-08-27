"""Unit and Invariant test suite for Sprint E17: Security Control Plane."""

from types import SimpleNamespace
from karsasec.analysis.e16_models import ReleaseArtifact
from karsasec.control_plane.engine import SecurityControlPlane
from karsasec.control_plane.models import ControlPlaneConfig, PolicyVersion
from karsasec.control_plane.policy_registry import PolicyRegistry


def test_control_plane_config_and_policy_version_creation():
    config = ControlPlaneConfig.create(tenant_id="TENANT-001")
    assert len(config.config_id) == 64
    assert config.fail_closed is True

    policy = PolicyVersion.create(
        name="PCI-DSS Policy",
        version="1.0.0",
        rules=({"id": "R1", "action": "BLOCK"},),
    )
    assert len(policy.policy_id) == 64
    assert policy.is_active is True


def test_policy_registry():
    registry = PolicyRegistry()
    policy = PolicyVersion.create(
        name="HIPAA Policy",
        version="2.0.0",
        rules=(),
    )
    pid = registry.register(policy)
    assert pid == policy.policy_id
    assert registry.get(pid) == policy
    assert len(registry.list_all()) == 1


def test_control_plane_fail_closed_on_none():
    cp = SecurityControlPlane()
    res = cp.evaluate_release(artifact=None, decision=None)
    assert res.status == "REJECTED"
    assert res.admission_status == "BLOCKED"
    assert len(res.audit_record_hash) == 64


def test_control_plane_evaluates_valid_release():
    cp = SecurityControlPlane()
    artifact = ReleaseArtifact.create(
        version="1.0.0",
        commit_sha="a1b2c3d4e5f6",
        decision_id="DEC-001",
        evaluation_id="EVAL-001",
        content_hash="hash-001",
    )
    decision = SimpleNamespace(
        decision="ALLOW",
        decision_id="DEC-001",
        confidence=0.95,
        evidence_valid=True,
        exploitability_valid=True,
        policy_hash="p-hash",
        findings=(),
    )

    res = cp.evaluate_release(artifact=artifact, decision=decision)
    assert res.status == "APPROVED"
    assert res.admission_status == "APPROVED"
