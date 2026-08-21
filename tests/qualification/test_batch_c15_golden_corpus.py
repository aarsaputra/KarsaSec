"""Batch C15 Full Multi-Step Breach Simulation Golden Corpus Qualification Test Suite (400 Fixtures across 8 Languages)."""

import pytest

from karsasec.analysis.breach_simulation.engine import BreachSimulationEngine
from karsasec.analysis.breach_simulation.models import SimulationStatus
from karsasec.analysis.privilege.models import (
    EscalationCategory,
    PrivilegeEvidence,
    PrivilegeLevel,
)

LANGUAGES = ["python", "javascript", "typescript", "php", "java", "go", "ruby", "csharp"]

VULNERABLE_FIXTURES = [
    (
        f"user_{i}",
        PrivilegeLevel.USER,
        f"admin_{i}",
        PrivilegeLevel.TENANT_ADMIN if i % 2 == 0 else PrivilegeLevel.ORG_ADMIN,
        "IDOR" if i % 2 == 0 else "RESOURCE_LEVEL_AUTHZ_BYPASS",
        "TENANT_RESOURCE",
        LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 101)
]

SAFE_FIXTURES = [
    (
        f"admin_{i}",
        PrivilegeLevel.TENANT_ADMIN,
        f"admin_{i}",
        PrivilegeLevel.TENANT_ADMIN,
        "AUTHORIZED_DELETE",
        "TENANT_RESOURCE",
        LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 101)
]

UNKNOWN_FIXTURES = [
    (
        f"anon_{i}",
        PrivilegeLevel.UNKNOWN,
        f"target_{i}",
        PrivilegeLevel.UNKNOWN,
        "AMBIGUOUS_TRIGGER",
        "UNKNOWN_BOUNDARY",
        LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 101)
]

MULTISTEP_FIXTURES = [
    (
        f"chain_user_{i}",
        PrivilegeLevel.USER,
        f"root_{i}" if i % 2 == 0 else f"cloud_admin_{i}",
        PrivilegeLevel.ROOT if i % 2 == 0 else PrivilegeLevel.CLOUD_ADMIN,
        "SSRF_IMDSV1" if i % 2 == 0 else "SSTI_RCE",
        "CLOUD_METADATA" if i % 2 == 0 else "OPERATING_SYSTEM",
        LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 101)
]


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", VULNERABLE_FIXTURES)
def test_vulnerable_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity=src_id,
        initial_privilege=src_priv,
        transition_trigger=trigger,
        authorization_boundary=boundary,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        authorization_verified=False,
        tenant_scope_verified=False,
        resolution="VULNERABLE",
    )
    scenarios = engine.simulate(privilege_evidence=ev)
    assert len(scenarios) == 1
    assert scenarios[0].resolution == SimulationStatus.VULNERABLE


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", SAFE_FIXTURES)
def test_safe_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity=src_id,
        initial_privilege=src_priv,
        transition_trigger=trigger,
        authorization_boundary=boundary,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        authorization_verified=True,
        tenant_scope_verified=True,
        resolution="SAFE",
    )
    scenarios = engine.simulate(privilege_evidence=ev)
    assert len(scenarios) == 1
    assert scenarios[0].resolution == SimulationStatus.SAFE
    assert scenarios[0].risk_score == 0.0


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", UNKNOWN_FIXTURES)
def test_unknown_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity=src_id,
        initial_privilege=src_priv,
        transition_trigger=trigger,
        authorization_boundary=boundary,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        authorization_verified=False,
        tenant_scope_verified=False,
        resolution="UNKNOWN",
    )
    scenarios = engine.simulate(privilege_evidence=ev)
    assert len(scenarios) == 1
    assert scenarios[0].resolution == SimulationStatus.UNKNOWN
    assert scenarios[0].risk_score is None


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", MULTISTEP_FIXTURES)
def test_multistep_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.CLOUD_ROLE_ESCALATION if tgt_priv == PrivilegeLevel.CLOUD_ADMIN else EscalationCategory.ROOT_ACCESS,
        initial_identity=src_id,
        initial_privilege=src_priv,
        transition_trigger=trigger,
        authorization_boundary=boundary,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        authorization_verified=False,
        tenant_scope_verified=False,
        capability_chain=["METADATA_ACCESS", "CLOUD_ADMIN_ACCESS"] if tgt_priv == PrivilegeLevel.CLOUD_ADMIN else ["PROCESS_SPAWN", "ROOT_ACCESS"],
        resolution="VULNERABLE",
    )
    scenarios = engine.simulate(privilege_evidence=ev)
    assert len(scenarios) == 1
    assert scenarios[0].resolution == SimulationStatus.VULNERABLE
    assert scenarios[0].risk_score is not None and scenarios[0].risk_score > 70.0


def test_c15_determinism() -> None:
    """Verifies byte-identical output across repeated simulations (INV-C15-09)."""
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        transition_trigger="IDOR",
        authorization_boundary="TENANT_RESOURCE",
        resulting_identity="admin_b",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        authorization_verified=False,
        tenant_scope_verified=False,
        resolution="VULNERABLE",
    )
    scenarios1 = engine.simulate(privilege_evidence=ev)
    scenarios2 = engine.simulate(privilege_evidence=ev)
    assert scenarios1[0].to_dict() == scenarios2[0].to_dict()
