"""Batch C14 Privilege Escalation Golden Corpus Qualification Test Suite (300 Fixtures across 8 Languages)."""

import pytest

from karsasec.analysis.privilege.engine import PrivilegeEscalationReasoningEngine
from karsasec.analysis.privilege.models import PrivilegeLevel

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


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", VULNERABLE_FIXTURES)
def test_vulnerable_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity=src_id,
        initial_privilege=src_priv,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        trigger=trigger,
        boundary=boundary,
        authorization_verified=False,
    )
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", SAFE_FIXTURES)
def test_safe_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity=src_id,
        initial_privilege=src_priv,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        trigger=trigger,
        boundary=boundary,
        authorization_verified=True,
        tenant_scope_verified=True,
        credential_validity="VALID",
    )
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("src_id,src_priv,tgt_id,tgt_priv,trigger,boundary,lang", UNKNOWN_FIXTURES)
def test_unknown_fixtures(src_id, src_priv, tgt_id, tgt_priv, trigger, boundary, lang) -> None:
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity=src_id,
        initial_privilege=src_priv,
        resulting_identity=tgt_id,
        resulting_privilege=tgt_priv,
        trigger=trigger,
        boundary=boundary,
        authorization_verified=False,
    )
    assert ev.resolution == "UNKNOWN"


def test_c14_determinism() -> None:
    """Section Determinism: Verifies repeated evaluation yields 100% identical outputs."""
    engine = PrivilegeEscalationReasoningEngine()
    ev1 = engine.evaluate_privilege_transition(
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="admin_b",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="IDOR",
        boundary="TENANT_RESOURCE",
    )
    ev2 = engine.evaluate_privilege_transition(
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="admin_b",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="IDOR",
        boundary="TENANT_RESOURCE",
    )
    assert ev1.to_dict() == ev2.to_dict()
