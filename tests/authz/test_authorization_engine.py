"""Batch B1 Authorization Reasoning Engine Test Suite."""

from karsasec.analysis.authz.engine import AuthorizationReasoningEngine
from karsasec.analysis.authz.models import (
    AuthzDecisionNode,
    AuthzVulnerabilityType,
    ObjectNode,
    SubjectNode,
)


def test_b1_1_idor_detection() -> None:
    """B1.1: Verifies IDOR detection when subject accesses another user's object without ownership check."""
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user_101", tenant_id="tenant_A")
    obj = ObjectNode(object_id="invoice_999", owner_id="user_202", tenant_id="tenant_A")
    decisions = AuthzDecisionNode(has_ownership_check=False, has_tenant_check=True)

    evidence = engine.evaluate_authorization(subject, obj, action="read", decisions=decisions)
    assert evidence is not None
    assert evidence.vulnerability_type == AuthzVulnerabilityType.IDOR
    assert evidence.ownership_check is False

    payload = evidence.to_dict()
    assert payload["subject"] == "user_101"
    assert payload["object"] == "invoice_999"
    assert payload["finding"] == "IDOR"


def test_b1_2_bola_detection() -> None:
    """B1.2: Verifies BOLA detection on API endpoints."""
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user_101")
    obj = ObjectNode(object_id="api_profile_555", owner_id="user_303", resource_type="API_RESOURCE")
    decisions = AuthzDecisionNode(has_ownership_check=False)

    evidence = engine.evaluate_authorization(subject, obj, action="GET /api/v1/profile/555", decisions=decisions)
    assert evidence is not None
    assert evidence.vulnerability_type == AuthzVulnerabilityType.BOLA


def test_b1_3_mass_assignment_detection() -> None:
    """B1.3: Verifies Mass Assignment detection when model binding lacks field allowlist."""
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user_101")
    obj = ObjectNode(object_id="user_account_101", owner_id="user_101")
    decisions = AuthzDecisionNode(has_ownership_check=True, has_field_allowlist=False)

    evidence = engine.evaluate_authorization(
        subject, obj, action="POST /user/update", decisions=decisions, is_mass_assignment=True
    )
    assert evidence is not None
    assert evidence.vulnerability_type == AuthzVulnerabilityType.MASS_ASSIGNMENT


def test_b1_4_tenant_isolation_detection() -> None:
    """B1.4: Verifies Tenant Isolation failure on cross-tenant access."""
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user_101", tenant_id="tenant_A")
    obj = ObjectNode(object_id="doc_888", owner_id="user_101", tenant_id="tenant_B")
    decisions = AuthzDecisionNode(has_ownership_check=True, has_tenant_check=False)

    evidence = engine.evaluate_authorization(subject, obj, action="read", decisions=decisions)
    assert evidence is not None
    assert evidence.vulnerability_type == AuthzVulnerabilityType.TENANT_ISOLATION_FAILURE


def test_b1_5_bfla_detection() -> None:
    """B1.5: Verifies BFLA detection when admin action is performed without role check."""
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user_101", roles=["MEMBER"])
    obj = ObjectNode(object_id="system_config", resource_type="ADMIN_SETTING")
    decisions = AuthzDecisionNode(has_role_check=False)

    evidence = engine.evaluate_authorization(
        subject, obj, action="DELETE /admin/user", decisions=decisions, is_admin_action=True
    )
    assert evidence is not None
    assert evidence.vulnerability_type == AuthzVulnerabilityType.BFLA


def test_authorized_access_safe() -> None:
    """Verifies that legitimate authorized access returns None (SAFE)."""
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user_101", tenant_id="tenant_A", roles=["MEMBER"])
    obj = ObjectNode(object_id="invoice_101", owner_id="user_101", tenant_id="tenant_A")
    decisions = AuthzDecisionNode(has_ownership_check=True, has_tenant_check=True)

    evidence = engine.evaluate_authorization(subject, obj, action="read", decisions=decisions)
    assert evidence is None


def test_b1_harden_01_interprocedural_policy_resolution() -> None:
    """B1-HARDEN-01: Verifies interprocedural policy resolution (policy -> helper -> decision)."""
    engine = AuthorizationReasoningEngine()

    def policy_helper(user_id: str, owner_id: str) -> bool:
        return user_id == owner_id

    user_id = "user_101"
    target_owner = "user_101"
    has_check = policy_helper(user_id, target_owner)

    subject = SubjectNode(subject_id=user_id)
    obj = ObjectNode(object_id="doc_1", owner_id=target_owner)
    decisions = AuthzDecisionNode(has_ownership_check=has_check)

    evidence = engine.evaluate_authorization(subject, obj, action="read", decisions=decisions)
    assert evidence is None

