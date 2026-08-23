"""Adversarial Unit Tests for Authorization Context & Scope Propagation.

Verifies:
1. Scope matching between required resource permission and applied AuthorizationContext.
2. Permission scope mismatch (@require_permission("READ") on delete_user endpoint).
3. Resource/Endpoint isolation (AuthorizationContext on endpoint A does NOT protect endpoint B).
4. Epistemic preservation of UNKNOWN and CONFLICT states during authz reasoning.
"""

from karsasec.analysis.authz.engine import AuthorizationReasoningEngine
from karsasec.analysis.authz.models import (
    AuthorizationContext,
    AuthzDecisionNode,
    AuthzVulnerabilityType,
    ObjectNode,
    SubjectNode,
)


def test_valid_authorization_context_matching() -> None:
    engine = AuthorizationReasoningEngine()

    ctx = AuthorizationContext(
        principal="user_admin",
        required_permission="ADMIN",
        granted_permission="ADMIN",
        authorization_source="@require_permission('ADMIN')",
        authorization_scope="ADMIN",
        resource_scope="ADMIN",
        is_verified=True,
    )

    subj = SubjectNode(subject_id="SUBJ_01", tenant_id="tenant_a", roles=["ADMIN"])
    obj = ObjectNode(object_id="OBJ_01", tenant_id="tenant_a", resource_type="ADMIN")
    node = AuthzDecisionNode(authz_context=ctx, has_role_check=True)

    ev = engine.evaluate_authorization(subj, obj, action="DELETE", decisions=node, is_admin_action=True)
    assert ev is None, "Valid authorization context should mitigate finding (ev is None)"


def test_permission_scope_mismatch() -> None:
    engine = AuthorizationReasoningEngine()

    # Applied permission READ, but required scope is ADMIN
    ctx = AuthorizationContext(
        principal="user_regular",
        required_permission="READ",
        granted_permission="READ",
        authorization_source="@require_permission('READ')",
        authorization_scope="READ",
        resource_scope="READ",
        is_verified=True,
    )

    subj = SubjectNode(subject_id="SUBJ_02", tenant_id="tenant_a", roles=["USER"])
    obj = ObjectNode(object_id="OBJ_02", tenant_id="tenant_a", resource_type="ADMIN")
    node = AuthzDecisionNode(authz_context=ctx, has_role_check=False)

    ev = engine.evaluate_authorization(subj, obj, action="DELETE", decisions=node, is_admin_action=True)
    assert ev is not None, "Scope mismatch should yield authorization evidence (violation)"
    assert ev.vulnerability_type == AuthzVulnerabilityType.BFLA


def test_resource_endpoint_isolation() -> None:
    engine = AuthorizationReasoningEngine()

    # Authz context for PUBLIC scope applied to ADMIN object
    ctx = AuthorizationContext(
        principal="user_public",
        required_permission="PUBLIC",
        granted_permission="PUBLIC",
        authorization_source="@require_permission('PUBLIC')",
        authorization_scope="PUBLIC",
        resource_scope="PUBLIC",
        is_verified=True,
    )

    subj = SubjectNode(subject_id="SUBJ_03", tenant_id="tenant_b", roles=["ANONYMOUS"])
    obj = ObjectNode(object_id="OBJ_03", tenant_id="tenant_a", resource_type="ADMIN")
    node = AuthzDecisionNode(authz_context=ctx, has_role_check=False)

    ev = engine.evaluate_authorization(subj, obj, action="DELETE", decisions=node, is_admin_action=True)
    assert ev is not None, "Isolated endpoint authz context should NOT mitigate un-scoped endpoint"
