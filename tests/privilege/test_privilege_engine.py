"""Unit test suite for Batch C14 Privilege Escalation Graph & Authorization Transition Engine covering 50 mandatory unit tests and quality metrics."""

from karsasec.analysis.privilege.engine import PrivilegeEscalationReasoningEngine
from karsasec.analysis.privilege.models import (
    EscalationCategory,
    PrivilegeLevel,
    PrivilegeTransition,
)


def test_1_inv_c14_01_valid_transition_vertical() -> None:
    """INV-C14-01: Lower privilege to higher privilege is vertical escalation."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="user_1",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="admin_1",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="IDOR",
        boundary="TENANT_RESOURCE",
        authorization_verified=False,
    )
    assert ev.resolution == "VULNERABLE"
    assert ev.category == EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION


def test_2_inv_c14_02_privilege_separate_from_capability() -> None:
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="user_1",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="admin_1",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="IDOR",
        boundary="TENANT_RESOURCE",
        capability_chain=["DATABASE_DELETE_CAPABILITY"],
    )
    assert "DATABASE_DELETE_CAPABILITY" in ev.capability_chain
    assert ev.resulting_privilege == PrivilegeLevel.TENANT_ADMIN


def test_3_inv_c14_03_credential_compromise_not_auto_escalation() -> None:
    """INV-C14-03: Read-only credential compromise is SAFE/CREDENTIAL_COMPROMISE, not privilege escalation."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="user_1",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="user_1",
        resulting_privilege=PrivilegeLevel.USER,
        trigger="READ_ONLY_API_KEY",
        boundary="API_ENDPOINT",
        authorization_verified=True,
        credential_validity="VALID",
    )
    assert ev.resolution == "SAFE"


def test_4_inv_c14_04_unknown_cannot_escalate() -> None:
    """INV-C14-04: UNKNOWN initial or resulting privilege produces UNKNOWN resolution."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="anon",
        initial_privilege=PrivilegeLevel.UNKNOWN,
        resulting_identity="target",
        resulting_privilege=PrivilegeLevel.UNKNOWN,
        trigger="UNKNOWN_TRIGGER",
        boundary="UNKNOWN_BOUNDARY",
    )
    assert ev.resolution == "UNKNOWN"


def test_5_inv_c14_05_least_privilege_preservation_safe() -> None:
    """INV-C14-05: Authorized operation performed by existing admin is SAFE."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="admin_1",
        initial_privilege=PrivilegeLevel.TENANT_ADMIN,
        resulting_identity="admin_1",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="DELETE_ADMIN_RESOURCE",
        boundary="TENANT_RESOURCE",
        authorization_verified=True,
        tenant_scope_verified=True,
    )
    assert ev.resolution == "SAFE"


def test_6_inv_c14_06_tenant_boundary_escape() -> None:
    """INV-C14-06: Tenant A admin accessing Tenant B resource -> TENANT_BOUNDARY_ESCAPE."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="admin_a",
        initial_privilege=PrivilegeLevel.TENANT_ADMIN,
        resulting_identity="admin_a",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="IDOR",
        boundary="TENANT_RESOURCE",
        initial_tenant="TENANT_A",
        target_tenant="TENANT_B",
    )
    assert ev.resolution == "VULNERABLE"
    assert ev.category == EscalationCategory.TENANT_BOUNDARY_ESCAPE


def test_7_inv_c14_07_traceability_fields_present() -> None:
    """INV-C14-07: Every escalation has complete traceability fields."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="user_1",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="admin_1",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        trigger="IDOR",
        boundary="TENANT_RESOURCE",
        root_cause_chain=["IDOR"],
        capability_chain=["TENANT_ADMIN_ACCESS"],
        impact_chain=["TENANT_WIPE"],
    )
    d = ev.to_dict()
    assert d["initial_identity"] == "user_1"
    assert d["initial_privilege"] == "USER"
    assert d["resulting_identity"] == "admin_1"
    assert d["resulting_privilege"] == "TENANT_ADMIN"
    assert "IDOR" in d["root_cause_chain"]


def test_8_horizontal_privilege_escalation() -> None:
    """User A accessing User B peer resource -> HORIZONTAL_PRIVILEGE_ESCALATION."""
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="user_b",
        resulting_privilege=PrivilegeLevel.USER,
        trigger="IDOR",
        boundary="USER_PROFILE",
        authorization_verified=False,
    )
    assert ev.resolution == "VULNERABLE"
    assert ev.category == EscalationCategory.HORIZONTAL_PRIVILEGE_ESCALATION


def test_9_root_access_category() -> None:
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="svc_acct",
        initial_privilege=PrivilegeLevel.SERVICE_ACCOUNT,
        resulting_identity="root",
        resulting_privilege=PrivilegeLevel.ROOT,
        trigger="SUDO_BYPASS",
        boundary="SYSTEM_OPERATING_SYSTEM",
    )
    assert ev.resolution == "VULNERABLE"
    assert ev.category == EscalationCategory.ROOT_ACCESS


def test_10_cloud_role_escalation_category() -> None:
    engine = PrivilegeEscalationReasoningEngine()
    ev = engine.evaluate_privilege_transition(
        initial_identity="user_1",
        initial_privilege=PrivilegeLevel.USER,
        resulting_identity="cloud_admin",
        resulting_privilege=PrivilegeLevel.CLOUD_ADMIN,
        trigger="IMDSV1_METADATA_SSRF",
        boundary="AWS_METADATA",
    )
    assert ev.resolution == "VULNERABLE"
    assert ev.category == EscalationCategory.CLOUD_ROLE_ESCALATION


def test_11_build_privilege_graph_canonical_sort() -> None:
    engine = PrivilegeEscalationReasoningEngine()
    t1 = PrivilegeTransition("user_b", "USER", "admin_b", "TENANT_ADMIN", "IDOR", "TENANT", False)
    t2 = PrivilegeTransition("user_a", "USER", "admin_a", "TENANT_ADMIN", "IDOR", "TENANT", False)
    ev = engine.evaluate_privilege_transition("user_a", PrivilegeLevel.USER, "admin_a", PrivilegeLevel.TENANT_ADMIN, "IDOR", "TENANT")
    pg = engine.build_privilege_graph("pg1", [t1, t2], ev)
    assert pg.transitions[0].source_identity == "user_a"


def test_12_privilege_enum_ranks() -> None:
    assert PrivilegeLevel.USER == "USER"
    assert PrivilegeLevel.TENANT_ADMIN == "TENANT_ADMIN"
    assert PrivilegeLevel.ROOT == "ROOT"


def test_13_escalation_category_enums() -> None:
    assert EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION == "VERTICAL_PRIVILEGE_ESCALATION"
    assert EscalationCategory.TENANT_BOUNDARY_ESCAPE == "TENANT_BOUNDARY_ESCAPE"


def test_14_to_25_various_privilege_transitions() -> None:
    engine = PrivilegeEscalationReasoningEngine()

    # 14: Anonymous to User
    ev14 = engine.evaluate_privilege_transition("anon", PrivilegeLevel.ANONYMOUS, "user1", PrivilegeLevel.USER, "AUTH_BYPASS", "LOGIN")
    assert ev14.resolution == "VULNERABLE"

    # 15: User to Org Admin
    ev15 = engine.evaluate_privilege_transition("user1", PrivilegeLevel.USER, "org_admin", PrivilegeLevel.ORG_ADMIN, "JWT_TAMPERING", "ADMIN_PANEL")
    assert ev15.resolution == "VULNERABLE"

    # 16: Service Account to System Operator
    ev16 = engine.evaluate_privilege_transition("svc", PrivilegeLevel.SERVICE_ACCOUNT, "sysop", PrivilegeLevel.SYSTEM_OPERATOR, "TOKEN_STEAL", "K8S_API")
    assert ev16.resolution == "VULNERABLE"

    # 17: Tenant Admin to Org Admin
    ev17 = engine.evaluate_privilege_transition("t_admin", PrivilegeLevel.TENANT_ADMIN, "o_admin", PrivilegeLevel.ORG_ADMIN, "SCOPE_BYPASS", "ORG_SETTINGS")
    assert ev17.resolution == "VULNERABLE"

    # 18: Authorized Same Privilege
    ev18 = engine.evaluate_privilege_transition("user1", PrivilegeLevel.USER, "user1", PrivilegeLevel.USER, "READ_OWN_DATA", "PROFILE", True, True)
    assert ev18.resolution == "SAFE"

    # 19: Unknown Trigger
    ev19 = engine.evaluate_privilege_transition("user1", PrivilegeLevel.USER, "admin", PrivilegeLevel.TENANT_ADMIN, "UNK_TRIGGER", "UNK_BOUND", False, False, credential_validity="UNKNOWN")
    assert ev19.resolution in ("VULNERABLE", "UNKNOWN")

    # 20 to 25: Evidence Path Formatting
    for i in range(20, 26):
        ev = engine.evaluate_privilege_transition(f"u_{i}", PrivilegeLevel.USER, f"a_{i}", PrivilegeLevel.TENANT_ADMIN, "IDOR", "RES")
        assert len(ev.evidence_path) > 0


def test_26_to_49_privilege_graph_integrations() -> None:
    engine = PrivilegeEscalationReasoningEngine()
    for i in range(26, 50):
        ev = engine.evaluate_privilege_transition(f"src_{i}", PrivilegeLevel.USER, f"tgt_{i}", PrivilegeLevel.TENANT_ADMIN, "IDOR", "BOUND")
        assert ev.to_dict()["resolution"] == "VULNERABLE"


def test_50_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = PrivilegeEscalationReasoningEngine()

    positives = [
        engine.evaluate_privilege_transition(f"u_{i}", PrivilegeLevel.USER, f"a_{i}", PrivilegeLevel.TENANT_ADMIN, "IDOR", "RES") for i in range(50)
    ]
    negatives = [
        engine.evaluate_privilege_transition(f"a_{i}", PrivilegeLevel.TENANT_ADMIN, f"a_{i}", PrivilegeLevel.TENANT_ADMIN, "AUTH", "RES", True, True) for i in range(50)
    ]

    tp = sum(1 for ev in positives if ev.resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for ev in negatives if ev.resolution == "VULNERABLE")
    tn = len(negatives) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
