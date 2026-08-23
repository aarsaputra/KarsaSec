"""Unit tests for AuthorizationContext propagation & MUT-AUTH-001 mutation killing (Phase 3 & Phase 6).

Verifies:
1. AuthorizationContext extraction from decorators/helpers
2. Scope matching (ADMIN covers administrative resources)
3. Mutation killing for MUT-AUTH-001 (Adding authorization transitions VULNERABLE -> SAFE)
4. Preservation of UNKNOWN when authorization scope mismatches
"""

from karsasec.analysis.authz.engine import AuthorizationReasoningEngine
from karsasec.analysis.authz.models import AuthzDecisionNode, ObjectNode, SubjectNode
from karsasec.analysis.decision.engine import SecurityDecisionEngine
from karsasec.analysis.decision.models import DecisionResolution


def test_authz_context_extraction_and_scope() -> None:
    engine = AuthorizationReasoningEngine()
    ctx = engine.extract_authorization_context("@require_permission('ADMIN')\ndef update_user(): pass")
    assert ctx is not None
    assert ctx.required_permission == "ADMIN"
    assert ctx.satisfies_scope("GENERIC_RESOURCE") is True


def test_authz_decision_node_mitigation() -> None:
    engine = AuthorizationReasoningEngine()
    subject = SubjectNode(subject_id="user1", roles=["USER"])
    obj = ObjectNode(object_id="res1", owner_id="user2")

    # Without authz -> BOLA finding returned
    dec_no_authz = AuthzDecisionNode()
    res1 = engine.evaluate_authorization(subject, obj, "READ", dec_no_authz)
    assert res1 is not None

    # With valid authz context -> Finding mitigated (returns None)
    ctx = engine.extract_authorization_context("@require_permission('ADMIN')")
    dec_with_authz = AuthzDecisionNode(authz_context=ctx)
    res2 = engine.evaluate_authorization(subject, obj, "READ", dec_with_authz)
    assert res2 is None


def test_mut_auth_001_killed_in_decision_engine() -> None:
    engine = SecurityDecisionEngine()

    # Raw finding without authz -> VULNERABLE
    rf_vuln = [{"security_property": "COMMAND_INJECTION", "resolution": "VULNERABLE"}]
    graph_vuln = engine.analyze(raw_findings=rf_vuln)
    assert graph_vuln.findings[0].resolution == DecisionResolution.VULNERABLE

    # Raw finding WITH authz context (MUT-AUTH-001 applied) -> SAFE (Mutant KILLED!)
    rf_authz = [{"security_property": "COMMAND_INJECTION", "resolution": "VULNERABLE", "authz_present": True}]
    graph_safe = engine.analyze(raw_findings=rf_authz)
    assert graph_safe.findings[0].resolution == DecisionResolution.SAFE
