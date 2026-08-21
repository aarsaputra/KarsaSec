"""Adversarial Attack Chains DA through DM for Batch D3 Distributed Security Consistency Engine."""

from karsasec.analysis.distributed.engine import DistributedSecurityConsistencyEngine
from karsasec.analysis.distributed.models import (
    DistributedEvidence,
    DistributedService,
    DistributedViolationCategory,
)


def test_chain_da_gateway_backend_mismatch() -> None:
    """Chain DA: Gateway trusts header -> Backend trusts forwarded identity."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DA",
        correlation_id="CORR_DA",
        category=DistributedViolationCategory.GATEWAY_BACKEND_SECURITY_MISMATCH,
        services=(
            DistributedService("s1", "gateway", "PUBLIC", "LOW"),
            DistributedService("s2", "backend", "INTERNAL", "HIGH"),
        ),
        validation_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.GATEWAY_BACKEND_SECURITY_MISMATCH
    assert violations[0].resolution == "VULNERABLE"


def test_chain_db_unexplicit_privilege_amplification() -> None:
    """Chain DB: User -> Service A -> Service B privilege increases without delegation."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DB",
        correlation_id="CORR_DB",
        category=DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
        explicit_delegation_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION
    assert violations[0].resolution == "VULNERABLE"


def test_chain_dc_cross_service_tenant_escape() -> None:
    """Chain DC: Tenant A -> Service A -> Service B -> Tenant B."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DC",
        correlation_id="CORR_DC",
        category=DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE,
        proof_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE
    assert violations[0].resolution == "VULNERABLE"


def test_chain_dd_async_authorization_drift() -> None:
    """Chain DD: Role revoked -> event queued -> worker executes privileged operation."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DD",
        correlation_id="CORR_DD",
        category=DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT,
        validation_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT
    assert violations[0].resolution == "VULNERABLE"


def test_chain_de_identity_provenance_loss() -> None:
    """Chain DE: User identity disappears between services."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DE",
        correlation_id="CORR_DE",
        category=DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS,
        proof_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS
    assert violations[0].resolution == "VULNERABLE"


def test_chain_df_service_user_identity_confusion() -> None:
    """Chain DF: Service identity incorrectly treated as user identity."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DF",
        correlation_id="CORR_DF",
        category=DistributedViolationCategory.SERVICE_USER_IDENTITY_CONFUSION,
        impersonation_proof_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.SERVICE_USER_IDENTITY_CONFUSION
    assert violations[0].resolution == "VULNERABLE"


def test_chain_dg_message_security_context_loss() -> None:
    """Chain DG: Sensitive event lacks tenant context."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DG",
        correlation_id="CORR_DG",
        category=DistributedViolationCategory.MESSAGE_SECURITY_CONTEXT_LOSS,
        proof_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.MESSAGE_SECURITY_CONTEXT_LOSS
    assert violations[0].resolution == "VULNERABLE"


def test_chain_dh_distributed_replay_violation() -> None:
    """Chain DH: Sensitive event has no replay identity."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DH",
        correlation_id="CORR_DH",
        category=DistributedViolationCategory.DISTRIBUTED_REPLAY_VIOLATION,
        replay_protection_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.DISTRIBUTED_REPLAY_VIOLATION
    assert violations[0].resolution == "VULNERABLE"


def test_chain_di_distributed_sod_violation() -> None:
    """Chain DI: Create payment -> Approve payment same actor across services."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DI",
        correlation_id="CORR_DI",
        category=DistributedViolationCategory.DISTRIBUTED_SOD_VIOLATION,
        proof_present=False,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == DistributedViolationCategory.DISTRIBUTED_SOD_VIOLATION
    assert violations[0].resolution == "VULNERABLE"


def test_chain_dj_incomplete_evidence_is_unknown() -> None:
    """Chain DJ: Incomplete evidence expects UNKNOWN."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DJ",
        correlation_id="MISSING_DELEGATION_EVIDENCE",
        category=DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


def test_chain_dk_correct_delegation_chain_is_safe() -> None:
    """Chain DK: Correct delegation chain expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DK",
        correlation_id="CORR_DK",
        category=DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
        explicit_delegation_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0  # SAFE


def test_chain_dl_correct_tenant_propagation_is_safe() -> None:
    """Chain DL: Correct tenant propagation expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DL",
        correlation_id="CORR_DL",
        category=DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE,
        proof_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0  # SAFE


def test_chain_dm_gateway_backend_matching_is_safe() -> None:
    """Chain DM: Gateway and backend enforce identical authorization expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_DM",
        correlation_id="CORR_DM",
        category=DistributedViolationCategory.GATEWAY_BACKEND_SECURITY_MISMATCH,
        validation_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0  # SAFE
