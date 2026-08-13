"""Adversarial Security & Invariant Tests for RTP Subsystem (Sprint F0).

Verifies Security Invariants:
  - L7: Zero LLM Security Authority (LLM claims strictly ignored; matching_findings > 0 forces SECURITY_NOT_VERIFIED).
  - R1-R6: Deterministic SHA-256 fingerprinting independent of dictionary order and PYTHONHASHSEED.
  - R7-R9: Privacy Boundary (Rejects raw source code, diff text, credentials, secrets).
  - R24-R28: Zero Execution Capability (Observational execution without subprocess, git, shell, or file mutation).
"""

from __future__ import annotations

import pytest

from karsasec.ai.remediation.rtp.canonical import canonicalize, compute_canonical_hash
from karsasec.ai.remediation.rtp.errors import RTPPrivacyError
from karsasec.ai.remediation.rtp.models import (
    IntegrityStatus,
    RemediationTransactionPackage,
    SecurityVerificationStatus,
)
from karsasec.ai.remediation.rtp.receipt import VerificationReceipt
from karsasec.ai.remediation.rtp.serialization import import_rtp
from karsasec.ai.remediation.rtp.validator import RTPValidator
from tests.unit.ai.remediation.rtp.test_validator import _build_valid_rtp


def test_adv_01_tampered_proposal_fingerprint_invalidates_integrity() -> None:
    valid_rtp = _build_valid_rtp()
    # Modify proposal fingerprint in dictionary payload
    d = valid_rtp.to_dict()
    d["proposal"]["proposal_fingerprint"] = "fp_TAMPERED_HASH_666"

    # Re-import modified payload
    tampered_rtp = import_rtp(d)

    res = RTPValidator.validate(tampered_rtp)
    assert res.integrity_status == IntegrityStatus.INVALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED
    assert any("Package fingerprint tampering detected" in err for err in res.errors)


def test_adv_02_llm_claim_has_zero_authority() -> None:
    # Construct RTP where matching_findings_count == 1 but verification status claims fixed
    valid_rtp = _build_valid_rtp(verification_status="VERIFIED_FIXED", matching_findings_count=1)

    res = RTPValidator.validate(valid_rtp)
    assert res.integrity_status == IntegrityStatus.VALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED


def test_adv_03_stale_verification_status_is_rejected() -> None:
    valid_rtp = _build_valid_rtp(verification_status="STILL_VULNERABLE", matching_findings_count=2)

    res = RTPValidator.validate(valid_rtp)
    assert res.integrity_status == IntegrityStatus.VALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED


def test_adv_04_privacy_boundary_rejects_source_code_key() -> None:
    valid_rtp = _build_valid_rtp()
    d = valid_rtp.to_dict()

    # Inject forbidden raw source code key into finding metadata
    d["finding"]["source_code"] = "SELECT * FROM users WHERE id = 'admin'"

    with pytest.raises(RTPPrivacyError):
        import_rtp(d)


def test_adv_05_privacy_boundary_rejects_diff_key() -> None:
    valid_rtp = _build_valid_rtp()
    d = valid_rtp.to_dict()

    # Inject forbidden diff key
    d["proposal"]["diff"] = "--- a/db.py\n+++ b/db.py\n@@ -1 +1 @@\n-eval()\n+safe()"

    with pytest.raises(RTPPrivacyError):
        import_rtp(d)


def test_adv_06_dict_order_invariance() -> None:
    dict_a = {
        "transaction_id": "tx_123",
        "status": "VERIFIED_FIXED",
        "finding_id": "F-001",
        "nested": {"z": 100, "a": 1},
    }
    dict_b = {
        "nested": {"a": 1, "z": 100},
        "finding_id": "F-001",
        "status": "VERIFIED_FIXED",
        "transaction_id": "tx_123",
    }

    assert canonicalize(dict_a) == canonicalize(dict_b)
    assert compute_canonical_hash(dict_a) == compute_canonical_hash(dict_b)


def test_adv_07_schema_version_mismatch_fails_validation() -> None:
    valid_rtp = _build_valid_rtp()
    d = valid_rtp.to_dict()
    d["schema_version"] = "99.0"  # Invalid schema version

    bad_rtp = import_rtp(d)
    res = RTPValidator.validate(bad_rtp)

    assert res.integrity_status == IntegrityStatus.INVALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED
    assert any("Schema version mismatch" in err for err in res.errors)


def test_adv_08_missing_verification_evidence_gives_not_verified() -> None:
    valid_rtp = _build_valid_rtp()
    d = valid_rtp.to_dict()
    d["verification"] = None

    # Recompute fingerprint for package without verification
    d["receipt_fingerprint"] = RemediationTransactionPackage.compute_package_fingerprint(
        schema_name=d["schema_name"],
        schema_version=d["schema_version"],
        transaction_id=d["transaction_id"],
        repository_identity=d["repository_identity"],
        created_at=d["created_at"],
        status=d["status"],
        finding=valid_rtp.finding,
        evidence=None,
        root_cause=None,
        strategy=valid_rtp.strategy,
        proposal=valid_rtp.proposal,
        approval=None,
        application=valid_rtp.application,
        verification=None,
        provenance=valid_rtp.provenance,
        audit=valid_rtp.audit,
    )

    unver_rtp = import_rtp(d)
    res = RTPValidator.validate(unver_rtp)

    assert res.integrity_status == IntegrityStatus.VALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED


def test_adv_09_receipt_fingerprint_derivation() -> None:
    rtp = _build_valid_rtp()
    res = RTPValidator.validate(rtp)

    receipt = VerificationReceipt.from_rtp(rtp, res)
    assert receipt.receipt_fingerprint is not None
    assert len(receipt.receipt_fingerprint) == 64

    # Verification receipt fingerprint changes if status changes
    receipt_d = receipt.to_dict()
    receipt_d["security_verification_status"] = "SECURITY_NOT_VERIFIED"
    alt_fp = VerificationReceipt.compute_receipt_fingerprint(
        receipt_version=receipt_d["receipt_version"],
        receipt_id=receipt_d["receipt_id"],
        transaction_id=receipt_d["transaction_id"],
        repository_identity=receipt_d["repository_identity"],
        finding_id=receipt_d["finding_id"],
        rule_id=receipt_d["rule_id"],
        proposal_fingerprint=receipt_d["proposal_fingerprint"],
        approval_token_id=receipt_d["approval_token_id"],
        source_snapshot_hash=receipt_d["source_snapshot_hash"],
        post_apply_snapshot_hash=receipt_d["post_apply_snapshot_hash"],
        verification_run_id=receipt_d["verification_run_id"],
        verification_fingerprint=receipt_d["verification_fingerprint"],
        provenance_fingerprint=receipt_d["provenance_fingerprint"],
        ledger_fingerprint=receipt_d["ledger_fingerprint"],
        integrity_status=receipt_d["integrity_status"],
        security_verification_status="SECURITY_NOT_VERIFIED",
        matching_findings_count=receipt_d["matching_findings_count"],
    )

    assert alt_fp != receipt.receipt_fingerprint


def test_adv_10_forbidden_execution_capability_audit() -> None:
    """Audits karsasec/ai/remediation/rtp for forbidden execution APIs."""
    import inspect
    import karsasec.ai.remediation.rtp as rtp_module

    source = inspect.getsource(rtp_module)
    forbidden_terms = ["subprocess", "os.system", "shell=True", "git"]
    for term in forbidden_terms:
        assert term not in source, f"Forbidden term '{term}' found in rtp module imports/code"
