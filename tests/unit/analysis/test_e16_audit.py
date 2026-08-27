"""Unit tests for Tamper-Evident Hash Chain Audit Ledger."""

import concurrent.futures
from karsasec.analysis.e16_audit import GENESIS_HASH, AuditRecord, ReleaseAuditLedger
from karsasec.analysis.e16_models import AdmissionStatus, ReleaseAdmission


def test_audit_ledger_genesis_and_chaining():
    ledger = ReleaseAuditLedger()
    assert ledger.record_count == 0
    assert ledger.verify_integrity() is True

    adm = ReleaseAdmission.create(
        status=AdmissionStatus.APPROVED,
        artifact_id="art1",
        artifact_content_hash="ch1",
        decision_id="dec1",
        policy_id="pol1",
        evaluation_id="eval1",
        reason_codes=("RELEASE APPROVED",),
    )

    rec1 = ledger.append(adm)
    assert rec1.sequence == 1
    assert rec1.previous_hash == GENESIS_HASH
    assert ledger.verify_integrity() is True

    adm2 = ReleaseAdmission.create(
        status=AdmissionStatus.BLOCKED,
        artifact_id="art2",
        artifact_content_hash="ch2",
        decision_id="dec2",
        policy_id="pol2",
        evaluation_id="eval2",
        reason_codes=("BLOCKED",),
    )

    rec2 = ledger.append(adm2)
    assert rec2.sequence == 2
    assert rec2.previous_hash == rec1.audit_hash
    assert ledger.verify_integrity() is True


def test_audit_ledger_detects_record_tampering():
    ledger = ReleaseAuditLedger()
    adm = ReleaseAdmission.create(
        status=AdmissionStatus.APPROVED,
        artifact_id="art1",
        artifact_content_hash="ch1",
        decision_id="dec1",
        policy_id="pol1",
        evaluation_id="eval1",
        reason_codes=("RELEASE APPROVED",),
    )
    ledger.append(adm)
    assert ledger.verify_integrity() is True

    # Mutate internal record directly to simulate tampering
    tampered_rec = AuditRecord(
        audit_id=ledger._records[0].audit_id,
        sequence=1,
        previous_hash=GENESIS_HASH,
        audit_hash=ledger._records[0].audit_hash,
        artifact_id="TAMPERED_ART",
        decision_id="dec1",
        policy_id="pol1",
        admission_id="adm1",
        status="APPROVED",
        reason_codes=("TAMPERED",),
    )
    ledger._records[0] = tampered_rec

    assert ledger.verify_integrity() is False


def test_audit_ledger_concurrent_writes():
    ledger = ReleaseAuditLedger()
    adm = ReleaseAdmission.create(
        status=AdmissionStatus.APPROVED,
        artifact_id="art1",
        artifact_content_hash="ch1",
        decision_id="dec1",
        policy_id="pol1",
        evaluation_id="eval1",
        reason_codes=("RELEASE APPROVED",),
    )

    def write_op(i):
        ledger.append(adm)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(write_op, i) for i in range(100)]
        concurrent.futures.wait(futures)

    assert ledger.record_count == 100
    assert ledger.verify_integrity() is True
