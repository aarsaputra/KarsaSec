"""PostgresReceiptRepository — Persistent Verification Receipt storage for Sprint F3.

Invariants:
  - Privacy: No source code, diffs, patches, credentials stored.
  - Immutability: receipts are write-once. No update is permitted after creation.
  - L7: security_verification_status is stored from RTPValidator output only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import ReceiptModel


# ---------------------------------------------------------------------------
# Domain DTO for receipt data (lightweight, no source code)
# ---------------------------------------------------------------------------

class ReceiptRecord:
    """Privacy-safe receipt record stored in and returned from the repository."""

    __slots__ = (
        "receipt_id",
        "transaction_id",
        "finding_id",
        "rule_id",
        "receipt_version",
        "integrity_status",
        "security_verification_status",
        "verification_run_id",
        "matching_findings_count",
        "proposal_fingerprint",
        "provenance_fingerprint",
        "ledger_fingerprint",
        "receipt_fingerprint",
    )

    def __init__(
        self,
        receipt_id: str,
        transaction_id: str,
        finding_id: str,
        rule_id: str,
        integrity_status: str,
        security_verification_status: str,
        provenance_fingerprint: str,
        ledger_fingerprint: str,
        receipt_fingerprint: str,
        receipt_version: str = "1.0",
        verification_run_id: str | None = None,
        matching_findings_count: int = -1,
        proposal_fingerprint: str | None = None,
    ) -> None:
        self.receipt_id = receipt_id
        self.transaction_id = transaction_id
        self.finding_id = finding_id
        self.rule_id = rule_id
        self.receipt_version = receipt_version
        self.integrity_status = integrity_status
        self.security_verification_status = security_verification_status
        self.verification_run_id = verification_run_id
        self.matching_findings_count = matching_findings_count
        self.proposal_fingerprint = proposal_fingerprint
        self.provenance_fingerprint = provenance_fingerprint
        self.ledger_fingerprint = ledger_fingerprint
        self.receipt_fingerprint = receipt_fingerprint


def _model_to_record(model: ReceiptModel) -> ReceiptRecord:
    return ReceiptRecord(
        receipt_id=model.receipt_id,
        transaction_id=model.transaction_id,
        finding_id=model.finding_id,
        rule_id=model.rule_id,
        receipt_version=model.receipt_version,
        integrity_status=model.integrity_status,
        security_verification_status=model.security_verification_status,
        verification_run_id=model.verification_run_id,
        matching_findings_count=model.matching_findings_count,
        proposal_fingerprint=model.proposal_fingerprint,
        provenance_fingerprint=model.provenance_fingerprint,
        ledger_fingerprint=model.ledger_fingerprint,
        receipt_fingerprint=model.receipt_fingerprint,
    )


# ---------------------------------------------------------------------------
# Abstract contract
# ---------------------------------------------------------------------------

class ReceiptRepository(ABC):
    """Abstract base for receipt persistence."""

    @abstractmethod
    def save_receipt(self, record: ReceiptRecord) -> None:
        """Persist a receipt. Write-once: raises if receipt_fingerprint already exists."""

    @abstractmethod
    def get_receipt(self, receipt_id: str) -> Optional[ReceiptRecord]:
        """Retrieve a receipt by receipt_id."""

    @abstractmethod
    def get_by_transaction(self, transaction_id: str) -> Optional[ReceiptRecord]:
        """Retrieve the receipt associated with a transaction."""


# ---------------------------------------------------------------------------
# InMemory fallback (tests / CI without Postgres)
# ---------------------------------------------------------------------------

class InMemoryReceiptRepository(ReceiptRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, ReceiptRecord] = {}
        self._by_fingerprint: dict[str, ReceiptRecord] = {}
        self._by_txn: dict[str, ReceiptRecord] = {}

    def save_receipt(self, record: ReceiptRecord) -> None:
        if record.receipt_fingerprint in self._by_fingerprint:
            raise ValueError(f"Receipt with fingerprint '{record.receipt_fingerprint}' already exists.")
        self._by_id[record.receipt_id] = record
        self._by_fingerprint[record.receipt_fingerprint] = record
        self._by_txn[record.transaction_id] = record

    def get_receipt(self, receipt_id: str) -> Optional[ReceiptRecord]:
        return self._by_id.get(receipt_id)

    def get_by_transaction(self, transaction_id: str) -> Optional[ReceiptRecord]:
        return self._by_txn.get(transaction_id)


# ---------------------------------------------------------------------------
# Postgres implementation
# ---------------------------------------------------------------------------

class PostgresReceiptRepository(ReceiptRepository):
    """Production PostgreSQL implementation of ReceiptRepository.

    Receipts are write-once. No UPDATE is allowed after creation.
    """

    def __init__(self, factory: DatabaseSessionFactory | None = None) -> None:
        self._factory = factory or get_session_factory()

    @contextmanager
    def _session(self) -> Generator[Session, None, None]:
        yield from self._factory.session_scope()

    def save_receipt(self, record: ReceiptRecord) -> None:
        with self._session() as session:
            existing = session.scalar(
                select(ReceiptModel).where(
                    ReceiptModel.receipt_fingerprint == record.receipt_fingerprint
                )
            )
            if existing:
                raise ValueError(
                    f"Receipt with fingerprint '{record.receipt_fingerprint}' already exists (immutability)."
                )
            model = ReceiptModel(
                receipt_id=record.receipt_id,
                transaction_id=record.transaction_id,
                finding_id=record.finding_id,
                rule_id=record.rule_id,
                receipt_version=record.receipt_version,
                integrity_status=record.integrity_status,
                security_verification_status=record.security_verification_status,
                verification_run_id=record.verification_run_id,
                matching_findings_count=record.matching_findings_count,
                proposal_fingerprint=record.proposal_fingerprint,
                provenance_fingerprint=record.provenance_fingerprint,
                ledger_fingerprint=record.ledger_fingerprint,
                receipt_fingerprint=record.receipt_fingerprint,
            )
            session.add(model)

    def get_receipt(self, receipt_id: str) -> Optional[ReceiptRecord]:
        with self._session() as session:
            model = session.scalar(
                select(ReceiptModel).where(ReceiptModel.receipt_id == receipt_id)
            )
            return _model_to_record(model) if model else None

    def get_by_transaction(self, transaction_id: str) -> Optional[ReceiptRecord]:
        with self._session() as session:
            model = session.scalar(
                select(ReceiptModel)
                .where(ReceiptModel.transaction_id == transaction_id)
                .order_by(ReceiptModel.created_at.asc())
                .limit(1)
            )
            return _model_to_record(model) if model else None
