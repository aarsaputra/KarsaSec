"""Sprint E15 — Decision Audit Trail.

Provides an immutable, thread-safe audit ledger for security gate decisions.
"""

from dataclasses import dataclass
import threading
from typing import Any

from karsasec.analysis.e15_models import SecurityDecision, SecurityGateResult


@dataclass(frozen=True)
class DecisionAuditRecord:
    """Immutable audit record entry for security gate decision."""
    audit_id: str
    decision_id: str
    gate_id: str
    decision: str
    policy_version: str
    evaluated_rules: tuple[str, ...]
    failed_rules: tuple[str, ...]
    rationale: str


class DecisionAuditTrail:
    """Thread-safe decision audit ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, DecisionAuditRecord] = {}

    def log(
        self,
        decision: SecurityDecision,
        gate_result: SecurityGateResult,
    ) -> DecisionAuditRecord:
        """Logs a decision and gate result into the thread-safe audit ledger."""
        with self._lock:
            if decision.decision_id in self._records:
                return self._records[decision.decision_id]

            rec = DecisionAuditRecord(
                audit_id=f"AUDIT-{decision.decision_id[:16]}",
                decision_id=decision.decision_id,
                gate_id=gate_result.gate_id,
                decision=str(decision.decision),
                policy_version=decision.policy_version,
                evaluated_rules=gate_result.evaluated_rules,
                failed_rules=gate_result.failed_rules,
                rationale=decision.rationale,
            )
            self._records[decision.decision_id] = rec
            return rec

    def get(self, decision_id: str) -> DecisionAuditRecord | None:
        """Retrieves audit record by decision ID."""
        with self._lock:
            return self._records.get(decision_id)

    def count(self) -> int:
        """Returns total audit records stored."""
        with self._lock:
            return len(self._records)
