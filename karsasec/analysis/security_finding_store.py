"""Authoritative, thread-safe, deduplicated SecurityFindingStore for Sprint E12."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.analysis.security_finding import SecurityFinding

logger = logging.getLogger("karsasec.analysis.security_finding_store")

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def finding_sort_key(finding: SecurityFinding) -> tuple[int, str, str, str]:
    """Deterministically orders findings by severity rank, rule key, flow ID, and finding ID (INV-E12-RULE-24)."""
    sev_rank = SEVERITY_ORDER.get(finding.severity.upper(), 5)
    return (sev_rank, finding.rule_key, finding.flow_id, finding.finding_id)


class SecurityFindingStore:
    """Thread-safe store for SecurityFinding objects with deterministic insertion & deduplication (INV-E12-RULE-17,18)."""

    def __init__(self) -> None:
        self._findings: dict[str, SecurityFinding] = {}
        self._rule_index: dict[str, list[SecurityFinding]] = {}
        self._flow_index: dict[str, list[SecurityFinding]] = {}
        self._severity_index: dict[str, list[SecurityFinding]] = {}
        self._lock = threading.RLock()

    def add(self, finding: SecurityFinding) -> bool:
        """Adds a SecurityFinding to the store.

        Returns True if newly inserted, False if duplicate finding_id (INV-E12-RULE-17).
        """
        with self._lock:
            if finding.finding_id in self._findings:
                return False

            self._findings[finding.finding_id] = finding

            # Rule Index (by rule_id and rule_key)
            for rk in (finding.rule_id, finding.rule_key):
                if rk not in self._rule_index:
                    self._rule_index[rk] = []
                self._rule_index[rk].append(finding)

            # Flow Index
            if finding.flow_id not in self._flow_index:
                self._flow_index[finding.flow_id] = []
            self._flow_index[finding.flow_id].append(finding)

            # Severity Index
            sev_key = finding.severity.upper()
            if sev_key not in self._severity_index:
                self._severity_index[sev_key] = []
            self._severity_index[sev_key].append(finding)

            return True

    def get(self, finding_id: str) -> SecurityFinding | None:
        """Retrieves finding by finding_id."""
        with self._lock:
            return self._findings.get(finding_id)

    def contains(self, finding_id: str) -> bool:
        """Checks if finding_id exists in store."""
        with self._lock:
            return finding_id in self._findings

    def get_by_rule(self, rule_key_or_id: str) -> tuple[SecurityFinding, ...]:
        """Retrieves all findings for a rule, deterministically sorted (INV-E12-RULE-24)."""
        with self._lock:
            findings = self._rule_index.get(rule_key_or_id, [])
            return tuple(sorted(findings, key=finding_sort_key))

    def get_by_flow(self, flow_id: str) -> tuple[SecurityFinding, ...]:
        """Retrieves all findings for a flow, deterministically sorted."""
        with self._lock:
            findings = self._flow_index.get(flow_id, [])
            return tuple(sorted(findings, key=finding_sort_key))

    def get_by_severity(self, severity: str) -> tuple[SecurityFinding, ...]:
        """Retrieves all findings matching a severity level, deterministically sorted."""
        with self._lock:
            findings = self._severity_index.get(severity.upper(), [])
            return tuple(sorted(findings, key=finding_sort_key))

    def all(self) -> tuple[SecurityFinding, ...]:
        """Returns all findings deterministically sorted (INV-E12-RULE-24)."""
        with self._lock:
            return tuple(sorted(self._findings.values(), key=finding_sort_key))

    def count(self) -> int:
        """Returns total stored findings."""
        with self._lock:
            return len(self._findings)

    def clear(self) -> None:
        """Clears all stored findings and indices."""
        with self._lock:
            self._findings.clear()
            self._rule_index.clear()
            self._flow_index.clear()
            self._severity_index.clear()
