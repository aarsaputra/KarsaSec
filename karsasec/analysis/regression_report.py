"""RegressionReport model, RegressionStatus and RegressionChange enums for Sprint E14."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class RegressionStatus(StrEnum):
    """Overall security regression evaluation status."""

    NOT_TESTED = "NOT_TESTED"
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class RegressionChange(StrEnum):
    """Classification of vulnerability fingerprint transition between baseline and current."""

    NEW = "NEW"
    PERSISTENT = "PERSISTENT"
    RESOLVED = "RESOLVED"
    CHANGED = "CHANGED"
    UNKNOWN = "UNKNOWN"


def compute_regression_report_id(
    new_fingerprints: Sequence[str],
    persistent_fingerprints: Sequence[str],
    resolved_fingerprints: Sequence[str],
    changed_fingerprints: Sequence[str],
    unknown_fingerprints: Sequence[str],
    schema_version: str = "1.0",
) -> str:
    """Computes deterministic SHA-256 regression report identity."""
    payload = {
        "schema_version": schema_version,
        "new": sorted(set(str(x) for x in new_fingerprints)),
        "persistent": sorted(set(str(x) for x in persistent_fingerprints)),
        "resolved": sorted(set(str(x) for x in resolved_fingerprints)),
        "changed": sorted(set(str(x) for x in changed_fingerprints)),
        "unknown": sorted(set(str(x) for x in unknown_fingerprints)),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"E14-REPORT:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class RegressionReport:
    """Immutable representation of a security regression comparison report."""

    report_id: str
    status: RegressionStatus
    new_fingerprints: tuple[str, ...]
    persistent_fingerprints: tuple[str, ...]
    resolved_fingerprints: tuple[str, ...]
    changed_fingerprints: tuple[str, ...]
    unknown_fingerprints: tuple[str, ...]
    regressions_detected: bool
    explanations: tuple[str, ...]
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        status: RegressionStatus,
        new_fingerprints: Sequence[str],
        persistent_fingerprints: Sequence[str],
        resolved_fingerprints: Sequence[str],
        changed_fingerprints: Sequence[str],
        unknown_fingerprints: Sequence[str],
        explanations: Sequence[str],
        schema_version: str = "1.0",
    ) -> RegressionReport:
        """Factory creating immutable RegressionReport."""
        r_id = compute_regression_report_id(
            new_fingerprints=new_fingerprints,
            persistent_fingerprints=persistent_fingerprints,
            resolved_fingerprints=resolved_fingerprints,
            changed_fingerprints=changed_fingerprints,
            unknown_fingerprints=unknown_fingerprints,
            schema_version=schema_version,
        )

        reg_detected = len(new_fingerprints) > 0 or len(changed_fingerprints) > 0

        return cls(
            report_id=r_id,
            status=status,
            new_fingerprints=tuple(sorted(set(str(x) for x in new_fingerprints))),
            persistent_fingerprints=tuple(sorted(set(str(x) for x in persistent_fingerprints))),
            resolved_fingerprints=tuple(sorted(set(str(x) for x in resolved_fingerprints))),
            changed_fingerprints=tuple(sorted(set(str(x) for x in changed_fingerprints))),
            unknown_fingerprints=tuple(sorted(set(str(x) for x in unknown_fingerprints))),
            regressions_detected=reg_detected,
            explanations=tuple(sorted(set(str(x) for x in explanations))),
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes regression report to dictionary."""
        return {
            "report_id": self.report_id,
            "status": self.status.value,
            "new_fingerprints": list(self.new_fingerprints),
            "persistent_fingerprints": list(self.persistent_fingerprints),
            "resolved_fingerprints": list(self.resolved_fingerprints),
            "changed_fingerprints": list(self.changed_fingerprints),
            "unknown_fingerprints": list(self.unknown_fingerprints),
            "regressions_detected": self.regressions_detected,
            "explanations": list(self.explanations),
            "schema_version": self.schema_version,
        }
