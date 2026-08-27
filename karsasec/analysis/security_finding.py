"""SecurityFinding domain model, FindingStatus, and deterministic finding identity algorithm for Sprint E12."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class FindingStatus(StrEnum):
    """Deterministic Finding Category for Sprint E12 Security Decisions."""

    CONFIRMED = "CONFIRMED"
    CANDIDATE = "CANDIDATE"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


def compute_finding_id(
    rule_id: str,
    rule_version: str,
    flow_id: str,
    source_fact_id: str,
    sink_fact_id: str,
    schema_version: str = "E12",
) -> str:
    """Computes a 64-character deterministic SHA-256 finding ID across process executions (INV-E12-RULE-02,16)."""
    payload: dict[str, str] = {
        "schema": schema_version,
        "rule_id": rule_id,
        "rule_version": rule_version,
        "flow_id": flow_id,
        "source_fact_id": source_fact_id,
        "sink_fact_id": sink_fact_id,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SecurityFinding:
    """Immutable, explainable SecurityFinding capturing deterministic rule decision evidence (INV-E12-RULE-24,25)."""

    finding_id: str
    rule_id: str
    rule_key: str
    rule_version: str
    vulnerability_class: str
    source_fact_id: str
    sink_fact_id: str
    flow_id: str
    source_node_id: str
    sink_node_id: str
    severity: str
    status: FindingStatus
    confidence: float
    source_evidence: tuple[tuple[str, str], ...]
    sink_evidence: tuple[tuple[str, str], ...]
    flow_evidence: tuple[tuple[str, str], ...]
    sanitizer_evidence: tuple[tuple[str, str], ...]
    condition_evidence: tuple[tuple[str, str], ...]
    file: str | None = None
    line: int | None = None
    symbol: str | None = None
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        rule_id: str,
        rule_key: str,
        rule_version: str,
        vulnerability_class: str,
        source_fact_id: str,
        sink_fact_id: str,
        flow_id: str,
        source_node_id: str,
        sink_node_id: str,
        severity: str,
        status: FindingStatus,
        confidence: float,
        source_evidence: dict[str, Any] | Sequence[Any] = (),
        sink_evidence: dict[str, Any] | Sequence[Any] = (),
        flow_evidence: dict[str, Any] | Sequence[Any] = (),
        sanitizer_evidence: dict[str, Any] | Sequence[Any] = (),
        condition_evidence: Sequence[Any] = (),
        file: str | None = None,
        line: int | None = None,
        symbol: str | None = None,
        schema_version: str = "1.0",
    ) -> SecurityFinding:
        """Factory method computing deterministic SHA-256 finding_id."""
        fid = compute_finding_id(
            rule_id=rule_id,
            rule_version=rule_version,
            flow_id=flow_id,
            source_fact_id=source_fact_id,
            sink_fact_id=sink_fact_id,
        )

        def dict_to_tuples(data: Any) -> tuple[tuple[str, str], ...]:
            if isinstance(data, dict):
                return tuple(sorted((str(k), str(v)) for k, v in data.items()))
            if isinstance(data, (list, tuple)):
                result = []
                for item in data:
                    if isinstance(item, tuple) and len(item) == 2:
                        result.append((str(item[0]), str(item[1])))
                    elif isinstance(item, dict):
                        result.extend((str(k), str(v)) for k, v in item.items())
                    else:
                        result.append(("item", str(item)))
                return tuple(sorted(result))
            return ()

        clamped_confidence = max(0.0, min(1.0, round(confidence, 4)))

        return cls(
            finding_id=fid,
            rule_id=rule_id,
            rule_key=rule_key,
            rule_version=rule_version,
            vulnerability_class=vulnerability_class,
            source_fact_id=source_fact_id,
            sink_fact_id=sink_fact_id,
            flow_id=flow_id,
            source_node_id=source_node_id,
            sink_node_id=sink_node_id,
            severity=severity.upper(),
            status=status,
            confidence=clamped_confidence,
            source_evidence=dict_to_tuples(source_evidence),
            sink_evidence=dict_to_tuples(sink_evidence),
            flow_evidence=dict_to_tuples(flow_evidence),
            sanitizer_evidence=dict_to_tuples(sanitizer_evidence),
            condition_evidence=dict_to_tuples(condition_evidence),
            file=file,
            line=line,
            symbol=symbol,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes SecurityFinding to dictionary deterministically for forensic auditability (INV-E12-RULE-25)."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_key": self.rule_key,
            "rule_version": self.rule_version,
            "vulnerability_class": self.vulnerability_class,
            "source_fact_id": self.source_fact_id,
            "sink_fact_id": self.sink_fact_id,
            "flow_id": self.flow_id,
            "source_node_id": self.source_node_id,
            "sink_node_id": self.sink_node_id,
            "severity": self.severity,
            "status": self.status.value,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "evidence": {
                "source": dict(self.source_evidence),
                "sink": dict(self.sink_evidence),
                "flow": dict(self.flow_evidence),
                "sanitizer": dict(self.sanitizer_evidence),
                "conditions": dict(self.condition_evidence),
            },
            "schema_version": self.schema_version,
        }
