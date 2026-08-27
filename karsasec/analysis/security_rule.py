"""SecurityRule data model and rule identity algorithm for Sprint E12."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.analysis.rule_condition import RuleCondition


def compute_rule_id(rule_key: str, version: str) -> str:
    """Computes a 64-character deterministic SHA-256 rule ID across process executions (INV-E12-RULE-01)."""
    canonical_rule = f"E12:{rule_key}:{version}"
    return hashlib.sha256(canonical_rule.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SecurityRule:
    """Immutable SecurityRule definition for deterministic rule evaluation."""

    rule_id: str
    rule_key: str
    name: str
    version: str
    vulnerability_class: str
    source_kinds: tuple[str, ...]
    sink_categories: tuple[str, ...]
    required_roles: tuple[str, ...]
    blocked_by_sanitizers: tuple[str, ...]
    minimum_confidence: float
    severity: str
    conditions: tuple[RuleCondition, ...] = ()

    @classmethod
    def create(
        cls,
        rule_key: str,
        name: str,
        version: str,
        vulnerability_class: str,
        source_kinds: tuple[str, ...] | list[str],
        sink_categories: tuple[str, ...] | list[str],
        required_roles: tuple[str, ...] | list[str] = (),
        blocked_by_sanitizers: tuple[str, ...] | list[str] = (),
        minimum_confidence: float = 0.60,
        severity: str = "HIGH",
        conditions: tuple[RuleCondition, ...] | list[RuleCondition] = (),
    ) -> SecurityRule:
        """Factory method computing deterministic SHA-256 rule_id."""
        rid = compute_rule_id(rule_key, version)
        return cls(
            rule_id=rid,
            rule_key=rule_key,
            name=name,
            version=version,
            vulnerability_class=vulnerability_class,
            source_kinds=tuple(source_kinds),
            sink_categories=tuple(sink_categories),
            required_roles=tuple(required_roles),
            blocked_by_sanitizers=tuple(blocked_by_sanitizers),
            minimum_confidence=round(minimum_confidence, 4),
            severity=severity.upper(),
            conditions=tuple(conditions),
        )

    def to_dict(self) -> dict[str, str | float | list[str]]:
        """Serializes rule identity deterministically."""
        return {
            "rule_id": self.rule_id,
            "rule_key": self.rule_key,
            "name": self.name,
            "version": self.version,
            "vulnerability_class": self.vulnerability_class,
            "source_kinds": list(self.source_kinds),
            "sink_categories": list(self.sink_categories),
            "required_roles": list(self.required_roles),
            "blocked_by_sanitizers": list(self.blocked_by_sanitizers),
            "minimum_confidence": self.minimum_confidence,
            "severity": self.severity,
        }
