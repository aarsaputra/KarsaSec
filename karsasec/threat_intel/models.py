"""Immutable domain models for Sprint E19 Threat Intelligence & Risk Context."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def compute_hash(prefix: str, payload: dict[str, Any]) -> str:
    """Computes canonical SHA-256 hash for threat intel artifacts."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prefix}:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class ThreatFeedRecord:
    """Immutable threat feed record representing CVE/EPSS intelligence."""

    record_id: str
    vulnerability_class: str
    epss_score: float
    cve_id: str
    is_exploited_in_wild: bool

    @classmethod
    def create(
        cls,
        vulnerability_class: str,
        epss_score: float,
        cve_id: str = "",
        is_exploited_in_wild: bool = False,
    ) -> ThreatFeedRecord:
        clamped_epss = max(0.0, min(1.0, round(float(epss_score), 4)))
        payload = {
            "vulnerability_class": vulnerability_class,
            "epss_score": clamped_epss,
            "cve_id": cve_id,
            "is_exploited_in_wild": is_exploited_in_wild,
        }
        rid = compute_hash("THREAT-REC", payload)
        return cls(
            record_id=rid,
            vulnerability_class=vulnerability_class,
            epss_score=clamped_epss,
            cve_id=cve_id,
            is_exploited_in_wild=is_exploited_in_wild,
        )


@dataclass(frozen=True)
class RiskContextAssessment:
    """Immutable risk context score for a cluster or asset."""

    assessment_id: str
    vulnerability_class: str
    risk_score: float
    asset_criticality: float
    epss_score: float
    is_high_risk: bool
    explanation: tuple[str, ...]

    @classmethod
    def create(
        cls,
        vulnerability_class: str,
        risk_score: float,
        asset_criticality: float,
        epss_score: float,
        explanation: tuple[str, ...],
    ) -> RiskContextAssessment:
        clamped_risk = max(0.0, min(1.0, round(float(risk_score), 4)))
        clamped_asset = max(0.0, min(1.0, round(float(asset_criticality), 4)))
        clamped_epss = max(0.0, min(1.0, round(float(epss_score), 4)))
        is_high = clamped_risk >= 0.70

        sorted_expl = tuple(sorted(explanation))
        payload = {
            "vulnerability_class": vulnerability_class,
            "risk_score": clamped_risk,
            "asset_criticality": clamped_asset,
            "epss_score": clamped_epss,
            "is_high_risk": is_high,
            "explanation": list(sorted_expl),
        }
        aid = compute_hash("RISK-ASSESS", payload)
        return cls(
            assessment_id=aid,
            vulnerability_class=vulnerability_class,
            risk_score=clamped_risk,
            asset_criticality=clamped_asset,
            epss_score=clamped_epss,
            is_high_risk=is_high,
            explanation=sorted_expl,
        )
