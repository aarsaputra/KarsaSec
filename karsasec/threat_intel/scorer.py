"""Threat Context Scorer for Sprint E19."""

from __future__ import annotations

from karsasec.threat_intel.models import RiskContextAssessment, ThreatFeedRecord


class ThreatContextScorer:
    """Calculates deterministic risk scores combining vulnerability severity, asset criticality, and threat feed data."""

    def __init__(self) -> None:
        self._intel_feed: dict[str, ThreatFeedRecord] = {}

    def register_intel(self, record: ThreatFeedRecord) -> str:
        """Registers a ThreatFeedRecord in scorer cache."""
        self._intel_feed[record.vulnerability_class.upper()] = record
        return record.record_id

    def assess_risk(
        self,
        vulnerability_class: str | None,
        base_confidence: float = 0.50,
        asset_criticality: float = 0.50,
    ) -> RiskContextAssessment:
        """Calculates deterministic risk score.

        Enforces fail-closed bounds on invalid or missing inputs.
        """
        if not vulnerability_class:
            return RiskContextAssessment.create(
                vulnerability_class="UNKNOWN",
                risk_score=0.85,
                asset_criticality=0.50,
                epss_score=0.0,
                explanation=("FAIL-CLOSED: Missing vulnerability_class input",),
            )

        v_class = vulnerability_class.upper()
        record = self._intel_feed.get(v_class)

        epss = record.epss_score if record else 0.20
        wild = record.is_exploited_in_wild if record else False

        # Deterministic Risk Scoring Formula:
        # Base confidence (40%) + Asset Criticality (30%) + EPSS (20%) + In-the-wild multiplier (10%)
        wild_bonus = 0.10 if wild else 0.0
        raw_score = (0.40 * base_confidence) + (0.30 * asset_criticality) + (0.20 * epss) + wild_bonus
        final_risk = max(0.0, min(1.0, round(raw_score, 4)))

        explanations = [
            f"Base Confidence Weight: {base_confidence:.2f}",
            f"Asset Criticality Weight: {asset_criticality:.2f}",
            f"EPSS Threat Weight: {epss:.2f}",
        ]
        if wild:
            explanations.append("THREAT ALERT: Vulnerability confirmed actively exploited in the wild")

        return RiskContextAssessment.create(
            vulnerability_class=v_class,
            risk_score=final_risk,
            asset_criticality=asset_criticality,
            epss_score=epss,
            explanation=tuple(explanations),
        )
