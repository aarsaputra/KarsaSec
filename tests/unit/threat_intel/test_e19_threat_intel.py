"""Unit and Invariant test suite for Sprint E19: Threat Intelligence & Risk Context."""

from karsasec.threat_intel.models import ThreatFeedRecord
from karsasec.threat_intel.scorer import ThreatContextScorer


def test_threat_feed_record_creation():
    rec = ThreatFeedRecord.create(
        vulnerability_class="SQL_INJECTION",
        epss_score=0.95,
        cve_id="CVE-2026-1001",
        is_exploited_in_wild=True,
    )
    assert len(rec.record_id) == 64
    assert rec.epss_score == 0.95


def test_threat_context_scorer_fail_closed_on_none():
    scorer = ThreatContextScorer()
    res = scorer.assess_risk(vulnerability_class=None)
    assert res.risk_score == 0.85
    assert res.vulnerability_class == "UNKNOWN"


def test_threat_context_scorer_evaluates_wild_vulnerability():
    scorer = ThreatContextScorer()
    rec = ThreatFeedRecord.create(
        vulnerability_class="COMMAND_INJECTION",
        epss_score=0.90,
        is_exploited_in_wild=True,
    )
    scorer.register_intel(rec)

    res = scorer.assess_risk(
        vulnerability_class="COMMAND_INJECTION",
        base_confidence=0.90,
        asset_criticality=0.90,
    )
    assert res.is_high_risk is True
    assert res.risk_score > 0.80
