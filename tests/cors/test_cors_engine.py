"""Batch C1 CORS Security Reasoning Engine Test Suite."""

from karsasec.analysis.cors.engine import CORSReasoningEngine
from karsasec.analysis.csrf.models import (
    CORSHeaderNode,
    CSRFVulnerabilityType,
)


def test_cors_wildcard_with_credentials() -> None:
    """C1.10: Verifies detection of Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true."""
    engine = CORSReasoningEngine()
    cors = CORSHeaderNode(allow_origin="*", allow_credentials=True)

    ev = engine.evaluate_cors(cors)
    assert ev is not None
    assert ev.category == CSRFVulnerabilityType.CORS_WILDCARD_WITH_CREDENTIALS


def test_cors_origin_reflection_unvalidated() -> None:
    """C1.13: Verifies detection of unvalidated origin reflection in CORS response headers."""
    engine = CORSReasoningEngine()
    cors = CORSHeaderNode(allow_origin="https://evil.com", allow_credentials=True, is_reflected_origin=True, is_validated_origin=False)

    ev = engine.evaluate_cors(cors)
    assert ev is not None
    assert ev.category == CSRFVulnerabilityType.CORS_ORIGIN_REFLECTION


def test_cors_weak_origin_validation_bypass() -> None:
    """C1.8: Verifies detection of weak origin matching (endswith, startswith, substring)."""
    engine = CORSReasoningEngine()

    ev_endswith = engine.evaluate_origin_validation_pattern("endswith")
    assert ev_endswith is not None
    assert ev_endswith.category == CSRFVulnerabilityType.ORIGIN_VALIDATION_BYPASS

    ev_startswith = engine.evaluate_origin_validation_pattern("startswith")
    assert ev_startswith is not None
    assert ev_startswith.category == CSRFVulnerabilityType.ORIGIN_VALIDATION_BYPASS


def test_cors_safe_config() -> None:
    """Verifies that strict validated CORS origin configurations return None (SAFE)."""
    engine = CORSReasoningEngine()
    cors = CORSHeaderNode(allow_origin="https://trusted.example.com", allow_credentials=True, is_reflected_origin=True, is_validated_origin=True)

    ev = engine.evaluate_cors(cors)
    assert ev is None
