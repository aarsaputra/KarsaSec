"""Master Integration Test Suite for Post-Gate-5 Independent Audit Verification."""

from karsasec.analysis.decision.models import DecisionResolution
from karsasec.analysis.taint.sanitizers import SanitizerResolver
from karsasec.analysis.taint.sources import SourceResolver


def test_master_audit_source_and_sanitizer_invariants() -> None:
    source_res = SourceResolver()
    san_res = SanitizerResolver()

    # Positive HTTP source
    s = source_res.resolve_source("request.getParameter('id')")
    assert s is not None and s.is_user_controlled

    # Negative control
    s_neg = source_res.resolve_source("config.get('id')")
    assert s_neg is not None and not s_neg.is_user_controlled

    # Context-sensitive sanitizer (html.escape safe for XSS, unsafe for SQLi)
    san_xss = san_res.resolve_sanitizer("html.escape(input)", target_property="CROSS_SITE_SCRIPTING")
    assert san_xss is not None and san_xss.is_verified_safe

    san_sqli = san_res.resolve_sanitizer("html.escape(input)", target_property="SQL_INJECTION")
    assert san_sqli is not None and not san_sqli.is_verified_safe


def test_master_audit_epistemic_safety_invariants() -> None:
    assert DecisionResolution.UNKNOWN != DecisionResolution.SAFE
    assert DecisionResolution.UNKNOWN != DecisionResolution.VULNERABLE
    assert DecisionResolution.CONFLICT != DecisionResolution.SAFE
    assert DecisionResolution.CONFLICT != DecisionResolution.VULNERABLE
