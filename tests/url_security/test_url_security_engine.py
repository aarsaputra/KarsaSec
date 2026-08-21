"""Unit test suite for Batch C9 Open Redirect & URL Parser Confusion Engine covering C9-HARDEN-01 through C9-HARDEN-05."""

from karsasec.analysis.url_security.engine import URLSecurityReasoningEngine
from karsasec.analysis.url_security.models import (
    URLCategory,
    URLSecurityContext,
)


def test_1_open_redirect_detection() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="next", raw_url="https://evil.com/phish", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.OPEN_REDIRECT


def test_2_relative_redirect_safe() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="next", raw_url="/dashboard", sink="redirect", sanitizer_type="relative_path_only")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_3_external_redirect_safe_allowlist() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="next", raw_url="https://trusted.com/home", sink="redirect", is_host_allowlisted=True, allowed_hosts=["trusted.com"], canonicalized_before_validation=True)
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_4_scheme_relative_redirect() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="next", raw_url="//evil.com/path", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.SCHEME_RELATIVE_REDIRECT


def test_5_javascript_scheme() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="javascript:alert(1)", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.SCHEME_CONFUSION


def test_6_data_scheme() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="data:text/html,<script>alert(1)</script>", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.SCHEME_CONFUSION


def test_7_userinfo_confusion() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="https://trusted.example@evil.com/path", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.USERINFO_CONFUSION
    assert ev.parsed_url["hostname"] == "evil.com"


def test_8_authority_confusion() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="https://trusted.example%40evil.com/", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_9_backslash_confusion() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="https://trusted.example\\@evil.com", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.BACKSLASH_URL_CONFUSION


def test_10_encoded_redirect() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="%2f%2fevil.com", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_11_double_encoded_redirect() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="%252f%252fevil.com", sink="redirect")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_12_validation_before_canonicalization() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="https://trusted.example@evil.com", sink="redirect", validation_type="startswith", canonicalized_before_validation=False)
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"  # Validation before canonicalization triggers UNKNOWN!


def test_13_canonicalization_before_validation() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="url", raw_url="https://trusted.com/home", sink="redirect", is_host_allowlisted=True, allowed_hosts=["trusted.com"], canonicalized_before_validation=True)
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_14_oauth_redirect_uri_bypass() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="OAUTH_PARAM", source_symbol="redirect_uri", raw_url="https://trusted.example.evil.com/callback", sink="oauth_callback", validation_type="startswith")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.OAUTH_REDIRECT_URI_BYPASS


def test_15_oauth_exact_match_safe() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="OAUTH_PARAM", source_symbol="redirect_uri", raw_url="https://trusted.com/callback", sink="oauth_callback", registered_oauth_uri="https://trusted.com/callback")
    policy = engine.evaluate_oauth_policy("https://trusted.com/callback", "https://trusted.com/callback")
    assert policy.is_exact_match is True


def test_16_password_reset_url_poisoning_graph() -> None:
    """C9-HARDEN-04: Verifies explicit boundary graph HOST_HEADER -> RESET_URL_BUILDER -> MAIL_TEMPLATE -> EMAIL_SINK."""
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HOST_HEADER", source_symbol="host_hdr", raw_url="attacker.com", sink="reset_url_gen")
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.category == URLCategory.PASSWORD_RESET_URL_POISONING
    assert ev.evidence_path == ["HOST_HEADER", "host_hdr", "RESET_URL_BUILDER", "MAIL_TEMPLATE", "EMAIL_SINK"]


def test_17_multi_parser_divergence() -> None:
    """C9-HARDEN-01: Verifies multi-parser semantics divergence detection."""
    engine = URLSecurityReasoningEngine()
    model = engine.evaluate_multi_parser_semantics("https://trusted.example\\@evil.example")
    assert model.has_parser_disagreement is True


def test_18_idna_punycode_confusion() -> None:
    """C9-HARDEN-05: Verifies IDNA punycode hostname decoding."""
    engine = URLSecurityReasoningEngine()
    parsed = engine.parse_url("https://xn--e1afmkfd.xn--p1ai/path")
    assert "idna_punycode_detected" in parsed.normalization_steps


def test_19_unknown_parser_preserved() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="unresolved", raw_url="http://unresolved", sink="redirect", framework_parser_resolved=False)
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"  # INV-GLOBAL-01 preserved!


def test_20_deterministic_evaluation() -> None:
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol="next", raw_url="https://evil.com/path", sink="redirect")
    ev1 = engine.evaluate_url_security(ctx)
    ev2 = engine.evaluate_url_security(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()


def test_c9_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = URLSecurityReasoningEngine()

    positives = [
        URLSecurityContext(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", raw_url=f"https://evil{i}.com/phish", sink="redirect") for i in range(50)
    ]
    negatives = [
        URLSecurityContext(source_kind="TRUSTED_CONSTANT", source_symbol=f"neg_{i}", raw_url=f"/safe_{i}", sink="redirect", is_user_controlled=False) for i in range(50)
    ]

    tp = sum(1 for ctx in positives if engine.evaluate_url_security(ctx).resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for ctx in negatives if engine.evaluate_url_security(ctx).resolution == "VULNERABLE")
    tn = len(negatives) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
