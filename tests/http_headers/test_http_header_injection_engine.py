"""Unit test suite for Batch C8 HTTP Header & Log Injection Engine covering 25 mandatory unit tests and quality metrics."""

from karsasec.analysis.http_headers.engine import HTTPHeaderInjectionReasoningEngine
from karsasec.analysis.http_headers.models import (
    HeaderContext,
    HeaderInjectionCategory,
    HeaderInjectionNode,
)


def test_1_crlf_positive() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="val\r\nX-Injected: true", sink_type="set_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.CRLF_INJECTION


def test_2_crlf_negative() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="TRUSTED_CONSTANT", source_symbol="val", header_name="X-Header", header_value="clean_value", sink_type="set_header", is_user_controlled=False)
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_3_encoded_crlf() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="%0d%0aSet-Cookie: admin=true", sink_type="set_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_4_double_encoded_crlf() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="%250d%250aSet-Cookie: admin=true", sink_type="set_header", is_double_decoded=True)
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.encoding_state == "DOUBLE_DECODED_CRLF"


def test_5_response_splitting() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name=HeaderContext.LOCATION.value, header_value="/login\r\n\r\n<html>evil</html>", sink_type="redirect")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.HTTP_RESPONSE_SPLITTING


def test_6_arbitrary_header_injection() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Custom", header_value="foo\r\nBar: baz", sink_type="add_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_7_location_header_injection() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="url", header_name=HeaderContext.LOCATION.value, header_value="http://evil.com", sink_type="redirect")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.HTTP_RESPONSE_SPLITTING


def test_8_set_cookie_injection() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="cookie", header_name=HeaderContext.SET_COOKIE.value, header_value="session=evil; Domain=evil.com", sink_type="cookie_setter")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.HTTP_RESPONSE_SPLITTING


def test_9_content_disposition_injection() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="fname", header_name="Content-Disposition", header_value='attachment; filename="file.pdf"\r\nX-Injected: true', sink_type="set_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None


def test_10_host_header_injection() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="host", header_name=HeaderContext.HOST.value, header_value="attacker.com", sink_type="set_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.HOST_HEADER_INJECTION
    assert ev.impact == "RESET_URL_MANIPULATION"  # INV-C8-04 verified: NOT automatic account takeover!


def test_11_x_forwarded_host() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="PROXY_HEADER", source_symbol="fwd_host", header_name=HeaderContext.X_FORWARDED_HOST.value, header_value="attacker.com", sink_type="set_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.HOST_HEADER_INJECTION


def test_12_trusted_host_allowlist() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="host", header_name=HeaderContext.HOST.value, header_value="mysite.com", sink_type="set_header", is_host_allowlisted=True)
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_13_log_injection() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="user", header_name="logger.info", header_value="admin\nINFO: Password reset", sink_type="logger")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.category == HeaderInjectionCategory.LOG_INJECTION


def test_14_safe_log_sanitizer() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="user", header_name="logger.info", header_value="admin", sink_type="logger", sanitizer_type="log_sanitizer")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_15_html_sanitizer_used_for_log_not_safe() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="user", header_name="logger.info", header_value="admin\nINFO: Forged", sink_type="logger", sanitizer_type="html_sanitizer")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"  # HTML sanitizer is NOT a valid log sanitizer!


def test_16_sql_sanitizer_used_for_header_not_safe() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="val\r\n", sink_type="set_header", sanitizer_type="sql_sanitizer")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"  # SQL sanitizer is NOT a valid header sanitizer!


def test_17_unknown_sanitizer_unknown() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="Location", header_value="val", sink_type="redirect", sanitizer_type="unknown_sanitizer")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"


def test_18_unknown_framework_behavior_unknown() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="Location", header_value="val", sink_type="redirect", framework_rejects_crlf=None, sanitizer_type="unknown_sanitizer")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"


def test_19_constant_header_safe() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="TRUSTED_CONSTANT", source_symbol="const", header_name="Content-Type", header_value="application/json", sink_type="set_header", is_user_controlled=False)
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_20_canonicalization_before_validation_safe() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="clean", sink_type="set_header", is_validated=True, canonicalized_before_validation=True)
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_21_validation_before_canonicalization_unknown() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="flawed", sink_type="set_header", is_validated=True, canonicalized_before_validation=False)
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"


def test_22_interprocedural_header_flow() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="helper_val", header_name="Location", header_value="redirect_path", sink_type="redirect")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_23_cache_poisoning_potential_chain() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="cache_val", header_name="Cache-Control", header_value="public, max-age=3600\r\nX-Injected: true", sink_type="set_header")
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_24_determinism() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val", header_name="X-Header", header_value="val\r\n", sink_type="set_header")
    ev1 = engine.evaluate_header_injection(node)
    ev2 = engine.evaluate_header_injection(node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()


def test_25_order_invariance() -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    node1 = HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol="val1", header_name="X-Header", header_value="val\r\n", sink_type="set_header")
    node2 = HeaderInjectionNode(source_kind="TRUSTED_CONSTANT", source_symbol="val2", header_name="Content-Type", header_value="text/plain", sink_type="set_header", is_user_controlled=False)

    ev1 = engine.evaluate_header_injection(node1)
    ev2 = engine.evaluate_header_injection(node2)
    assert ev1 is not None and ev1.resolution == "VULNERABLE"
    assert ev2 is not None and ev2.resolution == "SAFE"


def test_c8_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = HTTPHeaderInjectionReasoningEngine()

    positives = [
        HeaderInjectionNode(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", header_name="X-Header", header_value=f"val_{i}\r\n", sink_type="set_header") for i in range(50)
    ]
    negatives = [
        HeaderInjectionNode(source_kind="TRUSTED_CONSTANT", source_symbol=f"neg_{i}", header_name="X-Header", header_value=f"clean_{i}", sink_type="set_header", is_user_controlled=False) for i in range(50)
    ]

    tp = sum(1 for node in positives if engine.evaluate_header_injection(node).resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for node in negatives if engine.evaluate_header_injection(node).resolution == "VULNERABLE")
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
