"""Batch C8 HTTP Header & Log Injection Golden Corpus Qualification Test Suite (120 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.http_headers.engine import HTTPHeaderInjectionReasoningEngine
from karsasec.analysis.http_headers.models import (
    HeaderContext,
    HeaderInjectionNode,
)

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]
HEADERS = ["X-Custom-Header", "Location", "Set-Cookie", "Content-Type", "Host", "X-Forwarded-Host"]
SINKS = ["set_header", "add_header", "response.headers", "redirect", "logger"]

# --- 120 High-Quality Parametrized Fixtures ---

CRLF_POSITIVES = [
    HeaderInjectionNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"header_val_{i}",
        header_name=HEADERS[i % len(HEADERS)],
        header_value=f"user_input_{i}\r\nX-Injected: true",
        sink_type=SINKS[i % len(SINKS)],
        is_user_controlled=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

SAFE_CONSTANT_NEGATIVES = [
    HeaderInjectionNode(
        source_kind="TRUSTED_CONSTANT",
        source_symbol=f"const_header_{i}",
        header_name=HEADERS[i % len(HEADERS)],
        header_value="application/json",
        sink_type="set_header",
        is_user_controlled=False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

SANITIZED_FIXTURES = [
    HeaderInjectionNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"sanitized_val_{i}",
        header_name="logger.info" if i % 2 == 0 else "Location",
        header_value=f"clean_val_{i}",
        sink_type="logger" if i % 2 == 0 else "redirect",
        is_user_controlled=True,
        sanitizer_type="log_sanitizer" if i % 2 == 0 else None,
        is_validated=True if i % 2 != 0 else False,
        canonicalized_before_validation=True if i % 2 != 0 else None,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 21)
]

ENCODED_DOUBLE_DECODED_FIXTURES = [
    HeaderInjectionNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"encoded_val_{i}",
        header_name="Location",
        header_value="%250d%250aSet-Cookie: admin=true",
        sink_type="set_header",
        is_user_controlled=True,
        is_double_decoded=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 21)
]

INTERPROCEDURAL_FIXTURES = [
    HeaderInjectionNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"interproc_val_{i}",
        header_name="X-User-Role",
        header_value="admin\r\n",
        sink_type="add_header",
        is_user_controlled=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 11)
]

UNKNOWN_VALIDATION_FIXTURES = [
    HeaderInjectionNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"unknown_val_{i}",
        header_name=HeaderContext.LOCATION.value,
        header_value="unresolved",
        sink_type="redirect",
        is_user_controlled=True,
        is_validated=True,
        canonicalized_before_validation=False,
        sanitizer_type="unknown_sanitizer",
        language="python",
    )
    for i in range(1, 11)
]


@pytest.mark.parametrize("node", CRLF_POSITIVES)
def test_crlf_positive_detection(node: HeaderInjectionNode) -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("node", SAFE_CONSTANT_NEGATIVES)
def test_safe_constant_negatives(node: HeaderInjectionNode) -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("node", SANITIZED_FIXTURES)
def test_sanitized_fixtures(node: HeaderInjectionNode) -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("node", ENCODED_DOUBLE_DECODED_FIXTURES)
def test_encoded_double_decoded_fixtures(node: HeaderInjectionNode) -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("node", INTERPROCEDURAL_FIXTURES)
def test_interprocedural_fixtures(node: HeaderInjectionNode) -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("node", UNKNOWN_VALIDATION_FIXTURES)
def test_unknown_validation_fixtures(node: HeaderInjectionNode) -> None:
    engine = HTTPHeaderInjectionReasoningEngine()
    ev = engine.evaluate_header_injection(node)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"  # INV-GLOBAL-01 preserved!


def test_http_header_injection_determinism() -> None:
    """Section Determinism: Verifies repeated execution yields 100% identical outputs."""
    engine = HTTPHeaderInjectionReasoningEngine()
    node = HeaderInjectionNode(
        source_kind="HTTP_REQUEST",
        source_symbol="req.headers['X-Forwarded-Host']",
        header_name="Host",
        header_value="evil.com",
        sink_type="set_header",
    )

    ev1 = engine.evaluate_header_injection(node)
    ev2 = engine.evaluate_header_injection(node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
