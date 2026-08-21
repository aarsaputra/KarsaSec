"""Batch C10 SSRF Golden Corpus Qualification Test Suite (150 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.ssrf.engine import SSRFReasoningEngine
from karsasec.analysis.ssrf.models import (
    DNSResolutionEvidence,
    SSRFContext,
)

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]
LIBRARIES = ["requests", "urllib", "aiohttp", "fetch", "axios", "HttpClient", "curl"]

# --- 150 High-Quality Parametrized Fixtures ---

METADATA_POSITIVES = [
    SSRFContext(
        source_kind="HTTP_QUERY",
        source_symbol=f"meta_url_{i}",
        target_url="http://169.254.169.254/latest/meta-data/" if i % 2 == 0 else "http://metadata.google.internal/computeMetadata/v1/",
        sink_library=LIBRARIES[i % len(LIBRARIES)],
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

PRIVATE_NETWORK_POSITIVES = [
    SSRFContext(
        source_kind="HTTP_BODY",
        source_symbol=f"priv_url_{i}",
        target_url=f"http://10.0.0.{i}/internal" if i % 3 == 0 else (f"http://192.168.1.{i}/admin" if i % 3 == 1 else f"http://172.16.0.{i}/api"),
        sink_library=LIBRARIES[i % len(LIBRARIES)],
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

LOOPBACK_AND_KUBERNETES_POSITIVES = [
    SSRFContext(
        source_kind="HTTP_HEADER",
        source_symbol=f"loop_url_{i}",
        target_url="http://127.0.0.1:8080/metrics" if i % 2 == 0 else "http://kubernetes.default.svc/api/v1",
        sink_library=LIBRARIES[i % len(LIBRARIES)],
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 21)
]

PROTOCOL_SMUGGLING_POSITIVES = [
    SSRFContext(
        source_kind="XML_ENTITY",
        source_symbol=f"proto_url_{i}",
        target_url=f"gopher://127.0.0.1:6379/_flushall_{i}" if i % 2 == 0 else f"file:///etc/passwd_{i}",
        sink_library=LIBRARIES[i % len(LIBRARIES)],
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

DNS_REBINDING_POSITIVES = [
    SSRFContext(
        source_kind="TEMPLATE_INPUT",
        source_symbol=f"rebind_url_{i}",
        target_url=f"http://rebind{i}.attacker.com/data",
        dns_evidence=DNSResolutionEvidence(hostname=f"rebind{i}.attacker.com", first_resolution="93.184.216.34", second_resolution="127.0.0.1", changes_zone=True),
        sink_library=LIBRARIES[i % len(LIBRARIES)],
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

SAFE_ALLOWLIST_NEGATIVES = [
    SSRFContext(
        source_kind="HTTP_QUERY",
        source_symbol=f"safe_url_{i}",
        target_url=f"https://api.trusted{i}.com/data",
        is_host_allowlisted=True,
        allowed_hosts=[f"api.trusted{i}.com"],
        canonicalized_before_validation=True,
        sink_library=LIBRARIES[i % len(LIBRARIES)],
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]


@pytest.mark.parametrize("ctx", METADATA_POSITIVES)
def test_metadata_ssrf_positives(ctx: SSRFContext) -> None:
    engine = SSRFReasoningEngine()
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", PRIVATE_NETWORK_POSITIVES)
def test_private_network_ssrf_positives(ctx: SSRFContext) -> None:
    engine = SSRFReasoningEngine()
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", LOOPBACK_AND_KUBERNETES_POSITIVES)
def test_loopback_kubernetes_ssrf_positives(ctx: SSRFContext) -> None:
    engine = SSRFReasoningEngine()
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", PROTOCOL_SMUGGLING_POSITIVES)
def test_protocol_smuggling_positives(ctx: SSRFContext) -> None:
    engine = SSRFReasoningEngine()
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", DNS_REBINDING_POSITIVES)
def test_dns_rebinding_positives(ctx: SSRFContext) -> None:
    engine = SSRFReasoningEngine()
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", SAFE_ALLOWLIST_NEGATIVES)
def test_safe_allowlist_negatives(ctx: SSRFContext) -> None:
    engine = SSRFReasoningEngine()
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_ssrf_determinism() -> None:
    """Section Determinism: Verifies repeated evaluation yields 100% identical outputs."""
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(
        source_kind="HTTP_QUERY",
        source_symbol="url_param",
        target_url="http://169.254.169.254/latest/meta-data/",
        sink_library="requests",
    )

    ev1 = engine.evaluate_ssrf(ctx)
    ev2 = engine.evaluate_ssrf(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
