"""Unit test suite for Batch C10 SSRF Capability & Internal Network Reasoning Engine covering 25 mandatory unit tests and quality metrics."""

from karsasec.analysis.ssrf.engine import SSRFReasoningEngine
from karsasec.analysis.ssrf.models import (
    DNSResolutionEvidence,
    NetworkZone,
    SSRFCategory,
    SSRFContext,
)


def test_1_aws_metadata_access() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://169.254.169.254/latest/meta-data/")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.CLOUD_METADATA_ACCESS


def test_2_gcp_metadata_access() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://metadata.google.internal/computeMetadata/v1/")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.CLOUD_METADATA_ACCESS


def test_3_kubernetes_metadata_access() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://kubernetes.default.svc/api/v1")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.KUBERNETES_METADATA_ACCESS


def test_4_rfc1918_private_10_network() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://10.0.0.1/admin")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.INTERNAL_NETWORK_ACCESS


def test_5_rfc1918_private_192_network() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://192.168.1.1/router")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.INTERNAL_NETWORK_ACCESS


def test_6_loopback_127_access() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://127.0.0.1:8000/debug")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.INTERNAL_NETWORK_ACCESS


def test_7_localhost_alias_access() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://localhost:9000/metrics")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.INTERNAL_NETWORK_ACCESS


def test_8_gopher_protocol_smuggling() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="gopher://127.0.0.1:6379/_flushall")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.PROTOCOL_SMUGGLING


def test_9_file_protocol_smuggling() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="file:///etc/passwd")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.PROTOCOL_SMUGGLING


def test_10_redirect_based_ssrf() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://trusted.com/redir", redirect_chain=["http://trusted.com/redir", "http://169.254.169.254/latest/meta-data/"])
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.REDIRECT_BASED_SSRF


def test_11_dns_rebinding_risk() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(
        source_kind="HTTP_QUERY",
        source_symbol="url",
        target_url="http://rebind.evil.com/data",
        dns_evidence=DNSResolutionEvidence(hostname="rebind.evil.com", first_resolution="93.184.216.34", second_resolution="127.0.0.1", changes_zone=True),
    )
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.DNS_REBINDING_RISK


def test_12_url_parser_confusion_ssrf() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://trusted@127.0.0.1/", has_parser_disagreement=True)
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.URL_PARSER_CONFUSION_SSRF


def test_13_blind_ssrf_detection() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://public-target.com/webhook", is_response_accessible=False)
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.BLIND_SSRF


def test_14_safe_allowlisted_host() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="https://api.partner.com/data", is_host_allowlisted=True, canonicalized_before_validation=True)
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_15_validation_before_canonicalization_unknown() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="https://api.partner.com/data", is_host_allowlisted=True, canonicalized_before_validation=False)
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"  # Preserves INV-GLOBAL-01!


def test_16_general_public_ssrf() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://example.com/feed")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.SSRF


def test_17_classify_target_metadata() -> None:
    engine = SSRFReasoningEngine()
    cls = engine.classify_target("http://169.254.169.254/latest/meta-data/")
    assert cls.zone == NetworkZone.METADATA
    assert cls.is_internal is True


def test_18_classify_target_private() -> None:
    engine = SSRFReasoningEngine()
    cls = engine.classify_target("http://172.16.5.10/admin")
    assert cls.zone == NetworkZone.PRIVATE
    assert cls.is_internal is True


def test_19_classify_target_loopback() -> None:
    engine = SSRFReasoningEngine()
    cls = engine.classify_target("http://127.0.0.1:8080/metrics")
    assert cls.zone == NetworkZone.LOOPBACK
    assert cls.is_internal is True


def test_20_classify_target_public() -> None:
    engine = SSRFReasoningEngine()
    cls = engine.classify_target("https://public-api.com/v1")
    assert cls.zone == NetworkZone.PUBLIC
    assert cls.is_internal is False


def test_21_dict_protocol_smuggling() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="dict://127.0.0.1:11211/stats")
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.category == SSRFCategory.PROTOCOL_SMUGGLING


def test_22_alibaba_metadata_access() -> None:
    engine = SSRFReasoningEngine()
    cls = engine.classify_target("http://100.100.100.200/latest/meta-data/")
    assert cls.zone == NetworkZone.METADATA
    assert cls.metadata_service == "Alibaba"


def test_23_unknown_preservation_inv_global_01() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://unresolved", canonicalized_before_validation=False)
    ev = engine.evaluate_ssrf(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"


def test_24_deterministic_ssrf_evaluation() -> None:
    engine = SSRFReasoningEngine()
    ctx = SSRFContext(source_kind="HTTP_QUERY", source_symbol="url", target_url="http://169.254.169.254/latest/meta-data/")
    ev1 = engine.evaluate_ssrf(ctx)
    ev2 = engine.evaluate_ssrf(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()


def test_25_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = SSRFReasoningEngine()

    positives = [
        SSRFContext(source_kind="HTTP_QUERY", source_symbol=f"pos_{i}", target_url=f"http://10.0.0.{i}/admin") for i in range(50)
    ]
    negatives = [
        SSRFContext(source_kind="HTTP_QUERY", source_symbol=f"neg_{i}", target_url=f"https://api.trusted{i}.com/data", is_host_allowlisted=True, canonicalized_before_validation=True) for i in range(50)
    ]

    tp = sum(1 for ctx in positives if engine.evaluate_ssrf(ctx).resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for ctx in negatives if engine.evaluate_ssrf(ctx).resolution == "VULNERABLE")
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
