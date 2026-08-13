"""Unit tests for RTP Serialization Engine and OpenAPI Schema Generator (Sprint F0)."""

from __future__ import annotations


from karsasec.ai.remediation.rtp.canonical import compute_canonical_hash
from karsasec.ai.remediation.rtp.serialization import (
    export_rtp,
    generate_rtp_openapi_schema,
    import_rtp,
)
from tests.unit.ai.remediation.rtp.test_validator import _build_valid_rtp


def test_export_import_roundtrip() -> None:
    original_rtp = _build_valid_rtp()

    exported_json = export_rtp(original_rtp)
    assert isinstance(exported_json, str)
    assert "karsasec-remediation-transaction" in exported_json

    imported_rtp = import_rtp(exported_json)

    assert imported_rtp == original_rtp
    assert compute_canonical_hash(imported_rtp) == compute_canonical_hash(original_rtp)


def test_openapi_schema_generation() -> None:
    schema = generate_rtp_openapi_schema()

    assert schema["openapi"] == "3.1.0"
    assert "components" in schema
    assert "schemas" in schema["components"]

    schemas = schema["components"]["schemas"]
    assert "RemediationTransactionPackage" in schemas
    assert "VerificationReceipt" in schemas
    assert "RTPValidationResult" in schemas
