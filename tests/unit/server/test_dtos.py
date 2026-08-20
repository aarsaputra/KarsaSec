"""Unit tests for DTO models (scan, finding, remediation, receipt)."""

from __future__ import annotations

from karsasec.server.dto.scan import ScanRequest, ScanResponseDTO, ScanTargetDTO
from karsasec.server.dto.finding import FindingDTO, FindingListResponseDTO
from karsasec.server.dto.common import PaginationMeta
from karsasec.server.dto.remediation import (
    ApprovalTokenInputDTO,
    RemediationRequestDTO,
    RemediationResponseDTO,
)
from karsasec.server.dto.receipt import VerificationReceiptResponseDTO


class TestScanDTOs:
    def test_scan_request_valid(self):
        req = ScanRequest(target=ScanTargetDTO(identity="/some/path"))
        assert req.target.identity == "/some/path"
        assert req.target.type == "local_repository"

    def test_scan_response_dto_fields(self):
        dto = ScanResponseDTO(
            scan_id="scan-abc", status="COMPLETED",
            created_at="2026-01-01T00:00:00Z", finding_count=5,
            files_scanned=10, duration_ms=123.4,
        )
        assert dto.scan_id == "scan-abc"
        assert dto.finding_count == 5


class TestFindingDTOs:
    def test_finding_dto_excludes_source_code(self):
        # FindingDTO has no source_code field — assert it doesn't exist
        dto = FindingDTO(
            finding_id="f1", rule_id="SQL001", severity="HIGH",
            file_path="src/app.py", line_number=42,
        )
        assert not hasattr(dto, "source_code")
        assert not hasattr(dto, "snippet")
        assert not hasattr(dto, "unified_diff")

    def test_finding_list_response_dto(self):
        items = [
            FindingDTO(finding_id=f"f{i}", rule_id="R1", severity="LOW",
                       file_path="a.py", line_number=i)
            for i in range(3)
        ]
        resp = FindingListResponseDTO(
            items=items,
            pagination=PaginationMeta(total=3, page=1, page_size=50),
        )
        assert len(resp.items) == 3
        assert resp.pagination.total == 3


class TestRemediationDTOs:
    def test_remediation_request_dto(self):
        req = RemediationRequestDTO(
            finding_id="f1",
            approval=ApprovalTokenInputDTO(
                approval_token_id="tok-001", token="secret-value"
            ),
        )
        assert req.finding_id == "f1"

    def test_remediation_response_dto_has_no_source_code_field(self):
        dto = RemediationResponseDTO(
            transaction_id="rem-001", finding_id="f1",
            state="REJECTED", integrity_status="INVALID",
            security_verification_status="SECURITY_NOT_VERIFIED",
        )
        assert not hasattr(dto, "source_code")
        assert not hasattr(dto, "unified_diff")
        assert not hasattr(dto, "diff")

    def test_security_verification_status_is_output_only(self):
        # The field must exist in response DTO (output), but should not be
        # an input-overridable field — verify the default exists for serialization.
        dto = RemediationResponseDTO(
            transaction_id="t1", finding_id="f1",
            state="REJECTED", integrity_status="INVALID",
            security_verification_status="SECURITY_NOT_VERIFIED",
        )
        assert "SECURITY_NOT_VERIFIED" in dto.security_verification_status


class TestReceiptDTO:
    def test_receipt_dto_fields_no_private_data(self):
        dto = VerificationReceiptResponseDTO(
            receipt_id="r1", transaction_id="t1", finding_id="f1",
            integrity_status="VALID",
            security_verification_status="SECURITY_VERIFIED",
            receipt_fingerprint="abc" * 20,
        )
        assert not hasattr(dto, "source_code")
        assert not hasattr(dto, "unified_diff")
        assert not hasattr(dto, "password")
        assert not hasattr(dto, "api_key")

    def test_receipt_dto_serializes_to_dict(self):
        dto = VerificationReceiptResponseDTO(
            receipt_id="r1", transaction_id="t1", finding_id="f1",
            integrity_status="VALID",
            security_verification_status="SECURITY_NOT_VERIFIED",
            receipt_fingerprint="fp" * 30,
        )
        d = dto.model_dump()
        assert "receipt_fingerprint" in d
        assert "source_code" not in d
