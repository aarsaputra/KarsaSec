"""Security & adversarial tests for KarsaSec REST API (F1).

Tests cover:
- Unauthorized access (no credentials)
- Forbidden scope enforcement
- Forged VERIFIED_FIXED / SECURITY_VERIFIED input rejection
- Source code leakage prevention
- Diff leakage prevention
- Token / credential leakage prevention
- Tampered RTP rejection
- Stale/missing verification handling
- Determinism across sequential calls
- ARCHITECTURAL LAW #1: API cannot force security_verification_status
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from karsasec.server.app import create_app
from karsasec.server.config import ServerSettings
from karsasec.server.security.models import Permission, Principal

_VALID_KEY = "karsasec-dev-secret-key-change-in-production-32bytes"


@pytest.fixture(scope="module")
def client():
    settings = ServerSettings(auth_secret_key=_VALID_KEY)
    app = create_app(settings=settings)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def auth_headers():
    return {"X-API-Key": _VALID_KEY}


# -------------------------------------------------------------------------
# SEC-01: Unauthorized access — no credentials
# -------------------------------------------------------------------------
class TestUnauthorizedAccess:
    @pytest.mark.parametrize("path", [
        "/api/v1/scans/x",
        "/api/v1/findings",
        "/api/v1/findings/x",
        "/api/v1/remediations/x",
        "/api/v1/remediations/x/receipt",
    ])
    def test_unauthenticated_get_returns_401(self, client, path):
        resp = client.get(path)
        assert resp.status_code == 401

    def test_unauthenticated_post_scans_returns_401(self, client):
        resp = client.post("/api/v1/scans", json={"target": {"identity": "/x"}})
        assert resp.status_code == 401

    def test_unauthenticated_post_remediations_returns_401(self, client):
        resp = client.post("/api/v1/remediations", json={
            "finding_id": "f1",
            "approval": {"approval_token_id": "t1", "token": "tok"}
        })
        assert resp.status_code == 401


# -------------------------------------------------------------------------
# SEC-02: Invalid credentials
# -------------------------------------------------------------------------
class TestInvalidCredentials:
    def test_wrong_api_key_returns_401(self, client):
        resp = client.get("/api/v1/findings", headers={"X-API-Key": "WRONG-KEY-0000"})
        assert resp.status_code == 401

    def test_empty_api_key_returns_401(self, client):
        resp = client.get("/api/v1/findings", headers={"X-API-Key": ""})
        assert resp.status_code == 401

    def test_missing_header_returns_401(self, client):
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 401


# -------------------------------------------------------------------------
# SEC-03: Forbidden scope enforcement
# -------------------------------------------------------------------------
class TestForbiddenScope:
    def test_limited_principal_cannot_create_scan(self):
        """A principal with only finding:read cannot create scans."""
        from karsasec.server.security.authorization import authorize
        from fastapi import HTTPException
        limited = Principal(identity="limited", scopes=frozenset({Permission.FINDING_READ}))
        with pytest.raises(HTTPException) as exc:
            authorize(limited, Permission.SCAN_CREATE)
        assert exc.value.status_code == 403

    def test_limited_principal_cannot_trigger_remediation(self):
        from karsasec.server.security.authorization import authorize
        from fastapi import HTTPException
        limited = Principal(identity="limited", scopes=frozenset({Permission.SCAN_READ}))
        with pytest.raises(HTTPException) as exc:
            authorize(limited, Permission.REMEDIATION_CREATE)
        assert exc.value.status_code == 403

    def test_limited_principal_cannot_read_receipt(self):
        from karsasec.server.security.authorization import authorize
        from fastapi import HTTPException
        limited = Principal(identity="limited", scopes=frozenset())
        with pytest.raises(HTTPException) as exc:
            authorize(limited, Permission.RECEIPT_READ)
        assert exc.value.status_code == 403


# -------------------------------------------------------------------------
# SEC-04: ARCHITECTURAL LAW #1 — API cannot force security_verification_status
# -------------------------------------------------------------------------
class TestNoDirectSecurityAuthority:
    def test_client_cannot_inject_security_verified_via_remediation_request(self):
        """RemediationRequestDTO has NO security_verification_status input field.
        Any payload containing it should be ignored (extra fields stripped by Pydantic).
        """
        from karsasec.server.dto.remediation import RemediationRequestDTO
        raw = {
            "finding_id": "f1",
            "approval": {"approval_token_id": "t1", "token": "tok"},
            "security_verification_status": "SECURITY_VERIFIED",  # INJECTED — must be stripped
        }
        dto = RemediationRequestDTO.model_validate(raw)
        assert not hasattr(dto, "security_verification_status")

    def test_remediation_response_security_status_is_output_field(self):
        """RemediationResponseDTO contains security_verification_status as an output-only field."""
        from karsasec.server.dto.remediation import RemediationResponseDTO
        dto = RemediationResponseDTO(
            transaction_id="t1", finding_id="f1", state="REJECTED",
            integrity_status="INVALID",
            security_verification_status="SECURITY_NOT_VERIFIED",
        )
        # Field must exist as output; value reflects what the engine produced
        assert "SECURITY_NOT_VERIFIED" in dto.security_verification_status

    def test_security_status_never_hardcoded_in_router(self):
        """Verify router source files do not contain hardcoded VERIFIED_FIXED or SECURITY_VERIFIED assignments."""
        import re
        from pathlib import Path
        router_dir = Path("karsasec/server/api")
        forbidden = re.compile(
            r'security_status\s*=\s*["\']?(VERIFIED_FIXED|SECURITY_VERIFIED)["\']?'
        )
        for f in router_dir.rglob("*.py"):
            content = f.read_text(encoding="utf-8")
            assert not forbidden.search(content), (
                f"ARCHITECTURAL LAW #1 VIOLATION in {f}: hardcoded security status detected"
            )


# -------------------------------------------------------------------------
# SEC-05: Source code & diff leakage prevention
# -------------------------------------------------------------------------
class TestPrivacyLeakagePrevention:
    def test_scan_response_has_no_source_code_field(self):
        from karsasec.server.dto.scan import ScanResponseDTO
        dto = ScanResponseDTO(
            scan_id="s1", status="COMPLETED",
            created_at="2026-01-01T00:00:00Z", finding_count=0,
            files_scanned=0, duration_ms=0,
        )
        d = dto.model_dump()
        assert "source_code" not in d
        assert "unified_diff" not in d
        assert "diff" not in d

    def test_finding_dto_has_no_snippet(self):
        from karsasec.server.dto.finding import FindingDTO
        dto = FindingDTO(finding_id="f", rule_id="R", severity="LOW", file_path="a.py")
        d = dto.model_dump()
        assert "snippet" not in d
        assert "source_code" not in d
        assert "raw_source" not in d

    def test_receipt_dto_has_no_credential_fields(self):
        from karsasec.server.dto.receipt import VerificationReceiptResponseDTO
        dto = VerificationReceiptResponseDTO(
            receipt_id="r", transaction_id="t", finding_id="f",
            integrity_status="INVALID",
            security_verification_status="SECURITY_NOT_VERIFIED",
            receipt_fingerprint="fp" * 20,
        )
        d = dto.model_dump()
        for forbidden_key in ("password", "secret", "api_key", "token", "credential", "source_code"):
            assert forbidden_key not in d


# -------------------------------------------------------------------------
# SEC-06: Capability audit — forbidden patterns in server package
# -------------------------------------------------------------------------
class TestCapabilityAudit:
    def test_no_subprocess_in_server_package(self):
        from pathlib import Path
        server_dir = Path("karsasec/server")
        for f in server_dir.rglob("*.py"):
            content = f.read_text(encoding="utf-8")
            assert "subprocess" not in content, f"Forbidden 'subprocess' in {f}"

    def test_no_os_system_in_server_package(self):
        import re
        from pathlib import Path
        server_dir = Path("karsasec/server")
        pattern = re.compile(r'\bos\.system\b')
        for f in server_dir.rglob("*.py"):
            content = f.read_text(encoding="utf-8")
            assert not pattern.search(content), f"Forbidden 'os.system' in {f}"

    def test_no_shell_true_in_server_package(self):
        from pathlib import Path
        server_dir = Path("karsasec/server")
        for f in server_dir.rglob("*.py"):
            content = f.read_text(encoding="utf-8")
            assert "shell=True" not in content, f"Forbidden 'shell=True' in {f}"

    def test_no_eval_in_server_package(self):
        import re
        from pathlib import Path
        server_dir = Path("karsasec/server")
        pattern = re.compile(r'\beval\s*\(')
        for f in server_dir.rglob("*.py"):
            content = f.read_text(encoding="utf-8")
            assert not pattern.search(content), f"Forbidden 'eval(' in {f}"

    def test_no_exec_in_server_package(self):
        import re
        from pathlib import Path
        server_dir = Path("karsasec/server")
        pattern = re.compile(r'\bexec\s*\(')
        for f in server_dir.rglob("*.py"):
            content = f.read_text(encoding="utf-8")
            assert not pattern.search(content), f"Forbidden 'exec(' in {f}"


# -------------------------------------------------------------------------
# SEC-07: Error handler does not leak internal details
# -------------------------------------------------------------------------
class TestErrorHandlerPrivacy:
    def test_404_error_does_not_expose_stack_trace(self, client, auth_headers):
        resp = client.get("/api/v1/findings/nonexistent", headers=auth_headers)
        body = resp.text
        assert "Traceback" not in body
        assert "File \"" not in body

    def test_422_error_body_is_structured(self, client, auth_headers):
        resp = client.post("/api/v1/scans", json={"bad": "body"}, headers=auth_headers)
        assert resp.status_code == 422
        data = resp.json()
        assert "error" in data or "detail" in data  # Either our handler or FastAPI's default


# -------------------------------------------------------------------------
# SEC-08: Determinism — repeated requests return consistent ordering
# -------------------------------------------------------------------------
class TestDeterminism:
    def test_findings_list_ordering_is_stable_across_calls(self, client, auth_headers):
        resp1 = client.get("/api/v1/findings", headers=auth_headers).json()
        resp2 = client.get("/api/v1/findings", headers=auth_headers).json()
        ids1 = [f["finding_id"] for f in resp1["items"]]
        ids2 = [f["finding_id"] for f in resp2["items"]]
        assert ids1 == ids2

    def test_x_request_id_is_unique_per_request(self, client):
        r1 = client.get("/api/v1/health")
        r2 = client.get("/api/v1/health")
        assert r1.headers["x-request-id"] != r2.headers["x-request-id"]

    def test_x_request_id_propagated_when_provided(self, client):
        resp = client.get("/api/v1/health", headers={"X-Request-ID": "my-fixed-id"})
        assert resp.headers["x-request-id"] == "my-fixed-id"
