"""Integration tests for KarsaSec REST API v1 endpoints.

Uses FastAPI TestClient (httpx-based, synchronous) to exercise the full
request/response cycle through middleware, auth, and router layers.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from karsasec.server.app import create_app
from karsasec.server.config import ServerSettings

_VALID_KEY = "karsasec-dev-secret-key-change-in-production-32bytes"


@pytest.fixture(scope="module")
def client():
    settings = ServerSettings(auth_secret_key=_VALID_KEY)
    app = create_app(settings=settings)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers():
    return {"X-API-Key": _VALID_KEY}


# -------------------------------------------------------------------------
# Health
# -------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_health_response_body(self, client):
        data = client.get("/api/v1/health").json()
        assert data["status"] == "healthy"
        assert data["service"] == "karsasec"
        assert data["api_version"] == "v1"

    def test_health_does_not_expose_env_details(self, client):
        data = client.get("/api/v1/health").json()
        assert "database" not in str(data).lower()
        assert "password" not in str(data).lower()
        assert "secret" not in str(data).lower()

    def test_health_contains_x_request_id(self, client):
        resp = client.get("/api/v1/health")
        assert "x-request-id" in resp.headers

    def test_health_contains_security_headers(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"


# -------------------------------------------------------------------------
# Scans
# -------------------------------------------------------------------------
class TestScansEndpoint:
    def test_scan_create_requires_auth(self, client):
        resp = client.post("/api/v1/scans", json={"target": {"identity": "/some/path"}})
        assert resp.status_code == 401

    def test_scan_get_requires_auth(self, client):
        resp = client.get("/api/v1/scans/scan-999")
        assert resp.status_code == 401

    def test_scan_get_nonexistent_returns_404(self, client, auth_headers):
        resp = client.get("/api/v1/scans/no-such-scan", headers=auth_headers)
        assert resp.status_code == 404

    def test_scan_invalid_body_returns_422(self, client, auth_headers):
        resp = client.post("/api/v1/scans", json={"bad": "payload"}, headers=auth_headers)
        assert resp.status_code == 422


# -------------------------------------------------------------------------
# Findings
# -------------------------------------------------------------------------
class TestFindingsEndpoint:
    def test_findings_list_requires_auth(self, client):
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 401

    def test_findings_list_returns_200_with_auth(self, client, auth_headers):
        resp = client.get("/api/v1/findings", headers=auth_headers)
        assert resp.status_code == 200

    def test_findings_list_response_shape(self, client, auth_headers):
        data = client.get("/api/v1/findings", headers=auth_headers).json()
        assert "items" in data
        assert "pagination" in data
        assert isinstance(data["items"], list)

    def test_findings_list_pagination_meta(self, client, auth_headers):
        data = client.get("/api/v1/findings?page=1&page_size=10", headers=auth_headers).json()
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["page_size"] == 10

    def test_finding_get_nonexistent_returns_404(self, client, auth_headers):
        resp = client.get("/api/v1/findings/no-such-finding", headers=auth_headers)
        assert resp.status_code == 404


# -------------------------------------------------------------------------
# Remediations
# -------------------------------------------------------------------------
class TestRemediationsEndpoint:
    def test_remediation_trigger_requires_auth(self, client):
        resp = client.post(
            "/api/v1/remediations", json={"finding_id": "f1", "approval": {"approval_token_id": "t1", "token": "tok"}}
        )
        assert resp.status_code == 401

    def test_remediation_get_requires_auth(self, client):
        resp = client.get("/api/v1/remediations/rem-001")
        assert resp.status_code == 401

    def test_remediation_get_nonexistent_returns_404(self, client, auth_headers):
        resp = client.get("/api/v1/remediations/no-such-rem", headers=auth_headers)
        assert resp.status_code == 404

    def test_remediation_invalid_body_returns_422(self, client, auth_headers):
        resp = client.post("/api/v1/remediations", json={"bad": "body"}, headers=auth_headers)
        assert resp.status_code == 422


# -------------------------------------------------------------------------
# Receipts
# -------------------------------------------------------------------------
class TestReceiptsEndpoint:
    def test_receipt_requires_auth(self, client):
        resp = client.get("/api/v1/remediations/rem-001/receipt")
        assert resp.status_code == 401

    def test_receipt_nonexistent_transaction_returns_404(self, client, auth_headers):
        resp = client.get("/api/v1/remediations/no-such/receipt", headers=auth_headers)
        assert resp.status_code == 404
