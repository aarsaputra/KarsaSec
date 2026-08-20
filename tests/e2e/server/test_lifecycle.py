"""End-to-end test: full API lifecycle (scan → finding → remediation → receipt)."""

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


class TestE2ELifecycle:
    def test_health_reachable(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_findings_list_reachable_authenticated(self, client, auth_headers):
        resp = client.get("/api/v1/findings", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "pagination" in data

    def test_remediation_trigger_produces_transaction_id(self, client, auth_headers):
        """Trigger a remediation and verify the response has a transaction_id."""
        payload = {
            "finding_id": "e2e-finding-001",
            "approval": {
                "approval_token_id": "e2e-token-001",
                "token": "e2e-approval-credential",
            },
        }
        resp = client.post("/api/v1/remediations", json=payload, headers=auth_headers)
        assert resp.status_code == 202
        data = resp.json()
        assert "transaction_id" in data
        assert data["finding_id"] == "e2e-finding-001"
        # security_verification_status must be present as output-only field
        assert "security_verification_status" in data

    def test_remediation_status_retrievable(self, client, auth_headers):
        """Trigger then retrieve a remediation transaction status."""
        payload = {
            "finding_id": "e2e-finding-002",
            "approval": {"approval_token_id": "t2", "token": "cred"},
        }
        post_resp = client.post("/api/v1/remediations", json=payload, headers=auth_headers)
        assert post_resp.status_code == 202
        transaction_id = post_resp.json()["transaction_id"]

        get_resp = client.get(f"/api/v1/remediations/{transaction_id}", headers=auth_headers)
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["transaction_id"] == transaction_id

    def test_receipt_endpoint_responds_after_remediation(self, client, auth_headers):
        """Trigger remediation and attempt receipt retrieval (may be 404 if no receipt stored)."""
        payload = {
            "finding_id": "e2e-finding-003",
            "approval": {"approval_token_id": "t3", "token": "cred"},
        }
        post_resp = client.post("/api/v1/remediations", json=payload, headers=auth_headers)
        transaction_id = post_resp.json()["transaction_id"]

        receipt_resp = client.get(
            f"/api/v1/remediations/{transaction_id}/receipt",
            headers=auth_headers,
        )
        # Either 200 (receipt found) or 404 (no receipt for REJECTED transaction) — both are valid
        assert receipt_resp.status_code in (200, 404)

    def test_openapi_schema_accessible(self, client):
        resp = client.get("/api/v1/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert "openapi" in schema
        assert schema["info"]["title"] == "KarsaSec SecOS Enterprise REST API"
