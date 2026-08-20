"""FastAPI Dependency Injection providers for KarsaSec REST API.

These functions are the only bridge between FastAPI's DI system and
the pure application service layer.  All services are singletons
scoped to the application lifespan.
"""

from __future__ import annotations

from fastapi import Request

from karsasec.server.security.authentication import HeaderAuthenticationProvider
from karsasec.server.security.models import Principal

# ---------------------------------------------------------------------------
# Singleton service instances (replaced by proper DI container in Sprint F4)
# ---------------------------------------------------------------------------
from karsasec.server.services.scan_service import ScanService
from karsasec.server.services.finding_service import FindingService
from karsasec.server.services.remediation_service import RemediationService
from karsasec.server.services.receipt_service import ReceiptService

_scan_service = ScanService()
_finding_service = FindingService()
_remediation_service = RemediationService()
_receipt_service = ReceiptService(_remediation_service)

_auth_provider = HeaderAuthenticationProvider()


def get_current_principal(request: Request) -> Principal:
    """Resolve the authenticated Principal from the current request.

    Raises HTTP 401 when credentials are absent or invalid.
    Raw credentials are NEVER logged.
    """
    return _auth_provider.authenticate(request)


def get_scan_service() -> ScanService:
    """Return the application-scoped ScanService singleton."""
    return _scan_service


def get_finding_service() -> FindingService:
    """Return the application-scoped FindingService singleton."""
    return _finding_service


def get_remediation_service() -> RemediationService:
    """Return the application-scoped RemediationService singleton."""
    return _remediation_service


def get_receipt_service() -> ReceiptService:
    """Return the application-scoped ReceiptService singleton."""
    return _receipt_service
