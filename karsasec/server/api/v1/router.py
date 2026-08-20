"""Master v1 APIRouter — aggregates all v1 route handlers."""

from __future__ import annotations

from fastapi import APIRouter

from karsasec.server.api.v1.health import router as health_router
from karsasec.server.api.v1.scans import router as scans_router
from karsasec.server.api.v1.findings import router as findings_router
from karsasec.server.api.v1.remediation import router as remediation_router
from karsasec.server.api.v1.receipts import router as receipts_router

v1_router = APIRouter()

v1_router.include_router(health_router)
v1_router.include_router(scans_router)
v1_router.include_router(findings_router)
v1_router.include_router(remediation_router)
v1_router.include_router(receipts_router)
