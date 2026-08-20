"""Scan Application Service for KarsaSec REST API.

Pure application service — no HTTP code, no FastAPI dependency, no Request object.
Delegates to the core scan pipeline.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path

from karsasec.server.dto.scan import ScanRequest, ScanResponseDTO


@dataclass
class ScanRecord:
    """In-memory scan record for F1 (Sprint F2 will persist to DB)."""

    scan_id: str
    status: str
    created_at: str
    finding_count: int
    files_scanned: int
    duration_ms: float
    target_identity: str


class ScanService:
    """Application service for executing and querying SAST scans.

    Invariant: This service has zero knowledge of HTTP or FastAPI.
    It delegates scan execution to the core engine and returns
    plain Python data structures.
    """

    def __init__(self) -> None:
        # Sprint F1: in-memory store. Sprint F2 migrates to persistent store.
        self._records: dict[str, ScanRecord] = {}

    def execute_scan(self, request: ScanRequest) -> ScanResponseDTO:
        """Execute a SAST scan against the specified target and return a result DTO."""
        from karsasec.cli.commands.scan import _run_scan_pipeline

        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(UTC).isoformat()
        target_path = Path(request.target.identity)
        start = time.perf_counter()

        try:
            result = _run_scan_pipeline(
                target_path=target_path,
                config_file=None,
                rules_dir=None,
                diff_scan=False,
            )
            duration_ms = (time.perf_counter() - start) * 1000.0
            findings = result.findings if result else []
            finding_count = len(findings)
            files_scanned = getattr(result, "files_scanned", 0)
            status = "COMPLETED"
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000.0
            finding_count = 0
            files_scanned = 0
            status = "FAILED"

        record = ScanRecord(
            scan_id=scan_id,
            status=status,
            created_at=created_at,
            finding_count=finding_count,
            files_scanned=files_scanned,
            duration_ms=duration_ms,
            target_identity=request.target.identity,
        )
        self._records[scan_id] = record

        return ScanResponseDTO(
            scan_id=scan_id,
            status=status,
            created_at=created_at,
            finding_count=finding_count,
            files_scanned=files_scanned,
            duration_ms=duration_ms,
        )

    def get_scan(self, scan_id: str) -> ScanResponseDTO | None:
        """Retrieve a previously executed scan result by ID."""
        record = self._records.get(scan_id)
        if not record:
            return None
        return ScanResponseDTO(
            scan_id=record.scan_id,
            status=record.status,
            created_at=record.created_at,
            finding_count=record.finding_count,
            files_scanned=record.files_scanned,
            duration_ms=record.duration_ms,
        )
