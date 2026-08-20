"""Finding Application Service for KarsaSec REST API.

Pure application service — no HTTP code, no FastAPI dependency, no Request object.
Returns privacy-safe FindingDTO objects with deterministic sorting.
"""

from __future__ import annotations


from karsasec.server.dto.finding import FindingDTO, FindingListResponseDTO
from karsasec.server.dto.common import PaginationMeta

# Severity rank for deterministic ordering (CRITICAL=0 .. INFO=4)
_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.upper(), 99)


def _finding_to_dto(finding: object, scan_id: str = "") -> FindingDTO:
    """Map a domain Finding to a privacy-safe FindingDTO.

    Explicitly excludes: source_code, evidence.snippet, unified_diff,
    remediation instructions containing raw code, credentials.
    """
    severity = str(getattr(finding, "severity", "INFO"))
    if hasattr(severity, "value"):
        severity = severity.value  # type: ignore[union-attr]

    evidence = getattr(finding, "evidence", None)
    line_number = int(getattr(evidence, "line", 0)) if evidence else 0

    return FindingDTO(
        finding_id=str(getattr(finding, "finding_id", "")),
        rule_id=str(getattr(finding, "rule_id", "")),
        severity=str(severity),
        cwe=str(getattr(finding, "cwe_id", "")),
        file_path=str(getattr(finding, "file_path", "")).replace("\\", "/"),
        line_number=line_number,
        message=str(getattr(finding, "title", "")),
        scan_id=scan_id,
        status="OPEN",
    )


class FindingService:
    """Application service for querying SAST findings with deterministic ordering.

    DETERMINISM CONTRACT:
      All collections are sorted by (severity_rank, file_path, line_number, finding_id)
      before being returned, ensuring stable ordering regardless of PYTHONHASHSEED.
    """

    def __init__(self) -> None:
        # Sprint F1: in-memory store keyed by (scan_id, finding_id)
        self._findings: list[FindingDTO] = []

    def ingest_from_scan(self, findings: list[object], scan_id: str) -> None:
        """Ingest findings from a completed scan result."""
        dtos = [_finding_to_dto(f, scan_id) for f in findings]
        self._findings.extend(dtos)

    def _sort_key(self, f: FindingDTO) -> tuple[int, str, int, str]:
        return (
            _severity_rank(f.severity),
            f.file_path,
            f.line_number,
            f.finding_id,
        )

    def list_findings(
        self,
        scan_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> FindingListResponseDTO:
        """Return a deterministically ordered, paginated list of findings."""
        items = self._findings
        if scan_id:
            items = [f for f in items if f.scan_id == scan_id]

        # Deterministic sort: (severity_rank, file_path, line_number, finding_id)
        sorted_items = sorted(items, key=self._sort_key)

        total = len(sorted_items)
        start = (page - 1) * page_size
        end = start + page_size
        page_items = sorted_items[start:end]

        return FindingListResponseDTO(
            items=page_items,
            pagination=PaginationMeta(total=total, page=page, page_size=page_size),
        )

    def get_finding(self, finding_id: str) -> FindingDTO | None:
        """Retrieve a single finding by ID."""
        for f in self._findings:
            if f.finding_id == finding_id:
                return f
        return None
