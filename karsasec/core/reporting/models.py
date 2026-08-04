"""ReportMetadata model carrying schema_version = 1.0 and scanner telemetry."""

from dataclasses import dataclass

@dataclass(frozen=True)
class ReportMetadata:
    """Immutable metadata descriptor attached to generated security report artifacts."""
    schema_version: str = "1.0"
    scanner_name: str = "KarsaSec"
    scanner_version: str = "0.1.0"
    scan_id: str = ""
    timestamp: str = ""
    duration_ms: float = 0.0
    files_scanned: int = 0
    rules_checked: int = 0
