"""Data models for KarsaSec File Upload Security Reasoning Engine (Batch C2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FileUploadVulnerabilityType(StrEnum):
    UNRESTRICTED_FILE_UPLOAD = "UNRESTRICTED_FILE_UPLOAD"
    PATH_TRAVERSAL_UPLOAD = "PATH_TRAVERSAL_UPLOAD"
    MIME_CONTENT_MISMATCH = "MIME_CONTENT_MISMATCH"
    ZIP_SLIP_TRAVERSAL = "ZIP_SLIP_TRAVERSAL"
    PREDICTABLE_TEMP_FILE = "PREDICTABLE_TEMP_FILE"
    FILE_UPLOAD_TOCTOU = "FILE_UPLOAD_TOCTOU"


@dataclass
class UploadedFileNode:
    """Represents an uploaded file entity with separate filename and content properties."""

    filename: str
    declared_content_type: str | None = None
    magic_bytes: bytes | None = None
    storage_path: str = "/tmp/upload"
    is_web_accessible: bool = False
    is_executable_directory: bool = False
    is_canonicalized: bool = False
    is_containment_checked: bool = False
    permissions_octal: int = 0o644
    is_predictable_temp: bool = False
    is_archive_entry: bool = False


@dataclass
class FileUploadEvidence:
    """Machine-readable evidence output for File Upload findings."""

    category: FileUploadVulnerabilityType
    source_kind: str
    source_location: str
    sink_kind: str
    sink_location: str
    storage_target: str
    canonicalization: bool
    containment_check: bool
    authorization: bool
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "source": {
                "kind": self.source_kind,
                "location": self.source_location,
            },
            "sink": {
                "kind": self.sink_kind,
                "location": self.sink_location,
            },
            "storage_target": self.storage_target,
            "canonicalization": self.canonicalization,
            "containment_check": self.containment_check,
            "authorization": self.authorization,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
