"""Path Traversal, LFI, RFI & File Access Reasoning Engine for Batch C3."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PathVulnerabilityType(StrEnum):
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    ARBITRARY_FILE_READ = "ARBITRARY_FILE_READ"
    ARBITRARY_FILE_WRITE = "ARBITRARY_FILE_WRITE"
    LOCAL_FILE_INCLUSION = "LOCAL_FILE_INCLUSION"
    REMOTE_FILE_INCLUSION = "REMOTE_FILE_INCLUSION"
    SYMLINK_TRAVERSAL = "SYMLINK_TRAVERSAL"
    ZIP_SLIP_EXTRACTION = "ZIP_SLIP_EXTRACTION"
    TOCTOU_FILE_ACCESS = "TOCTOU_FILE_ACCESS"


@dataclass
class PathAccessNode:
    """Represents a file resource access node evaluated for path traversal and inclusion vulnerabilities."""

    path_input: str
    base_directory: str = "/srv/files"
    http_method: str = "GET"
    is_containment_checked: bool = False
    is_canonicalized: bool = False
    sink_type: str = "FILE_READ"  # FILE_READ, FILE_WRITE, FILE_DELETE, DYNAMIC_INCLUDE
    is_symlink: bool = False
    is_archive_member: bool = False
    language: str = "python"  # python, javascript, php, java, go, ruby, csharp


@dataclass
class PathEvidence:
    """Machine-readable evidence output for Path Traversal & File Access findings."""

    category: PathVulnerabilityType
    source_kind: str
    symbol: str
    sink_kind: str
    base_directory: str
    canonicalization: bool
    containment_check: bool
    trust_boundary_crossed: bool
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "source": {
                "kind": self.source_kind,
                "symbol": self.symbol,
            },
            "transformations": [
                "url_decode",
                "path_join",
            ],
            "sink": {
                "kind": self.sink_kind,
                "symbol": "open",
            },
            "base_directory": self.base_directory,
            "canonicalization": self.canonicalization,
            "containment_check": self.containment_check,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }


class PathTraversalReasoningEngine:
    """Deterministic reasoning engine for Path Traversal, File Inclusion, and File Resource Access vulnerabilities."""

    REMOTE_SCHEMES = ("http://", "https://", "ftp://", "php://", "data://", "file://")

    def evaluate_path_access(self, node: PathAccessNode) -> PathEvidence | None:
        """Evaluates path traversal, LFI, RFI, and archive traversal over file access nodes."""
        input_str = node.path_input.lower()

        # Remote File Inclusion (RFI) & Stream Wrapper Abuse
        if any(input_str.startswith(scheme) for scheme in self.REMOTE_SCHEMES):
            return PathEvidence(
                category=PathVulnerabilityType.REMOTE_FILE_INCLUSION,
                source_kind="HTTP_QUERY",
                symbol=node.path_input,
                sink_kind="DYNAMIC_INCLUDE",
                base_directory=node.base_directory,
                canonicalization=False,
                containment_check=False,
                trust_boundary_crossed=True,
                evidence_path=[f"input={node.path_input}", "remote_scheme_detected=True"],
                resolution="VULNERABLE",
            )

        # Local File Inclusion (LFI)
        if node.sink_type == "DYNAMIC_INCLUDE":
            if not node.is_containment_checked or not node.is_canonicalized:
                return PathEvidence(
                    category=PathVulnerabilityType.LOCAL_FILE_INCLUSION,
                    source_kind="HTTP_QUERY",
                    symbol=node.path_input,
                    sink_kind="DYNAMIC_INCLUDE",
                    base_directory=node.base_directory,
                    canonicalization=node.is_canonicalized,
                    containment_check=node.is_containment_checked,
                    trust_boundary_crossed=True,
                    evidence_path=[f"include_file={node.path_input}", "dynamic_lfi=True"],
                    resolution="VULNERABLE",
                )

        # Archive Traversal / Zip Slip
        if node.is_archive_member and ("../" in input_str or "..\\" in input_str or "%2e%2e" in input_str):
            if not node.is_containment_checked or not node.is_canonicalized:
                return PathEvidence(
                    category=PathVulnerabilityType.ZIP_SLIP_EXTRACTION,
                    source_kind="ARCHIVE_ENTRY",
                    symbol=node.path_input,
                    sink_kind="FILE_WRITE",
                    base_directory=node.base_directory,
                    canonicalization=node.is_canonicalized,
                    containment_check=node.is_containment_checked,
                    trust_boundary_crossed=True,
                    evidence_path=[f"archive_member={node.path_input}", "archive_containment_failed=True"],
                    resolution="VULNERABLE",
                )

        # Symlink Traversal
        if node.is_symlink and not node.is_containment_checked:
            return PathEvidence(
                category=PathVulnerabilityType.SYMLINK_TRAVERSAL,
                source_kind="SYMLINK_TARGET",
                symbol=node.path_input,
                sink_kind="FILE_READ",
                base_directory=node.base_directory,
                canonicalization=False,
                containment_check=False,
                trust_boundary_crossed=True,
                evidence_path=[f"symlink={node.path_input}", "symlink_escape=True"],
                resolution="VULNERABLE",
            )

        # Path Traversal (Direct, Encoded, Double-Decoding, Absolute)
        has_traversal = "../" in input_str or "..\\" in input_str or "%2e%2e" in input_str or input_str.startswith("/")
        if has_traversal:
            if not node.is_containment_checked or not node.is_canonicalized:
                category = PathVulnerabilityType.ARBITRARY_FILE_WRITE if node.sink_type == "FILE_WRITE" else PathVulnerabilityType.PATH_TRAVERSAL
                return PathEvidence(
                    category=category,
                    source_kind="HTTP_QUERY",
                    symbol=node.path_input,
                    sink_kind=node.sink_type,
                    base_directory=node.base_directory,
                    canonicalization=node.is_canonicalized,
                    containment_check=node.is_containment_checked,
                    trust_boundary_crossed=True,
                    evidence_path=[f"path_input={node.path_input}", f"containment_check={node.is_containment_checked}"],
                    resolution="VULNERABLE",
                )

        return None

    def evaluate_toctou_file_access(self, check_call: str, open_call: str, same_path: bool) -> PathEvidence | None:
        """C3.24: Evaluates TOCTOU file access race condition."""
        if same_path and check_call != open_call:
            return PathEvidence(
                category=PathVulnerabilityType.TOCTOU_FILE_ACCESS,
                source_kind="FILE_CHECK",
                symbol=check_call,
                sink_kind="FILE_OPEN",
                base_directory="/srv/files",
                canonicalization=False,
                containment_check=False,
                trust_boundary_crossed=True,
                evidence_path=[f"check={check_call}", f"open={open_call}", "race_gap=True"],
                resolution="VULNERABLE",
            )
        return None
