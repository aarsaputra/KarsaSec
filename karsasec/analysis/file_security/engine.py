"""File Upload Security Reasoning Engine for Batch C2."""

from __future__ import annotations

from karsasec.analysis.file_security.models import (
    FileUploadEvidence,
    FileUploadVulnerabilityType,
    UploadedFileNode,
)


class FileUploadReasoningEngine:
    """Deterministic reasoning engine for file upload security vulnerabilities."""

    DANGEROUS_EXTENSIONS = {".php", ".phtml", ".php3", ".php4", ".php5", ".exe", ".jsp", ".asp", ".aspx", ".pl", ".cgi", ".sh"}

    def evaluate_file_upload(self, file_node: UploadedFileNode) -> FileUploadEvidence | None:
        """Evaluates file upload security over filename, extension, path, and storage target."""

        # Archive Traversal / Zip Slip
        if file_node.is_archive_entry and ("../" in file_node.filename or "..\\" in file_node.filename):
            if not file_node.is_canonicalized or not file_node.is_containment_checked:
                return FileUploadEvidence(
                    category=FileUploadVulnerabilityType.ZIP_SLIP_TRAVERSAL,
                    source_kind="UNTRUSTED_ARCHIVE_ENTRY",
                    source_location=f"archive.entry['{file_node.filename}']",
                    sink_kind="FILESYSTEM_EXTRACTION",
                    sink_location="archive.extract()",
                    storage_target=file_node.storage_path,
                    canonicalization=file_node.is_canonicalized,
                    containment_check=file_node.is_containment_checked,
                    authorization=True,
                    evidence_path=[f"archive_entry={file_node.filename}", "containment_check=False"],
                    resolution="VULNERABLE",
                )

        # Path Traversal via Filename
        if "../" in file_node.filename or "..\\" in file_node.filename or file_node.filename.startswith("/"):
            if not file_node.is_canonicalized or not file_node.is_containment_checked:
                return FileUploadEvidence(
                    category=FileUploadVulnerabilityType.PATH_TRAVERSAL_UPLOAD,
                    source_kind="UPLOADED_FILENAME",
                    source_location=f"request.files['file'].filename = '{file_node.filename}'",
                    sink_kind="FILESYSTEM_WRITE",
                    sink_location=f"open('{file_node.storage_path}', 'wb')",
                    storage_target=file_node.storage_path,
                    canonicalization=file_node.is_canonicalized,
                    containment_check=file_node.is_containment_checked,
                    authorization=True,
                    evidence_path=[f"filename={file_node.filename}", "containment_check=False"],
                    resolution="VULNERABLE",
                )

        # Unrestricted Executable File Upload
        lower_filename = file_node.filename.lower()
        has_dangerous_ext = any(lower_filename.endswith(ext) for ext in self.DANGEROUS_EXTENSIONS)
        # Check double extension e.g. image.jpg.php
        if not has_dangerous_ext and ".php" in lower_filename:
            has_dangerous_ext = True

        if has_dangerous_ext and (file_node.is_executable_directory or file_node.is_web_accessible):
            return FileUploadEvidence(
                category=FileUploadVulnerabilityType.UNRESTRICTED_FILE_UPLOAD,
                source_kind="UPLOADED_FILENAME",
                source_location=f"request.files['file'].filename = '{file_node.filename}'",
                sink_kind="WEB_EXECUTABLE_STORAGE",
                sink_location=file_node.storage_path,
                storage_target=file_node.storage_path,
                canonicalization=file_node.is_canonicalized,
                containment_check=file_node.is_containment_checked,
                authorization=True,
                evidence_path=[f"dangerous_extension={file_node.filename}", f"target_executable={file_node.is_executable_directory}"],
                resolution="VULNERABLE",
            )

        # Predictable Temporary File Creation
        if file_node.is_predictable_temp:
            return FileUploadEvidence(
                category=FileUploadVulnerabilityType.PREDICTABLE_TEMP_FILE,
                source_kind="USER_CONTROLLED_TEMP_PATH",
                source_location=file_node.storage_path,
                sink_kind="TEMP_FILE_CREATE",
                sink_location="open(temp_path, 'w')",
                storage_target=file_node.storage_path,
                canonicalization=False,
                containment_check=False,
                authorization=True,
                evidence_path=[f"temp_path={file_node.storage_path}", "predictable=True"],
                resolution="VULNERABLE",
            )

        return None

    def evaluate_toctou_upload(self, check_location: str, write_location: str, same_resource: bool) -> FileUploadEvidence | None:
        """C2.20: Evaluates Time-of-Check to Time-of-Use upload race condition."""
        if same_resource and check_location != write_location:
            return FileUploadEvidence(
                category=FileUploadVulnerabilityType.FILE_UPLOAD_TOCTOU,
                source_kind="FILESYSTEM_CHECK",
                source_location=check_location,
                sink_kind="FILESYSTEM_MUTATION",
                sink_location=write_location,
                storage_target="MUTABLE_FILESYSTEM",
                canonicalization=False,
                containment_check=False,
                authorization=True,
                evidence_path=[f"check={check_location}", f"write={write_location}", "intervening_gap=True"],
                resolution="VULNERABLE",
            )
        return None
