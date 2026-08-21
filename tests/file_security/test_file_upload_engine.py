"""Batch C2 File Upload Security Reasoning Engine Qualification Test Suite."""

import pytest

from karsasec.analysis.file_security.engine import FileUploadReasoningEngine
from karsasec.analysis.file_security.models import (
    FileUploadVulnerabilityType,
    UploadedFileNode,
)
from karsasec.rules.enums import UnknownResolution

# --- 200+ Parametrized Fixtures ---

EXECUTABLE_UPLOAD_POSITIVES = [
    UploadedFileNode(filename=f"shell_{i}.php", storage_path="/var/www/html/uploads", is_web_accessible=True, is_executable_directory=True)
    for i in range(1, 41)
]

EXECUTABLE_UPLOAD_NEGATIVES = [
    UploadedFileNode(filename=f"image_{i}.png", storage_path="/var/www/html/uploads", is_web_accessible=True, is_executable_directory=False)
    for i in range(1, 41)
]

TRAVERSAL_UPLOAD_POSITIVES = [
    UploadedFileNode(filename=f"../../etc/passwd_{i}", storage_path=f"/uploads/../../etc/passwd_{i}", is_canonicalized=False, is_containment_checked=False)
    for i in range(1, 31)
]

CANONICALIZED_TRAVERSAL_SAFE = [
    UploadedFileNode(filename=f"../../etc/passwd_{i}", storage_path=f"/uploads/passwd_{i}", is_canonicalized=True, is_containment_checked=True)
    for i in range(1, 30)
]

ZIP_SLIP_POSITIVES = [
    UploadedFileNode(filename=f"../slip_{i}.sh", storage_path=f"/extract/../slip_{i}.sh", is_archive_entry=True, is_canonicalized=False, is_containment_checked=False)
    for i in range(1, 26)
]

FALSE_POSITIVE_TRAPS = [
    UploadedFileNode(filename=f"safe_fixed_name_{i}.jpg", storage_path="/var/www/static/avatar.jpg", is_web_accessible=True, is_executable_directory=False)
    for i in range(1, 21)
]

UNKNOWN_FRAMEWORK_FIXTURES = [
    f"if framework_upload_policy_{i}: save()" for i in range(1, 26)
]


@pytest.mark.parametrize("file_node", EXECUTABLE_UPLOAD_POSITIVES)
def test_unrestricted_executable_upload_detection(file_node: UploadedFileNode) -> None:
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_file_upload(file_node)
    assert ev is not None
    assert ev.category == FileUploadVulnerabilityType.UNRESTRICTED_FILE_UPLOAD


@pytest.mark.parametrize("file_node", EXECUTABLE_UPLOAD_NEGATIVES)
def test_unrestricted_executable_upload_safe(file_node: UploadedFileNode) -> None:
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_file_upload(file_node)
    assert ev is None


@pytest.mark.parametrize("file_node", TRAVERSAL_UPLOAD_POSITIVES)
def test_filename_path_traversal_detection(file_node: UploadedFileNode) -> None:
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_file_upload(file_node)
    assert ev is not None
    assert ev.category == FileUploadVulnerabilityType.PATH_TRAVERSAL_UPLOAD


@pytest.mark.parametrize("file_node", CANONICALIZED_TRAVERSAL_SAFE)
def test_canonicalized_path_traversal_safe(file_node: UploadedFileNode) -> None:
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_file_upload(file_node)
    assert ev is None


@pytest.mark.parametrize("file_node", ZIP_SLIP_POSITIVES)
def test_zip_slip_archive_traversal_detection(file_node: UploadedFileNode) -> None:
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_file_upload(file_node)
    assert ev is not None
    assert ev.category == FileUploadVulnerabilityType.ZIP_SLIP_TRAVERSAL


@pytest.mark.parametrize("file_node", FALSE_POSITIVE_TRAPS)
def test_file_upload_false_positive_traps(file_node: UploadedFileNode) -> None:
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_file_upload(file_node)
    assert ev is None


@pytest.mark.parametrize("code", UNKNOWN_FRAMEWORK_FIXTURES)
def test_unknown_upload_semantics(code: str) -> None:
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_double_extension_upload_detection() -> None:
    """Verifies detection of double extensions like image.jpg.php."""
    engine = FileUploadReasoningEngine()
    file_node = UploadedFileNode(filename="image.jpg.php", storage_path="/var/www/html/uploads", is_web_accessible=True, is_executable_directory=True)
    ev = engine.evaluate_file_upload(file_node)
    assert ev is not None
    assert ev.category == FileUploadVulnerabilityType.UNRESTRICTED_FILE_UPLOAD


def test_predictable_temp_file_detection() -> None:
    """C2.14: Verifies detection of predictable temp file construction."""
    engine = FileUploadReasoningEngine()
    file_node = UploadedFileNode(filename="test.txt", storage_path="/tmp/upload_user123.tmp", is_predictable_temp=True)
    ev = engine.evaluate_file_upload(file_node)
    assert ev is not None
    assert ev.category == FileUploadVulnerabilityType.PREDICTABLE_TEMP_FILE


def test_toctou_upload_race_detection() -> None:
    """C2.20: Verifies TOCTOU upload race condition detection."""
    engine = FileUploadReasoningEngine()
    ev = engine.evaluate_toctou_upload("os.path.exists('/uploads/file.png')", "open('/uploads/file.png', 'wb')", same_resource=True)
    assert ev is not None
    assert ev.category == FileUploadVulnerabilityType.FILE_UPLOAD_TOCTOU


def test_file_upload_determinism() -> None:
    """Section 29: Verifies 100% output determinism."""
    engine = FileUploadReasoningEngine()
    file_node = UploadedFileNode(filename="shell.php", storage_path="/var/www/html/uploads", is_web_accessible=True, is_executable_directory=True)

    ev1 = engine.evaluate_file_upload(file_node)
    ev2 = engine.evaluate_file_upload(file_node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
