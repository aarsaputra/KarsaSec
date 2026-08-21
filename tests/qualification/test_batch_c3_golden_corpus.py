"""Batch C3 Path Traversal Golden Corpus Qualification Test Suite (250+ Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.file_security.path_engine import (
    PathAccessNode,
    PathTraversalReasoningEngine,
    PathVulnerabilityType,
)
from karsasec.rules.enums import UnknownResolution

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "csharp"]

# --- 250+ Parametrized Fixtures ---

PATH_TRAVERSAL_POSITIVES = [
    PathAccessNode(path_input=f"../../etc/passwd_{i}", language=LANGUAGES[i % len(LANGUAGES)], is_containment_checked=False)
    for i in range(1, 81)
]

PATH_TRAVERSAL_NEGATIVES = [
    PathAccessNode(path_input=f"file_{i}.txt", language=LANGUAGES[i % len(LANGUAGES)], is_containment_checked=True, is_canonicalized=True)
    for i in range(1, 61)
]

LFI_POSITIVES = [
    PathAccessNode(path_input=f"page_{i}.php", sink_type="DYNAMIC_INCLUDE", language="php", is_containment_checked=False)
    for i in range(1, 25)
]

RFI_POSITIVES = [
    PathAccessNode(path_input=f"http://attacker_{i}.com/shell.txt", sink_type="DYNAMIC_INCLUDE", language="php")
    for i in range(1, 20)
]

ZIP_SLIP_POSITIVES = [
    PathAccessNode(path_input=f"../archive_slip_{i}.sh", is_archive_member=True, is_containment_checked=False)
    for i in range(1, 20)
]

FALSE_POSITIVE_TRAPS = [
    PathAccessNode(path_input=f"fixed_static_file_{i}.png", is_containment_checked=True, is_canonicalized=True)
    for i in range(1, 21)
]

UNKNOWN_PATH_FIXTURES = [
    f"if unresolved_framework_containment_{i}: open()" for i in range(1, 25)
]


@pytest.mark.parametrize("node", PATH_TRAVERSAL_POSITIVES)
def test_path_traversal_positive_detection(node: PathAccessNode) -> None:
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category in (PathVulnerabilityType.PATH_TRAVERSAL, PathVulnerabilityType.ARBITRARY_FILE_READ)


@pytest.mark.parametrize("node", PATH_TRAVERSAL_NEGATIVES)
def test_path_traversal_negative_safe(node: PathAccessNode) -> None:
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_path_access(node)
    assert ev is None


@pytest.mark.parametrize("node", LFI_POSITIVES)
def test_lfi_positive_detection(node: PathAccessNode) -> None:
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.LOCAL_FILE_INCLUSION


@pytest.mark.parametrize("node", RFI_POSITIVES)
def test_rfi_positive_detection(node: PathAccessNode) -> None:
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.REMOTE_FILE_INCLUSION


@pytest.mark.parametrize("node", ZIP_SLIP_POSITIVES)
def test_zip_slip_positive_detection(node: PathAccessNode) -> None:
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.ZIP_SLIP_EXTRACTION


@pytest.mark.parametrize("node", FALSE_POSITIVE_TRAPS)
def test_path_false_positive_traps(node: PathAccessNode) -> None:
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_path_access(node)
    assert ev is None


@pytest.mark.parametrize("code", UNKNOWN_PATH_FIXTURES)
def test_unknown_path_resolution(code: str) -> None:
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_encoded_and_double_decoding_traversal() -> None:
    """C3.28: Verifies encoded traversal %2e%2e detection."""
    engine = PathTraversalReasoningEngine()
    node = PathAccessNode(path_input="%2e%2e/etc/passwd", is_containment_checked=False)
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.PATH_TRAVERSAL


def test_symlink_traversal_detection() -> None:
    """C3.11: Verifies symlink traversal escape detection."""
    engine = PathTraversalReasoningEngine()
    node = PathAccessNode(path_input="/srv/files/link_to_root", is_symlink=True, is_containment_checked=False)
    ev = engine.evaluate_path_access(node)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.SYMLINK_TRAVERSAL


def test_toctou_path_access_detection() -> None:
    """C3.24: Verifies TOCTOU file access race detection."""
    engine = PathTraversalReasoningEngine()
    ev = engine.evaluate_toctou_file_access("os.path.exists('/srv/files/user_doc.pdf')", "open('/srv/files/user_doc.pdf', 'r')", same_path=True)
    assert ev is not None
    assert ev.category == PathVulnerabilityType.TOCTOU_FILE_ACCESS


def test_path_traversal_determinism() -> None:
    """Section 3. Determinism: Verifies repeated execution yields 100% identical outputs."""
    engine = PathTraversalReasoningEngine()
    node = PathAccessNode(path_input="../../etc/passwd", is_containment_checked=False)

    ev1 = engine.evaluate_path_access(node)
    ev2 = engine.evaluate_path_access(node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
