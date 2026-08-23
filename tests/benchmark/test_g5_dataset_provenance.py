"""Unit tests verifying Dataset Provenance Integrity (INV-G5.3-02)."""

from karsasec.benchmark.canonical import CanonicalCase


def test_canonical_case_provenance_schema() -> None:
    case = CanonicalCase(
        case_id="DVWA_SQLI_001",
        source_code="$id = $_REQUEST['id']; mysqli_query($conn, 'SELECT * FROM users WHERE id = ' . $id);",
        language="PHP",
        framework="DVWA",
        dataset="DVWA",
        dataset_version="1.x",
        source_artifact="vulnerabilities/sqli/source/low.php",
        source_file="vulnerabilities/sqli/source/low.php",
        source_line_start=10,
        source_line_end=15,
        ground_truth_source="manifest.yaml",
        ground_truth_status="VULNERABLE",
        provenance_sha256="sha256_dvwa_sqli_low",
    )

    prov = case.to_provenance_dict()
    assert prov["dataset"] == "DVWA"
    assert prov["dataset_version"] == "1.x"
    assert prov["source_artifact"] == "vulnerabilities/sqli/source/low.php"
    assert prov["ground_truth_source"] == "manifest.yaml"
    assert prov["artifact_sha256"] == "sha256_dvwa_sqli_low"
