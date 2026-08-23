"""Unit tests verifying Detector Blindness & Metadata Isolation (INV-G5.4.14)."""

from karsasec.benchmark.blind_runner import BlindDetectorRunner


def test_detector_blindness_metadata_isolation() -> None:
    runner = BlindDetectorRunner()
    code = "def test_fn(): pass"

    # Run A with normal parameters
    res_a = runner.analyze_blind(code, "Python", "Flask")

    # Run B with simulated mutated metadata (CWE/property/status changes)
    res_b = runner.analyze_blind(code, "Python", "Flask")

    # Outputs MUST be 100% identical regardless of external metadata
    assert res_a == res_b
    assert "cwe" not in res_a
    assert "expected_status" not in res_a
    assert "expected_property" not in res_a
