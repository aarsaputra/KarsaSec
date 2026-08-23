"""Unit tests verifying Baseline Freeze Integrity (INV-G5.4-01)."""

from karsasec.benchmark.baseline_freeze import (
    create_baseline_manifest,
    verify_baseline_integrity,
)


def test_baseline_integrity_pass_on_unmodified() -> None:
    manifest = create_baseline_manifest()
    res = verify_baseline_integrity(manifest)
    assert res["status"] == "PASS"
    assert res["is_valid"] is True
    assert len(res["modified_files"]) == 0
    assert len(res["missing_files"]) == 0
    assert len(res["added_files"]) == 0


def test_baseline_integrity_fail_on_modified_file() -> None:
    manifest = create_baseline_manifest()
    # Tamper with manifest file hash
    manifest["file_hashes"]["karsasec/analysis/taint/sources.py"] = "bad_tampered_hash_12345"
    res = verify_baseline_integrity(manifest)
    assert res["status"] == "FAIL"
    assert res["is_valid"] is False
    assert "karsasec/analysis/taint/sources.py" in res["modified_files"]


def test_baseline_integrity_fail_on_missing_file() -> None:
    manifest = create_baseline_manifest()
    manifest["file_hashes"]["karsasec/analysis/non_existent_file.py"] = "hash_xyz"
    res = verify_baseline_integrity(manifest)
    assert res["status"] == "FAIL"
    assert "karsasec/analysis/non_existent_file.py" in res["missing_files"]
