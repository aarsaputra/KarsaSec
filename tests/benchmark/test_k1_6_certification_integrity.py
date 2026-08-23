"""K1.6 Post-Certification Integrity & Drift Verification Test Suite.

Verifies fail-closed integrity semantics across 10 negative and positive attack scenarios.
Operates on isolated temporary directory mirrors to protect live baseline artifacts.
"""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

from karsasec.benchmark.k1_certification_integrity import (
    CertificationIntegrityStatus,
    sha256_file,
    verify_certification_integrity,
)


def setup_temp_repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Helper to set up a clean, isolated repository clone in tmp_path."""
    real_repo = Path(".")

    # Mirror manifest directory
    manifest_dir = tmp_path / "docs/g5_4_pre_knowledge_assurance"
    manifest_dir.mkdir(parents=True, exist_ok=True)

    real_m = real_repo / "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json"
    real_s = real_repo / "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256"

    tmp_m = manifest_dir / "k1_6_certification_manifest.json"
    tmp_s = manifest_dir / "k1_6_certification_manifest.sha256"

    shutil.copy(real_m, tmp_m)
    shutil.copy(real_s, tmp_s)

    # Mirror baseline directory
    base_dir = tmp_path / "benchmarks/k1/baseline"
    base_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy(real_repo / "benchmarks/k1/baseline/k1_4_findings.json", base_dir / "k1_4_findings.json")
    shutil.copy(real_repo / "benchmarks/k1/baseline/k1_4_provenance.json", base_dir / "k1_4_provenance.json")

    # Mirror corpus directory
    corpus_dir = tmp_path / "benchmarks/k1"
    shutil.copy(real_repo / "benchmarks/k1/manifest.json", corpus_dir / "manifest.json")
    shutil.copy(real_repo / "benchmarks/k1/holdout_manifest.json", corpus_dir / "holdout_manifest.json")

    return tmp_m, tmp_s, tmp_path


def test_01_unchanged_repository_is_valid(tmp_path: Path) -> None:
    """Test 1: Unchanged repository passes integrity check."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.VALID
    assert res.is_valid()


def test_02_baseline_findings_mutation_is_drifted(tmp_path: Path) -> None:
    """Test 2: Mutating one byte in k1_4_findings.json returns DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    f_path = root / "benchmarks/k1/baseline/k1_4_findings.json"
    f_path.write_bytes(f_path.read_bytes() + b"\n# drift mutation")

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.DRIFTED
    assert "Baseline SHA256 drift" in res.reason


def test_03_baseline_provenance_mutation_is_drifted(tmp_path: Path) -> None:
    """Test 3: Mutating k1_4_provenance.json returns DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    p_path = root / "benchmarks/k1/baseline/k1_4_provenance.json"
    p_path.write_bytes(p_path.read_bytes() + b" ")

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.DRIFTED
    assert "Baseline SHA256 drift" in res.reason


def test_04_manifest_mutation_is_invalid(tmp_path: Path) -> None:
    """Test 4: Mutating manifest file without updating detached SHA returns INVALID."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.write_bytes(tmp_m.read_bytes() + b"\n")

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.INVALID
    assert "Detached manifest SHA256 mismatch" in res.reason


def test_05_missing_baseline_artifact_is_missing(tmp_path: Path) -> None:
    """Test 5: Missing baseline artifact returns MISSING."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    f_path = root / "benchmarks/k1/baseline/k1_4_findings.json"
    f_path.unlink()

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.MISSING
    assert "Certified baseline artifact missing" in res.reason


def test_06_invalid_expected_hash_is_drifted(tmp_path: Path) -> None:
    """Test 6: Manifest containing zeroed expected SHA256 returns DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    m_data = json.loads(tmp_m.read_text(encoding="utf-8"))
    m_data["baseline"]["benchmarks/k1/baseline/k1_4_findings.json"] = "0" * 64

    tmp_m.write_text(json.dumps(m_data, indent=2), encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.DRIFTED
    assert "Baseline SHA256 drift" in res.reason


def test_07_simulated_production_detector_diff_is_drifted(tmp_path: Path) -> None:
    """Test 7: Production detector modification simulation returns DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)

    with patch("karsasec.benchmark.k1_certification_integrity.check_git_diff", return_value=False):
        res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=True)
        assert res.status == CertificationIntegrityStatus.DRIFTED
        assert "Production detector modification detected" in res.reason


def test_08_missing_corpus_manifest_is_missing(tmp_path: Path) -> None:
    """Test 8: Missing corpus manifest returns MISSING."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    (root / "benchmarks/k1/manifest.json").unlink()

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.MISSING
    assert "Corpus manifest file missing" in res.reason


def test_09_malformed_manifest_json_is_invalid(tmp_path: Path) -> None:
    """Test 9: Malformed JSON manifest returns INVALID."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.write_text("NOT_VALID_JSON{", encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.INVALID
    assert "Malformed manifest JSON" in res.reason


def test_10_trust_anchor_mismatch_is_invalid(tmp_path: Path) -> None:
    """Test 10: Trust anchor mismatch in manifest returns INVALID."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    m_data = json.loads(tmp_m.read_text(encoding="utf-8"))
    m_data["trust_anchors"]["k1_4_provenance_sha256"] = "1" * 64

    tmp_m.write_text(json.dumps(m_data, indent=2), encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    res = verify_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.status == CertificationIntegrityStatus.INVALID
    assert "Trust anchor digest mismatch" in res.reason
