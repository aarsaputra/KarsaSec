"""K1.6 Release Boundary Enforcement Test Suite (Task K1.6-LOCK).

Verifies invariants INV-K1.6-L01 through INV-K1.6-L07 across 15 adversarial release-boundary attack scenarios (R01-R15).
Operates on isolated temporary directory mirrors to ensure live baseline immutability.
"""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

from karsasec.benchmark.k1_certification_integrity import (
    CertificationGateState,
    CertificationIntegrityStatus,
    CertificationReleaseGuard,
    require_certification_integrity,
    sha256_file,
)
from karsasec.benchmark.k1_differential import ValidationGate, ValidationState


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


def test_r01_valid_certification_returns_ready(tmp_path: Path) -> None:
    """R01 — Valid certification returns READY."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.READY
    assert res.integrity_status == CertificationIntegrityStatus.VALID
    assert res.is_ready()


def test_r02_baseline_findings_modified_returns_blocked_drifted(tmp_path: Path) -> None:
    """R02 — Baseline findings modified returns BLOCKED / DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    f_path = root / "benchmarks/k1/baseline/k1_4_findings.json"
    f_path.write_bytes(f_path.read_bytes() + b"\n# drift")

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.DRIFTED


def test_r03_baseline_provenance_modified_returns_blocked_drifted(tmp_path: Path) -> None:
    """R03 — Baseline provenance modified returns BLOCKED / DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    p_path = root / "benchmarks/k1/baseline/k1_4_provenance.json"
    p_path.write_bytes(p_path.read_bytes() + b" ")

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.DRIFTED


def test_r04_certification_manifest_modified_returns_blocked_invalid(tmp_path: Path) -> None:
    """R04 — Certification manifest modified without updating detached SHA returns BLOCKED / INVALID."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.write_bytes(tmp_m.read_bytes() + b"\n")

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.INVALID


def test_r05_certification_manifest_deleted_returns_blocked_missing(tmp_path: Path) -> None:
    """R05 — Certification manifest deleted returns BLOCKED / MISSING."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.unlink()

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.MISSING


def test_r06_detached_sha256_modified_returns_blocked_invalid(tmp_path: Path) -> None:
    """R06 — Detached SHA256 record modified returns BLOCKED / INVALID."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_s.write_text("0" * 64 + "  k1_6_certification_manifest.json\n", encoding="utf-8")

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.INVALID


def test_r07_trust_anchor_modified_returns_blocked(tmp_path: Path) -> None:
    """R07 — Trust anchor modified in manifest returns BLOCKED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    m_data = json.loads(tmp_m.read_text(encoding="utf-8"))
    m_data["trust_anchors"]["k1_4_provenance_sha256"] = "bad_anchor"
    tmp_m.write_text(json.dumps(m_data), encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.INVALID


def test_r08_production_detector_modified_returns_blocked_drifted(tmp_path: Path) -> None:
    """R08 — Production detector modified returns BLOCKED / DRIFTED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)

    with patch("karsasec.benchmark.k1_certification_integrity.check_git_diff", return_value=False):
        res = require_certification_integrity(tmp_m, tmp_s, root, check_git=True)
        assert res.state == CertificationGateState.BLOCKED
        assert res.integrity_status == CertificationIntegrityStatus.DRIFTED


def test_r09_corpus_manifest_modified_returns_blocked_missing(tmp_path: Path) -> None:
    """R09 — Corpus manifest missing returns BLOCKED / MISSING."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    (root / "benchmarks/k1/manifest.json").unlink()

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.MISSING


def test_r10_integrity_verifier_exception_returns_blocked(tmp_path: Path) -> None:
    """R10 — Integrity verifier exception handling returns BLOCKED / INVALID."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)

    with patch("karsasec.benchmark.k1_certification_integrity.verify_certification_integrity", side_effect=RuntimeError("unexpected verifier error")):
        guard = CertificationReleaseGuard()
        res = guard.require_integrity(tmp_m, tmp_s, root, check_git=False)
        assert res.state == CertificationGateState.BLOCKED
        assert res.integrity_status == CertificationIntegrityStatus.INVALID
        assert "Integrity verifier exception" in res.reason


def test_r11_integrity_result_unavailable_returns_blocked() -> None:
    """R11 — Integrity result unavailable (missing manifest path) returns BLOCKED."""
    res = require_certification_integrity("non_existent_manifest.json", "non_existent.sha256", ".")
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.MISSING


def test_r12_attempted_bypass_triggers_gate_blocked(tmp_path: Path) -> None:
    """R12 — ValidationGate precondition failure blocks gate execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.unlink()

    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is False
    assert gate.is_blocked()
    assert gate.state == ValidationState.BLOCKED


def test_r13_repeated_verification_returns_identical_result(tmp_path: Path) -> None:
    """R13 — Repeated verification produces identical result."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    res1 = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    res2 = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res1.state == res2.state
    assert res1.integrity_status == res2.integrity_status


def test_r14_invalid_attempted_recovery_remains_blocked(tmp_path: Path) -> None:
    """R14 — Monotonic guard ensures once BLOCKED, execution context remains BLOCKED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    guard = CertificationReleaseGuard()

    # 1. Trigger BLOCKED
    tmp_m.unlink()
    res1 = guard.require_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res1.state == CertificationGateState.BLOCKED

    # 2. Attempt recovery by restoring file
    real_m = Path("docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json")
    shutil.copy(real_m, tmp_m)

    res2 = guard.require_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res2.state == CertificationGateState.BLOCKED
    assert "remains BLOCKED" in res2.reason


def test_r15_valid_repository_repeated_100_times(tmp_path: Path) -> None:
    """R15 — Valid repository repeated 100 times returns 100 identical READY results."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    for _ in range(100):
        res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
        assert res.state == CertificationGateState.READY
        assert res.integrity_status == CertificationIntegrityStatus.VALID
