"""K1.7 Certification Boundary Coverage & Consumer Audit Test Suite (Task K1.7-CBC).

Verifies invariants INV-K1.7-01 through INV-K1.7-08 across 12 adversarial bypass attack scenarios (B01-B12).
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


def test_b01_direct_consumer_invocation_with_precondition_check(tmp_path: Path) -> None:
    """B01 — Direct consumer invocation with valid integrity returns READY and gate PASS."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is True
    assert not gate.is_blocked()
    assert gate.state == ValidationState.RUNNING


def test_b02_baseline_mutation_blocks_consumer(tmp_path: Path) -> None:
    """B02 — Mutating baseline findings blocks consumer execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    f_path = root / "benchmarks/k1/baseline/k1_4_findings.json"
    f_path.write_bytes(f_path.read_bytes() + b"\n# bypass attempt")

    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is False
    assert gate.is_blocked()
    assert "DRIFTED" in gate.failure_reason


def test_b03_manifest_mutation_blocks_consumer(tmp_path: Path) -> None:
    """B03 — Mutating certification manifest blocks consumer execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.write_bytes(tmp_m.read_bytes() + b"\n")

    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is False
    assert gate.is_blocked()
    assert "INVALID" in gate.failure_reason


def test_b04_production_detector_mutation_blocks_consumer(tmp_path: Path) -> None:
    """B04 — Simulating production detector mutation blocks consumer execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)

    with patch("karsasec.benchmark.k1_certification_integrity.check_git_diff", return_value=False):
        gate = ValidationGate()
        ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=True)
        assert ok is False
        assert gate.is_blocked()
        assert "DRIFTED" in gate.failure_reason


def test_b05_trust_anchor_mutation_blocks_consumer(tmp_path: Path) -> None:
    """B05 — Mutating trust anchor in manifest blocks consumer execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    m_data = json.loads(tmp_m.read_text(encoding="utf-8"))
    m_data["trust_anchors"]["k1_4_provenance_sha256"] = "corrupted_anchor"
    tmp_m.write_text(json.dumps(m_data), encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is False
    assert gate.is_blocked()
    assert "INVALID" in gate.failure_reason


def test_b06_missing_certification_manifest_blocks_consumer(tmp_path: Path) -> None:
    """B06 — Missing certification manifest blocks consumer execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.unlink()

    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is False
    assert gate.is_blocked()
    assert "MISSING" in gate.failure_reason


def test_b07_invalid_certification_state_blocks_consumer(tmp_path: Path) -> None:
    """B07 — Invalid certification state status in manifest blocks consumer execution."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    m_data = json.loads(tmp_m.read_text(encoding="utf-8"))
    m_data["status"] = "UNCERTIFIED_DRAFT"
    tmp_m.write_text(json.dumps(m_data), encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    gate = ValidationGate()
    ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
    assert ok is False
    assert gate.is_blocked()
    assert "INVALID" in gate.failure_reason


def test_b08_exception_during_integrity_verification_blocks_consumer(tmp_path: Path) -> None:
    """B08 — Exception raised during integrity verification fails closed to BLOCKED."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)

    with patch("karsasec.benchmark.k1_certification_integrity.verify_certification_integrity", side_effect=RuntimeError("simulated verifier crash")):
        gate = ValidationGate()
        ok = gate.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)
        assert ok is False
        assert gate.is_blocked()
        assert "INVALID" in gate.failure_reason


def test_b09_direct_function_bypass_prevented(tmp_path: Path) -> None:
    """B09 — Direct helper call require_certification_integrity returns BLOCKED on corrupted detached SHA."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_s.write_text("bad_sha256  k1_6_certification_manifest.json\n", encoding="utf-8")

    res = require_certification_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.INVALID


def test_b10_alternate_entry_point_guarded(tmp_path: Path) -> None:
    """B10 — Alternate guard instance blocks invalid manifest."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    tmp_m.write_text("{bad_json", encoding="utf-8")
    tmp_s.write_text(f"{sha256_file(tmp_m)}  k1_6_certification_manifest.json\n", encoding="utf-8")

    guard = CertificationReleaseGuard()
    res = guard.require_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res.state == CertificationGateState.BLOCKED
    assert res.integrity_status == CertificationIntegrityStatus.INVALID


def test_b11_repeated_invocation_deterministic(tmp_path: Path) -> None:
    """B11 — Repeated invocation across consumer gate is 100% deterministic."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    gate1 = ValidationGate()
    ok1 = gate1.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)

    gate2 = ValidationGate()
    ok2 = gate2.verify_certification_precondition(tmp_m, tmp_s, root, check_git=False)

    assert ok1 is True and ok2 is True
    assert not gate1.is_blocked() and not gate2.is_blocked()


def test_b12_invalid_recovery_attempt_remains_blocked(tmp_path: Path) -> None:
    """B12 — Attempting recovery after invalid state remains BLOCKED due to monotonicity."""
    tmp_m, tmp_s, root = setup_temp_repo(tmp_path)
    guard = CertificationReleaseGuard()

    # 1. Mutate manifest -> BLOCKED
    tmp_m.write_bytes(tmp_m.read_bytes() + b"\n")
    res1 = guard.require_integrity(tmp_m, tmp_s, root, check_git=False)
    assert res1.state == CertificationGateState.BLOCKED

    # 2. Re-copy real manifest
    shutil.copy(Path("docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json"), tmp_m)
    res2 = guard.require_integrity(tmp_m, tmp_s, root, check_git=False)

    assert res2.state == CertificationGateState.BLOCKED
    assert "remains BLOCKED" in res2.reason
