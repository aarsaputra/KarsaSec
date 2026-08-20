"""Unit tests for BaselineManager, loading, saving, and diff comparison."""

from pathlib import Path

from karsasec.core.baseline import baseline_manager
from karsasec.core.finding import Evidence, Finding
from karsasec.rules.enums import Confidence, Severity


def create_sample_finding(fp: str, rule_id: str = "R1", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_id="f1",
        rule_id=rule_id,
        fingerprint=fp,
        title="Sample Finding",
        severity=severity,
        confidence=Confidence.HIGH,
        cwe_id="CWE-20",
        owasp="A03:2021-Injection",
        file_path=Path("main.py"),
        evidence=Evidence(snippet="test()", line=1, column=1),
        description="Desc",
        remediation="Fix",
    )


def test_baseline_save_and_load(tmp_path: Path) -> None:
    f1 = create_sample_finding("fp1")
    target_file = tmp_path / "baseline.json"

    baseline_manager.save_baseline((f1,), target_file)
    assert target_file.exists()

    loaded = baseline_manager.load_baseline(target_file)
    assert "fp1" in loaded.findings
    assert loaded.findings["fp1"].rule_id == "R1"


def test_baseline_comparison_new_existing_fixed_regressed() -> None:
    f_existing = create_sample_finding("fp1", severity=Severity.MEDIUM)
    f_new = create_sample_finding("fp2", severity=Severity.HIGH)
    f_regressed = create_sample_finding("fp3", severity=Severity.CRITICAL)  # Baseline was LOW

    # Save initial baseline
    f_base_regressed = create_sample_finding("fp3", severity=Severity.LOW)
    f_base_fixed = create_sample_finding("fp4", severity=Severity.HIGH)

    baseline_data = baseline_manager.save_baseline((f_existing, f_base_regressed, f_base_fixed), Path("/tmp/mock.json"))

    current_findings = (f_existing, f_new, f_regressed)
    diff = baseline_manager.compare(current_findings, baseline_data)

    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].fingerprint == "fp2"

    assert len(diff.existing_findings) == 1
    assert diff.existing_findings[0].fingerprint == "fp1"

    assert len(diff.regressed_findings) == 1
    assert diff.regressed_findings[0].fingerprint == "fp3"

    assert len(diff.fixed_findings) == 1
    assert diff.fixed_findings[0].fingerprint == "fp4"
