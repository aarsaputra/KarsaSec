"""Precision Hardening & E11 TP Recall Protection Gate Tests (E12-3)."""

from __future__ import annotations

from pathlib import Path

from karsasec.cli.commands.qualify import _scan_target
from karsasec.qualification.engine import QualificationEngine
from karsasec.qualification.model import ManifestLoader


class TestE11TPRecallProtection:
    """Ensures that Sprint E12-3 precision hardening strictly preserves all Sprint E11 TPs."""

    def test_e11_tp_cases_are_fully_retained(self) -> None:
        dvwa_root = Path("/home/lota1337/pentest/DVWA")
        scan_target = dvwa_root / "vulnerabilities"
        manifest_path = Path("benchmarks/dvwa/manifest.yaml")
        assert manifest_path.exists(), "DVWA manifest.yaml must exist"
        assert scan_target.exists(), "DVWA vulnerabilities directory must exist"

        raw_findings, correlated_findings = _scan_target(scan_target)

        benchmark = ManifestLoader().load(manifest_path)
        engine = QualificationEngine()
        result = engine.qualify(
            benchmark=benchmark,
            final_findings=correlated_findings,
            scan_root=scan_target,
            raw_finding_count=len(raw_findings),
            raw_findings=raw_findings,
        )

        # Baseline E11 TP expectation: at least 13 TPs
        assert result.true_positives >= 13, f"Recall Regression! Expected result.true_positives >= 13, got {result.true_positives}"

        # Per category recall gates
        assert result.per_category["COMMAND_INJECTION"].recall == 1.0, f"Command Injection recall dropped! {result.per_category['COMMAND_INJECTION'].recall}"
        assert result.per_category["PATH_TRAVERSAL"].recall == 1.0, f"Path Traversal recall dropped! {result.per_category['PATH_TRAVERSAL'].recall}"
        assert result.per_category["SQL_INJECTION"].recall >= 0.70, f"SQL Injection recall dropped! {result.per_category['SQL_INJECTION'].recall}"
        assert result.recall >= 0.65, f"Overall recall dropped! {result.recall}"
