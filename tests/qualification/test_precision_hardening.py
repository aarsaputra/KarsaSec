"""Precision Hardening & E11/E12-4 TP Recall Protection Gate Tests (E12-4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from karsasec.cli.commands.qualify import _scan_target
from karsasec.qualification.engine import QualificationEngine
from karsasec.qualification.model import ManifestLoader


class TestE11TPRecallProtection:
    """Ensures that Sprint E12-4 evidence quality & correlation hardening strictly preserves all recall gates."""

    def test_e11_tp_cases_are_fully_retained(self) -> None:
        import os

        env_dvwa = os.getenv("KARSASEC_DVWA_PATH") or os.getenv("DVWA_TARGET_PATH") or "/opt/DVWA/vulnerabilities"
        scan_target = Path(env_dvwa)
        manifest_path = Path("benchmarks/dvwa/manifest.yaml")
        assert manifest_path.exists(), "DVWA manifest.yaml must exist"
        if not scan_target.exists():
            pytest.skip("DVWA vulnerabilities directory not found (skipped in CI)")

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

        # E12-4 Hard Recall Protection Gates
        assert result.per_category["COMMAND_INJECTION"].recall >= 1.0, (
            f"Command Injection recall dropped! {result.per_category['COMMAND_INJECTION'].recall}"
        )
        assert result.per_category["PATH_TRAVERSAL"].recall == 1.0, (
            f"Path Traversal recall dropped! {result.per_category['PATH_TRAVERSAL'].recall}"
        )
        assert result.per_category["SQL_INJECTION"].recall >= 0.85, (
            f"SQL Injection recall dropped! {result.per_category['SQL_INJECTION'].recall}"
        )
        assert result.recall >= 0.70, f"Overall recall dropped! {result.recall}"

        # E12-4 Telemetry & Provenance Assertions
        assert result.candidate_count > 0, "Candidate count should be positive"
        assert result.candidate_count == len(raw_findings)
        assert result.qualified_count > 0, "Qualified count should be positive"
        assert result.qualified_count + result.unresolved_count == len(correlated_findings)
