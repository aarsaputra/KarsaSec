"""Tests for DVWA manifest integrity (E12-1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from karsasec.qualification.model import GroundTruthExpectation, ManifestLoader

MANIFEST_PATH = Path(__file__).parents[2] / "benchmarks" / "dvwa" / "manifest.yaml"
DVWA_RULES_DIR = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns"


class TestDVWAManifest:
    def setup_method(self) -> None:
        self.bm = ManifestLoader().load(MANIFEST_PATH)

    def test_manifest_loads(self) -> None:
        assert self.bm.benchmark_id == "dvwa"

    def test_minimum_case_count(self) -> None:
        assert len(self.bm.cases) >= 30, f"Expected ≥30 cases, got {len(self.bm.cases)}"

    def test_minimum_tp_count(self) -> None:
        tp = len(self.bm.tp_cases)
        assert tp >= 20, f"Expected ≥20 TP cases, got {tp}"

    def test_minimum_tn_count(self) -> None:
        tn = len(self.bm.tn_cases)
        assert tn >= 10, f"Expected ≥10 TN cases, got {tn}"

    def test_no_duplicate_case_ids(self) -> None:
        ids = [c.case_id for c in self.bm.cases]
        assert len(ids) == len(set(ids)), "Duplicate case IDs found"

    def test_all_cases_have_description(self) -> None:
        for case in self.bm.cases:
            assert case.description.strip(), f"Case '{case.case_id}' has empty description"

    def test_all_cases_have_file(self) -> None:
        for case in self.bm.cases:
            assert case.file, f"Case '{case.case_id}' has no file"

    def test_all_cases_have_expected(self) -> None:
        for case in self.bm.cases:
            assert case.expected in (
                GroundTruthExpectation.TRUE_POSITIVE,
                GroundTruthExpectation.TRUE_NEGATIVE,
            )

    def test_multiple_rules_covered(self) -> None:
        rules = self.bm.rules_covered
        assert len(rules) >= 3, f"Expected ≥3 rules, got {len(rules)}: {rules}"

    def test_no_fp_expectation_in_manifest(self) -> None:
        """Ground truth must not encode FP directly — only TP and TN."""
        for case in self.bm.cases:
            assert case.expected != "FALSE_POSITIVE", (
                f"Case '{case.case_id}': FP must not appear in ground truth. "
                "Use TRUE_NEGATIVE for code that should not be flagged."
            )

    def test_dvwa_files_exist(self) -> None:
        """Verify that referenced DVWA files exist on this system."""
        dvwa_root = Path("/home/lota1337/pentest/DVWA/vulnerabilities")
        if not dvwa_root.exists():
            pytest.skip("DVWA not installed at expected path — skipping file existence check")

        missing = []
        for case in self.bm.cases:
            full = dvwa_root / case.file.replace("vulnerabilities/", "", 1)
            if not full.exists():
                missing.append(f"{case.case_id}: {full}")
        assert not missing, "Missing DVWA files:\n" + "\n".join(missing)

    def test_manifest_is_reproducible(self) -> None:
        """Loading the same manifest twice gives identical results."""
        bm2 = ManifestLoader().load(MANIFEST_PATH)
        assert len(self.bm.cases) == len(bm2.cases)
        ids1 = {c.case_id for c in self.bm.cases}
        ids2 = {c.case_id for c in bm2.cases}
        assert ids1 == ids2
