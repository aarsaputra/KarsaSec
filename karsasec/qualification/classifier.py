"""Qualification Classifier: deterministic TP/FP/FN classification (E12-1).

Algorithm:
    For each TRUE_POSITIVE case in ground truth:
        If a matching finding exists in actual findings → TP
        Else                                            → FN

    For each actual finding NOT matched by any TP case:
        If it matches a TRUE_NEGATIVE case              → FP
        If there is no ground-truth expectation at all  → FP

    For each TRUE_NEGATIVE case:
        If a matching finding exists                    → FP
        Else                                            → (correctly absent, contributes to TN count)

    UNKNOWN findings (from rules with UNKNOWN confidence):
        Tracked separately. Never forced into TP or FP.

Matching semantics:
    A finding matches a ground-truth case when FindingIdentity.matches_finding() is True.
    See identity.py for the exact algorithm (exact file + line + rule_id).

Anti-circularity note:
    This classifier is pure: it receives ground truth and findings as inputs.
    It never modifies or re-derives ground truth from KarsaSec output.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from karsasec.core.finding.model import Finding
from karsasec.qualification.identity import FindingIdentity
from karsasec.qualification.model import GroundTruthBenchmark, GroundTruthCase, GroundTruthExpectation


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """Output of a single ground-truth case classification."""
    case: GroundTruthCase
    outcome: str            # "TP" | "FP" | "FN" | "TN"
    matched_finding: Finding | None = None


@dataclass(frozen=True)
class ClassificationReport:
    """Full classification report for one benchmark run."""
    benchmark_id: str
    scan_root: Path
    results: tuple[ClassificationResult, ...]
    unmatched_findings: tuple[Finding, ...]   # Findings with no TP expectation → FP candidates
    unknown_findings: tuple[Finding, ...]     # UNKNOWN confidence findings

    @property
    def tp(self) -> int:
        return sum(1 for r in self.results if r.outcome == "TP")

    @property
    def fn(self) -> int:
        return sum(1 for r in self.results if r.outcome == "FN")

    @property
    def fp_from_tn(self) -> int:
        """FP: finding produced where TN case was expected."""
        return sum(1 for r in self.results if r.outcome == "FP")

    @property
    def fp_unmatched(self) -> int:
        """FP: finding produced with no ground-truth expectation at all."""
        return len(self.unmatched_findings)

    @property
    def fp(self) -> int:
        return self.fp_from_tn + self.fp_unmatched

    @property
    def tn(self) -> int:
        return sum(1 for r in self.results if r.outcome == "TN")

    @property
    def unknown(self) -> int:
        return len(self.unknown_findings)


class QualificationClassifier:
    """Deterministic classifier: ground truth + findings → TP/FP/FN/TN/UNKNOWN."""

    def classify(
        self,
        benchmark: GroundTruthBenchmark,
        findings: tuple[Finding, ...] | list[Finding],
        scan_root: Path,
    ) -> ClassificationReport:
        """Classify findings against benchmark ground truth.

        Args:
            benchmark:  Ground-truth benchmark.
            findings:   Final correlated findings from the scan.
            scan_root:  Base path used to normalize finding file paths.

        Returns:
            ClassificationReport with TP/FP/FN/TN/UNKNOWN breakdown.
        """
        findings_list = list(findings)

        # Separate UNKNOWN-confidence and REJECTED findings (tracked separately, never TP/FP)
        unknown_findings: list[Finding] = []
        active_findings: list[Finding] = []
        for f in findings_list:
            qstate = getattr(f, "qualification_state", None)
            if qstate == "REJECTED" or getattr(qstate, "value", str(qstate)) == "REJECTED":
                continue
            if str(f.confidence).upper() == "UNKNOWN":
                unknown_findings.append(f)
            else:
                active_findings.append(f)

        # Build FindingIdentity for each active finding
        finding_identities: list[tuple[FindingIdentity, Finding]] = [
            (FindingIdentity.from_finding(f, scan_root), f) for f in active_findings
        ]

        results: list[ClassificationResult] = []
        matched_finding_ids: set[str] = set()  # finding_id of matched findings

        # --- Evaluate each ground-truth case ---
        for case in benchmark.cases:
            case_identity = FindingIdentity.from_case(case)
            matched: Finding | None = None

            for fi, f in finding_identities:
                corr_rules = f.metadata.get("correlated_rules") if isinstance(getattr(f, "metadata", None), dict) else None
                if case_identity.matches_finding(fi, correlated_rules=corr_rules):
                    matched = f
                    matched_finding_ids.add(f.finding_id)
                    break

            if case.expected == GroundTruthExpectation.TRUE_POSITIVE:
                outcome = "TP" if matched else "FN"
            else:  # TRUE_NEGATIVE
                outcome = "FP" if matched else "TN"

            results.append(ClassificationResult(case=case, outcome=outcome, matched_finding=matched))

        # --- Unmatched findings → FP candidates ---
        unmatched: list[Finding] = [
            f for _, f in finding_identities if f.finding_id not in matched_finding_ids
        ]

        return ClassificationReport(
            benchmark_id=benchmark.benchmark_id,
            scan_root=scan_root,
            results=tuple(results),
            unmatched_findings=tuple(unmatched),
            unknown_findings=tuple(unknown_findings),
        )
