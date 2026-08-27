"""Domain models and canonical SHA-256 identity computation for Phase V0 Real-World Validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def deterministic_id(namespace: str, payload: dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hex digest for a given namespace and payload.

    Guarantees:
    - Exactly 64 hex characters
    - Sorted keys and canonical json formatting
    - UTF-8 encoding
    - Zero dependence on Python dict hash ordering or PYTHONHASHSEED
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{namespace}{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class GroundTruthFinding:
    """Immutable representation of ground-truth security expectations for a benchmark sample."""

    truth_id: str
    vuln_class: str
    expected_severity: str
    expected_decision: str
    expected_admission: str
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        vuln_class: str,
        expected_severity: str = "HIGH",
        expected_decision: str = "BLOCK",
        expected_admission: str = "BLOCKED",
        schema_version: str = "1.0.0",
    ) -> GroundTruthFinding:
        """Factory creating GroundTruthFinding with canonical SHA-256 identity."""
        payload = {
            "vuln_class": vuln_class,
            "expected_severity": expected_severity,
            "expected_decision": expected_decision,
            "expected_admission": expected_admission,
            "schema_version": schema_version,
        }
        t_id = deterministic_id("V0-TRUTH:v1:", payload)
        return cls(
            truth_id=t_id,
            vuln_class=vuln_class,
            expected_severity=expected_severity,
            expected_decision=expected_decision,
            expected_admission=expected_admission,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes ground truth finding to dictionary."""
        return {
            "truth_id": self.truth_id,
            "vuln_class": self.vuln_class,
            "expected_severity": self.expected_severity,
            "expected_decision": self.expected_decision,
            "expected_admission": self.expected_admission,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class BenchmarkSample:
    """Immutable representation of a real-world security benchmark sample."""

    sample_id: str
    category: str
    name: str
    vulnerable_code: str
    fixed_code: str
    mutated_code: str
    ground_truth: GroundTruthFinding
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        category: str,
        name: str,
        vulnerable_code: str,
        fixed_code: str,
        mutated_code: str,
        ground_truth: GroundTruthFinding,
        schema_version: str = "1.0.0",
    ) -> BenchmarkSample:
        """Factory creating BenchmarkSample with canonical SHA-256 identity."""
        payload = {
            "category": category,
            "name": name,
            "vulnerable_code": vulnerable_code,
            "fixed_code": fixed_code,
            "mutated_code": mutated_code,
            "ground_truth_id": ground_truth.truth_id,
            "schema_version": schema_version,
        }
        s_id = deterministic_id("V0-SAMPLE:v1:", payload)
        return cls(
            sample_id=s_id,
            category=category,
            name=name,
            vulnerable_code=vulnerable_code,
            fixed_code=fixed_code,
            mutated_code=mutated_code,
            ground_truth=ground_truth,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes benchmark sample to dictionary."""
        return {
            "sample_id": self.sample_id,
            "category": self.category,
            "name": self.name,
            "vulnerable_code": self.vulnerable_code,
            "fixed_code": self.fixed_code,
            "mutated_code": self.mutated_code,
            "ground_truth": self.ground_truth.to_dict(),
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class ValidationRunResult:
    """Immutable representation of execution results for a single benchmark sample."""

    result_id: str
    sample_id: str
    actual_findings: tuple[str, ...]
    actual_decision: str
    actual_admission: str
    is_true_positive: bool
    is_false_positive: bool
    is_false_negative: bool
    mutation_detected: bool
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        sample_id: str,
        actual_findings: tuple[str, ...],
        actual_decision: str,
        actual_admission: str,
        is_true_positive: bool,
        is_false_positive: bool,
        is_false_negative: bool,
        mutation_detected: bool,
        schema_version: str = "1.0.0",
    ) -> ValidationRunResult:
        """Factory creating ValidationRunResult with canonical SHA-256 identity."""
        sorted_findings = tuple(sorted(actual_findings))
        payload = {
            "sample_id": sample_id,
            "actual_findings": list(sorted_findings),
            "actual_decision": actual_decision,
            "actual_admission": actual_admission,
            "is_true_positive": is_true_positive,
            "is_false_positive": is_false_positive,
            "is_false_negative": is_false_negative,
            "mutation_detected": mutation_detected,
            "schema_version": schema_version,
        }
        r_id = deterministic_id("V0-RESULT:v1:", payload)
        return cls(
            result_id=r_id,
            sample_id=sample_id,
            actual_findings=sorted_findings,
            actual_decision=actual_decision,
            actual_admission=actual_admission,
            is_true_positive=is_true_positive,
            is_false_positive=is_false_positive,
            is_false_negative=is_false_negative,
            mutation_detected=mutation_detected,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes result to dictionary."""
        return {
            "result_id": self.result_id,
            "sample_id": self.sample_id,
            "actual_findings": list(self.actual_findings),
            "actual_decision": self.actual_decision,
            "actual_admission": self.actual_admission,
            "is_true_positive": self.is_true_positive,
            "is_false_positive": self.is_false_positive,
            "is_false_negative": self.is_false_negative,
            "mutation_detected": self.mutation_detected,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class ValidationScorecard:
    """Immutable representation of Phase V0 real-world validation scorecard."""

    scorecard_id: str
    total_samples: int
    true_positives: int
    false_positives: int
    false_negatives: int
    tp_rate: float
    fp_rate: float
    mutation_sensitivity_score: float
    gate_status: str
    schema_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        total_samples: int,
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        tp_rate: float,
        fp_rate: float,
        mutation_sensitivity_score: float,
        gate_status: str,
        schema_version: str = "1.0.0",
    ) -> ValidationScorecard:
        """Factory creating ValidationScorecard with canonical SHA-256 identity."""
        payload = {
            "total_samples": total_samples,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "tp_rate": float(tp_rate),
            "fp_rate": float(fp_rate),
            "mutation_sensitivity_score": float(mutation_sensitivity_score),
            "gate_status": gate_status,
            "schema_version": schema_version,
        }
        sc_id = deterministic_id("V0-SCORECARD:v1:", payload)
        return cls(
            scorecard_id=sc_id,
            total_samples=total_samples,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            tp_rate=float(tp_rate),
            fp_rate=float(fp_rate),
            mutation_sensitivity_score=float(mutation_sensitivity_score),
            gate_status=gate_status,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes scorecard to dictionary."""
        return {
            "scorecard_id": self.scorecard_id,
            "total_samples": self.total_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "tp_rate": self.tp_rate,
            "fp_rate": self.fp_rate,
            "mutation_sensitivity_score": self.mutation_sensitivity_score,
            "gate_status": self.gate_status,
            "schema_version": self.schema_version,
        }
