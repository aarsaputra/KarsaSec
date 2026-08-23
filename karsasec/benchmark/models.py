"""Data models for KarsaSec External Benchmark Infrastructure (Gate 5).

Includes:
- BenchmarkRun provenance model for reproducible external validity tracking
- GroundTruthManifest for independent ground truth label representation
- BenchmarkOutcome strict 6-tuple classification
- ErrorTaxonomyCategory for FP/FN root cause classification (Gate 5G)
- GateVerdict 4-tier gate status (Gate 5 Final Verdict)
- ConfidenceInterval for 95% Wilson score statistical bounds (Gate 5H)
- BenchmarkMetricResult for mathematical precision, recall, F1, and epistemic uncertainty metrics
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class GroundTruthStatus(StrEnum):
    """Ground truth expected status for a test case."""

    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"


class BenchmarkOutcome(StrEnum):
    """Strict 6-tuple classification outcome for benchmark evaluation."""

    TP = "TP"                     # Ground Truth: VULNERABLE, Prediction: VULNERABLE
    FP = "FP"                     # Ground Truth: SAFE,       Prediction: VULNERABLE
    TN = "TN"                     # Ground Truth: SAFE,       Prediction: SAFE
    FN = "FN"                     # Ground Truth: SAFE/VULN,  Prediction: SAFE
    FN_EPISTEMIC = "FN_EPISTEMIC" # Ground Truth: VULNERABLE, Prediction: UNKNOWN / CONFLICT
    UNCERTAIN_TN = "UNCERTAIN_TN" # Ground Truth: SAFE,       Prediction: UNKNOWN / CONFLICT


class ErrorTaxonomyCategory(StrEnum):
    """Gate 5G — Root cause failure mode taxonomy for FP and FN outcomes."""

    # False Positive failure modes
    FP_AST = "FP_AST"
    FP_DATAFLOW = "FP_DATAFLOW"
    FP_CONTEXT = "FP_CONTEXT"
    FP_CORRELATION = "FP_CORRELATION"
    FP_PROPERTY = "FP_PROPERTY"
    FP_DECISION = "FP_DECISION"

    # False Negative failure modes
    FN_SOURCE = "FN_SOURCE"
    FN_SINK = "FN_SINK"
    FN_DATAFLOW = "FN_DATAFLOW"
    FN_INTERPROCEDURAL = "FN_INTERPROCEDURAL"
    FN_FRAMEWORK = "FN_FRAMEWORK"
    FN_SEMANTIC = "FN_SEMANTIC"
    FN_CONTEXT = "FN_CONTEXT"

    # Epistemic failure modes
    UNRESOLVED_WRAPPER = "UNRESOLVED_WRAPPER"
    CONTRADICTORY_SANITY = "CONTRADICTORY_SANITY"


class GateVerdict(StrEnum):
    """4-tier Gate Verdict as defined by Chief Architect Directive."""

    G5_BLOCKED = "G5_BLOCKED"                                         # 🔴 Infrastructure/Oracle compromised
    G5_EXTERNAL_VALIDITY_INSUFFICIENT = "G5_EXTERNAL_VALIDITY_INSUFFICIENT" # 🟠 Harness ok, dataset coverage insufficient
    G5_PASS_WITH_KNOWN_GAPS = "G5_PASS_WITH_KNOWN_GAPS"               # 🟡 External validity proven with documented gaps; K1 permitted
    G5_PASS = "G5_PASS"                                               # 🟢 All targets met; zero critical epistemic failures


@dataclass(frozen=True)
class ConfidenceInterval:
    """95% Confidence Interval representation (Gate 5H)."""

    lower_bound: float
    upper_bound: float
    confidence_level: float = 0.95

    def to_dict(self) -> dict[str, float]:
        return {
            "lower_bound": round(self.lower_bound, 4),
            "upper_bound": round(self.upper_bound, 4),
            "confidence_level": self.confidence_level,
        }


@dataclass(frozen=True)
class GroundTruthManifest:
    """Immutable ground truth manifest for a single benchmark test case."""

    test_case_id: str
    dataset_name: str
    vulnerability_class: str
    cwe: str
    expected_status: GroundTruthStatus
    file_path: str
    language: str = "java"
    framework: str = "servlet"
    line_number: int = 0
    sink_function: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_case_id": self.test_case_id,
            "dataset_name": self.dataset_name,
            "vulnerability_class": self.vulnerability_class,
            "cwe": self.cwe,
            "expected_status": self.expected_status.value,
            "file_path": self.file_path,
            "language": self.language,
            "framework": self.framework,
            "line_number": self.line_number,
            "sink_function": self.sink_function,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class BenchmarkRun:
    """Immutable benchmark provenance record ensuring scientific reproducibility."""

    run_id: str
    commit_sha: str
    dataset_name: str
    dataset_version: str
    adapter_version: str
    oracle_version: str
    engine_version: str
    timestamp: str
    configuration_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "commit_sha": self.commit_sha,
            "dataset_name": self.dataset_name,
            "dataset_version": self.dataset_version,
            "adapter_version": self.adapter_version,
            "oracle_version": self.oracle_version,
            "engine_version": self.engine_version,
            "timestamp": self.timestamp,
            "configuration_hash": self.configuration_hash,
        }

    def compute_hash(self) -> str:
        s = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class BenchmarkMetricResult:
    """Mathematically strict metrics calculated over a benchmark evaluation run."""

    run: BenchmarkRun
    total_cases: int
    tp: int
    fp: int
    tn: int
    fn: int
    fn_epistemic: int
    uncertain_tn: int
    strict_precision: float
    precision_ci: ConfidenceInterval
    strict_recall: float
    recall_ci: ConfidenceInterval
    epistemic_recall: float
    epistemic_recall_ci: ConfidenceInterval
    f1_score: float
    epistemic_uncertainty_ratio: float
    unknown_rate: float
    conflict_rate: float
    error_taxonomy_breakdown: dict[str, int] = field(default_factory=dict)
    language_framework_matrix: dict[str, dict[str, float]] = field(default_factory=dict)
    verdict: GateVerdict = GateVerdict.G5_PASS_WITH_KNOWN_GAPS

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run.to_dict(),
            "total_cases": self.total_cases,
            "verdict": self.verdict.value,
            "counts": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
                "fn_epistemic": self.fn_epistemic,
                "uncertain_tn": self.uncertain_tn,
            },
            "metrics": {
                "strict_precision": round(self.strict_precision, 4),
                "precision_ci": self.precision_ci.to_dict(),
                "strict_recall": round(self.strict_recall, 4),
                "recall_ci": self.recall_ci.to_dict(),
                "epistemic_recall": round(self.epistemic_recall, 4),
                "epistemic_recall_ci": self.epistemic_recall_ci.to_dict(),
                "f1_score": round(self.f1_score, 4),
                "epistemic_uncertainty_ratio": round(self.epistemic_uncertainty_ratio, 4),
                "unknown_rate": round(self.unknown_rate, 4),
                "conflict_rate": round(self.conflict_rate, 4),
            },
            "error_taxonomy_breakdown": self.error_taxonomy_breakdown,
            "language_framework_matrix": self.language_framework_matrix,
        }
