"""karsasec.qualification — Security Detection Qualification System (Sprint E12-1).

Public surface:
    model      → GroundTruthCase, GroundTruthBenchmark, GroundTruthExpectation
    identity   → FindingIdentity
    metrics    → calculate_precision, calculate_recall, calculate_f1
    classifier → QualificationClassifier
    engine     → QualificationEngine, QualificationResult
"""
from __future__ import annotations

from karsasec.qualification.engine import QualificationEngine, QualificationResult, RuleQualificationResult
from karsasec.qualification.model import GroundTruthBenchmark, GroundTruthCase, GroundTruthExpectation

__all__ = [
    "GroundTruthExpectation",
    "GroundTruthCase",
    "GroundTruthBenchmark",
    "QualificationEngine",
    "QualificationResult",
    "RuleQualificationResult",
]
