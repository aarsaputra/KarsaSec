"""Unit tests for Evidence Validator Engine."""

from types import SimpleNamespace
import pytest

from karsasec.analysis.e15_evidence_validator import EvidenceValidator


def test_validate_null_cluster():
    validator = EvidenceValidator()
    ev = validator.validate(None)
    assert ev.evidence_valid is False
    assert "cluster" in ev.missing_dimensions


def test_validate_valid_cluster():
    validator = EvidenceValidator()
    finding = SimpleNamespace(
        vulnerability_class="CWE-89",
        sink_category="SQL",
        source_fact=SimpleNamespace(node_id="n1"),
        sink_fact=SimpleNamespace(node_id="n2"),
        confidence=0.9,
    )
    cluster = SimpleNamespace(status="CONFIRMED", findings=(finding,))
    ev = validator.validate(cluster)
    assert ev.evidence_valid is True
    assert ev.completeness == 1.0
    assert ev.contradictions == 0


def test_validate_contradictory_cluster():
    validator = EvidenceValidator()
    f1 = SimpleNamespace(
        vulnerability_class="CWE-89",
        sink_category="SQL",
        source_fact=SimpleNamespace(node_id="n1"),
        sink_fact=SimpleNamespace(node_id="n2"),
        confidence=0.9,
    )
    f2 = SimpleNamespace(
        vulnerability_class="CWE-79",  # Contradicting vulnerability class
        sink_category="HTML",
        source_fact=SimpleNamespace(node_id="n3"),
        sink_fact=SimpleNamespace(node_id="n4"),
        confidence=0.9,
    )
    cluster = SimpleNamespace(status="CONFIRMED", findings=(f1, f2))
    ev = validator.validate(cluster)
    assert ev.evidence_valid is False
    assert ev.contradictions >= 1
