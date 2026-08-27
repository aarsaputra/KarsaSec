"""Unit tests for FrameworkDetector, evidence scoring, and UNKNOWN boundary."""

from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.detector import FrameworkDetector
from karsasec.framework.semantic_fact import ConfidenceLevel


@dataclass
class MockASTNode:
    node_type: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)


def test_framework_detector_flask() -> None:
    """Flask framework detection via imports and route decorator."""
    detector = FrameworkDetector()
    nodes = [
        MockASTNode("IMPORT", "from flask import Flask, request"),
        MockASTNode("DECORATOR", "@app.route('/api')"),
    ]
    res = detector.detect_from_ast(nodes, "app.py")
    assert res.framework == "FLASK"
    assert res.confidence >= 0.60
    assert res.confidence_level in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)
    assert len(res.evidence) >= 2


def test_framework_detector_fastapi() -> None:
    """FastAPI framework detection via imports and app.get."""
    detector = FrameworkDetector()
    nodes = [
        MockASTNode("IMPORT", "from fastapi import FastAPI"),
        MockASTNode("CALL", "app = FastAPI()"),
    ]
    res = detector.detect_from_ast(nodes, "main.py")
    assert res.framework == "FASTAPI"
    assert res.confidence >= 0.50


def test_framework_detector_unknown_fallback() -> None:
    """Ambiguous or non-framework code must return UNKNOWN verdict (INV-E10-SEM-04 & Guard 2)."""
    detector = FrameworkDetector()
    nodes = [
        MockASTNode("FUNCTION", "def calculate_total(a, b):"),
        MockASTNode("RETURN", "return a + b"),
    ]
    res = detector.detect_from_ast(nodes, "utils.py")
    assert res.framework == "UNKNOWN"
    assert res.confidence == 0.0
    assert res.confidence_level == ConfidenceLevel.UNKNOWN
    assert res.is_known() is False


def test_framework_detector_scoring_determinism() -> None:
    """Detection scores must be 100% deterministic across multiple calls."""
    detector = FrameworkDetector()
    nodes = [
        MockASTNode("IMPORT", "import express"),
        MockASTNode("CALL", "app.get('/users', handler)"),
    ]
    res1 = detector.detect_from_ast(nodes, "server.js")
    res2 = detector.detect_from_ast(nodes, "server.js")
    assert res1.framework == res2.framework == "EXPRESS"
    assert res1.confidence == res2.confidence
