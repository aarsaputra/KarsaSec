"""Framework Test Kit providing shared testing utilities, assertions, and fixture loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from karsasec.framework.intermediate import CURRENT_ISR_SCHEMA_VERSION, IntermediateSemanticRepresentation


class FixtureLoader:
    """Utility for loading project fixtures and mock artifacts."""

    @staticmethod
    def get_fixture_path(framework_name: str) -> Path:
        """Returns Path to golden fixture directory for a given framework."""
        base_dir = Path(__file__).parent / "fixtures" / framework_name.lower()
        return base_dir.resolve()

    @staticmethod
    def load_fixture_file(framework_name: str, relative_file_path: str) -> str:
        """Reads file text from fixture directory."""
        p = FixtureLoader.get_fixture_path(framework_name) / relative_file_path
        if not p.exists():
            raise FileNotFoundError(f"Fixture file not found: {p}")
        return p.read_text(encoding="utf-8")

    @staticmethod
    def list_fixture_files(framework_name: str) -> list[Path]:
        """Lists all files in fixture directory."""
        p = FixtureLoader.get_fixture_path(framework_name)
        if not p.exists():
            return []
        return [f for f in p.rglob("*") if f.is_file()]


class FrameworkAssertions:
    """Assertion helpers for checking framework semantic definitions in ISR or Graph."""

    @staticmethod
    def assert_route_exists(isr: IntermediateSemanticRepresentation, path: str, method: str = "GET") -> None:
        """Asserts that a route definition with given path and method exists in ISR."""
        matches = [r for r in isr.routes if r.path == path and r.method.upper() == method.upper()]
        assert len(matches) > 0, f"Route '{method} {path}' not found in ISR"

    @staticmethod
    def assert_handler_exists(isr: IntermediateSemanticRepresentation, handler_name: str) -> None:
        """Asserts that a handler definition exists in ISR."""
        matches = [h for h in isr.handlers if h.name == handler_name or h.function_name == handler_name]
        assert len(matches) > 0, f"Handler '{handler_name}' not found in ISR"

    @staticmethod
    def assert_middleware_exists(isr: IntermediateSemanticRepresentation, middleware_name: str) -> None:
        """Asserts that a middleware definition exists in ISR."""
        matches = [m for m in isr.middlewares if m.name == middleware_name]
        assert len(matches) > 0, f"Middleware '{middleware_name}' not found in ISR"

    @staticmethod
    def assert_model_exists(isr: IntermediateSemanticRepresentation, model_name: str) -> None:
        """Asserts that a model definition exists in ISR."""
        matches = [m for m in isr.models if m.model_name == model_name]
        assert len(matches) > 0, f"Model '{model_name}' not found in ISR"

    @staticmethod
    def assert_config_exists(isr: IntermediateSemanticRepresentation, key: str) -> None:
        """Asserts that a config setting key exists in ISR."""
        matches = [c for c in isr.configs if c.key == key]
        assert len(matches) > 0, f"Config key '{key}' not found in ISR"


class SnapshotAssertions:
    """Assertion helpers for snapshot and dictionary comparisons."""

    @staticmethod
    def assert_snapshot_match(actual: dict[str, Any], expected: dict[str, Any]) -> None:
        """Asserts that actual dictionary matches expected snapshot dictionary."""
        assert actual == expected, f"Snapshot mismatch.\nActual: {actual}\nExpected: {expected}"

    @staticmethod
    def assert_json_snapshot(actual_json: str, expected_json: str) -> None:
        """Asserts that formatted JSON strings match."""
        actual_dict = json.loads(actual_json)
        expected_dict = json.loads(expected_json)
        assert actual_dict == expected_dict, "JSON snapshot mismatch"


class ASTAssertions:
    """Assertion helpers for AST node inspection."""

    @staticmethod
    def assert_node_type(node: Any, expected_type: str) -> None:
        """Asserts node node_type property or class name."""
        actual = getattr(node, "node_type", node.__class__.__name__)
        assert str(actual).lower() == expected_type.lower(), f"Expected node type {expected_type}, got {actual}"


class ISRAssertions:
    """Assertion helpers for verifying ISR schema integrity and versioning."""

    @staticmethod
    def assert_valid_isr(isr: IntermediateSemanticRepresentation) -> None:
        """Asserts that ISR exposes schema_version and valid definition structures."""
        assert hasattr(isr, "schema_version")
        assert isr.schema_version == CURRENT_ISR_SCHEMA_VERSION
        for r in isr.routes:
            assert hasattr(r, "semantic_id")
            assert hasattr(r, "framework")
            assert hasattr(r, "language")
            assert hasattr(r, "confidence")
