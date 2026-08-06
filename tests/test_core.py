"""Unit tests for Core Container and Component Registry."""

from pathlib import Path

import pytest

from karsasec.core.container import Container
from karsasec.core.context import AnalysisContext
from karsasec.core.registry import ComponentRegistry


def test_container_singleton() -> None:
    """Test singleton registration and resolution."""
    c = Container()

    class DummyService:
        pass

    instance = DummyService()
    c.register_singleton(DummyService, instance)

    resolved = c.resolve(DummyService)
    assert resolved is instance

def test_container_unregistered_raises() -> None:
    """Test resolving unregistered service raises KeyError."""
    c = Container()

    class UnknownService:
        pass

    with pytest.raises(KeyError):
        c.resolve(UnknownService)

def test_component_registry() -> None:
    """Test registering and retrieving components."""
    registry = ComponentRegistry[type]("test_registry")

    class DummyComponent:
        pass

    registry.register("dummy", DummyComponent)
    assert registry.get("dummy") is DummyComponent
    assert "dummy" in registry.list_keys()

def test_analysis_context() -> None:
    """Test analysis context creation."""
    ctx = AnalysisContext(scan_id="SCAN-001", target_path=Path("."))
    assert ctx.scan_id == "SCAN-001"
    assert len(ctx.findings) == 0
