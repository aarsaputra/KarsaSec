from __future__ import annotations

from typing import Any

from karsasec.core.pipeline.artifact_store import ArtifactStore
from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassDependencyError, PassManager


class MockParserPass(AnalysisPass):
    @property
    def name(self) -> str:
        return "MockParserPass"

    @property
    def requires(self) -> list[str]:
        return []

    @property
    def produces(self) -> list[str]:
        return ["AST"]

    def run(self, context: PassContext) -> Any:
        return {"file": "main.py", "nodes": 10}


class MockSymbolPass(AnalysisPass):
    @property
    def name(self) -> str:
        return "MockSymbolPass"

    @property
    def requires(self) -> list[str]:
        return ["AST"]

    @property
    def produces(self) -> list[str]:
        return ["SymbolGraph"]

    def run(self, context: PassContext) -> Any:
        ast = context.artifact_store.get("AST")
        return {"symbols": ["main", "db"], "ast_ref": ast["file"]}


def test_artifact_store() -> None:
    store = ArtifactStore()
    store.store("SymbolGraph", {"db": "sqlite3"})
    assert store.has("SymbolGraph")
    assert store.get("SymbolGraph") == {"db": "sqlite3"}
    assert "SymbolGraph" in store.keys()


def test_pass_manager_execution() -> None:
    context = PassContext()
    manager = PassManager()

    # Register in reverse order to test topological sort
    manager.register_pass(MockSymbolPass())
    manager.register_pass(MockParserPass())

    final_context = manager.run_passes(context)

    assert final_context.artifact_store.has("AST")
    assert final_context.artifact_store.has("SymbolGraph")
    assert final_context.artifact_store.get("SymbolGraph")["ast_ref"] == "main.py"


def test_pass_manager_missing_dependency() -> None:
    class FailingPass(AnalysisPass):
        @property
        def name(self) -> str:
            return "FailingPass"

        @property
        def requires(self) -> list[str]:
            return ["NonExistentArtifact"]

        @property
        def produces(self) -> list[str]:
            return ["Result"]

        def run(self, context: PassContext) -> Any:
            return None

    context = PassContext()
    manager = PassManager()
    manager.register_pass(FailingPass())

    import pytest
    with pytest.raises(PassDependencyError) as exc_info:
        manager.run_passes(context)
    assert "requires artifact 'NonExistentArtifact'" in str(exc_info.value)
