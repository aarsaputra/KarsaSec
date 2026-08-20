"""BuilderContext for FrameworkGraphBuilder graph construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.intermediate import IntermediateSemanticRepresentation
from karsasec.framework.semantic_registry import SemanticRegistry, semantic_registry
from karsasec.framework.symbol_table import SemanticSymbolTable, semantic_symbol_table


@dataclass
class BuilderOptions:
    """Configuration options controlling graph construction, optimization, and validation behavior."""

    auto_freeze: bool = True
    auto_optimize: bool = True
    validate_integrity: bool = True
    deduplicate: bool = True
    remove_orphans: bool = False
    generator_version: str = "1.0.0"
    schema_version: str = "1.0"
    compatibility_version: str = "1.0"


@dataclass
class BuilderContext:
    """Context passed into FrameworkGraphBuilder for graph building."""

    isr: IntermediateSemanticRepresentation = field(default_factory=IntermediateSemanticRepresentation)
    registry: SemanticRegistry = field(default_factory=lambda: semantic_registry)
    symbol_table: SemanticSymbolTable = field(default_factory=lambda: semantic_symbol_table)
    artifact_store: Any | None = None
    options: BuilderOptions = field(default_factory=BuilderOptions)
