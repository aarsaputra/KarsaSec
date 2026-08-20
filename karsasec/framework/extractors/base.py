"""Abstract Base Class and context/result data structures for Framework Semantic Extractors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.framework.intermediate import IntermediateSemanticRepresentation


class ExtractorCapability(StrEnum):
    """Capabilities provided by semantic extractors."""

    ROUTING = "routing"
    MIDDLEWARE = "middleware"
    CONTROLLER = "controller"
    ORM = "orm"
    AUTH = "auth"
    CONFIG = "config"
    TEMPLATE = "template"
    DEPENDENCY_INJECTION = "dependency_injection"
    WEBSOCKET = "websocket"
    API = "api"


class ExtractionError(Exception):
    """Exception raised during semantic extraction failure."""

    def __init__(self, message: str, extractor_name: str = "UnknownExtractor", cause: Exception | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.extractor_name = extractor_name
        self.cause = cause


@dataclass
class ExtractorContext:
    """Context provided to semantic extractors containing metadata, AST, CPG, and store references."""

    project_path: str = ""
    language: str = "Generic"
    framework: str = "GENERIC"
    ast_nodes: list[Any] = field(default_factory=list)
    cpg: Any | None = None
    artifact_store: Any | None = None
    pass_manager: Any | None = None
    config: dict[str, Any] = field(default_factory=dict)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("karsasec.framework.extractor"))


@dataclass
class ExtractionResult:
    """Result object returned by a semantic extractor execution."""

    isr: IntermediateSemanticRepresentation = field(default_factory=IntermediateSemanticRepresentation)
    diagnostics: list[Any] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    telemetry: dict[str, float] = field(default_factory=dict)

    def merge(self, other: ExtractionResult) -> ExtractionResult:
        """Merges another ExtractionResult into self."""
        # Merge ISR
        merged_routes = self.isr.routes + other.isr.routes
        merged_mw = self.isr.middlewares + other.isr.middlewares
        merged_ctrl = self.isr.controllers + other.isr.controllers
        merged_h = self.isr.handlers + other.isr.handlers
        merged_s = self.isr.services + other.isr.services
        merged_o = self.isr.orms + other.isr.orms
        merged_m = self.isr.models + other.isr.models
        merged_a = self.isr.auths + other.isr.auths
        merged_cfg = self.isr.configs + other.isr.configs
        merged_t = self.isr.templates + other.isr.templates
        merged_d = self.isr.dependencies + other.isr.dependencies

        merged_isr = IntermediateSemanticRepresentation(
            routes=merged_routes,
            middlewares=merged_mw,
            controllers=merged_ctrl,
            handlers=merged_h,
            services=merged_s,
            orms=merged_o,
            models=merged_m,
            auths=merged_a,
            configs=merged_cfg,
            templates=merged_t,
            dependencies=merged_d,
        )

        merged_diagnostics = list(self.diagnostics) + list(other.diagnostics)
        merged_warnings = list(self.warnings) + list(other.warnings)
        merged_stats = {**self.statistics, **other.statistics}
        merged_telemetry = {**self.telemetry, **other.telemetry}

        return ExtractionResult(
            isr=merged_isr,
            diagnostics=merged_diagnostics,
            warnings=merged_warnings,
            statistics=merged_stats,
            telemetry=merged_telemetry,
        )


class SemanticExtractor(ABC):
    """Abstract Base Class for all framework semantic extractors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name of the extractor."""
        ...

    @property
    def priority(self) -> int:
        """Priority order of execution (lower number runs earlier). Default is 100."""
        return 100

    @property
    def dependencies(self) -> tuple[str, ...]:
        """Names of extractors that must execute before this extractor."""
        return ()

    @property
    def supported_languages(self) -> tuple[str, ...]:
        """Tuple of supported programming languages (e.g. ('Python', 'JavaScript'))."""
        return ("Generic",)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        """Tuple of supported frameworks (e.g. ('FLASK', 'FASTAPI'))."""
        return ("GENERIC",)

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        """Capabilities provided by this extractor."""
        return ()

    @property
    def incremental(self) -> bool:
        """Whether this extractor supports incremental file-level analysis."""
        return True

    @property
    def cacheable(self) -> bool:
        """Whether extraction output can be cached across scans."""
        return True

    def can_extract(self, ctx: ExtractorContext) -> bool:
        """Determines if extractor can run given current ExtractorContext."""
        lang_ok = (
            "Generic" in self.supported_languages
            or ctx.language == "Generic"
            or ctx.language in self.supported_languages
        )
        fw_ok = (
            "GENERIC" in self.supported_frameworks
            or ctx.framework == "GENERIC"
            or ctx.framework in self.supported_frameworks
        )
        return lang_ok and fw_ok

    def collect(self, ctx: ExtractorContext) -> Any:
        """Phase 1: Collects raw data and candidate elements from AST/CPG."""
        return None

    def validate(self, raw_items: Any, ctx: ExtractorContext) -> tuple[Any, list[Any]]:
        """Phase 2: Validates raw data and returns (validated_items, diagnostics)."""
        return raw_items, []

    def emit(self, validated_items: Any, ctx: ExtractorContext) -> ExtractionResult:
        """Phase 3: Constructs final ExtractionResult from validated items."""
        return ExtractionResult()

    def extract(self, ctx: ExtractorContext) -> ExtractionResult:
        """Executes complete extractor lifecycle: collect() -> validate() -> emit()."""
        raw_items = self.collect(ctx)
        validated_items, diagnostics = self.validate(raw_items, ctx)
        res = self.emit(validated_items, ctx)
        if diagnostics:
            res.diagnostics.extend(diagnostics)
        return res
