"""Framework Semantic Layer Package."""

from karsasec.framework.builder import FrameworkGraphBuilder, GraphFrozenError
from karsasec.framework.builder_context import BuilderContext, BuilderOptions
from karsasec.framework.cache import FrameworkCache, framework_cache
from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP, get_framework_capabilities, has_capability
from karsasec.framework.detector import FrameworkDetectionResult, FrameworkDetector
from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.extractors.base import (
    ExtractionError,
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.registry import ExtractorRegistry, extractor_registry
from karsasec.framework.factories import FrameworkEdgeFactory, FrameworkNodeFactory
from karsasec.framework.id_generator import generate_semantic_node_id
from karsasec.framework.integrity import FrameworkGraphIntegrityChecker
from karsasec.framework.intermediate import (
    CURRENT_ISR_SCHEMA_VERSION,
    AuthDefinition,
    ConfigDefinition,
    ControllerDefinition,
    DependencyDefinition,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    ISRMigrator,
    ISRSchemaValidationError,
    MiddlewareDefinition,
    ModelDefinition,
    ORMDefinition,
    RouteDefinition,
    ServiceDefinition,
    TemplateDefinition,
)
from karsasec.framework.manifest import CapabilityResolver, FrameworkManifest, ManifestLoader
from karsasec.framework.models import (
    DetectorResult,
    FrameworkCapability,
    FrameworkDefinition,
    FrameworkEdge,
    FrameworkGraph,
    FrameworkMetadata,
    FrameworkNode,
    FrameworkNodeType,
    FrameworkType,
    FrameworkVersion,
)
from karsasec.framework.optimizer import FrameworkGraphOptimizer
from karsasec.framework.origin import (
    Confidence,
    Evidence,
    ExtractorInfo,
    OriginMetadata,
    SourceLocation,
)
from karsasec.framework.pipeline import FrameworkSemanticPipeline
from karsasec.framework.registry import FrameworkRegistry, framework_registry
from karsasec.framework.reporter import FrameworkReporter
from karsasec.framework.resolver import FrameworkResolver
from karsasec.framework.semantic_models import (
    FrameworkSemanticEdge,
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    SemanticEdgeType,
    SemanticNodeType,
)
from karsasec.framework.semantic_registry import SemanticRegistry, semantic_registry
from karsasec.framework.serializer import FrameworkGraphSerializer, SerializationError
from karsasec.framework.snapshot import FrameworkGraphSnapshot, GraphDiffResult
from karsasec.framework.statistics import GraphStatistics
from karsasec.framework.symbol_table import SemanticSymbolTable, SymbolBinding, semantic_symbol_table
from karsasec.framework.validator import FrameworkValidator, ISRValidator

__all__ = [
    # E10-1 Core Detection Models
    "FrameworkType",
    "FrameworkCapability",
    "FrameworkVersion",
    "FrameworkDefinition",
    "DetectorResult",
    "FrameworkMetadata",
    "FrameworkNodeType",
    "FrameworkNode",
    "FrameworkEdge",
    "FrameworkGraph",
    "FrameworkRegistry",
    "framework_registry",
    "FrameworkDetector",
    "FrameworkDetectionResult",
    "FrameworkResolver",
    "FrameworkCache",
    "framework_cache",
    "FrameworkReporter",
    "FrameworkValidator",
    "FRAMEWORK_CAPABILITIES_MAP",
    "get_framework_capabilities",
    "has_capability",
    # E10-2A Core Semantic Foundation
    "CURRENT_ISR_SCHEMA_VERSION",
    "ISRMigrator",
    "ISRSchemaValidationError",
    "SemanticNodeType",

    "SemanticEdgeType",
    "FrameworkSemanticNode",
    "FrameworkSemanticEdge",
    "FrameworkSemanticGraph",
    "Confidence",
    "SourceLocation",
    "Evidence",
    "ExtractorInfo",
    "OriginMetadata",
    "RouteDefinition",
    "MiddlewareDefinition",
    "ControllerDefinition",
    "HandlerDefinition",
    "ServiceDefinition",
    "ModelDefinition",
    "ORMDefinition",
    "AuthDefinition",
    "ConfigDefinition",
    "TemplateDefinition",
    "DependencyDefinition",
    "IntermediateSemanticRepresentation",
    "SemanticRegistry",
    "semantic_registry",
    "SymbolBinding",
    "SemanticSymbolTable",
    "semantic_symbol_table",
    # E10-2B Extractor Infrastructure
    "ExtractorCapability",
    "ExtractionError",
    "ExtractorContext",
    "ExtractionResult",
    "SemanticExtractor",
    "ExtractorRegistry",
    "extractor_registry",
    "Severity",
    "ErrorCode",
    "SemanticDiagnostic",
    "FrameworkManifest",
    "ManifestLoader",
    "CapabilityResolver",
    "ISRValidator",
    "FrameworkSemanticPipeline",
    # E10-2C Framework Semantic Graph Engine
    "generate_semantic_node_id",
    "FrameworkNodeFactory",
    "FrameworkEdgeFactory",
    "BuilderOptions",
    "BuilderContext",
    "FrameworkGraphBuilder",
    "GraphFrozenError",
    "FrameworkGraphOptimizer",
    "FrameworkGraphIntegrityChecker",
    "FrameworkGraphSerializer",
    "SerializationError",
    "GraphStatistics",
    "FrameworkGraphSnapshot",
    "GraphDiffResult",
]
