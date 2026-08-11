"""Flask Middleware Semantic Extractor implementing 3-phase collect -> validate -> emit lifecycle."""

from __future__ import annotations

from pathlib import Path

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.extractors.base import (
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.flask.middleware.collector import FlaskMiddlewareCollector
from karsasec.framework.extractors.flask.middleware.normalizer import FlaskMiddlewareNormalizer
from karsasec.framework.extractors.flask.middleware.state import FlaskMiddlewareState
from karsasec.framework.intermediate import IntermediateSemanticRepresentation, MiddlewareDefinition
from karsasec.framework.origin import SourceLocation
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskMiddlewareExtractor(SemanticExtractor):
    """Semantic Extractor for Flask request lifecycle hooks, error handlers, extensions, and class middleware."""

    KNOWN_EXTENSIONS = {
        "CORS", "FlaskCors",
        "Limiter", "FlaskLimiter",
        "LoginManager", "FlaskLogin",
        "Cache", "FlaskCache",
        "CSRFProtect", "FlaskWTF",
        "Session", "FlaskSession",
        "Bcrypt", "Talisman",
    }

    @property
    def name(self) -> str:
        return "FlaskMiddlewareExtractor"

    @property
    def priority(self) -> int:
        return 10

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python",)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK", "flask")

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.MIDDLEWARE,)

    def collect(self, ctx: ExtractorContext) -> FlaskMiddlewareState:
        """Phase 1: Parse Python ASTs and collect raw Flask middleware candidates into state."""
        state = FlaskMiddlewareState()
        collector = FlaskMiddlewareCollector(state)

        ast_trees: list[ASTNodeWrapper] = []

        if ctx.ast_nodes:
            for node in ctx.ast_nodes:
                if isinstance(node, ASTNodeWrapper):
                    ast_trees.append(node)
                elif hasattr(node, "body") or hasattr(node, "__class__"):
                    ast_trees.append(PythonASTAdapter.from_ast(node))

        if ctx.project_path:
            project_path = Path(ctx.project_path)
            if project_path.is_file() and project_path.suffix == ".py":
                tree = PythonASTAdapter.parse_file(project_path)
                if tree:
                    ast_trees.append(tree)
            elif project_path.is_dir():
                for py_file in sorted(project_path.rglob("*.py")):
                    if not py_file.name.startswith("."):
                        tree = PythonASTAdapter.parse_file(py_file)
                        if tree:
                            ast_trees.append(tree)

        collector.collect_from_asts(ast_trees)
        return state

    def validate(self, raw_state: FlaskMiddlewareState, ctx: ExtractorContext | None = None) -> tuple[list[MiddlewareDefinition], list[SemanticDiagnostic]]:
        """Phase 2: Normalize candidate records and run diagnostic validation checks."""
        normalizer = FlaskMiddlewareNormalizer(raw_state)
        mw_defs = normalizer.normalize()

        diagnostics: list[SemanticDiagnostic] = []
        seen_candidates: set[tuple[str, str, str | None]] = set()

        for mw in raw_state.middleware_candidates:
            key = (mw.handler, mw.phase, mw.blueprint)
            if key in seen_candidates:
                diag = SemanticDiagnostic(
                    code=ErrorCode.DUP_MIDDLEWARE,
                    severity=Severity.WARNING,
                    message=f"Duplicate middleware handler '{mw.handler}' in phase '{mw.phase}'",
                    location=SourceLocation(file_path=mw.file_path, line=mw.line),
                    evidence=mw.decorator,
                )
                diagnostics.append(diag)
            else:
                seen_candidates.add(key)

            if not mw.handler or mw.handler.startswith("<"):
                diag = SemanticDiagnostic(
                    code=ErrorCode.INVALID_MIDDLEWARE_HANDLER,
                    severity=Severity.ERROR,
                    message=f"Invalid middleware handler name '{mw.handler}'",
                    location=SourceLocation(file_path=mw.file_path, line=mw.line),
                )
                diagnostics.append(diag)

        for ext in raw_state.extensions:
            if ext.extension_name not in self.KNOWN_EXTENSIONS and not any(k in ext.extension_name for k in ("CORS", "Limiter", "Login", "Cache")):
                diag = SemanticDiagnostic(
                    code=ErrorCode.UNKNOWN_EXTENSION,
                    severity=Severity.INFO,
                    message=f"Unknown or custom Flask extension initialization '{ext.extension_name}'",
                    location=SourceLocation(file_path=ext.file_path, line=ext.line),
                    evidence=ext.constructor,
                )
                diagnostics.append(diag)

        return mw_defs, diagnostics

    def emit(self, validated_mw: list[MiddlewareDefinition], ctx: ExtractorContext | None = None) -> ExtractionResult:
        """Phase 3: Construct ExtractionResult populated with normalized MiddlewareDefinitions."""
        isr = IntermediateSemanticRepresentation(middlewares=tuple(validated_mw))
        return ExtractionResult(
            isr=isr,
            statistics={"middlewares_count": len(validated_mw)},
        )
