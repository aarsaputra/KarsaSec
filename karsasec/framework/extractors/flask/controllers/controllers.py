"""Flask Controller Semantic Extractor implementing 3-phase collect -> validate -> emit lifecycle."""

from __future__ import annotations

from pathlib import Path

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.extractors.base import (
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.flask.controllers.collector import FlaskControllerCollector
from karsasec.framework.extractors.flask.controllers.normalizer import FlaskControllerNormalizer
from karsasec.framework.extractors.flask.controllers.state import FlaskControllerState
from karsasec.framework.intermediate import ControllerDefinition, HandlerDefinition, IntermediateSemanticRepresentation
from karsasec.framework.origin import SourceLocation
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskControllerExtractor(SemanticExtractor):
    """Semantic Extractor for Flask function-based controllers, MethodViews, Class-Based Views, and Handlers."""

    @property
    def name(self) -> str:
        return "FlaskControllerExtractor"

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
        return (ExtractorCapability.CONTROLLER,)

    def collect(self, ctx: ExtractorContext) -> FlaskControllerState:
        """Phase 1: Parse Python ASTs and collect raw Flask controller candidates into state."""
        state = FlaskControllerState()
        collector = FlaskControllerCollector(state)

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

    def validate(
        self, raw_state: FlaskControllerState, ctx: ExtractorContext | None = None
    ) -> tuple[tuple[list[ControllerDefinition], list[HandlerDefinition]], list[SemanticDiagnostic]]:
        """Phase 2: Normalize candidate records and run diagnostic validation checks."""
        normalizer = FlaskControllerNormalizer(raw_state)
        ctrl_defs, handler_defs = normalizer.normalize()

        diagnostics: list[SemanticDiagnostic] = []
        seen_ctrls: set[str] = set()

        for c in raw_state.controllers:
            if c.name in seen_ctrls:
                diag = SemanticDiagnostic(
                    code=ErrorCode.DUP_CONTROLLER,
                    severity=Severity.WARNING,
                    message=f"Duplicate controller definition '{c.name}'",
                    location=SourceLocation(file_path=c.file_path, line=c.line),
                )
                diagnostics.append(diag)
            else:
                seen_ctrls.add(c.name)

        return (ctrl_defs, handler_defs), diagnostics

    def emit(
        self,
        validated_tuple: tuple[list[ControllerDefinition], list[HandlerDefinition]],
        ctx: ExtractorContext | None = None,
    ) -> ExtractionResult:
        """Phase 3: Construct ExtractionResult populated with ControllerDefinition and HandlerDefinition ISR objects."""
        ctrl_defs, handler_defs = validated_tuple
        isr = IntermediateSemanticRepresentation(
            controllers=tuple(ctrl_defs),
            handlers=tuple(handler_defs),
        )
        return ExtractionResult(
            isr=isr,
            statistics={
                "controllers_count": len(ctrl_defs),
                "handlers_count": len(handler_defs),
            },
        )
