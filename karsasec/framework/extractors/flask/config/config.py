"""Flask Configuration Intelligence Semantic Extractor implementation."""

from __future__ import annotations

from pathlib import Path

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.extractors.base import (
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.flask.config.collector import FlaskConfigCollector
from karsasec.framework.extractors.flask.config.normalizer import FlaskConfigNormalizer
from karsasec.framework.extractors.flask.config.state import FlaskConfigState
from karsasec.framework.intermediate import ConfigDefinition, IntermediateSemanticRepresentation
from karsasec.framework.origin import SourceLocation
from karsasec.framework.parser.ast_adapter import PythonASTAdapter


class FlaskConfigExtractor(SemanticExtractor):
    """Semantic Extractor for Flask Configuration Intelligence."""

    @property
    def name(self) -> str:
        return "FlaskConfigExtractor"

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python",)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK", "flask")

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.CONFIG,)

    def collect(self, ctx: ExtractorContext) -> FlaskConfigState:
        """Phase 1: Parse Python ASTs and collect raw Flask configuration candidates into state."""
        state = FlaskConfigState()
        collector = FlaskConfigCollector(state)

        proj_path = Path(ctx.project_path)
        if proj_path.is_file() and proj_path.suffix == ".py":
            tree = PythonASTAdapter.parse_file(proj_path)
            if tree:
                collector.collect_from_ast(tree)
        elif proj_path.is_dir():
            trees = PythonASTAdapter.parse_directory(proj_path)
            collector.collect_from_asts(trees)

        return state

    def validate(
        self, state: FlaskConfigState, ctx: ExtractorContext | None = None
    ) -> tuple[list[ConfigDefinition], list[SemanticDiagnostic]]:
        """Phase 2: Normalize candidates into ISR objects and emit semantic diagnostics."""
        normalizer = FlaskConfigNormalizer(state)
        config_defs = normalizer.normalize()
        diagnostics: list[SemanticDiagnostic] = []

        seen_keys: set[str] = set()
        has_secret_key = False

        for c_def in config_defs:
            if c_def.key in seen_keys and not c_def.key.startswith("__"):
                loc = c_def.origin.location_info
                diag = SemanticDiagnostic(
                    code=ErrorCode.DUP_CONFIG_KEY,
                    severity=Severity.WARNING,
                    message=f"Duplicate configuration key '{c_def.key}' detected.",
                    location=loc,
                )
                diagnostics.append(diag)
            seen_keys.add(c_def.key)

            if c_def.key == "SECRET_KEY":
                has_secret_key = True
                if isinstance(c_def.value, str) and c_def.value.lower() in {
                    "dev",
                    "development",
                    "secret",
                    "123456",
                    "change_me",
                    "test",
                }:
                    loc = c_def.origin.location_info
                    diag = SemanticDiagnostic(
                        code=ErrorCode.WEAK_SECRET_KEY,
                        severity=Severity.ERROR,
                        message=f"Weak or default SECRET_KEY '{c_def.value}' detected.",
                        location=loc,
                    )
                    diagnostics.append(diag)

            if c_def.key == "DEBUG" and c_def.value is True:
                loc = c_def.origin.location_info
                diag = SemanticDiagnostic(
                    code=ErrorCode.DANGEROUS_CONFIG,
                    severity=Severity.WARNING,
                    message="DEBUG mode explicitly enabled in configuration.",
                    location=loc,
                )
                diagnostics.append(diag)

        # Check for duplicate candidates in raw state if normalizer didn't emit duplicates
        if len(state.configs) > len(config_defs) and not any(d.code == ErrorCode.DUP_CONFIG_KEY for d in diagnostics):
            loc = config_defs[0].origin.location_info if config_defs else SourceLocation(file_path="", line=1)
            diagnostics.append(
                SemanticDiagnostic(
                    code=ErrorCode.DUP_CONFIG_KEY,
                    severity=Severity.WARNING,
                    message="Duplicate configuration candidates detected.",
                    location=loc,
                )
            )

        if not has_secret_key and config_defs:
            loc = SourceLocation(file_path=config_defs[0].origin.location_info.file_path, line=1)
            diag = SemanticDiagnostic(
                code=ErrorCode.MISSING_SECRET_KEY,
                severity=Severity.WARNING,
                message="SECRET_KEY is missing from Flask application configuration.",
                location=loc,
            )
            diagnostics.append(diag)

        return config_defs, diagnostics

    def emit(self, validated_items: list[ConfigDefinition], ctx: ExtractorContext | None = None) -> ExtractionResult:
        """Phase 3: Package ConfigDefinitions into IntermediateSemanticRepresentation result."""
        isr = IntermediateSemanticRepresentation(
            configs=tuple(validated_items),
        )
        return ExtractionResult(isr=isr)
