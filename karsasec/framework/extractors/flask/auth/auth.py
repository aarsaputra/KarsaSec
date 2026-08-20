"""Flask Auth Extractor implementing 3-phase collect -> validate -> emit lifecycle."""

from __future__ import annotations

from pathlib import Path

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.extractors.base import (
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.flask.auth.collector import FlaskAuthCollector
from karsasec.framework.extractors.flask.auth.normalizer import FlaskAuthNormalizer
from karsasec.framework.extractors.flask.auth.state import FlaskAuthState
from karsasec.framework.intermediate import AuthDefinition, IntermediateSemanticRepresentation
from karsasec.framework.origin import SourceLocation
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskAuthExtractor(SemanticExtractor):
    """Semantic Extractor for Flask Authentication & Authorization Intelligence."""

    KNOWN_PROVIDERS = {"flask-login", "flask-jwt-extended", "flask-httpauth", "session", "custom"}

    @property
    def name(self) -> str:
        return "FlaskAuthExtractor"

    @property
    def priority(self) -> int:
        return 12

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python",)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK", "flask")

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.AUTH,)

    def collect(self, ctx: ExtractorContext) -> FlaskAuthState:
        """Phase 1: Parse Python ASTs and collect raw Flask auth candidates into state."""
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

        collector = FlaskAuthCollector()
        return collector.collect_from_asts(ast_trees)

    def validate(
        self, raw_state: FlaskAuthState, ctx: ExtractorContext | None = None
    ) -> tuple[list[AuthDefinition], list[SemanticDiagnostic]]:
        """Phase 2: Normalize candidate records and run diagnostic validation checks."""
        normalizer = FlaskAuthNormalizer()
        auth_defs = list(normalizer.normalize(raw_state))

        diagnostics: list[SemanticDiagnostic] = []
        seen_policies: set[tuple[str, str, str, int]] = set()

        for cand in raw_state.auth_candidates:
            key = (cand.provider, cand.scheme, cand.handler, cand.line)
            if key in seen_policies:
                diag = SemanticDiagnostic(
                    code=ErrorCode.DUP_AUTH_POLICY,
                    severity=Severity.WARNING,
                    message=f"Duplicate auth policy for handler '{cand.handler}'",
                    location=SourceLocation(file_path=cand.file_path, line=cand.line),
                    evidence=cand.decorator,
                )
                diagnostics.append(diag)
            else:
                seen_policies.add(key)

            if cand.provider not in self.KNOWN_PROVIDERS:
                diag = SemanticDiagnostic(
                    code=ErrorCode.UNKNOWN_AUTH_PROVIDER,
                    severity=Severity.INFO,
                    message=f"Unknown auth provider '{cand.provider}'",
                    location=SourceLocation(file_path=cand.file_path, line=cand.line),
                )
                diagnostics.append(diag)

        for r_cand in raw_state.role_candidates:
            if not r_cand.roles:
                diag = SemanticDiagnostic(
                    code=ErrorCode.INVALID_ROLE,
                    severity=Severity.ERROR,
                    message=f"Role requirement for handler '{r_cand.handler}' is empty or invalid",
                    location=SourceLocation(file_path=r_cand.file_path, line=r_cand.line),
                )
                diagnostics.append(diag)

        for p_cand in raw_state.permission_candidates:
            if not p_cand.permissions:
                diag = SemanticDiagnostic(
                    code=ErrorCode.INVALID_PERMISSION,
                    severity=Severity.ERROR,
                    message=f"Permission requirement for handler '{p_cand.handler}' is empty or invalid",
                    location=SourceLocation(file_path=p_cand.file_path, line=p_cand.line),
                )
                diagnostics.append(diag)

        return auth_defs, diagnostics

    def emit(self, validated_auths: list[AuthDefinition], ctx: ExtractorContext | None = None) -> ExtractionResult:
        """Phase 3: Construct ExtractionResult populated with normalized AuthDefinitions."""
        isr = IntermediateSemanticRepresentation(auths=tuple(validated_auths))
        return ExtractionResult(
            isr=isr,
            statistics={"auths_count": len(validated_auths)},
        )
