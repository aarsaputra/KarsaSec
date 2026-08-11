"""Flask Middleware Normalizer mapping candidates into MiddlewareDefinition ISR v1.0."""

from __future__ import annotations

from karsasec.framework.extractors.flask.middleware.state import (
    ErrorHandlerCandidate,
    ExtensionCandidate,
    FlaskMiddlewareState,
    MiddlewareCandidate,
)
from karsasec.framework.intermediate import MiddlewareDefinition
from karsasec.framework.origin import OriginMetadata, SourceLocation


class FlaskMiddlewareNormalizer:
    """Normalizes raw candidate records from FlaskMiddlewareState into ISR MiddlewareDefinition objects."""

    def __init__(self, state: FlaskMiddlewareState) -> None:
        self.state = state

    def normalize(
        self,
        candidates: list[MiddlewareCandidate] | None = None,
        error_handlers: list[ErrorHandlerCandidate] | None = None,
        extensions: list[ExtensionCandidate] | None = None,
        class_middlewares: list[MiddlewareCandidate] | None = None,
    ) -> list[MiddlewareDefinition]:
        """Converts raw candidate lists into normalized MiddlewareDefinition ISR objects."""
        c_hooks = candidates if candidates is not None else self.state.middleware_candidates
        c_errs = error_handlers if error_handlers is not None else self.state.error_handlers
        c_exts = extensions if extensions is not None else self.state.extensions
        c_cls = class_middlewares if class_middlewares is not None else self.state.class_middlewares

        result: list[MiddlewareDefinition] = []
        order_counter = 1

        # 1. Normalize request hooks (before_request, after_request, teardown)
        for cand in c_hooks:
            scope = cand.blueprint or "global"
            target_routes = (f"{scope}/*",) if scope != "global" else ("*",)

            location_info = SourceLocation(file_path=cand.file_path, line=cand.line)
            origin = OriginMetadata(location_info=location_info, evidence_list=cand.evidence)

            mw_def = MiddlewareDefinition(
                name=cand.name,
                scope=scope,
                order=order_counter,
                target_routes=target_routes,
                language="Python",
                framework="FLASK",
                confidence=cand.confidence,
                origin=origin,
            )
            result.append(mw_def)
            order_counter += 1

        # 2. Normalize extensions (CORS, Limiter, LoginManager, Cache)
        for ext in c_exts:
            location_info = SourceLocation(file_path=ext.file_path, line=ext.line)
            origin = OriginMetadata(location_info=location_info, evidence_list=ext.evidence)

            mw_def = MiddlewareDefinition(
                name=ext.extension_name,
                scope="global",
                order=order_counter,
                target_routes=("*",),
                language="Python",
                framework="FLASK",
                confidence=0.85,
                origin=origin,
            )
            result.append(mw_def)
            order_counter += 1

        # 3. Normalize error handlers
        for err in c_errs:
            scope = err.blueprint or "global"
            location_info = SourceLocation(file_path=err.file_path, line=err.line)
            origin = OriginMetadata(location_info=location_info, evidence_list=err.evidence)

            name = f"ErrorHandler[{err.exception_type}]"
            mw_def = MiddlewareDefinition(
                name=name,
                scope=scope,
                order=order_counter,
                target_routes=("*",),
                language="Python",
                framework="FLASK",
                confidence=0.95 if err.blueprint else 1.0,
                origin=origin,
            )
            result.append(mw_def)
            order_counter += 1

        # 4. Normalize class-based middleware
        for cls_mw in c_cls:
            location_info = SourceLocation(file_path=cls_mw.file_path, line=cls_mw.line)
            origin = OriginMetadata(location_info=location_info, evidence_list=cls_mw.evidence)

            mw_def = MiddlewareDefinition(
                name=cls_mw.name,
                scope="global",
                order=order_counter,
                target_routes=("*",),
                language="Python",
                framework="FLASK",
                confidence=0.80,
                origin=origin,
            )
            result.append(mw_def)
            order_counter += 1

        return result
