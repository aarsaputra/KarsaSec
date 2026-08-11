"""Transforms raw Flask controller and handler candidates into ISR v1.0 definitions."""

from __future__ import annotations

from karsasec.framework.extractors.flask.controllers.state import FlaskControllerState
from karsasec.framework.intermediate import ControllerDefinition, HandlerDefinition
from karsasec.framework.origin import OriginMetadata, SourceLocation


class FlaskControllerNormalizer:
    """Normalizes ControllerCandidates and HandlerCandidates into ISR v1.0 definitions."""

    def __init__(self, state: FlaskControllerState) -> None:
        self.state = state

    def normalize(self) -> tuple[list[ControllerDefinition], list[HandlerDefinition]]:
        ctrl_defs: list[ControllerDefinition] = []
        handler_defs: list[HandlerDefinition] = []

        # 1. Normalize HandlerCandidates
        seen_handlers: set[str] = set()
        for h in self.state.handlers:
            if h.qualified_name in seen_handlers:
                continue
            seen_handlers.add(h.qualified_name)

            loc = SourceLocation(file_path=h.file_path, line=h.line)
            origin = OriginMetadata(location_info=loc, evidence_list=h.evidence)

            h_def = HandlerDefinition(
                name=h.name,
                function_name=h.function_name,
                parameters=h.parameters,
                return_type=h.return_type,
                language="Python",
                framework="FLASK",
                confidence=h.confidence,
                origin=origin,
            )
            handler_defs.append(h_def)

        # 2. Normalize ControllerCandidates
        seen_controllers: set[str] = set()
        for c in self.state.controllers:
            if c.name in seen_controllers:
                continue
            seen_controllers.add(c.name)

            loc = SourceLocation(file_path=c.file_path, line=c.line)
            origin = OriginMetadata(location_info=loc, evidence_list=c.evidence)

            # Resolve bound handlers and as_view dynamic bindings if present
            class_name = c.name if c.controller_type in {"method_view", "class_view"} else ""
            parent_class = c.parent_class

            # Dynamic confidence adjustments
            confidence = c.confidence
            if c.name in self.state.as_view_map:
                confidence = 0.80

            c_def = ControllerDefinition(
                name=c.name,
                class_name=class_name,
                handlers=c.handlers,
                parent_class=parent_class,
                language="Python",
                framework="FLASK",
                confidence=confidence,
                origin=origin,
            )
            ctrl_defs.append(c_def)

        return ctrl_defs, handler_defs
