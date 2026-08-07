"""FrameworkValidator and ISRValidator for verifying FrameworkGraph and ISR integrity."""

from __future__ import annotations

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.intermediate import IntermediateSemanticRepresentation
from karsasec.framework.models import DetectorResult, FrameworkDefinition, FrameworkGraph


class FrameworkValidator:
    """Validates structural integrity of FrameworkGraph, confidence scores, and definitions."""

    def validate_definition(self, definition: FrameworkDefinition) -> list[str]:
        """Validates a FrameworkDefinition object."""
        errors: list[str] = []
        if not definition.id or not definition.name:
            errors.append("FrameworkDefinition missing required id or name")
        if not definition.language:
            errors.append("FrameworkDefinition missing required language")
        return errors

    def validate_detector_result(self, result: DetectorResult) -> list[str]:
        """Validates a DetectorResult object."""
        errors: list[str] = []
        if not (0.0 <= result.confidence <= 1.0):
            errors.append(f"Confidence score {result.confidence} out of range [0.0, 1.0]")
        if not result.reason:
            errors.append("DetectorResult missing descriptive reason")
        return errors

    def validate_graph(self, graph: FrameworkGraph) -> list[str]:
        """Validates node uniqueness, node types, and edge connectivity in FrameworkGraph."""
        errors: list[str] = []
        node_ids = set(graph.nodes.keys())

        for edge in graph.edges:
            if edge.source_id not in node_ids:
                errors.append(f"Dangling edge source: '{edge.source_id}' not found in graph nodes")
            if edge.target_id not in node_ids:
                errors.append(f"Dangling edge target: '{edge.target_id}' not found in graph nodes")

        return errors


class ISRValidator:
    """Validates IntermediateSemanticRepresentation (ISR) instances and emits compiler-style diagnostics."""

    def validate(self, isr: IntermediateSemanticRepresentation) -> list[SemanticDiagnostic]:
        """Performs semantic validation on ISR definitions."""
        diagnostics: list[SemanticDiagnostic] = []

        # Track registered definitions
        known_routes: set[tuple[str, str]] = set()  # (method, path)
        known_handlers: set[str] = {h.name for h in isr.handlers}
        known_controllers: set[str] = {c.name for c in isr.controllers}
        known_models: set[str] = {m.model_name for m in isr.models}

        # 1. Duplicate Routes
        for r in isr.routes:
            key = (r.method.upper(), r.path)
            if key in known_routes:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.DUP_ROUTE,
                        severity=Severity.ERROR,
                        message=f"Duplicate route endpoint detected: {r.method} {r.path}",
                        location=r.origin.location_info,
                        evidence=f"{r.method} {r.path} -> {r.handler}",
                        remediation="Ensure route paths and methods are unique across routing tables.",
                    )
                )
            else:
                known_routes.add(key)

            # 2. Missing Handlers for routes
            if r.handler and r.handler not in known_handlers:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.MISSING_HANDLER,
                        severity=Severity.WARNING,
                        message=f"Route '{r.path}' references handler '{r.handler}' which is not defined in ISR handlers",
                        location=r.origin.location_info,
                        evidence=f"handler: {r.handler}",
                        remediation="Declare or register the missing request handler function.",
                    )
                )

        # 3. Duplicate Handlers
        seen_handlers: set[str] = set()
        for h in isr.handlers:
            if h.name in seen_handlers:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.DUP_HANDLER,
                        severity=Severity.ERROR,
                        message=f"Duplicate handler definition detected: {h.name}",
                        location=h.origin.location_info,
                        evidence=h.name,
                        remediation="Ensure handler function names are distinct.",
                    )
                )
            else:
                seen_handlers.add(h.name)

        # 4. Missing Controllers for handlers or routes if class_name specified
        for ctrl in isr.controllers:
            for h_name in ctrl.handlers:
                if h_name not in known_handlers:
                    diagnostics.append(
                        SemanticDiagnostic(
                            code=ErrorCode.MISSING_HANDLER,
                            severity=Severity.WARNING,
                            message=f"Controller '{ctrl.name}' references handler '{h_name}' which is not declared",
                            location=ctrl.origin.location_info,
                            evidence=h_name,
                        )
                    )

        # 5. Orphan Middleware
        for mw in isr.middlewares:
            if mw.scope == "route":
                for target_route in mw.target_routes:
                    if not any(r.path == target_route for r in isr.routes):
                        diagnostics.append(
                            SemanticDiagnostic(
                                code=ErrorCode.ORPHAN_MIDDLEWARE,
                                severity=Severity.WARNING,
                                message=f"Route middleware '{mw.name}' targets route '{target_route}' which does not exist",
                                location=mw.origin.location_info,
                                evidence=target_route,
                                remediation="Verify middleware target route binding or path definition.",
                            )
                        )

        # 6. Duplicate Models
        seen_models: set[str] = set()
        for m in isr.models:
            if m.model_name in seen_models:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.DUP_MODEL,
                        severity=Severity.ERROR,
                        message=f"Duplicate ORM model definition detected: {m.model_name}",
                        location=m.origin.location_info,
                        evidence=m.model_name,
                    )
                )
            else:
                seen_models.add(m.model_name)

        # 7. Broken Dependencies
        for dep in isr.dependencies:
            if dep.target_class_or_fn and dep.target_class_or_fn not in known_handlers and dep.target_class_or_fn not in known_controllers:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.BROKEN_DEP,
                        severity=Severity.WARNING,
                        message=f"Dependency injection '{dep.dependency_name}' references target '{dep.target_class_or_fn}' which is not defined",
                        location=dep.origin.location_info,
                        evidence=dep.target_class_or_fn,
                    )
                )

        # 8. Unknown Auth
        valid_auth_types = {"JWT", "OAUTH", "OAUTH2", "SESSION", "COOKIE", "APIKEY", "RBAC", "ABAC", "BASIC"}
        for auth in isr.auths:
            if auth.auth_type.upper() not in valid_auth_types:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.UNKNOWN_AUTH,
                        severity=Severity.WARNING,
                        message=f"Unknown or unrecognised authentication policy type: '{auth.auth_type}'",
                        location=auth.origin.location_info,
                        evidence=auth.auth_type,
                        remediation="Use standard auth types (JWT, Session, Cookie, OAuth2, APIKey, RBAC).",
                    )
                )

        return diagnostics
