"""Node and Edge Factories for Framework Semantic Graph construction."""

from __future__ import annotations

from typing import Any

from karsasec.framework.id_generator import generate_semantic_node_id
from karsasec.framework.intermediate import (
    AuthDefinition,
    ConfigDefinition,
    ControllerDefinition,
    HandlerDefinition,
    MiddlewareDefinition,
    ModelDefinition,
    RouteDefinition,
    TemplateDefinition,
)
from karsasec.framework.semantic_models import (
    FrameworkSemanticEdge,
    FrameworkSemanticNode,
    SemanticEdgeType,
    SemanticNodeType,
)


class FrameworkNodeFactory:
    """Factory creating FrameworkSemanticNode instances for semantic definitions."""

    @staticmethod
    def create_route_node(route: RouteDefinition) -> FrameworkSemanticNode:
        file_path = route.origin.location_info.file_path
        line = route.origin.location_info.line
        qual_name = f"{route.method.upper()} {route.path}"
        node_id = generate_semantic_node_id(route.framework, SemanticNodeType.ROUTE.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.ROUTE,
            name=qual_name,
            language=route.language,
            cpg_node_id=route.cpg_ref,
            labels=("ROUTE", route.method.upper()),
            attributes={
                "path": route.path,
                "method": route.method.upper(),
                "handler": route.handler,
                "middleware_chain": list(route.middleware_chain),
                "framework": route.framework,
            },
            origin=route.origin,
        )

    @staticmethod
    def create_controller_node(controller: ControllerDefinition) -> FrameworkSemanticNode:
        file_path = controller.origin.location_info.file_path
        line = controller.origin.location_info.line
        qual_name = controller.class_name or controller.name
        node_id = generate_semantic_node_id(controller.framework, SemanticNodeType.CONTROLLER.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.CONTROLLER,
            name=controller.name,
            language=controller.language,
            cpg_node_id=controller.cpg_ref,
            labels=("CONTROLLER",),
            attributes={
                "class_name": controller.class_name,
                "handlers": list(controller.handlers),
                "parent_class": controller.parent_class,
                "framework": controller.framework,
            },
            origin=controller.origin,
        )

    @staticmethod
    def create_handler_node(handler: HandlerDefinition) -> FrameworkSemanticNode:
        file_path = handler.origin.location_info.file_path
        line = handler.origin.location_info.line
        qual_name = handler.function_name or handler.name
        node_id = generate_semantic_node_id(handler.framework, SemanticNodeType.HANDLER.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.HANDLER,
            name=handler.name,
            language=handler.language,
            cpg_node_id=handler.cpg_ref,
            labels=("HANDLER",),
            attributes={
                "function_name": handler.function_name,
                "parameters": list(handler.parameters),
                "return_type": handler.return_type,
                "framework": handler.framework,
            },
            origin=handler.origin,
        )

    @staticmethod
    def create_middleware_node(mw: MiddlewareDefinition) -> FrameworkSemanticNode:
        file_path = mw.origin.location_info.file_path
        line = mw.origin.location_info.line
        qual_name = mw.name
        node_id = generate_semantic_node_id(mw.framework, SemanticNodeType.MIDDLEWARE.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.MIDDLEWARE,
            name=mw.name,
            language=mw.language,
            cpg_node_id=mw.cpg_ref,
            labels=("MIDDLEWARE", mw.scope.upper()),
            attributes={
                "scope": mw.scope,
                "order": mw.order,
                "target_routes": list(mw.target_routes),
                "framework": mw.framework,
            },
            origin=mw.origin,
        )

    @staticmethod
    def create_model_node(model: ModelDefinition) -> FrameworkSemanticNode:
        file_path = model.origin.location_info.file_path
        line = model.origin.location_info.line
        qual_name = model.model_name
        node_id = generate_semantic_node_id(model.framework, SemanticNodeType.MODEL.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.MODEL,
            name=model.model_name,
            language=model.language,
            cpg_node_id=model.cpg_ref,
            labels=("MODEL", "ORM"),
            attributes={
                "table_name": model.table_name,
                "fields": list(model.fields),
                "relations": list(model.relations),
                "framework": model.framework,
            },
            origin=model.origin,
        )

    @staticmethod
    def create_config_node(config: ConfigDefinition) -> FrameworkSemanticNode:
        file_path = config.origin.location_info.file_path
        line = config.origin.location_info.line
        qual_name = config.key
        node_id = generate_semantic_node_id(config.framework, SemanticNodeType.CONFIG.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.CONFIG,
            name=config.key,
            language=config.language,
            cpg_node_id=config.cpg_ref,
            labels=("CONFIG",),
            attributes={
                "key": config.key,
                "value": str(config.value) if config.value is not None else None,
                "is_sensitive": config.is_sensitive,
                "framework": config.framework,
            },
            origin=config.origin,
        )

    @staticmethod
    def create_template_node(tmpl: TemplateDefinition) -> FrameworkSemanticNode:
        file_path = tmpl.origin.location_info.file_path
        line = tmpl.origin.location_info.line
        qual_name = tmpl.template_name
        node_id = generate_semantic_node_id(tmpl.framework, SemanticNodeType.TEMPLATE.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.TEMPLATE,
            name=tmpl.template_name,
            language=tmpl.language,
            cpg_node_id=tmpl.cpg_ref,
            labels=("TEMPLATE", tmpl.engine.upper()),
            attributes={
                "engine": tmpl.engine,
                "is_autoescape": tmpl.is_autoescape,
                "framework": tmpl.framework,
            },
            origin=tmpl.origin,
        )

    @staticmethod
    def create_auth_node(auth: AuthDefinition) -> FrameworkSemanticNode:
        file_path = auth.origin.location_info.file_path
        line = auth.origin.location_info.line
        qual_name = f"AUTH:{auth.auth_type}"
        node_id = generate_semantic_node_id(auth.framework, SemanticNodeType.AUTH.value, qual_name, file_path, line)

        return FrameworkSemanticNode(
            id=node_id,
            node_type=SemanticNodeType.AUTH,
            name=auth.auth_type,
            language=auth.language,
            cpg_node_id=auth.cpg_ref,
            labels=("AUTH", auth.auth_type.upper()),
            attributes={
                "auth_type": auth.auth_type,
                "protected_routes": list(auth.protected_routes),
                "roles_or_scopes": list(auth.roles_or_scopes),
                "framework": auth.framework,
            },
            origin=auth.origin,
        )


class FrameworkEdgeFactory:
    """Factory creating FrameworkSemanticEdge instances for relationships."""

    @staticmethod
    def create_edge(
        source_id: str,
        target_id: str,
        edge_type: SemanticEdgeType | str,
        attributes: dict[str, Any] | None = None,
    ) -> FrameworkSemanticEdge:
        etype = SemanticEdgeType(edge_type) if isinstance(edge_type, str) else edge_type
        return FrameworkSemanticEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=etype,
            attributes=attributes or {},
        )
