"""Intermediate Semantic Representation (ISR) container and definition dataclasses."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.id_generator import generate_semantic_node_id
from karsasec.framework.origin import OriginMetadata

CURRENT_ISR_SCHEMA_VERSION = "1.0"


class ISRSchemaValidationError(Exception):
    """Exception raised when an ISR payload fails schema validation."""
    pass


@dataclass(frozen=True)
class RouteDefinition:
    """HTTP Route endpoint definition."""
    path: str
    method: str
    handler: str
    middleware_chain: tuple[str, ...] = ()
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "route", f"{self.method} {self.path}", self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "path": self.path,
            "method": self.method,
            "handler": self.handler,
            "middleware_chain": list(self.middleware_chain),
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RouteDefinition:
        return cls(
            path=data["path"],
            method=data["method"],
            handler=data["handler"],
            middleware_chain=tuple(data.get("middleware_chain", [])),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class MiddlewareDefinition:
    """Middleware component definition."""
    name: str
    scope: str = "global"
    order: int = 0
    target_routes: tuple[str, ...] = ()
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "middleware", self.name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "name": self.name,
            "scope": self.scope,
            "order": self.order,
            "target_routes": list(self.target_routes),
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MiddlewareDefinition:
        return cls(
            name=data["name"],
            scope=data.get("scope", "global"),
            order=data.get("order", 0),
            target_routes=tuple(data.get("target_routes", [])),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class ControllerDefinition:
    """Controller component definition."""
    name: str
    class_name: str = ""
    handlers: tuple[str, ...] = ()
    parent_class: str | None = None
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "controller", self.name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "name": self.name,
            "class_name": self.class_name,
            "handlers": list(self.handlers),
            "parent_class": self.parent_class,
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ControllerDefinition:
        return cls(
            name=data["name"],
            class_name=data.get("class_name", ""),
            handlers=tuple(data.get("handlers", [])),
            parent_class=data.get("parent_class"),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class HandlerDefinition:
    """Request handler function/method definition."""
    name: str
    function_name: str
    parameters: tuple[str, ...] = ()
    return_type: str = "Any"
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "handler", self.name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "name": self.name,
            "function_name": self.function_name,
            "parameters": list(self.parameters),
            "return_type": self.return_type,
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HandlerDefinition:
        return cls(
            name=data["name"],
            function_name=data.get("function_name", data["name"]),
            parameters=tuple(data.get("parameters", [])),
            return_type=data.get("return_type", "Any"),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class ServiceDefinition:
    """Service or business logic component definition."""
    name: str
    service_type: str = "generic"
    methods: tuple[str, ...] = ()
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "service", self.name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "name": self.name,
            "service_type": self.service_type,
            "methods": list(self.methods),
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceDefinition:
        return cls(
            name=data["name"],
            service_type=data.get("service_type", "generic"),
            methods=tuple(data.get("methods", [])),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class ModelDefinition:
    """Database model entity definition."""
    model_name: str
    table_name: str = ""
    fields: tuple[str, ...] = ()
    relations: tuple[str, ...] = ()
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "model", self.model_name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "model_name": self.model_name,
            "table_name": self.table_name,
            "fields": list(self.fields),
            "relations": list(self.relations),
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelDefinition:
        return cls(
            model_name=data["model_name"],
            table_name=data.get("table_name", ""),
            fields=tuple(data.get("fields", [])),
            relations=tuple(data.get("relations", [])),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class ORMDefinition:
    """Object-Relational Mapping component definition."""
    orm_name: str
    models: tuple[ModelDefinition, ...] = ()
    query_methods: tuple[str, ...] = ()
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "orm", self.orm_name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "orm_name": self.orm_name,
            "models": [m.to_dict() for m in self.models],
            "query_methods": list(self.query_methods),
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ORMDefinition:
        return cls(
            orm_name=data["orm_name"],
            models=tuple(ModelDefinition.from_dict(m) for m in data.get("models", [])),
            query_methods=tuple(data.get("query_methods", [])),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class AuthDefinition:
    """Authentication/Authorization policy definition."""
    auth_type: str = "JWT"
    protected_routes: tuple[str, ...] = ()
    roles_or_scopes: tuple[str, ...] = ()
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "auth", self.auth_type, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "auth_type": self.auth_type,
            "protected_routes": list(self.protected_routes),
            "roles_or_scopes": list(self.roles_or_scopes),
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthDefinition:
        return cls(
            auth_type=data.get("auth_type", "JWT"),
            protected_routes=tuple(data.get("protected_routes", [])),
            roles_or_scopes=tuple(data.get("roles_or_scopes", [])),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class ConfigDefinition:
    """Framework configuration setting definition."""
    key: str
    value: Any = None
    is_sensitive: bool = False
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "config", self.key, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "key": self.key,
            "value": self.value,
            "is_sensitive": self.is_sensitive,
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConfigDefinition:
        return cls(
            key=data["key"],
            value=data.get("value"),
            is_sensitive=data.get("is_sensitive", False),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class TemplateDefinition:
    """Template view component definition."""
    template_name: str
    engine: str = "Jinja2"
    is_autoescape: bool = True
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "template", self.template_name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "template_name": self.template_name,
            "engine": self.engine,
            "is_autoescape": self.is_autoescape,
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TemplateDefinition:
        return cls(
            template_name=data["template_name"],
            engine=data.get("engine", "Jinja2"),
            is_autoescape=data.get("is_autoescape", True),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class DependencyDefinition:
    """Dependency injection definition."""
    dependency_name: str
    target_class_or_fn: str
    provider: str = "Container"
    language: str = "Generic"
    framework: str = "GENERIC"
    confidence: float = 1.0
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    cpg_ref: str | None = None
    ast_ref: str | None = None
    ir_ref: str | None = None
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    @property
    def semantic_id(self) -> str:
        return generate_semantic_node_id(self.framework, "dependency", self.dependency_name, self.origin.location_info.file_path, self.origin.location_info.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "dependency_name": self.dependency_name,
            "target_class_or_fn": self.target_class_or_fn,
            "provider": self.provider,
            "language": self.language,
            "framework": self.framework,
            "confidence": self.confidence,
            "schema_version": self.schema_version,
            "cpg_ref": self.cpg_ref,
            "ast_ref": self.ast_ref,
            "ir_ref": self.ir_ref,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DependencyDefinition:
        return cls(
            dependency_name=data["dependency_name"],
            target_class_or_fn=data.get("target_class_or_fn", ""),
            provider=data.get("provider", "Container"),
            language=data.get("language", "Generic"),
            framework=data.get("framework", "GENERIC"),
            confidence=float(data.get("confidence", 1.0)),
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            cpg_ref=data.get("cpg_ref"),
            ast_ref=data.get("ast_ref"),
            ir_ref=data.get("ir_ref"),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class IntermediateSemanticRepresentation:
    """Container holding all raw extracted framework semantic definitions before graph construction."""
    schema_version: str = CURRENT_ISR_SCHEMA_VERSION
    routes: tuple[RouteDefinition, ...] = ()
    middlewares: tuple[MiddlewareDefinition, ...] = ()
    controllers: tuple[ControllerDefinition, ...] = ()
    handlers: tuple[HandlerDefinition, ...] = ()
    services: tuple[ServiceDefinition, ...] = ()
    orms: tuple[ORMDefinition, ...] = ()
    models: tuple[ModelDefinition, ...] = ()
    auths: tuple[AuthDefinition, ...] = ()
    configs: tuple[ConfigDefinition, ...] = ()
    templates: tuple[TemplateDefinition, ...] = ()
    dependencies: tuple[DependencyDefinition, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "routes": [r.to_dict() for r in self.routes],
            "middlewares": [m.to_dict() for m in self.middlewares],
            "controllers": [c.to_dict() for c in self.controllers],
            "handlers": [h.to_dict() for h in self.handlers],
            "services": [s.to_dict() for s in self.services],
            "orms": [o.to_dict() for o in self.orms],
            "models": [m.to_dict() for m in self.models],
            "auths": [a.to_dict() for a in self.auths],
            "configs": [cfg.to_dict() for cfg in self.configs],
            "templates": [t.to_dict() for t in self.templates],
            "dependencies": [d.to_dict() for d in self.dependencies],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IntermediateSemanticRepresentation:
        return cls(
            schema_version=data.get("schema_version", CURRENT_ISR_SCHEMA_VERSION),
            routes=tuple(RouteDefinition.from_dict(r) for r in data.get("routes", [])),
            middlewares=tuple(MiddlewareDefinition.from_dict(m) for m in data.get("middlewares", [])),
            controllers=tuple(ControllerDefinition.from_dict(c) for c in data.get("controllers", [])),
            handlers=tuple(HandlerDefinition.from_dict(h) for h in data.get("handlers", [])),
            services=tuple(ServiceDefinition.from_dict(s) for s in data.get("services", [])),
            orms=tuple(ORMDefinition.from_dict(o) for o in data.get("orms", [])),
            models=tuple(ModelDefinition.from_dict(m) for m in data.get("models", [])),
            auths=tuple(AuthDefinition.from_dict(a) for a in data.get("auths", [])),
            configs=tuple(ConfigDefinition.from_dict(cfg) for cfg in data.get("configs", [])),
            templates=tuple(TemplateDefinition.from_dict(t) for t in data.get("templates", [])),
            dependencies=tuple(DependencyDefinition.from_dict(d) for d in data.get("dependencies", [])),
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> IntermediateSemanticRepresentation:
        return cls.from_dict(json.loads(json_str))


class ISRMigrator:
    """Helper class for upgrading, downgrading, and validating ISR payloads against schema versions."""

    @staticmethod
    def validate(data: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validates dictionary representation of ISR against schema requirements."""
        errors: list[str] = []
        if "schema_version" not in data:
            errors.append("Missing required field 'schema_version'")

        for category in ["routes", "middlewares", "controllers", "handlers", "models", "configs"]:
            if category in data and not isinstance(data[category], list):
                errors.append(f"Category '{category}' must be a list")

        return (len(errors) == 0, errors)

    @staticmethod
    def upgrade(data: dict[str, Any], target_version: str = CURRENT_ISR_SCHEMA_VERSION) -> dict[str, Any]:
        """Upgrades older ISR dictionary representation to target version."""
        upgraded = dict(data)
        upgraded["schema_version"] = target_version
        return upgraded

    @staticmethod
    def downgrade(data: dict[str, Any], target_version: str = "1.0") -> dict[str, Any]:
        """Downgrades ISR dictionary representation to target version."""
        downgraded = dict(data)
        downgraded["schema_version"] = target_version
        return downgraded
