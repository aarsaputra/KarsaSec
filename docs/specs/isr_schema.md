# Intermediate Semantic Representation (ISR) Schema v1.0

## 1. Specification

ISR acts as the intermediate exchange format between framework extractors and the semantic graph builder.

Current Schema Version: `1.0`

## 2. Mandatory Contract Fields

Every definition dataclass inside ISR exposes:
- `semantic_id`: SHA-256 deterministic node identifier.
- `framework`: Associated framework name.
- `language`: Source programming language.
- `confidence`: Extraction confidence score [0.0 - 1.0].
- `schema_version`: Frozen schema version string (e.g. `"1.0"`).
- `origin`: `OriginMetadata` tracking provenance and source code coordinates.

## 3. ISR Collections
- `routes`: `RouteDefinition` items.
- `middlewares`: `MiddlewareDefinition` items.
- `controllers`: `ControllerDefinition` items.
- `handlers`: `HandlerDefinition` items.
- `models`: `ModelDefinition` items.
- `orms`: `ORMDefinition` items.
- `auths`: `AuthDefinition` items.
- `configs`: `ConfigDefinition` items.
- `templates`: `TemplateDefinition` items.
- `dependencies`: `DependencyDefinition` items.
