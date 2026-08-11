"""Canonical node identity utilities for semantic correlation."""

from __future__ import annotations

from typing import Any

from karsasec.framework.id_generator import generate_semantic_node_id


def resolve_canonical_node_id(entity: Any) -> str:
    """Resolve or compute canonical semantic node ID for an ISR entity."""
    if hasattr(entity, "semantic_id") and entity.semantic_id:
        return str(entity.semantic_id)

    # Fallback to SHA-256 node ID computation
    framework = getattr(entity, "framework", "GENERIC")
    node_type = getattr(entity, "node_type", "entity")
    name = getattr(entity, "name", getattr(entity, "key", "unnamed"))
    file_path = ""
    line = 0

    if hasattr(entity, "origin") and entity.origin and hasattr(entity.origin, "location_info"):
        file_path = entity.origin.location_info.file_path or ""
        line = entity.origin.location_info.line or 0

    return generate_semantic_node_id(framework, str(node_type), str(name), file_path, line)
