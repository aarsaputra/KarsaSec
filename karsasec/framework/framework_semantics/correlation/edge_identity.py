"""Canonical edge identity and deterministic serialization utilities."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from karsasec.framework.semantic_models import SemanticEdgeType


def canonicalize_attributes(attributes: dict[str, Any]) -> str:
    """Serialize attribute dictionary deterministically into sorted JSON string."""
    clean_attrs: dict[str, Any] = {}
    for key in sorted(attributes.keys()):
        val = attributes[key]
        if isinstance(val, tuple):
            val = list(val)
        clean_attrs[key] = val
    return json.dumps(clean_attrs, sort_keys=True, separators=(",", ":"))


def generate_canonical_edge_id(
    source_id: str,
    target_id: str,
    edge_type: SemanticEdgeType | str,
    attributes: dict[str, Any] | None = None,
) -> str:
    """Generate byte-for-byte deterministic SHA-256 ID for a semantic edge."""
    edge_str = edge_type.value if isinstance(edge_type, SemanticEdgeType) else str(edge_type)
    attr_str = canonicalize_attributes(attributes or {})
    raw_key = f"{source_id}:{edge_str}:{target_id}:{attr_str}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
