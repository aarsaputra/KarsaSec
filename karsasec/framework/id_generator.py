"""Deterministic SHA-256 Node ID Generator for Framework Semantic Graph."""

from __future__ import annotations

import hashlib


def generate_semantic_node_id(
    framework: str,
    semantic_type: str,
    qualified_name: str,
    file_path: str = "",
    line: int = 1,
) -> str:
    """Generates a deterministic SHA-256 node ID string.

    Format: SHA256(framework + semantic_type + qualified_name + file_path + line)
    """
    raw_payload = f"{framework.upper()}:{semantic_type.upper()}:{qualified_name}:{file_path}:{line}"
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
