"""Canonical Serialization Engine for KarsaSec RTP Subsystem (Sprint F0).

Provides byte-identical UTF-8 canonical JSON serialization and SHA-256 fingerprinting.
Enforces Invariants R1-R6:
  - Insertion order independence for dict keys.
  - PYTHONHASHSEED independence.
  - Memory address & runtime ordering exclusion.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Any

from karsasec.ai.remediation.rtp.errors import RTPSerializationError


def _normalize_canonical_value(val: Any) -> Any:
    """Recursively normalize data into canonical JSON-serializable primitives."""
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        return val
    if isinstance(val, Enum):
        return str(val.value)
    if isinstance(val, dict):
        return {str(k): _normalize_canonical_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_normalize_canonical_value(item) for item in val]
    if isinstance(val, set):
        # Sets are inherently unordered; sort their normalized representations
        normalized_items = [_normalize_canonical_value(item) for item in val]
        return sorted(normalized_items, key=lambda x: json.dumps(x, sort_keys=True))

    # Support objects with a to_dict() method
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return _normalize_canonical_value(val.to_dict())

    # Support dataclasses
    if is_dataclass(val) and not isinstance(val, type):
        return _normalize_canonical_value(asdict(val))

    raise RTPSerializationError(
        f"Unsupported non-canonical value type '{type(val).__name__}' for deterministic serialization."
    )


def canonicalize(data: Any) -> bytes:
    """Produces byte-identical canonical UTF-8 JSON encoding for any data payload (R1-R6).

    Sorted keys, compact separators (',', ':'), no trailing whitespace, UTF-8 encoded.
    """
    normalized = _normalize_canonical_value(data)
    canonical_str = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return canonical_str.encode("utf-8")


def compute_canonical_hash(data: Any) -> str:
    """Computes deterministic SHA-256 hex digest over canonicalized data payload."""
    canonical_bytes = canonicalize(data)
    return hashlib.sha256(canonical_bytes).hexdigest()
