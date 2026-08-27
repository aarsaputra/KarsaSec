"""RegressionFingerprint model, canonical path normalization, and line-independent fingerprint identity for Sprint E14."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any


def normalize_path(path: str) -> str:
    """Normalizes file path to canonical line-independent repository path.

    Handles:
    - Stripping trailing line/col numbers (:10, :1000, :42:10)
    - Path separator unification (\\ -> /)
    - Relative parent resolution (foo/../foo/app.py -> foo/app.py)
    """
    if not path:
        return "unknown_file"

    # Strip trailing line/col numbers (e.g., app.py:42 or app.py:42:10)
    clean_path = re.sub(r":\d+(:\d+)?$", "", path)

    # Normalize backslashes
    clean_path = clean_path.replace("\\", "/")

    # Normalize dot components
    norm = os.path.normpath(clean_path).replace("\\", "/")

    # Strip leading ./
    if norm.startswith("./"):
        norm = norm[2:]

    return norm.lower()


def compute_regression_fingerprint(
    vulnerability_class: str,
    source_kind: str,
    sink_category: str,
    normalized_path: str,
    rule_key: str,
    call_context: str = "",
    schema_version: str = "1.0",
) -> str:
    """Computes deterministic line-independent semantic regression fingerprint."""
    payload = {
        "schema_version": schema_version,
        "vulnerability_class": vulnerability_class,
        "source_kind": source_kind,
        "sink_category": sink_category,
        "normalized_path": normalize_path(normalized_path),
        "rule_key": rule_key,
        "call_context": call_context,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"E14-FINGERPRINT:{canonical}".encode()).hexdigest()


@dataclass(frozen=True)
class RegressionFingerprint:
    """Immutable representation of a line-independent security regression fingerprint."""

    fingerprint_id: str
    vulnerability_class: str
    source_kind: str
    sink_category: str
    normalized_path: str
    rule_key: str
    call_context: str
    cluster_id: str
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        vulnerability_class: str,
        source_kind: str,
        sink_category: str,
        file_path: str,
        rule_key: str,
        cluster_id: str,
        call_context: str = "",
        schema_version: str = "1.0",
    ) -> RegressionFingerprint:
        """Factory creating immutable RegressionFingerprint."""
        norm_path = normalize_path(file_path)
        f_id = compute_regression_fingerprint(
            vulnerability_class=vulnerability_class,
            source_kind=source_kind,
            sink_category=sink_category,
            normalized_path=norm_path,
            rule_key=rule_key,
            call_context=call_context,
            schema_version=schema_version,
        )

        return cls(
            fingerprint_id=f_id,
            vulnerability_class=vulnerability_class,
            source_kind=source_kind,
            sink_category=sink_category,
            normalized_path=norm_path,
            rule_key=rule_key,
            call_context=call_context,
            cluster_id=cluster_id,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes fingerprint to dictionary."""
        return {
            "fingerprint_id": self.fingerprint_id,
            "vulnerability_class": self.vulnerability_class,
            "source_kind": self.source_kind,
            "sink_category": self.sink_category,
            "normalized_path": self.normalized_path,
            "rule_key": self.rule_key,
            "call_context": self.call_context,
            "cluster_id": self.cluster_id,
            "schema_version": self.schema_version,
        }
