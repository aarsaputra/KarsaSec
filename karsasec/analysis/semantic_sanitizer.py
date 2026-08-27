"""Sanitizer / Barrier Model and Classification Engine for Sprint E11."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.cpg.models import CPGNode

logger = logging.getLogger("karsasec.analysis.semantic_sanitizer")

# Authoritative mapping of genuine sanitizers to supported sink categories
VALID_SANITIZERS: dict[str, tuple[str, ...]] = {
    "int": ("sql", "command_execution", "file_path", "code_execution", "html_render"),
    "float": ("sql", "command_execution", "file_path", "code_execution", "html_render"),
    "bool": ("sql", "command_execution", "file_path", "code_execution", "html_render"),
    "escape_html": ("html_render", "xss"),
    "html_escape": ("html_render", "xss"),
    "sanitize_sql": ("sql", "database"),
    "parameterized_sql": ("sql", "database"),
    "shlex_quote": ("command_execution", "shell"),
    "shlex.quote": ("command_execution", "shell"),
    "abspath": ("file_path", "path_traversal"),
    "basename": ("file_path", "path_traversal"),
}

# Explicit fake sanitizers that must NEVER act as barriers (INV-E11-FLOW-13)
FAKE_SANITIZERS: set[str] = {
    "str",
    "repr",
    "format",
    "lower",
    "upper",
    "strip",
    "lstrip",
    "rstrip",
    "encode",
    "decode",
    "sanitize",  # generic unverified string function name
    "clean",
    "safe",
    "filter",
}


@dataclass(frozen=True)
class SanitizerEvidence:
    """Immutable sanitizer evidence attached to a node along a dataflow path."""

    node_id: str
    sanitizer_kind: str
    input_ssa: str
    output_ssa: str
    sink_categories: tuple[str, ...]
    confidence: float = 1.0


class SanitizerAnalyzer:
    """Analyzer classifying nodes along dataflow path as valid barriers or fake sanitizers."""

    def analyze_node(self, node: CPGNode) -> SanitizerEvidence | None:
        """Analyzes a CPG node to detect sanitizer function calls."""
        # Extract function call name from attributes or code
        func_name = node.attributes.get("function_name") or node.attributes.get("code", "").split("(")[0].strip()
        func_name_clean = func_name.lower().split(".")[-1]

        # INV-E11-FLOW-13: Reject fake sanitizers
        if func_name_clean in FAKE_SANITIZERS or func_name in FAKE_SANITIZERS:
            logger.debug("Node %s (%s) identified as FAKE sanitizer", node.id, func_name)
            return None

        # Check valid sanitizers dictionary
        for valid_key, categories in VALID_SANITIZERS.items():
            if valid_key.lower() in (func_name.lower(), func_name_clean):
                return SanitizerEvidence(
                    node_id=node.id,
                    sanitizer_kind=valid_key,
                    input_ssa=str(node.attributes.get("ssa_version", "v1")),
                    output_ssa=str(node.attributes.get("ssa_version", "v1")),
                    sink_categories=categories,
                    confidence=1.0,
                )

        return None

    def is_valid_barrier_for_sink(
        self,
        evidence: SanitizerEvidence,
        sink_category: str,
    ) -> bool:
        """Validates if sanitizer evidence matches the target sink category."""
        if not sink_category:
            return False
        sink_cat_clean = sink_category.lower()
        return any(c.lower() in sink_cat_clean or sink_cat_clean in c.lower() for c in evidence.sink_categories)
