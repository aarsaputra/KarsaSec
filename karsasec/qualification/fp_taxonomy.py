"""FP Taxonomy Engine: Deterministic candidate finding rejection taxonomy (E12-3)."""

from enum import StrEnum


class FPTaxonomyReason(StrEnum):
    """Explicit, deterministic reasons for rejecting candidate findings.

    Every candidate finding that fails qualification must have an explicit reason.
    Silently dropping candidate findings is prohibited.
    """
    LEXICAL_ONLY = "LEXICAL_ONLY"
    COMMENT_OR_STRING_MATCH = "COMMENT_OR_STRING_MATCH"
    UNCONSTRAINED_SINK = "UNCONSTRAINED_SINK"
    UNTAINTED_INPUT = "UNTAINTED_INPUT"
    STATIC_INPUT = "STATIC_INPUT"
    SANITIZED_INPUT = "SANITIZED_INPUT"
    WRONG_SINK_CATEGORY = "WRONG_SINK_CATEGORY"
    WRONG_SANITIZER = "WRONG_SANITIZER"
    WRONG_RULE_SCOPE = "WRONG_RULE_SCOPE"
    DUPLICATE_SEMANTIC_FINDING = "DUPLICATE_SEMANTIC_FINDING"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    UNKNOWN_FLOW = "UNKNOWN_FLOW"
