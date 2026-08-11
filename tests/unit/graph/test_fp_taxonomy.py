"""Unit tests for FP Taxonomy Enum (E12-3)."""

from karsasec.qualification.fp_taxonomy import FPTaxonomyReason


def test_fp_taxonomy_reasons() -> None:
    reasons = [e.value for e in FPTaxonomyReason]
    assert "LEXICAL_ONLY" in reasons
    assert "COMMENT_OR_STRING_MATCH" in reasons
    assert "UNTAINTED_INPUT" in reasons
    assert "STATIC_INPUT" in reasons
    assert "SANITIZED_INPUT" in reasons
    assert "UNKNOWN_FLOW" in reasons
