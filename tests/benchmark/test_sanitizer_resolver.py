"""Unit tests for SanitizerResolver & Property Mitigation Semantics (Phase 2).

Verifies:
1. Property-specific sanitizer matching (PreparedStatement -> SQL_INJECTION = SAFE)
2. Property mismatch handling (htmlspecialchars -> SQL_INJECTION = INEFFECTIVE / UNSAFE)
3. Misleading/fake sanitizer handling (fake_sanitize -> UNSAFE)
4. Preservation of UNKNOWN state for unknown sanitizer wrappers
"""

from karsasec.analysis.taint.sanitizers import SanitizerContext, SanitizerRegistry, SanitizerResolver, TransformationType


def test_sanitizer_resolver_property_matching() -> None:
    resolver = SanitizerResolver()

    # PreparedStatement for SQL_INJECTION -> SAFE
    sem1 = resolver.resolve_sanitizer("PreparedStatement stmt = conn.prepareStatement(sql)", "SQL_INJECTION")
    assert sem1 is not None
    assert sem1.is_verified_safe is True
    assert sem1.transformation_type == TransformationType.PARAMETERIZE

    # htmlspecialchars for SQL_INJECTION -> INEFFECTIVE (Unsafe for SQL)
    sem2 = resolver.resolve_sanitizer("String clean = htmlspecialchars(val)", "SQL_INJECTION")
    assert sem2 is not None
    assert sem2.is_verified_safe is False
    assert sem2.transformation_type == TransformationType.INEFFECTIVE

    # Fake sanitizer -> UNSAFE
    sem3 = resolver.resolve_sanitizer("fake_sanitize(val)", "SQL_INJECTION")
    assert sem3 is not None
    assert sem3.is_verified_safe is False

    # Unrecognized wrapper -> None (UNKNOWN state)
    sem4 = resolver.resolve_sanitizer("unregistered_cleaner(val)", "SQL_INJECTION")
    assert sem4 is None


def test_sanitizer_registry_context_matching() -> None:
    reg = SanitizerRegistry()
    assert reg.is_sanitizer_for_context("PreparedStatement", SanitizerContext.SQL_QUERY) is True
    assert reg.is_sanitizer_for_context("htmlspecialchars", SanitizerContext.HTML_BODY) is True
    assert reg.is_sanitizer_for_context("htmlspecialchars", SanitizerContext.SQL_QUERY) is False
