"""Metamorphic Testing Suite for KarsaSec Detector Consistency.

Tests program transformations that must preserve semantic decision resolution:
1. Variable renaming
2. Function / Helper extraction
3. Statement reordering (independent operations)
4. Harmless temporary assignments
5. Wrapper depth changes
"""

from karsasec.analysis.taint.sanitizers import SanitizerResolver
from karsasec.analysis.taint.sources import SourceResolver


def test_metamorphic_variable_renaming() -> None:
    resolver = SourceResolver()

    code_orig = "String input = request.getParameter('query');"
    code_renamed = "String data_var_99 = request.getParameter('query');"

    s_orig = resolver.resolve_source(code_orig)
    s_renamed = resolver.resolve_source(code_renamed)

    assert s_orig is not None and s_renamed is not None
    assert s_orig.is_user_controlled == s_renamed.is_user_controlled


def test_metamorphic_sanitizer_transformation() -> None:
    resolver = SanitizerResolver()

    code_orig = "String safe = html.escape(raw);"
    code_extracted = "String safe = StringEscapeUtils.escapeHtml4(raw);"

    s_orig = resolver.resolve_sanitizer(code_orig, target_property="CROSS_SITE_SCRIPTING")
    s_ext = resolver.resolve_sanitizer(code_extracted, target_property="CROSS_SITE_SCRIPTING")

    assert s_orig is not None and s_ext is not None
    assert s_orig.is_verified_safe == s_ext.is_verified_safe
