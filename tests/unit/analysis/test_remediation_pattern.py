"""Unit tests for RemediationPattern model and RemediationPatternRegistry negative barrier matrices."""

from __future__ import annotations

from karsasec.analysis.remediation_pattern import RemediationPatternRegistry


def test_remediation_pattern_registry_defaults() -> None:
    """Verifies built-in default remediation patterns and negative barrier matrix rejection."""
    sql_pattern = RemediationPatternRegistry.get_for_sink_category("SQL")
    assert sql_pattern is not None
    assert sql_pattern.preferred_fix == "parameterized_query"
    assert sql_pattern.is_forbidden_fix("str()") is True
    assert sql_pattern.is_forbidden_fix("trim()") is True
    assert sql_pattern.is_forbidden_fix("escape_html()") is True

    cmd_pattern = RemediationPatternRegistry.get_for_sink_category("COMMAND")
    assert cmd_pattern is not None
    assert cmd_pattern.preferred_fix == "command_allowlist"
    assert cmd_pattern.is_forbidden_fix("sanitize_sql()") is True


def test_remediation_pattern_sink_compatibility() -> None:
    """Verifies sink category compatibility check."""
    sql_pattern = RemediationPatternRegistry.get_for_sink_category("SQL")
    assert sql_pattern is not None
    assert sql_pattern.is_sink_compatible("SQL") is True
    assert sql_pattern.is_sink_compatible("COMMAND") is False
