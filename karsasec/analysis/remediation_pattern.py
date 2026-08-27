"""RemediationPattern model, RemediationStatus enum, and built-in RemediationPatternRegistry for Sprint E14."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class RemediationStatus(StrEnum):
    """Remediation status level."""

    REQUIRED = "REQUIRED"
    RECOMMENDED = "RECOMMENDED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RemediationPattern:
    """Immutable representation of a remediation pattern for a specific sink category."""

    pattern_id: str
    vulnerability_class: str
    sink_category: str
    preferred_fix: str
    alternative_fixes: tuple[str, ...]
    forbidden_fixes: tuple[str, ...]
    validation_requirements: tuple[str, ...]

    def is_sink_compatible(self, sink_category: str) -> bool:
        """Checks if pattern sink category is compatible with target sink category."""
        return self.sink_category.upper() == sink_category.upper()

    def is_forbidden_fix(self, fix_name: str) -> bool:
        """Checks if a fix technique is in the explicit negative matrix."""
        clean_name = fix_name.lower().strip()
        return any(f.lower().strip() in clean_name for f in self.forbidden_fixes)

    def to_dict(self) -> dict[str, Any]:
        """Serializes remediation pattern to dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "vulnerability_class": self.vulnerability_class,
            "sink_category": self.sink_category,
            "preferred_fix": self.preferred_fix,
            "alternative_fixes": list(self.alternative_fixes),
            "forbidden_fixes": list(self.forbidden_fixes),
            "validation_requirements": list(self.validation_requirements),
        }


class RemediationPatternRegistry:
    """Built-in registry of remediation patterns with negative barrier matrices."""

    _PATTERNS: dict[str, RemediationPattern] = {}

    @classmethod
    def initialize_defaults(cls) -> None:
        """Initializes default remediation patterns for core vulnerability classes."""
        cls._PATTERNS = {
            "SQL": RemediationPattern(
                pattern_id="REM-SQL-01",
                vulnerability_class="SQL_INJECTION",
                sink_category="SQL",
                preferred_fix="parameterized_query",
                alternative_fixes=("prepared_statement", "sanitize_sql", "strict_numeric_conversion"),
                forbidden_fixes=("str()", "str", "trim()", "trim", "escape_html()", "escape_html"),
                validation_requirements=("ast_parameter_binding_check", "dataflow_sanitizer_validation"),
            ),
            "COMMAND": RemediationPattern(
                pattern_id="REM-CMD-01",
                vulnerability_class="COMMAND_INJECTION",
                sink_category="COMMAND",
                preferred_fix="command_allowlist",
                alternative_fixes=("shlex.quote", "safe_exec"),
                forbidden_fixes=("str()", "str", "trim()", "trim", "sanitize_sql()", "sanitize_sql"),
                validation_requirements=("subprocess_argument_list_validation",),
            ),
            "HTML": RemediationPattern(
                pattern_id="REM-XSS-01",
                vulnerability_class="XSS",
                sink_category="HTML",
                preferred_fix="context_aware_html_escape",
                alternative_fixes=("framework_auto_escape", "csp_policy"),
                forbidden_fixes=("str()", "str", "trim()", "trim", "sanitize_sql()", "sanitize_sql"),
                validation_requirements=("html_encoding_verification",),
            ),
            "PATH": RemediationPattern(
                pattern_id="REM-PATH-01",
                vulnerability_class="PATH_TRAVERSAL",
                sink_category="PATH",
                preferred_fix="safe_join",
                alternative_fixes=("realpath_boundary_check", "basename"),
                forbidden_fixes=("string replacement only", "escape_html()", "escape_html", "str()", "str"),
                validation_requirements=("canonical_path_boundary_verification",),
            ),
            "CODE": RemediationPattern(
                pattern_id="REM-CODE-01",
                vulnerability_class="CODE_INJECTION",
                sink_category="CODE",
                preferred_fix="static_dispatch",
                alternative_fixes=("strict_allowlist", "ast.literal_eval"),
                forbidden_fixes=("eval()", "exec()", "compile()", "str()", "str"),
                validation_requirements=("dynamic_eval_elimination_check",),
            ),
        }

    @classmethod
    def get_for_sink_category(cls, sink_category: str) -> RemediationPattern | None:
        """Retrieves remediation pattern by sink category."""
        if not cls._PATTERNS:
            cls.initialize_defaults()
        return cls._PATTERNS.get(sink_category.upper())

    @classmethod
    def register(cls, pattern: RemediationPattern) -> None:
        """Registers a custom remediation pattern."""
        if not cls._PATTERNS:
            cls.initialize_defaults()
        cls._PATTERNS[pattern.sink_category.upper()] = pattern


RemediationPatternRegistry.initialize_defaults()
