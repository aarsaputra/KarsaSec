"""Compatibility Engine: Declarative Source/Sink and Sanitizer/Sink semantic compatibility matrix (E12-3)."""

from typing import Final


class CompatibilityRegistry:
    """Declarative semantic matrix enforcing valid combinations of sources, sinks, and sanitizers."""

    # Sink category definitions
    COMMAND_EXECUTION: Final = "COMMAND_EXECUTION"
    SQL_EXECUTION: Final = "SQL_EXECUTION"
    FILE_INCLUSION: Final = "FILE_INCLUSION"
    HTML_OUTPUT: Final = "HTML_OUTPUT"
    CODE_EVALUATION: Final = "CODE_EVALUATION"
    CRYPTOGRAPHIC_OPERATION: Final = "CRYPTOGRAPHIC_OPERATION"

    # Sanitizer capability definitions
    SHELL_ESCAPE: Final = "SHELL_ESCAPE"
    SQL_ESCAPE: Final = "SQL_ESCAPE"
    HTML_ESCAPE: Final = "HTML_ESCAPE"
    INTEGER_COERCION: Final = "INTEGER_COERCION"
    PATH_CANONICALIZATION: Final = "PATH_CANONICALIZATION"
    NONE: Final = "NONE"

    # Matrix mapping Sanitizer Capability -> List[Compatible Sink Categories]
    _SANITIZER_COMPATIBILITY_MATRIX: Final[dict[str, set[str]]] = {
        SHELL_ESCAPE: {COMMAND_EXECUTION, CODE_EVALUATION},
        SQL_ESCAPE: {SQL_EXECUTION},
        HTML_ESCAPE: {HTML_OUTPUT},
        INTEGER_COERCION: {SQL_EXECUTION, COMMAND_EXECUTION, FILE_INCLUSION, HTML_OUTPUT, CODE_EVALUATION},
        PATH_CANONICALIZATION: {FILE_INCLUSION},
        NONE: set(),
    }

    # Matrix mapping Source Category -> List[Compatible Sink Categories]
    _SOURCE_COMPATIBILITY_MATRIX: Final[dict[str, set[str]]] = {
        "USER_INPUT": {COMMAND_EXECUTION, SQL_EXECUTION, FILE_INCLUSION, HTML_OUTPUT, CODE_EVALUATION, CRYPTOGRAPHIC_OPERATION},
        "HTTP_REQUEST": {COMMAND_EXECUTION, SQL_EXECUTION, FILE_INCLUSION, HTML_OUTPUT, CODE_EVALUATION, CRYPTOGRAPHIC_OPERATION},
        "ENVIRONMENT": {COMMAND_EXECUTION, SQL_EXECUTION, FILE_INCLUSION, HTML_OUTPUT, CODE_EVALUATION},
        "STATIC_CONSTANT": set(),
        "STATIC_LITERAL": set(),
    }

    @classmethod
    def is_sanitizer_compatible(cls, sanitizer_capability: str, sink_category: str) -> bool:
        """Evaluates whether a given sanitizer capability effectively neutralizes taint for a sink category.

        Example:
            htmlspecialchars() (HTML_ESCAPE) is NOT compatible with shell_exec() (COMMAND_EXECUTION).
            escapeshellarg() (SHELL_ESCAPE) IS compatible with shell_exec() (COMMAND_EXECUTION).
        """
        compatible_sinks = cls._SANITIZER_COMPATIBILITY_MATRIX.get(sanitizer_capability, set())
        return sink_category in compatible_sinks

    @classmethod
    def is_source_compatible(cls, source_category: str, sink_category: str) -> bool:
        """Evaluates whether a source category can trigger a vulnerability in a target sink category."""
        compatible_sinks = cls._SOURCE_COMPATIBILITY_MATRIX.get(source_category, set())
        return sink_category in compatible_sinks
