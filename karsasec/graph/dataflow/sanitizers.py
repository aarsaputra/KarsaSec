"""Sink-aware sanitizer capability registry (E11)."""

from __future__ import annotations

import re
from enum import StrEnum

from karsasec.graph.dataflow.sinks import SinkCategory


class SanitizerCapability(StrEnum):
    """Specific neutralizing capabilities offered by sanitizers."""

    HTML_ESCAPE = "HTML_ESCAPE"
    SHELL_ESCAPE = "SHELL_ESCAPE"
    SQL_ESCAPE = "SQL_ESCAPE"
    INTEGER_COERCION = "INTEGER_COERCION"
    HASH_OUTPUT = "HASH_OUTPUT"
    PATH_COMPONENT_NORMALIZATION = "PATH_COMPONENT_NORMALIZATION"
    PATH_CANONICALIZATION = "PATH_CANONICALIZATION"


# Mapping from SanitizerCapability to SinkCategories that it safely neutralizes
_CAPABILITY_COMPATIBILITY: dict[SanitizerCapability, frozenset[SinkCategory]] = {
    SanitizerCapability.HTML_ESCAPE: frozenset(
        {
            SinkCategory.HTML_OUTPUT,
        }
    ),
    SanitizerCapability.SHELL_ESCAPE: frozenset(
        {
            SinkCategory.COMMAND_EXECUTION,
        }
    ),
    SanitizerCapability.SQL_ESCAPE: frozenset(
        {
            SinkCategory.SQL_EXECUTION,
        }
    ),
    SanitizerCapability.INTEGER_COERCION: frozenset(
        {
            SinkCategory.SQL_EXECUTION,
            SinkCategory.COMMAND_EXECUTION,
            SinkCategory.FILE_INCLUSION,
            SinkCategory.FILE_READ,
            SinkCategory.HTML_OUTPUT,
            SinkCategory.CODE_EVALUATION,
        }
    ),
    SanitizerCapability.HASH_OUTPUT: frozenset(
        {
            SinkCategory.SQL_EXECUTION,
            SinkCategory.COMMAND_EXECUTION,
            SinkCategory.FILE_INCLUSION,
            SinkCategory.FILE_READ,
            SinkCategory.HTML_OUTPUT,
            SinkCategory.CODE_EVALUATION,
        }
    ),
    SanitizerCapability.PATH_COMPONENT_NORMALIZATION: frozenset(
        {
            SinkCategory.FILE_INCLUSION,
            SinkCategory.FILE_READ,
        }
    ),
    SanitizerCapability.PATH_CANONICALIZATION: frozenset(
        {
            SinkCategory.FILE_INCLUSION,
            SinkCategory.FILE_READ,
        }
    ),
}


# Default function to capability mapping for PHP
_PHP_SANITIZERS: dict[str, SanitizerCapability] = {
    "htmlspecialchars": SanitizerCapability.HTML_ESCAPE,
    "htmlentities": SanitizerCapability.HTML_ESCAPE,
    "strip_tags": SanitizerCapability.HTML_ESCAPE,
    "escapeshellarg": SanitizerCapability.SHELL_ESCAPE,
    "escapeshellcmd": SanitizerCapability.SHELL_ESCAPE,
    "mysqli_real_escape_string": SanitizerCapability.SQL_ESCAPE,
    "mysql_real_escape_string": SanitizerCapability.SQL_ESCAPE,
    "addslashes": SanitizerCapability.SQL_ESCAPE,
    "intval": SanitizerCapability.INTEGER_COERCION,
    "floatval": SanitizerCapability.INTEGER_COERCION,
    "abs": SanitizerCapability.INTEGER_COERCION,
    "is_numeric": SanitizerCapability.INTEGER_COERCION,
    "ctype_digit": SanitizerCapability.INTEGER_COERCION,
    "is_int": SanitizerCapability.INTEGER_COERCION,
    "is_integer": SanitizerCapability.INTEGER_COERCION,
    "md5": SanitizerCapability.HASH_OUTPUT,
    "sha1": SanitizerCapability.HASH_OUTPUT,
    "hash": SanitizerCapability.HASH_OUTPUT,
    "password_hash": SanitizerCapability.HASH_OUTPUT,
    "crypt": SanitizerCapability.HASH_OUTPUT,
    "crc32": SanitizerCapability.HASH_OUTPUT,
    "basename": SanitizerCapability.PATH_COMPONENT_NORMALIZATION,
    "realpath": SanitizerCapability.PATH_CANONICALIZATION,
}


class SanitizerRegistry:
    """Registry managing sink-aware sanitizer interpretation."""

    def __init__(self) -> None:
        self._php_sanitizers = dict(_PHP_SANITIZERS)

    def identify_sanitizer(self, symbol: str, snippet: str = "", language: str = "php") -> SanitizerCapability | None:
        """Identify if a function call or expression represents a known sanitizer."""
        clean_sym = symbol.strip().lower()
        lang = (language or "").strip().lower()

        if lang == "php":
            if clean_sym in self._php_sanitizers:
                return self._php_sanitizers[clean_sym]

            # Check explicit type casts like (int) or (float) in expression/snippet
            if snippet:
                if re.search(r"\(\s*(?:int|integer|float|double)\s*\)", snippet, re.IGNORECASE):
                    return SanitizerCapability.INTEGER_COERCION
                for func, cap in self._php_sanitizers.items():
                    if re.search(rf"\b{re.escape(func)}\s*\(", snippet, re.IGNORECASE):
                        return cap

        return None

    def is_compatible(self, capability: SanitizerCapability, sink_category: SinkCategory) -> bool:
        """Verify whether a sanitizer capability safely neutralizes taint for a given sink category."""
        allowed_sinks = _CAPABILITY_COMPATIBILITY.get(capability, frozenset())
        return sink_category in allowed_sinks


# Global singleton instance
sanitizer_registry = SanitizerRegistry()
