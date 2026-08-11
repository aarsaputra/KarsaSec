"""Sink categories and central sink registry (E11)."""
from __future__ import annotations

import re
from enum import StrEnum


class SinkCategory(StrEnum):
    """Semantic classifications of dangerous sink functions and language constructs."""
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    SQL_EXECUTION = "SQL_EXECUTION"
    FILE_INCLUSION = "FILE_INCLUSION"
    FILE_READ = "FILE_READ"
    HTML_OUTPUT = "HTML_OUTPUT"
    CODE_EVALUATION = "CODE_EVALUATION"
    CRYPTOGRAPHIC_OPERATION = "CRYPTOGRAPHIC_OPERATION"


# Default sink mappings per language
_PHP_SINKS: dict[str, SinkCategory] = {
    "shell_exec": SinkCategory.COMMAND_EXECUTION,
    "exec": SinkCategory.COMMAND_EXECUTION,
    "system": SinkCategory.COMMAND_EXECUTION,
    "passthru": SinkCategory.COMMAND_EXECUTION,
    "popen": SinkCategory.COMMAND_EXECUTION,
    "proc_open": SinkCategory.COMMAND_EXECUTION,
    "pcntl_exec": SinkCategory.COMMAND_EXECUTION,
    "eval": SinkCategory.CODE_EVALUATION,
    "assert": SinkCategory.CODE_EVALUATION,
    "create_function": SinkCategory.CODE_EVALUATION,
    "include": SinkCategory.FILE_INCLUSION,
    "include_once": SinkCategory.FILE_INCLUSION,
    "require": SinkCategory.FILE_INCLUSION,
    "require_once": SinkCategory.FILE_INCLUSION,
    "file_get_contents": SinkCategory.FILE_READ,
    "readfile": SinkCategory.FILE_READ,
    "fopen": SinkCategory.FILE_READ,
    "echo": SinkCategory.HTML_OUTPUT,
    "print": SinkCategory.HTML_OUTPUT,
    "printf": SinkCategory.HTML_OUTPUT,
    "mysqli_query": SinkCategory.SQL_EXECUTION,
    "mysql_query": SinkCategory.SQL_EXECUTION,
    "pg_query": SinkCategory.SQL_EXECUTION,
    "md5": SinkCategory.CRYPTOGRAPHIC_OPERATION,
    "sha1": SinkCategory.CRYPTOGRAPHIC_OPERATION,
}

_PHP_METHOD_SINKS: dict[str, SinkCategory] = {
    "query": SinkCategory.SQL_EXECUTION,
    "exec": SinkCategory.SQL_EXECUTION,
    "execute": SinkCategory.SQL_EXECUTION,
    "prepare": SinkCategory.SQL_EXECUTION,
}


class SinkRegistry:
    """Centralized registry for identifying dangerous sinks and their categories."""

    def __init__(self) -> None:
        self._php_sinks = dict(_PHP_SINKS)
        self._php_method_sinks = dict(_PHP_METHOD_SINKS)

    def classify_sink(self, symbol: str, snippet: str = "", language: str = "php") -> SinkCategory | None:
        """Identify the SinkCategory of a function or expression."""
        clean_sym = symbol.strip()
        lang = (language or "").strip().lower()

        if lang == "php":
            if clean_sym in self._php_sinks:
                return self._php_sinks[clean_sym]

            if clean_sym in self._php_method_sinks:
                return self._php_method_sinks[clean_sym]

            # Regex inspection on snippet if symbol alone is generic
            if snippet:
                if re.search(r'\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(', snippet, re.IGNORECASE):
                    return SinkCategory.COMMAND_EXECUTION
                if re.search(r'\b(include|require)(?:_once)?\b', snippet, re.IGNORECASE):
                    return SinkCategory.FILE_INCLUSION
                if re.search(r'->(?:query|exec|execute|prepare)\s*\(', snippet, re.IGNORECASE):
                    return SinkCategory.SQL_EXECUTION
                if re.search(r'\b(mysqli_query|mysql_query|pg_query)\s*\(', snippet, re.IGNORECASE):
                    return SinkCategory.SQL_EXECUTION
                if re.search(r'\b(eval|assert)\s*\(', snippet, re.IGNORECASE):
                    return SinkCategory.CODE_EVALUATION
                if re.search(r'\b(echo|print|printf)\b', snippet, re.IGNORECASE):
                    return SinkCategory.HTML_OUTPUT

        return None


# Global singleton instance
sink_registry = SinkRegistry()
