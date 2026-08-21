"""Sanitizer Registry managing security cleaning routines across supported languages and execution contexts."""

from __future__ import annotations

from enum import StrEnum
from karsasec.analysis.taint.models import TaintCategory, TaintSanitizer


class SanitizerContext(StrEnum):
    HTML_BODY = "HTML_BODY"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    JAVASCRIPT_CONTEXT = "JAVASCRIPT_CONTEXT"
    SQL_QUERY = "SQL_QUERY"
    URL_DESTINATION = "URL_DESTINATION"
    FILE_PATH = "FILE_PATH"
    COMMAND = "COMMAND"
    GENERIC = "GENERIC"


class SanitizerRegistry:
    """Registry maintaining multi-language security sanitizers categorized by vulnerability type and context."""

    DEFAULT_CONTEXT_SANITIZERS: dict[SanitizerContext, list[str]] = {
        SanitizerContext.HTML_BODY: [
            "htmlspecialchars",
            "html.escape",
            "escape(",
            "sanitize_html",
        ],
        SanitizerContext.HTML_ATTRIBUTE: [
            "htmlspecialchars",
            "attribute_escape",
        ],
        SanitizerContext.JAVASCRIPT_CONTEXT: [
            "encodeURIComponent",
            "JSON.stringify",
            "DOMPurify.sanitize",
            "js_escape",
        ],
        SanitizerContext.SQL_QUERY: [
            "PreparedStatement",
            "parameterized",
            "int(",
            "intval",
            "int()",
            "escape_string",
            "quote_identifier",
        ],
        SanitizerContext.URL_DESTINATION: [
            "strict_url_allowlist",
            "validate_origin",
        ],
        SanitizerContext.FILE_PATH: [
            "Path.normalize",
            "filepath.Clean",
            "basename",
            "safe_join",
            "secure_filename",
        ],
        SanitizerContext.COMMAND: [
            "shlex.quote",
            "escapeshellarg",
            "escapeshellcmd",
        ],
    }

    def __init__(self) -> None:
        self.context_sanitizers: dict[SanitizerContext, list[str]] = {
            ctx: list(pats) for ctx, pats in self.DEFAULT_CONTEXT_SANITIZERS.items()
        }

    def is_sanitizer(self, text: str) -> bool:
        """Returns True if text matches any registered sanitizer pattern."""
        for patterns in self.context_sanitizers.values():
            if any(pat in text for pat in patterns):
                return True
        return False

    def is_sanitizer_for_context(self, text: str, target_context: SanitizerContext) -> bool:
        """Returns True ONLY if text matches a sanitizer valid for the target context."""
        patterns = self.context_sanitizers.get(target_context, [])
        return any(pat in text for pat in patterns)

    def match_sanitizer(self, text: str, line_number: int = 1) -> TaintSanitizer | None:
        """Returns TaintSanitizer object if text matches a sanitizer pattern, else None."""
        for ctx, patterns in self.context_sanitizers.items():
            for pat in patterns:
                if pat in text:
                    return TaintSanitizer(name=pat, category=TaintCategory.GENERIC, line_number=line_number, pattern=pat)
        return None
