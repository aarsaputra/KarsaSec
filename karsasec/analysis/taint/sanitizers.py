"""Sanitizer Registry managing security cleaning routines across supported languages."""

from __future__ import annotations

from karsasec.analysis.taint.models import TaintCategory, TaintSanitizer


class SanitizerRegistry:
    """Registry maintaining multi-language security sanitizers categorized by vulnerability type."""

    DEFAULT_SANITIZERS: dict[TaintCategory, list[str]] = {
        TaintCategory.SQL_INJECTION: [
            "escape_string",
            "PreparedStatement",
            "parameterized",
            "int(",
            "intval",
            "int()",
            "quote_identifier",
        ],
        TaintCategory.XSS: [
            "escape(",
            "html.escape",
            "htmlspecialchars",
            "sanitize_html",
            "encodeURIComponent",
        ],
        TaintCategory.PATH_TRAVERSAL: [
            "Path.normalize",
            "filepath.Clean",
            "basename",
            "safe_join",
            "secure_filename",
        ],
        TaintCategory.COMMAND_INJECTION: [
            "shlex.quote",
            "escapeshellarg",
            "escapeshellcmd",
        ],
    }

    def __init__(self) -> None:
        self.sanitizers: dict[TaintCategory, list[str]] = {cat: list(pats) for cat, pats in self.DEFAULT_SANITIZERS.items()}

    def register_sanitizer(self, category: TaintCategory, pattern: str) -> None:
        if category not in self.sanitizers:
            self.sanitizers[category] = []
        if pattern not in self.sanitizers[category]:
            self.sanitizers[category].append(pattern)

    def is_sanitizer(self, text: str) -> bool:
        """Returns True if the text matches any registered sanitizer pattern."""
        for patterns in self.sanitizers.values():
            if any(pat in text for pat in patterns):
                return True
        return False

    def match_sanitizer(self, text: str, line_number: int = 1) -> TaintSanitizer | None:
        """Returns TaintSanitizer object if text matches a sanitizer pattern, else None."""
        for cat, patterns in self.sanitizers.items():
            for pat in patterns:
                if pat in text:
                    return TaintSanitizer(name=pat, category=cat, line_number=line_number, pattern=pat)
        return None
