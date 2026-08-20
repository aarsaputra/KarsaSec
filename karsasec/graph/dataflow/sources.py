"""Untrusted input source registry and language-specific source definitions (E11)."""

from __future__ import annotations

import re

# Language untrusted source sets
UNTRUSTED_SOURCES_PHP: frozenset[str] = frozenset(
    {
        "$_GET",
        "$_POST",
        "$_REQUEST",
        "$_SERVER",
        "$_COOKIE",
        "$_FILES",
        "$_ENV",
        "$HTTP_RAW_POST_DATA",
        "$argv",
        "php://input",
    }
)

UNTRUSTED_SOURCES_PYTHON: frozenset[str] = frozenset(
    {
        "request.args",
        "request.form",
        "request.json",
        "request.GET",
        "request.POST",
        "request.values",
        "sys.argv",
        "os.environ",
    }
)

UNTRUSTED_SOURCES_JS: frozenset[str] = frozenset(
    {
        "req.query",
        "req.body",
        "req.params",
        "req.headers",
        "location.href",
        "location.search",
        "document.cookie",
        "window.name",
    }
)

UNTRUSTED_SOURCES_GO: frozenset[str] = frozenset(
    {
        "r.URL.Query()",
        "r.FormValue",
        "r.PostFormValue",
        "r.Body",
        "os.Args",
    }
)

UNTRUSTED_SOURCES_JAVA: frozenset[str] = frozenset(
    {
        "args[",
        "request.getParameter",
        "request.getHeader",
        "HttpServletRequest",
        "System.getenv",
        "System.getProperty",
        "System.in",
    }
)

UNTRUSTED_SOURCES_RUST: frozenset[str] = frozenset(
    {
        "env::args",
        "env::args_os",
        "env::var",
        "env::var_os",
        "std::env::args",
        "std::env::args_os",
        "std::env::var",
        "std::env::var_os",
    }
)


class SourceRegistry:
    """Centralized registry for identifying untrusted user input sources."""

    def __init__(self) -> None:
        self._sources_by_lang: dict[str, frozenset[str]] = {
            "php": UNTRUSTED_SOURCES_PHP,
            "python": UNTRUSTED_SOURCES_PYTHON,
            "py": UNTRUSTED_SOURCES_PYTHON,
            "javascript": UNTRUSTED_SOURCES_JS,
            "js": UNTRUSTED_SOURCES_JS,
            "typescript": UNTRUSTED_SOURCES_JS,
            "ts": UNTRUSTED_SOURCES_JS,
            "go": UNTRUSTED_SOURCES_GO,
            "java": UNTRUSTED_SOURCES_JAVA,
            "rust": UNTRUSTED_SOURCES_RUST,
        }

    def get_sources_for_language(self, language: str) -> frozenset[str]:
        """Return untrusted source symbols for a target language."""
        lang = (language or "").strip().lower()
        return self._sources_by_lang.get(lang, frozenset())

    def contains_source(self, text: str, language: str = "php") -> bool:
        """Check if a text snippet contains any untrusted source pattern."""
        sources = self.get_sources_for_language(language)
        if not sources or not text:
            return False

        for source in sources:
            if re.search(r"[^A-Za-z0-9_]", source):
                pattern = re.escape(source)
            else:
                pattern = rf"(?<!\w){re.escape(source)}(?!\w)"
            if re.search(pattern, text, flags=re.IGNORECASE):
                return True
        return False

    def find_matching_sources(self, text: str, language: str = "php") -> list[str]:
        """Return all matching untrusted source symbols found in text."""
        sources = self.get_sources_for_language(language)
        if not sources or not text:
            return []

        matched: list[str] = []
        for source in sorted(sources, key=len, reverse=True):
            if re.search(r"[^A-Za-z0-9_]", source):
                pattern = re.escape(source)
            else:
                pattern = rf"(?<!\w){re.escape(source)}(?!\w)"
            if re.search(pattern, text, flags=re.IGNORECASE):
                matched.append(source)
        return matched


# Global singleton instance
source_registry = SourceRegistry()
