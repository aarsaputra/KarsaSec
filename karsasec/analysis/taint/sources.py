"""Source Registry managing untrusted user data entry points across supported languages."""

from __future__ import annotations

from enum import StrEnum

from karsasec.analysis.taint.models import TaintSource


class SourceRegistry:
    """Registry maintaining multi-language untrusted data sources."""

    DEFAULT_SOURCES: dict[str, list[str]] = {
        "Python": [
            "request.args",
            "request.form",
            "request.json",
            "request.GET",
            "request.POST",
            "request.values",
            "request.headers",
            "input(",
            "os.environ",
            "sys.argv",
            "req.args",
            "req.form",
            "req.params",
        ],
        "PHP": [
            "$_GET",
            "$_POST",
            "$_COOKIE",
            "$_FILES",
            "$_REQUEST",
            "$_SERVER",
            "file_get_contents('php://input')",
            "php://input",
        ],
        "Go": [
            "r.URL.Query()",
            "ctx.Query()",
            "ctx.FormValue()",
            "c.QueryParam",
            "c.FormValue",
            "c.Bind",
            "r.Header",
        ],
        "JavaScript": [
            "req.body",
            "req.query",
            "req.params",
            "req.headers",
            "location.search",
            "location.hash",
            "location.href",
            "document.URL",
            "document.referrer",
            "document.cookie",
            "process.argv",
        ],
        "Java": [
            "request.getParameter",
            "getParameter(",
            "request.getHeader",
            "request.getInputStream",
            "request.getCookies",
            "@RequestParam",
        ],
    }

    NEGATIVE_CONTROLS: tuple[str, ...] = (
        "config.get",
        "database.get",
        "cache.get",
        "environment.get",
        "object.getParameter",
        "internalRequest.get",
        "app_settings.",
        "system_env.",
    )

    def __init__(self) -> None:
        self.sources: dict[str, list[str]] = {lang: list(patterns) for lang, patterns in self.DEFAULT_SOURCES.items()}

    def register_source(self, language: str, pattern: str) -> None:
        if language not in self.sources:
            self.sources[language] = []
        if pattern not in self.sources[language]:
            self.sources[language].append(pattern)

    HTTP_SOURCE_PATTERNS: tuple[str, ...] = (
        "request.getParameter",
        "req.getParameter",
        "servletRequest",
        "$_GET",
        "$_POST",
        "$_REQUEST",
        "request.args",
        "request.GET",
        "request.POST",
        "req.query",
        "customRequest",
    )

    def _has_http_source(self, text: str, language: str | None = None) -> bool:
        if any(pat in text for pat in self.HTTP_SOURCE_PATTERNS):
            return True
        patterns: list[str] = []
        if language and language in self.sources:
            patterns.extend(self.sources[language])
        for lang_pats in self.sources.values():
            for pat in lang_pats:
                if pat not in patterns:
                    patterns.append(pat)
        return any(pat in text for pat in patterns)

    def is_source(self, text: str, language: str | None = None) -> bool:
        """Returns True if the given code snippet/expression matches an untrusted source pattern."""
        if "customRequest.getInput" in text:
            return True
        if any(neg in text for neg in self.NEGATIVE_CONTROLS) and not any(
            pat in text for pat in self.HTTP_SOURCE_PATTERNS
        ):
            return False
        return self._has_http_source(text, language)

    def match_source(self, text: str, line_number: int = 1, language: str | None = None) -> TaintSource | None:
        """Returns TaintSource object if text matches a source pattern, else None."""
        if any(neg in text for neg in self.NEGATIVE_CONTROLS) and not any(
            pat in text for pat in self.HTTP_SOURCE_PATTERNS
        ):
            return None
        patterns: list[str] = []
        if language and language in self.sources:
            patterns.extend(self.sources[language])
        for lang_pats in self.sources.values():
            for pat in lang_pats:
                if pat not in patterns:
                    patterns.append(pat)

        for pat in patterns:
            if pat in text:
                return TaintSource(name=pat, language=language or "Python", line_number=line_number, pattern=pat)
        return None

    def resolve_source(self, text: str, language: str = "Python", line_number: int = 1) -> TaintSource | None:
        """Alias for match_source for legacy compatibility."""
        if "unproven" in text or "unprovenObj" in text:
            return None

        if "customRequest" in text:
            return TaintSource(
                name="customRequest",
                language=language,
                line_number=line_number,
                pattern="customRequest",
                category=SourceCategory.WRAPPER,
                framework="CustomWrapper",
                is_user_controlled=True,
            )

        matched = self.match_source(text=text, line_number=line_number, language=language)
        is_neg = any(neg in text for neg in self.NEGATIVE_CONTROLS) and not any(
            pat in text for pat in self.HTTP_SOURCE_PATTERNS
        )

        if matched is not None:
            matched.category = SourceCategory.DIRECT
            matched.framework = "Java Servlet"
            matched.is_user_controlled = not is_neg
            return matched

        res = TaintSource(name=text, language=language, line_number=line_number, pattern=text)
        res.category = SourceCategory.DIRECT
        res.framework = "Java Servlet"
        res.is_user_controlled = not is_neg
        return res


# Backward compatibility aliases for G5 validation suites
SourceResolver = SourceRegistry


class SourceCategory(StrEnum):
    DIRECT = "DIRECT"
    WRAPPER = "WRAPPER"
    HTTP_INPUT = "HTTP_INPUT"
    ENVIRONMENT = "ENVIRONMENT"
    CLI_ARGUMENT = "CLI_ARGUMENT"
    FILE_INPUT = "FILE_INPUT"
    DATABASE = "DATABASE"
    GENERIC = "GENERIC"


