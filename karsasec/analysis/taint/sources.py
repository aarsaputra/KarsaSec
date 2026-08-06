"""Source Registry managing untrusted user data entry points across supported languages."""

from __future__ import annotations

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
            "input(",
            "os.environ",
            "sys.argv",
            "req.args",
            "req.form",
        ],
        "PHP": [
            "$_GET",
            "$_POST",
            "$_COOKIE",
            "$_FILES",
            "$_REQUEST",
            "file_get_contents('php://input')",
        ],
        "Go": [
            "r.URL.Query()",
            "ctx.Query()",
            "ctx.FormValue()",
            "c.QueryParam",
            "c.FormValue",
        ],
        "JavaScript": [
            "req.body",
            "req.query",
            "req.params",
            "location.search",
            "document.cookie",
            "process.argv",
        ],
    }

    def __init__(self) -> None:
        self.sources: dict[str, list[str]] = {lang: list(patterns) for lang, patterns in self.DEFAULT_SOURCES.items()}

    def register_source(self, language: str, pattern: str) -> None:
        if language not in self.sources:
            self.sources[language] = []
        if pattern not in self.sources[language]:
            self.sources[language].append(pattern)

    def is_source(self, text: str, language: str = "Python") -> bool:
        """Returns True if the given code snippet/expression matches an untrusted source pattern."""
        patterns = self.sources.get(language, []) + self.sources.get("Python", [])
        return any(pat in text for pat in patterns)

    def match_source(self, text: str, line_number: int = 1, language: str = "Python") -> TaintSource | None:
        """Returns TaintSource object if text matches a source pattern, else None."""
        patterns = self.sources.get(language, []) + self.sources.get("Python", [])
        for pat in patterns:
            if pat in text:
                return TaintSource(name=pat, language=language, line_number=line_number, pattern=pat)
        return None
