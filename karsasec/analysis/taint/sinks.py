"""Sink Registry managing dangerous execution sinks across supported languages."""

from __future__ import annotations

from karsasec.analysis.taint.models import TaintCategory, TaintSink


class SinkRegistry:
    """Registry maintaining multi-language security sinks categorized by vulnerability type."""

    DEFAULT_SINKS: dict[TaintCategory, list[str]] = {
        TaintCategory.SQL_INJECTION: [
            "execute(",
            "query(",
            "raw(",
            "Exec(",
            "db.execute",
            "cursor.execute",
            "mysqli_query",
            "PDO::query",
            "PDO::prepare",
            "mysqli::prepare",
            "DB::select",
            "DB::raw",
            "DB::statement",
        ],
        TaintCategory.COMMAND_INJECTION: [
            "exec(",
            "system(",
            "shell_exec(",
            "subprocess.Popen",
            "subprocess.run",
            "Process.Start",
            "os.system",
            "passthru",
        ],
        TaintCategory.PATH_TRAVERSAL: [
            "open(",
            "File(",
            "SendFile(",
            "NamedFile(",
            "read_file",
            "unlink",
            "file_get_contents",
        ],
        TaintCategory.SSRF: [
            "requests.get",
            "requests.post",
            "requests.request",
            "urllib.request.urlopen",
            "fetch(",
            "axios.get",
            "axios.post",
            "http.Get(",
            "curl_exec",
            "reqwest::get",
        ],
        TaintCategory.XSS: [
            "response.write",
            "echo",
            "print(",
            "printf(",
            "document.write",
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "dangerouslySetInnerHTML",
            "v-html",
            "eval(",
        ],
    }

    def __init__(self) -> None:
        self.sinks: dict[TaintCategory, list[str]] = {cat: list(pats) for cat, pats in self.DEFAULT_SINKS.items()}

    def register_sink(self, category: TaintCategory, pattern: str) -> None:
        if category not in self.sinks:
            self.sinks[category] = []
        if pattern not in self.sinks[category]:
            self.sinks[category].append(pattern)

    def is_sink(self, text: str) -> bool:
        """Returns True if the text matches any registered sink pattern."""
        for patterns in self.sinks.values():
            if any(pat in text for pat in patterns):
                return True
        return False

    def match_sink(self, text: str, line_number: int = 1) -> TaintSink | None:
        """Returns TaintSink object if text matches a sink pattern, else None."""
        for cat, patterns in self.sinks.items():
            for pat in patterns:
                if pat in text:
                    return TaintSink(name=pat, category=cat, line_number=line_number, pattern=pat)
        return None
