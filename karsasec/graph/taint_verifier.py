"""Taint and Guard Verifier analyzing AST nodes and source snippets for taint sources and static guards."""

import re
from dataclasses import dataclass
from typing import Optional, Set
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.enums import Confidence, Severity

# Superglobals and untrusted source indicators per language
UNTRUSTED_SOURCES_PHP: Set[str] = {
    "$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE", "$_FILES", "$_ENV", "$HTTP_RAW_POST_DATA", "$argv", "input"
}

UNTRUSTED_SOURCES_JS: Set[str] = {
    "req.query", "req.body", "req.params", "req.headers", "location.href", "location.search", "document.cookie", "window.name", "input"
}

UNTRUSTED_SOURCES_GO: Set[str] = {
    "r.URL.Query()", "r.FormValue", "r.PostFormValue", "r.Body", "os.Args", "input"
}

UNTRUSTED_SOURCES_PYTHON: Set[str] = {
    "request.args", "request.form", "request.json", "request.GET", "request.POST", "sys.argv", "os.environ", "user_input", "input"
}

UNTRUSTED_SOURCES_JAVA: Set[str] = {
    "args[",
    "request.getParameter",
    "request.getHeader",
    "HttpServletRequest",
    "System.getenv",
    "System.getProperty",
    "System.in",
}

UNTRUSTED_SOURCES_RUST: Set[str] = {
    "env::args",
    "env::args_os",
    "env::var",
    "env::var_os",
    "std::env::args",
    "std::env::args_os",
    "std::env::var",
    "std::env::var_os",
}

# Configuration / IaC target formats where code taint does not apply
IAC_LANGUAGES: Set[str] = {
    "dockerfile", "kubernetes", "github actions", "terraform", "hcl", "yaml", "yml", "json", "generic"
}


@dataclass(slots=True, frozen=True)
class TaintAnalysisResult:
    """Outcome of evaluating taint sources, sanitizers, and static guards on a sink."""
    has_taint_source: bool
    is_hardcoded_static: bool
    is_whitelisted_guard: bool
    adjusted_confidence: Confidence
    adjusted_severity: Severity
    reason: str


class TaintVerifier:
    """Verifies whether a rule match at a sink node actually receives untrusted user input."""

    def verify_sink(
        self,
        node: ASTNode,
        snippet: str,
        context_text: str,
        source_text: str = "",
        language: str = "",
        base_severity: Severity = Severity.HIGH,
        base_confidence: Confidence = Confidence.CONFIDENT,
    ) -> TaintAnalysisResult:
        """Analyzes a sink location for presence of taint sources vs hardcoded static literals.

        Args:
            node: Target AST node of the sink.
            snippet: Exact source snippet matched.
            context_text: Enclosing code window (e.g. 5 lines above/below).
            language: Program language (PHP, JavaScript, Python, Go, etc.).
            base_severity: Severity defined in the rule schema.
            base_confidence: Confidence defined in the rule schema.

        Returns:
            TaintAnalysisResult: Adjusted confidence, severity, and rationale.
        """
        lang = (language or "").strip().lower()
        clean_snippet = snippet.strip()
        clean_context = context_text.strip()

        # IaC / Misconfiguration checks are structural, bypass code taint analysis
        if lang in IAC_LANGUAGES or any(iac_kw in lang for iac_kw in ("docker", "k8s", "kubernetes", "actions", "yaml", "tf")):
            return TaintAnalysisResult(
                has_taint_source=True,
                is_hardcoded_static=False,
                is_whitelisted_guard=False,
                adjusted_confidence=base_confidence,
                adjusted_severity=base_severity,
                reason="IaC configuration check bypasses code taint analysis",
            )

        # 1. Check if the sink call uses a 100% hardcoded static string literal (zero variables)
        is_static = False
        hardcoded_patterns = [
            r'shell_exec\s*\(\s*["\'][^"\']+\s*["\']\s*\)',        # shell_exec("constant string")
            r'exec\s*\(\s*["\'][^"\']+\s*["\']\s*\)',              # exec("constant string")
            r'system\s*\(\s*["\'][^"\']+\s*["\']\s*\)',            # system("constant string")
            r'require(?:_once)?\s+__DIR__\s*\.\s*["\'][^"\']+["\']',  # require __DIR__ . '/file.php'
            r'include(?:_once)?\s+__DIR__\s*\.\s*["\'][^"\']+["\']',  # include __DIR__ . '/file.php'
            r'require_once\s+DVWA_WEB_PAGE_TO_ROOT\s*\.\s*["\'][^"\']+["\']', # require_once DVWA_WEB_PAGE_TO_ROOT . 'static.php'
        ]

        for pat in hardcoded_patterns:
            if re.search(pat, clean_snippet):
                is_static = True
                break

        if not is_static and lang == "php":
            func_arg_match = re.search(r'\b(shell_exec|exec|system|passthru|eval)\s*\(\s*["\']([^"\']+)["\']\s*\)', clean_snippet)
            if func_arg_match and "$" not in func_arg_match.group(2):
                is_static = True

        # 2. Detect untrusted source usage in the sink snippet or surrounding context
        source_patterns = self._untrusted_sources_for_language(lang)
        has_taint = self._contains_untrusted_source(clean_snippet, source_patterns) or self._contains_untrusted_source(clean_context, source_patterns)

        # 3. If no direct taint is found, resolve variable assignments from the full source text.
        if not has_taint and source_text:
            variables = self._extract_variables(clean_snippet)
            for variable in variables:
                if self._variable_assignment_contains_taint(variable, source_text, source_patterns):
                    has_taint = True
                    break

        # 4. Check for Whitelist Guard (e.g. switch ($var) { case 'low.php': require ... })
        is_whitelisted = False
        if ("switch (" in clean_context or "switch(" in clean_context) and ("case '" in clean_context or 'case "' in clean_context):
            is_whitelisted = True

        # 5. Compute adjusted confidence and severity
        adj_severity = base_severity
        adj_confidence = base_confidence
        reason = "Valid rule match"

        if is_static:
            adj_confidence = Confidence.LOW
            adj_severity = Severity.LOW
            reason = "Sink argument is a hardcoded static literal"
        elif is_whitelisted:
            adj_confidence = Confidence.LOW
            adj_severity = Severity.LOW
            reason = "Sink argument is guarded by a static switch/whitelist control flow"
        elif not has_taint:
            adj_confidence = Confidence.LOW
            adj_severity = Severity.LOW
            reason = "No untrusted source detected in sink context"
        else:
            reason = "Untrusted source detected in sink context"

        return TaintAnalysisResult(
            has_taint_source=has_taint,
            is_hardcoded_static=is_static,
            is_whitelisted_guard=is_whitelisted,
            adjusted_confidence=adj_confidence,
            adjusted_severity=adj_severity,
            reason=reason,
        )

    def _extract_variables(self, text: str) -> Set[str]:
        variables = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', text))
        if variables:
            return variables

        # Fallback for non-PHP languages: extract identifier names from expressions.
        return set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', text))

    def _variable_assignment_contains_taint(self, variable: str, source_text: str, sources: Set[str]) -> bool:
        if not variable or not source_text or not sources:
            return False

        assign_pattern = re.compile(rf'{re.escape(variable)}\s*=\s*([^;]+);')
        for match in assign_pattern.finditer(source_text):
            expression = match.group(1)
            if self._contains_untrusted_source(expression, sources):
                return True
            # If the assigned expression references another variable, recursively resolve it once.
            nested_vars = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', expression))
            for nested in nested_vars:
                if nested != variable and self._variable_assignment_contains_taint(nested, source_text, sources):
                    return True
        return False

    def _untrusted_sources_for_language(self, language: str) -> Set[str]:
        lang = (language or "").strip().lower()
        if lang == "php":
            return UNTRUSTED_SOURCES_PHP
        if lang in ("js", "javascript", "typescript", "ts"):
            return UNTRUSTED_SOURCES_JS
        if lang == "go":
            return UNTRUSTED_SOURCES_GO
        if lang in ("py", "python"):
            return UNTRUSTED_SOURCES_PYTHON
        if lang == "java":
            return UNTRUSTED_SOURCES_JAVA
        if lang == "rust":
            return UNTRUSTED_SOURCES_RUST
        return set()

    def _contains_untrusted_source(self, text: str, sources: Set[str]) -> bool:
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


# Global default instance
taint_verifier = TaintVerifier()
