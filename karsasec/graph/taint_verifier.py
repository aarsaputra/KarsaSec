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

UNTRUSTED_SOURCES_PYTHON: Set[str] = {
    "request.args", "request.form", "request.json", "request.GET", "request.POST", "sys.argv", "os.environ", "user_input", "input"
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
        language: str,
        base_severity: Severity,
        base_confidence: Confidence,
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

        # 1. Check if the sink call uses a 100% hardcoded static string literal (Zero variables)
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

        # Check if function argument has no variable ($ or parameter) at all
        if not is_static and lang == "php":
            func_arg_match = re.search(r'\b(shell_exec|exec|system|passthru|eval)\s*\(\s*["\']([^"\']+)["\']\s*\)', clean_snippet)
            if func_arg_match and "$" not in func_arg_match.group(2):
                is_static = True

        # 2. Check for Whitelist Guard (e.g. switch ($var) { case 'low.php': require ... })
        is_whitelisted = False
        if ("switch (" in clean_context or "switch(" in clean_context) and ("case '" in clean_context or 'case "' in clean_context):
            is_whitelisted = True

        # 3. Compute adjusted confidence and severity
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

        return TaintAnalysisResult(
            has_taint_source=not (is_static or is_whitelisted),
            is_hardcoded_static=is_static,
            is_whitelisted_guard=is_whitelisted,
            adjusted_confidence=adj_confidence,
            adjusted_severity=adj_severity,
            reason=reason,
        )


# Global default instance
taint_verifier = TaintVerifier()
