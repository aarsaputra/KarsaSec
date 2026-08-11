"""TaintVerifier: sink-level taint and static evidence analysis.

Refactored in E10-3K to integrate ConstantResolver for generic PHP constant tracking.
Removed all project-specific regex exceptions. Resolution is now generic via ConstantResolver.

Architecture:
    Rule Matcher
         |
    TaintVerifier
         |
    ConstantResolver (E10-3K)
         |
    Evidence Classification
         |
    Finding decision
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from karsasec.graph.constant_resolver import (
    _RE_CONST_IDENT,
    _STATIC_RESOLUTIONS,
    ConstantResolution,
    ConstantResolver,
)
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.enums import Confidence, Severity

# ---------------------------------------------------------------------------
# Untrusted source sets per language
# ---------------------------------------------------------------------------

UNTRUSTED_SOURCES_PHP: set[str] = {
    "$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE",
    "$_FILES", "$_ENV", "$HTTP_RAW_POST_DATA", "$argv", "input",
}
UNTRUSTED_SOURCES_JS: set[str] = {
    "req.query", "req.body", "req.params", "req.headers",
    "location.href", "location.search", "document.cookie", "window.name", "input",
}
UNTRUSTED_SOURCES_GO: set[str] = {
    "r.URL.Query()", "r.FormValue", "r.PostFormValue", "r.Body", "os.Args", "input",
}
UNTRUSTED_SOURCES_PYTHON: set[str] = {
    "request.args", "request.form", "request.json", "request.GET",
    "request.POST", "sys.argv", "os.environ", "user_input", "input",
}
UNTRUSTED_SOURCES_JAVA: set[str] = {
    "args[", "request.getParameter", "request.getHeader",
    "HttpServletRequest", "System.getenv", "System.getProperty", "System.in",
}
UNTRUSTED_SOURCES_RUST: set[str] = {
    "env::args", "env::args_os", "env::var", "env::var_os",
    "std::env::args", "std::env::args_os", "std::env::var", "std::env::var_os",
}

IAC_LANGUAGES: set[str] = {
    "dockerfile", "kubernetes", "github actions", "terraform",
    "hcl", "yaml", "yml", "json", "generic",
}

# Maximum recursive depth for variable assignment backtracking
_MAX_BACKTRACK_DEPTH: int = 4


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

from karsasec.graph.dataflow import DataFlowAnalyzer, DataFlowEvidence, TaintState, dataflow_analyzer

@dataclass(slots=True, frozen=True)
class TaintAnalysisResult:
    """Outcome of evaluating taint sources, sanitizers, and static guards on a sink."""
    has_taint_source: bool
    is_hardcoded_static: bool
    is_whitelisted_guard: bool
    adjusted_confidence: Confidence
    adjusted_severity: Severity
    reason: str
    constant_resolution: ConstantResolution | None = None  # E10-3K: constant evidence
    dataflow_evidence: DataFlowEvidence | None = None       # E11: data-flow evidence


# ---------------------------------------------------------------------------
# TaintVerifier
# ---------------------------------------------------------------------------

class TaintVerifier:
    """Verifies whether a rule match at a sink actually receives untrusted user input.

    E10-3K changes:
    - Added ConstantResolver for generic PHP constant tracking
    E11 changes:
    - Integrated DataFlowAnalyzer for backward taint propagation, Def/Use analysis, and sink-aware sanitization
    """

    def __init__(self) -> None:
        self._const_resolver = ConstantResolver()
        self._df_analyzer = dataflow_analyzer

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
        """Analyze a sink location for taint vs. static evidence."""
        lang = (language or "").strip().lower()
        clean_snippet = snippet.strip()
        clean_context = context_text.strip()
        full_source = source_text or clean_context

        # IaC: bypass code taint analysis
        if lang in IAC_LANGUAGES or any(k in lang for k in ("docker", "k8s", "kubernetes", "actions", "yaml", "tf")):
            return TaintAnalysisResult(
                has_taint_source=True,
                is_hardcoded_static=False,
                is_whitelisted_guard=False,
                adjusted_confidence=base_confidence,
                adjusted_severity=base_severity,
                reason="IaC configuration check bypasses code taint analysis",
            )

        # -- Step 1: Hardcoded static literal patterns (language-agnostic) ----------
        is_static = False
        hardcoded_patterns = [
            r'shell_exec\s*\(\s*["\'][^"\'$]+\s*["\']\s*\);?',
            r'\bexec\s*\(\s*["\'][^"\'$]+\s*["\']\s*\);?',
            r'\bsystem\s*\(\s*["\'][^"\'$]+\s*["\']\s*\);?',
            r'require(?:_once)?\s+__DIR__\s*\.\s*["\'][^"\']+["\']',
            r'include(?:_once)?\s+__DIR__\s*\.\s*["\'][^"\']+["\']',
        ]
        for pat in hardcoded_patterns:
            if re.search(pat, clean_snippet):
                is_static = True
                break

        if not is_static and lang == "php":
            m = re.search(r'\b(shell_exec|exec|system|passthru|eval)\s*\(\s*["\']([^"\']+)["\']\s*\)', clean_snippet)
            if m and "$" not in m.group(2):
                is_static = True

        # -- Step 2: PHP Constant Resolution (E10-3K) ----------------------------
        const_resolution: ConstantResolution | None = None
        if lang == "php" and not is_static:
            const_resolution, is_static = self._resolve_php_constants(
                clean_snippet, full_source
            )

        if is_static:
            return TaintAnalysisResult(
                has_taint_source=False,
                is_hardcoded_static=True,
                is_whitelisted_guard=False,
                adjusted_confidence=Confidence.LOW,
                adjusted_severity=Severity.LOW,
                reason="Sink argument is a hardcoded or statically-resolved constant",
                constant_resolution=const_resolution,
            )

        # -- Step 3: Incremental Data-Flow Analysis (E11) ------------------------
        df_evidence: DataFlowEvidence | None = None
        if full_source:
            df_evidence = self._df_analyzer.analyze_sink(
                snippet=clean_snippet,
                source_text=full_source,
                language=lang,
                base_severity=base_severity,
                base_confidence=base_confidence,
            )

            if df_evidence.state == TaintState.TAINTED:
                return TaintAnalysisResult(
                    has_taint_source=True,
                    is_hardcoded_static=False,
                    is_whitelisted_guard=False,
                    adjusted_confidence=df_evidence.adjusted_confidence,
                    adjusted_severity=df_evidence.adjusted_severity,
                    reason=df_evidence.reason,
                    constant_resolution=const_resolution,
                    dataflow_evidence=df_evidence,
                )
            elif df_evidence.state == TaintState.SANITIZED:
                return TaintAnalysisResult(
                    has_taint_source=False,
                    is_hardcoded_static=False,
                    is_whitelisted_guard=True,
                    adjusted_confidence=Confidence.LOW,
                    adjusted_severity=Severity.LOW,
                    reason=df_evidence.reason,
                    constant_resolution=const_resolution,
                    dataflow_evidence=df_evidence,
                )
            elif df_evidence.state == TaintState.STATIC:
                return TaintAnalysisResult(
                    has_taint_source=False,
                    is_hardcoded_static=True,
                    is_whitelisted_guard=False,
                    adjusted_confidence=Confidence.LOW,
                    adjusted_severity=Severity.LOW,
                    reason=df_evidence.reason,
                    constant_resolution=const_resolution,
                    dataflow_evidence=df_evidence,
                )

        # -- Step 4: Untrusted source detection (Legacy Fallback) ----------------
        source_patterns = self._untrusted_sources_for_language(lang)
        has_taint = (
            self._contains_untrusted_source(clean_snippet, source_patterns)
            or self._contains_untrusted_source(clean_context, source_patterns)
        )

        # -- Step 5: Variable assignment backtracking fallback -------------------
        if not has_taint and full_source:
            variables = self._extract_variables(clean_snippet)
            visited: frozenset[str] = frozenset()
            for var in variables:
                if self._variable_assignment_contains_taint(var, full_source, source_patterns, visited, 0):
                    has_taint = True
                    break

        # -- Step 6: Whitelist guard (static switch/case control flow) -------------
        is_whitelisted = (
            ("switch (" in clean_context or "switch(" in clean_context)
            and ("case '" in clean_context or 'case "' in clean_context)
        )

        # -- Step 7: Resolve final confidence/severity ----------------------------
        adj_severity = base_severity
        adj_confidence = base_confidence
        reason = "Valid rule match"

        if is_whitelisted:
            adj_confidence = Confidence.LOW
            adj_severity = Severity.LOW
            reason = "Sink argument is guarded by a static switch/whitelist"
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
            constant_resolution=const_resolution,
            dataflow_evidence=df_evidence,
        )

    # ---------------------------------------------------------------------------
    # PHP Constant Resolution helpers (E10-3K)
    # ---------------------------------------------------------------------------

    def _resolve_php_constants(
        self,
        snippet: str,
        source_text: str,
    ) -> tuple[ConstantResolution | None, bool]:
        """Resolve PHP constant identifiers found in snippet.

        Returns (ConstantResolution | None, is_static: bool).
        is_static=True only when ALL parts of the expression are provably static.
        TAINTED constant -> has_taint (handled by caller).
        """
        const_ids = _RE_CONST_IDENT.findall(snippet)
        if not const_ids:
            return None, False

        decls = self._const_resolver.discover_declarations(source_text)

        # If no declarations at all in source, cannot resolve -> UNKNOWN -> not static
        if not decls:
            return ConstantResolution.UNKNOWN, False

        any_tainted = False
        any_unknown = False
        all_static = True

        for cid in const_ids:
            ev = self._const_resolver.resolve(cid, source_text, _decls=decls)
            if ev.resolution == ConstantResolution.TAINTED:
                any_tainted = True
                all_static = False
            elif ev.resolution not in _STATIC_RESOLUTIONS:
                any_unknown = True
                all_static = False

        if any_tainted:
            return ConstantResolution.TAINTED, False

        # Even if constants are static, PHP variables ($id, $security) in the snippet
        # make the expression dynamic — check for interpolated variables
        php_vars_in_snippet = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', snippet)
        # Also check for interpolated string variables like "path/{$id}/..."
        interpolated = re.findall(r'\{?\$[A-Za-z_][A-Za-z0-9_]*\}?', snippet)
        if php_vars_in_snippet or interpolated:
            # Constants may be static but the expression is still dynamic
            return ConstantResolution.DERIVED_STATIC, False

        if all_static:
            return ConstantResolution.DERIVED_STATIC, True

        if any_unknown:
            return ConstantResolution.UNKNOWN, False

        return None, False

    # ---------------------------------------------------------------------------
    # Language-agnostic helpers
    # ---------------------------------------------------------------------------

    def _extract_variables(self, text: str) -> set[str]:
        variables = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', text))
        if variables:
            return variables
        return set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', text))

    def _variable_assignment_contains_taint(
        self,
        variable: str,
        source_text: str,
        sources: set[str],
        visited: frozenset[str],
        depth: int,
    ) -> bool:
        """Backtrack variable assignments with cycle protection and max depth."""
        if depth >= _MAX_BACKTRACK_DEPTH:
            return False
        if variable in visited:
            return False  # Cycle — conservative: not tainted (avoid FP from cycles)
        if not variable or not source_text or not sources:
            return False

        visited = visited | {variable}
        assign_pattern = re.compile(rf'{re.escape(variable)}\s*=\s*([^;]+);')
        for m in assign_pattern.finditer(source_text):
            expression = m.group(1)
            if self._contains_untrusted_source(expression, sources):
                return True
            nested_vars = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', expression))
            for nested in nested_vars:
                if nested != variable and self._variable_assignment_contains_taint(
                    nested, source_text, sources, visited, depth + 1
                ):
                    return True
        return False

    def _untrusted_sources_for_language(self, language: str) -> set[str]:
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

    def _contains_untrusted_source(self, text: str, sources: set[str]) -> bool:
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
