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
from pathlib import Path

from karsasec.graph.cfg import CFGBuilder
from karsasec.graph.constant_resolver import (
    _RE_CONST_IDENT,
    _STATIC_RESOLUTIONS,
    ConstantResolution,
    ConstantResolver,
)
from karsasec.graph.dataflow.abstract_state import AbstractEnvironment, SemanticConstraint, TaintState as AbstractTaintState
from karsasec.graph.dataflow.constant_evaluator import constant_evaluator
from karsasec.graph.dataflow.crypto_context import CryptoContextAnalyzer, CryptoContextKind
from karsasec.graph.dataflow.guard_propagation import WorklistFixpointAnalyzer
from karsasec.graph.dataflow.interprocedural_guard import InterproceduralGuardManager
from karsasec.graph.dataflow.model import DataFlowEvidence, TaintState
from karsasec.graph.dataflow.sink_matrix import CompatibilityDecision, SinkContext, sink_compatibility_matrix
from karsasec.graph.resource_graph import ResourceGraph
from karsasec.graph.symbol_resolver import SymbolResolver
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

from karsasec.graph.dataflow import dataflow_analyzer


from karsasec.graph.dataflow.security_decision import SecurityDecisionEngine
from karsasec.graph.dataflow.security_verdict import SecurityVerdict


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
    verdict: SecurityVerdict | None = None                   # E18: security decision verdict


# ---------------------------------------------------------------------------
# TaintVerifier
# ---------------------------------------------------------------------------

from karsasec.graph.dataflow.semantic_correlator import SemanticSinkCorrelator
from karsasec.graph.dataflow.semantic_evidence import ProofStatus


class TaintVerifier:
    """Verifies whether a rule match at a sink actually receives untrusted user input.

    E10-3K changes:
    - Added ConstantResolver for generic PHP constant tracking
    E11 changes:
    - Integrated DataFlowAnalyzer for backward taint propagation, Def/Use analysis, and sink-aware sanitization
    E12-17 changes:
    - Integrated SemanticSinkCorrelator for evidence correlation while preserving E12-13 final authority
    E12-18 changes:
    - Integrated SecurityDecisionEngine for evidence-backed security verdicts
    """

    def __init__(self) -> None:
        self._const_resolver = ConstantResolver()
        self._df_analyzer = dataflow_analyzer
        self._resource_graph = ResourceGraph()
        self._symbol_resolver = SymbolResolver(self._resource_graph)
        self._interproc_manager = InterproceduralGuardManager(self._resource_graph)
        self._crypto_analyzer = CryptoContextAnalyzer()
        self._correlator = SemanticSinkCorrelator(self._resource_graph)
        self._decision_engine = SecurityDecisionEngine()
        self.project_files: dict[str, str] = {}

    def verify_sink(
        self,
        node: ASTNode,
        snippet: str,
        context_text: str,
        source_text: str = "",
        language: str = "",
        base_severity: Severity = Severity.HIGH,
        base_confidence: Confidence = Confidence.CONFIDENT,
        file_path: Path | None = None,
    ) -> TaintAnalysisResult:
        """Analyze a sink location for taint vs. static evidence."""
        lang = (language or "php").strip().lower()
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

        const_resolution: ConstantResolution | None = None

        # -- Step 1B: Static SQL query payload detection ---------------------------
        if lang == "php" and not is_static:
            if self._is_static_sql_argument(clean_snippet, full_source, lang):
                is_static = True

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

        # -- Step 2: PHP Constant Resolution (E10-3K) ----------------------------
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
                file_path=file_path,
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
        has_taint = self._contains_untrusted_source(clean_snippet, source_patterns)

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

        # -- Step 6B: Path-Sensitive Control-Flow Guard & Compatibility Evaluation --
        rule_cat = "SQL_INJECTION"
        if any(k in clean_snippet for k in ("exec", "shell_exec", "system", "passthru")):
            rule_cat = "COMMAND_INJECTION"
        elif any(k in clean_snippet for k in ("include", "require", "readfile")):
            rule_cat = "PATH_TRAVERSAL"
        elif any(k in clean_snippet for k in ("echo", "print", "header")):
            rule_cat = "XSS"

        is_guarded, guard_reason, guard_df_ev = self._evaluate_cfg_path_guards(
            snippet=clean_snippet,
            full_source=full_source,
            lang=lang,
            rule_category=rule_cat,
        )
        if is_guarded:
            return TaintAnalysisResult(
                has_taint_source=False,
                is_hardcoded_static=False,
                is_whitelisted_guard=True,
                adjusted_confidence=Confidence.LOW,
                adjusted_severity=Severity.LOW,
                reason=guard_reason,
                dataflow_evidence=guard_df_ev,
            )

        # -- Step 6C: HMAC / Signature Guard Detection ----------------------------
        has_hmac_guard = bool(
            re.search(r'\bhash_equals\s*\(', full_source, re.IGNORECASE)
            and re.search(r'\b(wp_hash|hash_hmac|openssl_verify|verify_signature)\b', full_source, re.IGNORECASE)
        )
        if has_hmac_guard and any(k in clean_snippet for k in ("unserialize", "eval", "unserialize(")):
            df_evidence = DataFlowEvidence(
                state=TaintState.SANITIZED,
                path=(),
                sanitizer_capability="HMAC_INTEGRITY",
                adjusted_confidence=Confidence.LOW,
                adjusted_severity=Severity.LOW,
                reason="Sink is protected by HMAC signature verification (hash_equals/wp_hash)",
                truncated=False,
                hop_count=0,
            )
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

    def _is_static_sql_argument(self, snippet: str, full_source: str, lang: str) -> bool:
        """Determines if a SQL query execution argument is a provably hardcoded static string literal."""
        m_call = re.search(r'\b(?:mysqli_query|pg_query|mysql_query|sqlite_query|query|exec)\s*\(\s*(?:[^,\)]+\s*,\s*)?(.+?)\s*\)', snippet, re.IGNORECASE)
        if not m_call:
            return False

        arg = m_call.group(1).strip()
        # Use ConstantEvaluator pre-dataflow evaluation
        env = constant_evaluator.build_scope_environment(full_source, language=lang)
        lat_val = constant_evaluator.evaluate_expression(arg, full_source, env=env, language=lang)
        if lat_val.is_constant():
            return True

        # Fallback direct string literal argument without variable interpolation
        if (arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'")):
            if "$" not in arg and not re.search(r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b', arg):
                return True

        return False

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
        assign_pattern = re.compile(rf'(?:var|let|const)?\s*{re.escape(variable)}\s*(?::=|=)\s*([^\n;]+)')
        for m in assign_pattern.finditer(source_text):
            expression = m.group(1)
            if self._contains_untrusted_source(expression, sources):
                return True
            nested_vars = self._extract_variables(expression)
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

    def _evaluate_cfg_path_guards(
        self,
        snippet: str,
        full_source: str,
        lang: str,
        rule_category: str = "SQL_INJECTION",
    ) -> tuple[bool, str, DataFlowEvidence | None]:
        """Performs path-sensitive CFG abstract interpretation and evaluates sink compatibility."""
        if not full_source or lang != "php":
            return False, "", None

        lines = [line for line in full_source.splitlines() if line.strip()]
        builder = CFGBuilder()
        cfg = builder.build_cfg("main", lines)

        if not cfg.reachable_blocks:
            return False, "", None

        # Initial environment
        init_env = AbstractEnvironment()
        for sg in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"):
            init_env.assignment_kill(sg, new_taint=AbstractTaintState.TAINTED, prov_desc="Superglobal input")

        analyzer = WorklistFixpointAnalyzer()
        in_states = analyzer.analyze(cfg, init_env)

        # Determine SinkContext
        context = SinkContext.SQL_VALUE
        if "SQL" in rule_category.upper():
            if re.search(r'FROM\s+\$[a-zA-Z0-9_]+|INTO\s+\$[a-zA-Z0-9_]+', snippet, re.IGNORECASE):
                context = SinkContext.SQL_IDENTIFIER
            else:
                context = SinkContext.SQL_VALUE
        elif "COMMAND" in rule_category.upper() or "EXEC" in rule_category.upper() or "SHELL" in rule_category.upper():
            context = SinkContext.SHELL_ARGUMENT
        elif "XSS" in rule_category.upper() or "HTML" in rule_category.upper():
            context = SinkContext.HTML_TEXT
        elif "FILE" in rule_category.upper() or "PATH" in rule_category.upper() or "LFI" in rule_category.upper():
            context = SinkContext.FILE_PATH

        # E12-17 Whole-Program Semantic Sink Correlation Layer
        ev_bundle = self._correlator.correlate_and_evaluate(
            sink_node_id=f"sink_{hash(snippet)}",
            snippet=snippet,
            full_source=full_source,
            language=lang,
            sink_category=rule_category,
            sink_context=context,
        )
        if ev_bundle.proof_status == ProofStatus.PROVEN and ev_bundle.evaluation_result and ev_bundle.evaluation_result.decision == CompatibilityDecision.COMPATIBLE:
            ev_reason = ev_bundle.evaluation_result.reason
            df_ev = DataFlowEvidence(
                state=TaintState.SANITIZED,
                path=(),
                adjusted_confidence=Confidence.LOW,
                adjusted_severity=Severity.LOW,
                reason=ev_reason,
                truncated=False,
            )
            return True, ev_reason, df_ev

        vars_in_snip = self._extract_variables(snippet)
        env_at_sink = self._correlator._compute_path_environment(full_source, snippet) or init_env
        for var in vars_in_snip:
            val = env_at_sink.get_value(var)
            constraints_to_eval = set(val.all_constraints) if val else set()

            # E12-14: Interprocedural Guard Provenance (Guardrail 2)
            interproc_facts = self._interproc_manager.get_propagated_facts("", var, env_at_sink)
            constraints_to_eval.update(interproc_facts)

            if constraints_to_eval:
                eval_res = sink_compatibility_matrix.evaluate(constraints_to_eval, rule_category, context)
                if eval_res.decision == CompatibilityDecision.COMPATIBLE:
                    ev_reason = f"Path-sensitive guard proved {eval_res.matching_constraint} compatible with {rule_category} in {eval_res.sink_context} context"
                    df_ev = DataFlowEvidence(
                        state=TaintState.SANITIZED,
                        path=(),
                        adjusted_confidence=Confidence.LOW,
                        adjusted_severity=Severity.LOW,
                        reason=ev_reason,
                        truncated=False,
                    )
                    return True, ev_reason, df_ev

        # E12-14: Static Include & Constant Interpolation Resolution (Guardrail 5)
        if "FILE" in rule_category.upper() or "PATH" in rule_category.upper() or "LFI" in rule_category.upper() or "TRAVERSAL" in rule_category.upper():
            if any(inc in snippet for inc in ("require", "include", "require_once", "include_once")):
                clean_inc_expr = re.sub(r'^\s*(?:require_once|include_once|require|include)\s*\(?\s*', '', snippet)
                clean_inc_expr = re.sub(r'\s*\)?\s*;?\s*$', '', clean_inc_expr)
                all_files = dict(self.project_files) if self.project_files else {"current": full_source}
                if "current" not in all_files:
                    all_files["current"] = full_source
                ev = self._symbol_resolver.resolve_expression(clean_inc_expr, all_files, requesting_file="current")
                if ev.resolution in (ConstantResolution.DERIVED_STATIC, ConstantResolution.STATIC_CONSTANT, ConstantResolution.STATIC_LITERAL):
                    eval_res = sink_compatibility_matrix.evaluate({SemanticConstraint.PATH_NORMALIZED}, rule_category, SinkContext.FILE_PATH)
                    if eval_res.decision == CompatibilityDecision.COMPATIBLE:
                        ev_reason = f"Static include expression provenance resolved: {ev.provenance}"
                        df_ev = DataFlowEvidence(
                            state=TaintState.SANITIZED,
                            path=(),
                            adjusted_confidence=Confidence.LOW,
                            adjusted_severity=Severity.LOW,
                            reason=ev_reason,
                            truncated=False,
                        )
                        return True, ev_reason, df_ev

        # E12-14: Cryptographic Usage Context Evaluation (Guardrail 1)
        if "CRYPTO" in rule_category.upper() or "HASH" in rule_category.upper() or "MD5" in rule_category.upper():
            hash_match = re.search(r'\b(md5|sha1|hash)\s*\(\s*([^)]+)\s*\)', snippet, re.IGNORECASE)
            if hash_match:
                func_name = hash_match.group(1)
                input_arg = hash_match.group(2)
                assigned_match = re.search(r'(\$[a-zA-Z0-9_]+)\s*=\s*(?:md5|sha1|hash)', snippet)
                assigned_var = assigned_match.group(1) if assigned_match else ""

                ctx_ev = self._crypto_analyzer.analyze_hash_usage(
                    hash_func=func_name,
                    input_expr=input_arg,
                    assigned_var=assigned_var,
                    surrounding_stmts=lines,
                )
                if ctx_ev.context_kind in (CryptoContextKind.CACHE_KEY, CryptoContextKind.CHECKSUM, CryptoContextKind.NON_SECURITY_IDENTIFIER):
                    eval_res = sink_compatibility_matrix.evaluate({SemanticConstraint.PATH_NORMALIZED}, rule_category, SinkContext.UNKNOWN)
                    if eval_res.decision == CompatibilityDecision.COMPATIBLE:
                        ev_reason = f"Non-security cryptographic usage context confirmed: {ctx_ev.provenance}"
                        df_ev = DataFlowEvidence(
                            state=TaintState.SANITIZED,
                            path=(),
                            adjusted_confidence=Confidence.LOW,
                            adjusted_severity=Severity.LOW,
                            reason=ev_reason,
                            truncated=False,
                        )
                        return True, ev_reason, df_ev

        return False, "", None

    def evaluate_security_verdict(
        self,
        snippet: str,
        full_source: str,
        lang: str = "php",
        rule_id: str = "KS-SECURITY-0001",
        rule_category: str = "SQL_INJECTION",
        file_path: str = "",
        line_number: int = 0,
        function_name: str = "",
        variable_version: str = "",
        call_context: str | None = None,
        branch_polarity: str = "",
    ) -> SecurityVerdict:
        """Evaluates path-sensitive evidence and constructs a SecurityVerdict (E12-18)."""
        context = SinkContext.SQL_VALUE
        if "SQL" in rule_category.upper():
            if re.search(r'FROM\s+\$[a-zA-Z0-9_]+|INTO\s+\$[a-zA-Z0-9_]+', snippet, re.IGNORECASE):
                context = SinkContext.SQL_IDENTIFIER
            else:
                context = SinkContext.SQL_VALUE
        elif "COMMAND" in rule_category.upper() or "EXEC" in rule_category.upper() or "SHELL" in rule_category.upper():
            context = SinkContext.SHELL_ARGUMENT
        elif "XSS" in rule_category.upper() or "HTML" in rule_category.upper():
            context = SinkContext.HTML_TEXT
        elif "FILE" in rule_category.upper() or "PATH" in rule_category.upper() or "LFI" in rule_category.upper():
            context = SinkContext.FILE_PATH

        ev_bundle = self._correlator.correlate_and_evaluate(
            sink_node_id=f"sink_{hash(snippet)}",
            snippet=snippet,
            full_source=full_source,
            language=lang,
            sink_category=rule_category,
            sink_context=context,
        )

        return self._decision_engine.evaluate_verdict(
            bundle=ev_bundle,
            rule_id=rule_id,
            file_path=file_path,
            function_name=function_name,
            line_number=line_number,
            variable_version=variable_version,
            call_context=call_context,
            branch_polarity=branch_polarity,
        )


# Global default instance
taint_verifier = TaintVerifier()
