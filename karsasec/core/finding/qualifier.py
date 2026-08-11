"""Semantic Finding Qualifier: State machine evaluating candidate findings into qualified findings or taxonomy rejections (E12-3)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from karsasec.core.finding.candidate import CandidateFinding
from karsasec.core.finding.evidence import Evidence, FindingEvidence
from karsasec.core.finding.model import QualificationState, QualifiedFinding, compute_stable_finding_fingerprint
from karsasec.graph.dataflow.compatibility import CompatibilityRegistry
from karsasec.graph.dataflow.model import TaintState
from karsasec.graph.taint_verifier import TaintVerifier
from karsasec.parser.ast_nodes import ASTNode
from karsasec.qualification.fp_taxonomy import FPTaxonomyReason
from karsasec.rules.enums import Confidence, Severity

if TYPE_CHECKING:
    from karsasec.rules.schema import Rule


class SemanticFindingQualifier:
    """Evaluates CandidateFindings against AST context, sink semantics, taint flow, and sanitizer compatibility."""

    def __init__(self, taint_verifier: TaintVerifier | None = None) -> None:
        self.taint_verifier = taint_verifier or TaintVerifier()

    def qualify_candidate(self, candidate: CandidateFinding) -> QualifiedFinding:
        """Runs candidate finding through the semantic qualification state machine.

        Guarantees:
          - No silent candidate drop. Every candidate returns a QualifiedFinding carrying an explicit state and reason.
          - Retains complete evidence provenance trail (FindingEvidence).
        """
        snippet = candidate.snippet
        line = candidate.line
        source_text = candidate.source_text
        rule = candidate.rule

        # 1. Lexical / Comment / HTML String pre-qualification
        is_comment_or_string, lexical_reason = self._check_lexical_context(snippet, source_text, line)
        if is_comment_or_string:
            return self._build_rejected_finding(
                candidate=candidate,
                reason=lexical_reason,
                explanation=f"Match occurred inside non-executable context ({lexical_reason.value}).",
            )

        # 2. Sink Category Identification
        sink_category = self._derive_sink_category(rule, candidate.matched_text)

        # 3. Taint Verification via TaintVerifier & DataFlowAnalyzer
        verifier_res = self.taint_verifier.verify_sink(
            node=candidate.ast_node or ASTNode(node_id=candidate.candidate_id, node_type="sink", start=None, end=None),
            snippet=snippet,
            context_text=snippet,
            source_text=source_text,
            language=candidate.language,
        )

        # Extract evidence metrics
        df_evidence = getattr(verifier_res, "df_evidence", None)
        taint_state = df_evidence.state if df_evidence else TaintState.UNKNOWN
        sanitizer_capability = df_evidence.sanitizer_capability if df_evidence else "NONE"
        constant_res = df_evidence.constant_resolution if df_evidence else "UNKNOWN"

        # 4. Check for Static Input (ConstantResolver / DataFlow)
        if verifier_res.is_hardcoded_static or taint_state == TaintState.STATIC or constant_res == "STATIC_LITERAL":
            return self._build_rejected_finding(
                candidate=candidate,
                reason=FPTaxonomyReason.STATIC_INPUT,
                explanation="Sink argument resolved to hardcoded static literal or constant.",
                sink_category=sink_category,
                taint_state=TaintState.STATIC,
            )

        # 5. Check Sanitizer Compatibility
        if taint_state == TaintState.SANITIZED:
            is_compatible = CompatibilityRegistry.is_sanitizer_compatible(sanitizer_capability, sink_category)
            if is_compatible:
                return self._build_rejected_finding(
                    candidate=candidate,
                    reason=FPTaxonomyReason.SANITIZED_INPUT,
                    explanation=f"Sanitizer ({sanitizer_capability}) effectively neutralizes sink category ({sink_category}).",
                    sink_category=sink_category,
                    taint_state=TaintState.SANITIZED,
                    sanitizer_capability=sanitizer_capability,
                )
            else:
                # Incompatible sanitizer (e.g. htmlspecialchars for shell_exec) -> Taint remains ACTIVE
                taint_state = TaintState.TAINTED

        # 6. Check Taint Requirement
        require_taint = "user_input" in getattr(rule.evidence, "require", [])
        if require_taint and not verifier_res.has_taint_source and taint_state != TaintState.TAINTED:
            if taint_state == TaintState.UNKNOWN:
                # UNKNOWN_FLOW: preserve UNKNOWN state, do NOT convert to FP
                return self._build_unresolved_finding(
                    candidate=candidate,
                    explanation="Taint flow analysis inconclusive cap reached.",
                    sink_category=sink_category,
                )
            return self._build_rejected_finding(
                candidate=candidate,
                reason=FPTaxonomyReason.UNTAINTED_INPUT,
                explanation="Rule requires user input evidence, but no untrusted source was detected.",
                sink_category=sink_category,
                taint_state=taint_state,
            )

        # 7. Final Qualification — Confirmed Security Finding
        return self._build_confirmed_finding(
            candidate=candidate,
            sink_category=sink_category,
            taint_state=taint_state,
            sanitizer_capability=sanitizer_capability,
            verifier_res=verifier_res,
        )

    @staticmethod
    def _check_lexical_context(snippet: str, source_text: str, line_number: int) -> tuple[bool, FPTaxonomyReason]:
        """Detects whether snippet match occurs inside comments, string literals, or HTML tags."""
        trimmed = snippet.strip()

        # Comment detection
        if trimmed.startswith("//") or trimmed.startswith("#") or trimmed.startswith("/*") or trimmed.startswith("*"):
            return True, FPTaxonomyReason.COMMENT_OR_STRING_MATCH

        # Check line in source text for comment wrapper
        lines = source_text.splitlines()
        if 1 <= line_number <= len(lines):
            line_str = lines[line_number - 1].strip()
            if line_str.startswith("//") or line_str.startswith("#") or line_str.startswith("/*") or line_str.startswith("*"):
                return True, FPTaxonomyReason.COMMENT_OR_STRING_MATCH

        # HTML form / tag detection (non-executable snippet)
        if re.search(r"^\s*<(?:input|form|a|h[1-6]|p|div|span|table|td|tr|!--)\b", trimmed, re.IGNORECASE):
            return True, FPTaxonomyReason.LEXICAL_ONLY

        # Pure string assignment without function invocation (e.g. $var = "exec()")
        if re.match(r"^\$\w+\s*=\s*['\"][^'\"]*['\"];?$", trimmed):
            return True, FPTaxonomyReason.COMMENT_OR_STRING_MATCH

        return False, FPTaxonomyReason.LEXICAL_ONLY

    @staticmethod
    def _derive_sink_category(rule: Rule, matched_text: str) -> str:
        rule_cat = getattr(rule.metadata, "category", "") or getattr(rule.metadata, "tags", [])
        cat_str = str(rule_cat).upper()

        if "COMMAND" in cat_str or "RCE" in cat_str:
            return CompatibilityRegistry.COMMAND_EXECUTION
        if "SQL" in cat_str:
            return CompatibilityRegistry.SQL_EXECUTION
        if "LFI" in cat_str or "INCLUDE" in cat_str or "FILE" in cat_str:
            return CompatibilityRegistry.FILE_INCLUSION
        if "XSS" in cat_str or "HTML" in cat_str:
            return CompatibilityRegistry.HTML_OUTPUT
        if "EVAL" in cat_str or "CODE" in cat_str:
            return CompatibilityRegistry.CODE_EVALUATION
        if "CRYPTO" in cat_str:
            return CompatibilityRegistry.CRYPTOGRAPHIC_OPERATION
        return "GENERIC_SINK"

    def _build_confirmed_finding(
        self,
        candidate: CandidateFinding,
        sink_category: str,
        taint_state: TaintState,
        sanitizer_capability: str,
        verifier_res: Any,
    ) -> QualifiedFinding:
        rule = candidate.rule
        output = rule.output
        meta = rule.metadata

        severity = getattr(output, "severity", Severity.HIGH)
        confidence = getattr(output, "confidence", Confidence.CONFIDENT)

        finding_id = candidate.candidate_id
        fingerprint = compute_stable_finding_fingerprint(
            rule_id=candidate.rule_id,
            file_path=candidate.file_path,
            snippet=candidate.snippet,
            line=candidate.line,
            cwe_id=getattr(meta, "cwe", "CWE-20") or "CWE-20",
        )

        legacy_ev = Evidence(
            snippet=candidate.snippet,
            line=candidate.line,
            column=candidate.column,
        )

        df_ev = getattr(verifier_res, "df_evidence", None)
        hops = df_ev.hops if df_ev else ()

        enriched_ev = FindingEvidence(
            snippet=candidate.snippet,
            line=candidate.line,
            column=candidate.column,
            sink_symbol=candidate.matched_text,
            sink_category=sink_category,
            source_symbol=df_ev.source_node.symbol if df_ev and df_ev.source_node else "",
            source_category="USER_INPUT" if verifier_res.has_taint_source else "UNKNOWN",
            taint_state=taint_state,
            constant_resolution="TAINTED" if taint_state == TaintState.TAINTED else "DYNAMIC",
            sanitizer_capability=sanitizer_capability,
            taint_path=hops,
            ast_match=True,
            semantic_match=True,
        )

        return QualifiedFinding(
            finding_id=finding_id,
            rule_id=candidate.rule_id,
            fingerprint=fingerprint,
            title=getattr(meta, "name", candidate.rule_id) or candidate.rule_id,
            severity=severity,
            confidence=confidence,
            cwe_id=getattr(meta, "cwe", "CWE-20") or "CWE-20",
            owasp=getattr(meta, "owasp", "A03:2021-Injection") or "A03:2021-Injection",
            file_path=candidate.file_path,
            evidence=legacy_ev,
            description=getattr(output, "message", "Security finding detected.") or "Security finding detected.",
            remediation=getattr(output, "remediation", "") or "",
            rule_version=getattr(meta, "version", "1.0") or "1.0",
            qualification_state=QualificationState.CONFIRMED,
            rejection_reason=None,
            enriched_evidence=enriched_ev,
        )

    def _build_rejected_finding(
        self,
        candidate: CandidateFinding,
        reason: FPTaxonomyReason,
        explanation: str,
        sink_category: str = "UNKNOWN",
        taint_state: TaintState = TaintState.UNKNOWN,
        sanitizer_capability: str = "NONE",
    ) -> QualifiedFinding:
        rule = candidate.rule
        meta = rule.metadata

        fingerprint = compute_stable_finding_fingerprint(
            rule_id=candidate.rule_id,
            file_path=candidate.file_path,
            snippet=candidate.snippet,
            line=candidate.line,
            cwe_id=getattr(meta, "cwe", "CWE-20") or "CWE-20",
        )

        legacy_ev = Evidence(
            snippet=candidate.snippet,
            line=candidate.line,
            column=candidate.column,
        )

        enriched_ev = FindingEvidence(
            snippet=candidate.snippet,
            line=candidate.line,
            column=candidate.column,
            sink_symbol=candidate.matched_text,
            sink_category=sink_category,
            taint_state=taint_state,
            sanitizer_capability=sanitizer_capability,
            ast_match=True,
            semantic_match=False,
        )

        return QualifiedFinding(
            finding_id=candidate.candidate_id,
            rule_id=candidate.rule_id,
            fingerprint=fingerprint,
            title=getattr(meta, "name", candidate.rule_id) or candidate.rule_id,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            cwe_id=getattr(meta, "cwe", "CWE-20") or "CWE-20",
            owasp=getattr(meta, "owasp", "A03:2021-Injection") or "A03:2021-Injection",
            file_path=candidate.file_path,
            evidence=legacy_ev,
            description=f"REJECTED [{reason.value}]: {explanation}",
            remediation="",
            rule_version=getattr(meta, "version", "1.0") or "1.0",
            qualification_state=QualificationState.REJECTED,
            rejection_reason=reason,
            enriched_evidence=enriched_ev,
        )

    def _build_unresolved_finding(
        self,
        candidate: CandidateFinding,
        explanation: str,
        sink_category: str = "UNKNOWN",
    ) -> QualifiedFinding:
        rule = candidate.rule
        meta = rule.metadata

        fingerprint = compute_stable_finding_fingerprint(
            rule_id=candidate.rule_id,
            file_path=candidate.file_path,
            snippet=candidate.snippet,
            line=candidate.line,
            cwe_id=getattr(meta, "cwe", "CWE-20") or "CWE-20",
        )

        legacy_ev = Evidence(
            snippet=candidate.snippet,
            line=candidate.line,
            column=candidate.column,
        )

        enriched_ev = FindingEvidence(
            snippet=candidate.snippet,
            line=candidate.line,
            column=candidate.column,
            sink_symbol=candidate.matched_text,
            sink_category=sink_category,
            taint_state=TaintState.UNKNOWN,
            ast_match=True,
            semantic_match=False,
        )

        return QualifiedFinding(
            finding_id=candidate.candidate_id,
            rule_id=candidate.rule_id,
            fingerprint=fingerprint,
            title=getattr(meta, "name", candidate.rule_id) or candidate.rule_id,
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
            cwe_id=getattr(meta, "cwe", "CWE-20") or "CWE-20",
            owasp=getattr(meta, "owasp", "A03:2021-Injection") or "A03:2021-Injection",
            file_path=candidate.file_path,
            evidence=legacy_ev,
            description=f"UNRESOLVED [UNKNOWN_FLOW]: {explanation}",
            remediation="",
            rule_version=getattr(meta, "version", "1.0") or "1.0",
            qualification_state=QualificationState.UNRESOLVED,
            rejection_reason=FPTaxonomyReason.UNKNOWN_FLOW,
            enriched_evidence=enriched_ev,
        )
