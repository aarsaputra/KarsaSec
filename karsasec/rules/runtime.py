"""Semantic Rule Runtime executing compiled Execution Plans against CPG and producing Finding objects."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding, compute_stable_finding_fingerprint
from karsasec.cpg.models import CPGGraph
from karsasec.query.context import ExecutionContext
from karsasec.query.executor import QueryExecutor
from karsasec.query.explain import ExplainEngine
from karsasec.rules.compiler import RuleCompiler
from karsasec.rules.enums import Confidence, Severity


class SemanticRuleRuntime:
    """Runtime executing compiled CPG rules and converting results to Findings."""

    def __init__(self) -> None:
        self.compiler = RuleCompiler()
        self.executor = QueryExecutor()
        self.explainer = ExplainEngine()

    def execute_rule(
        self,
        rule_data: dict[str, Any],
        graph: CPGGraph,
        context: ExecutionContext | None = None,
    ) -> list[Finding]:
        if context is None:
            context = ExecutionContext()

        # 1. Compile YAML rule to optimized execution plan
        query_ast, execution_plan = self.compiler.compile(rule_data)

        # 2. Execute plan against CPG
        matched_nodes = self.executor.execute(execution_plan, graph, context=context)

        # 3. Generate Findings from matches
        findings: list[Finding] = []
        rule_id = str(rule_data.get("id", "QUERY_RULE"))
        title = str(rule_data.get("title", f"Vulnerability detected by {rule_id}"))
        severity = Severity(str(rule_data.get("severity", "HIGH")).upper())
        conf_str = str(rule_data.get("confidence", "HIGH")).upper()
        if conf_str == "HIGH":
            confidence = Confidence.CONFIDENT
        elif conf_str == "MEDIUM":
            confidence = Confidence.LIKELY
        elif conf_str == "LOW":
            confidence = Confidence.POSSIBLE
        else:
            try:
                confidence = Confidence(conf_str)
            except ValueError:
                confidence = Confidence.CONFIDENT
        cwe_id = str(rule_data.get("cwe", "CWE-20"))
        owasp = str(rule_data.get("owasp", "A01:2021-Broken Access Control"))
        desc = str(rule_data.get("description", "Vulnerability detected during semantic CPG query analysis."))
        remediation = str(rule_data.get("remediation", "Review and sanitize input flow."))

        for node in matched_nodes:
            file_path = Path(node.file_path or "unknown.py")
            line = node.line_number or 1
            snippet = node.label or ""

            fingerprint = compute_stable_finding_fingerprint(rule_id, file_path, snippet, line, cwe_id)
            evidence_tree = self.explainer.build_evidence(rule_id, desc, [node], graph)

            ev = Evidence(
                snippet=snippet,
                line=line,
                column=getattr(node, "column", 0),
                context_lines=(),
            )

            finding = Finding(
                finding_id=f"FINDING-{uuid.uuid4().hex[:8]}",
                rule_id=rule_id,
                fingerprint=fingerprint,
                title=title,
                severity=severity,
                confidence=confidence,
                cwe_id=cwe_id,
                owasp=owasp,
                file_path=file_path,
                evidence=ev,
                description=desc,
                remediation=remediation,
                metadata={"evidence_tree": evidence_tree.to_dict()},
            )
            findings.append(finding)

        return findings
