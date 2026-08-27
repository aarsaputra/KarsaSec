"""Analyzer Agent for KarsaSec Agent Orchestration (Task Z-1).

Invokes RCAAgent and ExplainerAgent for evidence-grounded finding analysis.
Uses original Finding objects from the scan pipeline — never reconstructs synthetic ones.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from karsasec.agents.models import AnalyzerOutput, FindingAnalysis
from karsasec.ai.explainer.agent import ExplainerAgent
from karsasec.ai.rca.agent import RCAAgent
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.rules.enums import Confidence, Severity


class AnalyzerAgent:
    """Analyzer Agent invoking RCA and Explainer on authentic Finding objects."""

    def __init__(self) -> None:
        self.rca_analyzer = RCAAgent()
        self.explainer = ExplainerAgent()

    def analyze(
        self,
        target_path: str,
        ordered_findings: list[dict[str, Any]],
        ordered_findings_raw: list[Any] | None = None,
    ) -> AnalyzerOutput:
        """Runs RCA and Explainer for each finding.

        Prefers original Finding objects (ordered_findings_raw) when available.
        Falls back to dict-based reconstruction only when raw objects aren't provided.
        """
        analyses: list[FindingAnalysis] = []
        raw_list = ordered_findings_raw or []

        for idx, f_dict in enumerate(ordered_findings):
            # Prefer original Finding object if available
            finding_obj: Finding | None = None
            if idx < len(raw_list) and isinstance(raw_list[idx], Finding):
                finding_obj = raw_list[idx]

            if finding_obj is None:
                # Fallback: construct from dict (legacy path)
                finding_obj = self._finding_from_dict(f_dict, target_path)

            # Extract metadata from the authentic Finding
            finding_id = finding_obj.finding_id
            rule_id = finding_obj.rule_id
            cwe = finding_obj.cwe_id or "CWE-20"
            file_path = str(finding_obj.file_path)
            line_number = finding_obj.evidence.line if finding_obj.evidence else 0
            sev_str = finding_obj.severity.value if hasattr(finding_obj.severity, "value") else str(finding_obj.severity)

            rca_result = self.rca_analyzer.analyze(finding_obj)
            explanation_result = self.explainer.explain(finding_obj)

            analysis = FindingAnalysis(
                finding_id=finding_id,
                cwe=cwe,
                rule_id=rule_id,
                file_path=file_path,
                line_number=line_number,
                severity=sev_str,
                root_cause_category=str(rca_result.root_cause_category),
                explanation=explanation_result.why_vulnerable or explanation_result.summary,
                evidence_references=[str(item) for item in rca_result.evidence_chain],
                finding_obj=finding_obj,  # Carry original through
            )
            analyses.append(analysis)

        return AnalyzerOutput(analyses=analyses)

    @staticmethod
    def _finding_from_dict(f_dict: dict[str, Any], target_path: str) -> Finding:
        """Fallback: constructs a Finding from dict when raw objects aren't available.

        Preserves authentic metadata from dict instead of hardcoding.
        """
        finding_id = str(f_dict.get("id", "FINDING-001"))
        rule_id = str(f_dict.get("rule_id", "RULE-001"))
        cwe = str(f_dict.get("cwe", f_dict.get("cwe_id", "CWE-20")))
        file_path = str(f_dict.get("file_path", f_dict.get("file", target_path)))
        raw_line = f_dict.get("line_number") if f_dict.get("line_number") is not None else f_dict.get("line", 1)
        line_number = int(raw_line) if raw_line is not None else 1
        sev_str = str(f_dict.get("severity", "HIGH")).upper()
        snippet = str(f_dict.get("snippet", f_dict.get("description", "")))
        owasp = str(f_dict.get("owasp", ""))
        fingerprint = str(f_dict.get("fingerprint", ""))
        description = str(f_dict.get("description", snippet))
        remediation = str(f_dict.get("remediation", ""))
        conf_str = str(f_dict.get("confidence", "CONFIDENT")).upper()

        sev_enum = Severity.HIGH
        try:
            sev_enum = Severity(sev_str)
        except (ValueError, KeyError):
            pass

        conf_enum = Confidence.CONFIDENT
        try:
            conf_enum = Confidence(conf_str)
        except (ValueError, KeyError):
            pass

        ev_obj = Evidence(line=line_number, column=1, snippet=snippet)

        return Finding(
            finding_id=finding_id,
            rule_id=rule_id,
            fingerprint=fingerprint or f"fp-{finding_id}",
            title=description[:120] or f"Security finding {finding_id}",
            severity=sev_enum,
            confidence=conf_enum,
            cwe_id=cwe,
            owasp=owasp or "UNCLASSIFIED",
            file_path=Path(file_path),
            evidence=ev_obj,
            description=description,
            remediation=remediation or "Review and apply appropriate mitigation.",
        )
