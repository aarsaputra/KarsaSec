"""Reporter Agent for KarsaSec Agent Orchestration (Task Z-1).

Formats execution summary and proposals into Console, JSON, or SARIF reports.
Includes AnalyzerOutput (RCA + Explainer results) in report output.
"""

from __future__ import annotations

import json
from typing import Any
from karsasec.agents.models import AnalyzerOutput, PlannerOutput, RemediatorOutput, ReporterOutput


class ReporterAgent:
    """Reporter Agent formatting end-to-end multi-agent review results."""

    def report(
        self,
        planner_out: PlannerOutput,
        analyzer_out: AnalyzerOutput,
        remediator_out: RemediatorOutput,
        output_format: str = "console",
        rag_init_error: str | None = None,
    ) -> ReporterOutput:
        """Formats review results into console, json, or sarif format."""
        # Build analysis lookup by finding_id for cross-referencing
        analysis_map = {a.finding_id: a for a in analyzer_out.analyses}

        summary: dict[str, Any] = {
            "target_path": planner_out.target_path,
            "total_findings": planner_out.total_findings,
            "total_proposals": len(remediator_out.proposals),
            "validated_proposals": sum(
                1 for p in remediator_out.proposals if p.validation.confidence == "VALIDATED"
            ),
            "syntax_only_proposals": sum(
                1 for p in remediator_out.proposals if p.validation.confidence == "SYNTAX_ONLY"
            ),
            "unvalidated_proposals": sum(
                1 for p in remediator_out.proposals if p.validation.confidence == "UNVALIDATED"
            ),
        }

        if rag_init_error:
            summary["rag_init_error"] = rag_init_error

        if output_format.lower() == "json":
            formatted = self._format_json(summary, analyzer_out, remediator_out)
        elif output_format.lower() == "sarif":
            formatted = self._format_sarif(planner_out, analyzer_out, remediator_out)
        else:
            formatted = self._format_console(
                planner_out, analyzer_out, remediator_out, summary, analysis_map, rag_init_error
            )

        return ReporterOutput(
            report_format=output_format,
            formatted_report=formatted,
            summary=summary,
        )

    @staticmethod
    def _format_json(
        summary: dict[str, Any], analyzer_out: AnalyzerOutput, remediator_out: RemediatorOutput
    ) -> str:
        data = {
            "summary": summary,
            "analyses": [
                {
                    "finding_id": a.finding_id,
                    "cwe": a.cwe,
                    "rule_id": a.rule_id,
                    "root_cause": a.root_cause_category,
                    "explanation": a.explanation,
                }
                for a in analyzer_out.analyses
            ],
            "proposals": [p.model_dump() for p in remediator_out.proposals],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def _format_sarif(
        planner_out: PlannerOutput, analyzer_out: AnalyzerOutput, remediator_out: RemediatorOutput
    ) -> str:
        # B9: Build proper SARIF 2.1.0 with rules array, level, and fixes
        analysis_map = {a.finding_id: a for a in analyzer_out.analyses}
        severity_to_level = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }

        # Collect unique rules
        seen_rules: dict[str, dict[str, Any]] = {}
        for p in remediator_out.proposals:
            analysis = analysis_map.get(p.finding_id)
            rule_id = analysis.rule_id if analysis else p.finding_id
            if rule_id not in seen_rules:
                seen_rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": analysis.explanation[:200] if analysis else "Security finding"},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{analysis.cwe.replace('CWE-', '')}.html"
                    if analysis
                    else "",
                }

        results = []
        for p in remediator_out.proposals:
            analysis = analysis_map.get(p.finding_id)
            rule_id = analysis.rule_id if analysis else p.finding_id
            level = severity_to_level.get(analysis.severity.upper(), "warning") if analysis else "warning"

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": analysis.explanation if analysis else p.rationale,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": p.file_path},
                            "region": {"startLine": p.start_line},
                        }
                    }
                ],
            }

            # Add fixes if unified diff is present
            if p.unified_diff:
                result["fixes"] = [
                    {
                        "description": {"text": p.rationale},
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": p.file_path},
                                "replacements": [
                                    {
                                        "deletedRegion": {"startLine": p.start_line},
                                        "insertedContent": {"text": p.unified_diff},
                                    }
                                ],
                            }
                        ],
                    }
                ]

            results.append(result)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "KarsaSec Agent Review Engine",
                            "version": "1.0.0",
                            "rules": list(seen_rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    @staticmethod
    def _format_console(
        planner_out: PlannerOutput,
        analyzer_out: AnalyzerOutput,
        remediator_out: RemediatorOutput,
        summary: dict[str, Any],
        analysis_map: dict[str, Any],
        rag_init_error: str | None,
    ) -> str:
        lines = [
            "===========================================================",
            "             KARSASEC MULTI-AGENT REVIEW REPORT            ",
            "===========================================================",
            f"Target Path: {planner_out.target_path}",
            f"Total Findings Processed: {planner_out.total_findings}",
            f"Total Remediation Proposals: {len(remediator_out.proposals)}",
            f"Validation Summary: {summary['validated_proposals']} Validated, {summary['syntax_only_proposals']} Syntax-Only, {summary['unvalidated_proposals']} Unvalidated",
        ]

        if rag_init_error:
            lines.append(f"⚠ RAG Initialization Error: {rag_init_error}")

        lines.append("-----------------------------------------------------------")

        for i, prop in enumerate(remediator_out.proposals, start=1):
            analysis = analysis_map.get(prop.finding_id)

            lines.extend([
                f"\n[{i}] Finding ID: {prop.finding_id} | File: {prop.file_path}:{prop.start_line}",
            ])

            # B7: Include RCA and Explainer results
            if analysis:
                lines.extend([
                    f"    CWE: {analysis.cwe} | Root Cause: {analysis.root_cause_category}",
                    f"    Explanation: {analysis.explanation[:200]}",
                ])

            lines.extend([
                f"    Strategy: {prop.strategy_type}",
                f"    Grounding: {prop.validation.grounding_status} | Syntax: {'✓' if prop.validation.syntax_valid else '✗'} | Confidence: {prop.validation.confidence}",
            ])

            if prop.unified_diff:
                lines.append("    Proposed Diff (Not Applied):")
                for diff_line in prop.unified_diff.splitlines()[:6]:
                    lines.append(f"      {diff_line}")

        lines.append("\n===========================================================")
        return "\n".join(lines)
