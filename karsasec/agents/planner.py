"""Planner Agent for KarsaSec Agent Orchestration (Task Z-1).

Ranks and sequences findings by severity and confidence.
"""

from __future__ import annotations

from typing import Any
from karsasec.agents.models import PlannerOutput
from karsasec.core.finding.model import Finding

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def _finding_sort_key(f: Finding | dict[str, Any]) -> tuple[int, float]:
    """Extracts sort key from either a Finding object or a dict."""
    if isinstance(f, Finding):
        sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        conf_val = 1.0
        if hasattr(f, "confidence") and hasattr(f.confidence, "value"):
            conf_map = {"CONFIDENT": 1.0, "LIKELY": 0.7, "POSSIBLE": 0.4}
            conf_val = conf_map.get(f.confidence.value, 0.5)
        return (SEVERITY_ORDER.get(sev_str.upper(), 0), conf_val)
    else:
        return (
            SEVERITY_ORDER.get(str(f.get("severity", "LOW")).upper(), 0),
            float(f.get("confidence", 1.0)),
        )


def _finding_to_dict(f: Finding | dict[str, Any]) -> dict[str, Any]:
    """Converts a Finding to dict for serialized representation."""
    if isinstance(f, Finding):
        return {
            "id": f.finding_id,
            "rule_id": f.rule_id,
            "file_path": str(f.file_path),
            "line_number": f.evidence.line if f.evidence else 0,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
            "description": f.description or "",
            "snippet": f.evidence.snippet if f.evidence else "",
            "cwe": f.cwe_id or "CWE-20",
            "owasp": f.owasp or "",
            "fingerprint": f.fingerprint or "",
            "remediation": f.remediation or "",
        }
    return f


class PlannerAgent:
    """Planner Agent sequencing findings for analysis and remediation."""

    def plan(self, target_path: str, findings: list[Any]) -> PlannerOutput:
        """Sorts findings by severity and confidence, preserving original objects."""
        sorted_findings = sorted(findings, key=_finding_sort_key, reverse=True)

        exec_seq = []
        for i, f in enumerate(sorted_findings, start=1):
            if isinstance(f, Finding):
                exec_seq.append(f.finding_id)
            else:
                exec_seq.append(f.get("id", f"finding_{i}"))

        ordered_dicts = [_finding_to_dict(f) for f in sorted_findings]
        ordered_raw = sorted_findings  # Preserve original objects

        return PlannerOutput(
            target_path=target_path,
            total_findings=len(sorted_findings),
            ordered_findings=ordered_dicts,
            ordered_findings_raw=ordered_raw,
            execution_sequence=exec_seq,
        )
