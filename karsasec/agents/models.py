"""Inter-agent data contract models for KarsaSec Agent Orchestration."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class FixValidationInfo(BaseModel):
    """Validation status metadata for generated remediation proposals."""

    syntax_valid: bool = False
    rag_grounded: bool = False
    rescan_clean: bool | None = None
    confidence: Literal["VALIDATED", "SYNTAX_ONLY", "UNVALIDATED"] = "UNVALIDATED"
    grounding_status: str = "NO_GROUNDING_FOUND"
    syntax_error: str | None = None


class AgentInput(BaseModel):
    """Input payload to the agent pipeline.

    Carries both the raw Finding objects (for type-safe downstream processing)
    and a serialized dict form (for Pydantic compatibility).
    """

    model_config = {"arbitrary_types_allowed": True}

    target_path: str
    findings_raw: Any = None  # list[Finding] — opaque to Pydantic, type-safe at runtime
    findings: list[dict[str, Any]] = Field(default_factory=list)  # serialized fallback


class PlannerOutput(BaseModel):
    """Output from the Planner Agent."""

    model_config = {"arbitrary_types_allowed": True}

    target_path: str
    total_findings: int
    ordered_findings: list[dict[str, Any]] = Field(default_factory=list)
    ordered_findings_raw: Any = None  # list[Finding] — opaque, type-safe at runtime
    execution_sequence: list[str] = Field(default_factory=list)


class FindingAnalysis(BaseModel):
    """Combined analysis for a single finding from RCA and Explainer."""

    model_config = {"arbitrary_types_allowed": True}

    finding_id: str
    cwe: str
    rule_id: str
    file_path: str
    line_number: int
    severity: str
    root_cause_category: str
    explanation: str
    evidence_references: list[str] = Field(default_factory=list)
    finding_obj: Any = None  # Original Finding object carried through


class AnalyzerOutput(BaseModel):
    """Output from the Analyzer Agent."""

    analyses: list[FindingAnalysis] = Field(default_factory=list)


class RemediationProposalResult(BaseModel):
    """Remediation proposal result for a single finding."""

    finding_id: str
    file_path: str
    start_line: int
    unified_diff: str
    rationale: str
    strategy_type: str
    validation: FixValidationInfo
    rag_snippets: list[dict[str, str]] = Field(default_factory=list)


class RemediatorOutput(BaseModel):
    """Output from the Remediator Agent."""

    proposals: list[RemediationProposalResult] = Field(default_factory=list)


class ReporterOutput(BaseModel):
    """Output from the Reporter Agent."""

    report_format: str
    formatted_report: str
    summary: dict[str, Any] = Field(default_factory=dict)
