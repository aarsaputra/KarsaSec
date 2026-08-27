"""Master Agent Orchestrator pipeline connecting 4 MVP agents end-to-end (Task Z-1)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from karsasec.agents.analyzer import AnalyzerAgent
from karsasec.agents.models import AgentInput, ReporterOutput
from karsasec.agents.planner import PlannerAgent
from karsasec.agents.remediator import RemediatorAgent
from karsasec.agents.reporter import ReporterAgent
from karsasec.rag.service import RAGService

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Orchestrates Planner -> Analyzer -> Remediator -> Reporter end-to-end."""

    def __init__(self, rag_corpus_path: Path | None = None) -> None:
        self.planner = PlannerAgent()
        self.analyzer = AnalyzerAgent()
        self.rag_service = None
        self._rag_init_error: str | None = None

        if rag_corpus_path and rag_corpus_path.exists():
            try:
                self.rag_service = RAGService.from_directory(rag_corpus_path)
            except Exception as err:
                # B8: Log RAG initialization failure explicitly
                self._rag_init_error = str(err)
                logger.warning("RAG corpus initialization failed: %s", err)

        self.remediator = RemediatorAgent(rag_service=self.rag_service)
        self.reporter = ReporterAgent()

    def run_review(self, agent_input: AgentInput, output_format: str = "console") -> ReporterOutput:
        """Runs 4 agents in sequence and produces formatted report stopping at proposals (before apply)."""
        # Determine input: prefer raw Finding objects when available
        findings_input = agent_input.findings_raw or agent_input.findings

        # 1. Planner
        planner_out = self.planner.plan(
            target_path=agent_input.target_path,
            findings=findings_input,
        )

        # 2. Analyzer (RCA + Explainer) — pass raw Finding objects through
        analyzer_out = self.analyzer.analyze(
            target_path=agent_input.target_path,
            ordered_findings=planner_out.ordered_findings,
            ordered_findings_raw=planner_out.ordered_findings_raw,
        )

        # 3. Remediator (RAG + Native Syntax Validation)
        remediator_out = self.remediator.remediate(
            target_path=agent_input.target_path,
            analyses=analyzer_out.analyses,
        )

        # 4. Reporter — includes analyzer output (B7)
        return self.reporter.report(
            planner_out=planner_out,
            analyzer_out=analyzer_out,
            remediator_out=remediator_out,
            output_format=output_format,
            rag_init_error=self._rag_init_error,
        )
