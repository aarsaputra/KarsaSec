"""CLI command module for generating evidence-grounded AI security explanations (E13-1)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from karsasec.ai.artifacts import SecurityArtifactReader
from karsasec.ai.explainer.agent import ExplainerAgent
from karsasec.ai.retrieval.adapter import KnowledgeRetrieverAdapter
from karsasec.cli.commands.scan import _run_scan_pipeline
from karsasec.utils.logging import console

explain_app = typer.Typer(
    name="explain",
    help="Generate evidence-grounded AI explanations for detected findings.",
    no_args_is_help=True,
)


@explain_app.callback(invoke_without_command=True)
def explain_command(
    finding_id: str = typer.Option(
        ...,
        "--finding",
        "-f",
        help="Target finding ID or fingerprint to explain.",
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Path to project directory or file to analyze.",
        exists=True,
    ),
    rag: bool = typer.Option(
        True,
        "--rag/--no-rag",
        help="Enable RAG knowledge retrieval context.",
    ),
    root_cause: bool = typer.Option(
        False,
        "--root-cause",
        "-r",
        help="Perform evidence reflection and root cause analysis (E13-2).",
    ),
    remediation: bool = typer.Option(
        False,
        "--remediation",
        help="Generate evidence-grounded remediation strategy (E13-3).",
    ),
    patch: bool = typer.Option(
        False,
        "--patch",
        help="Generate safe patch proposal diff DATA ONLY (E13-3).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output result as formatted JSON.",
    ),
) -> None:
    """Run deterministic SAST scan and explain a specific finding using evidence-grounded AI Explainer."""
    if not json_output:
        console.print(
            f"[bold cyan]KarsaSec AI Agent[/bold cyan] analyzing finding '[bold yellow]{finding_id}[/bold yellow]'..."
        )

    # Run SAST scan pipeline to collect deterministic findings & verdicts
    findings, artifact_store, duration = _run_scan_pipeline(path)
    if not findings:
        if json_output:
            import json

            print(json.dumps({"error": "No findings detected in target scan."}))
        else:
            console.print("[bold red]No findings detected in target scan.[/bold red]")
        raise typer.Exit(code=1)

    reader = SecurityArtifactReader.from_findings(findings)

    # Locate finding by finding_id or fingerprint prefix
    matched_finding = reader.get_finding(finding_id)
    if matched_finding is None:
        for f in findings:
            if f.fingerprint.startswith(finding_id) or f.rule_id.lower() == finding_id.lower():
                matched_finding = f
                break

    if matched_finding is None:
        if json_output:
            import json

            print(json.dumps({"error": f"Finding '{finding_id}' not found in scan results."}))
        else:
            console.print(f"[bold red]Error:[/bold red] Finding '{finding_id}' not found in scan results.")
        raise typer.Exit(code=1)

    verdict = reader.get_verdict(matched_finding.finding_id)

    # Retrieve RAG knowledge if enabled
    knowledge_chunks = []
    if rag:
        retriever = KnowledgeRetrieverAdapter.from_directory(path)
        query = f"{matched_finding.rule_id} {matched_finding.cwe_id} {matched_finding.title}"
        ret_result = retriever.retrieve(query=query, top_k=3)
        knowledge_chunks = list(ret_result.chunks)

    if remediation or patch:
        from karsasec.ai.rca.agent import RCAAgent
        from karsasec.ai.remediation.agent import RemediationAgent

        rca_res = RCAAgent().analyze(finding=matched_finding, verdict=verdict, knowledge_chunks=knowledge_chunks)
        rem_agent = RemediationAgent()
        strategy, proposal = rem_agent.plan_and_propose(
            finding=matched_finding,
            verdict=verdict,
            rca=rca_res,
            knowledge_chunks=knowledge_chunks,
        )

        if json_output:
            import json

            out = {
                "verdict_status": verdict.status.value if verdict else "UNKNOWN",
                "remediation_strategy": strategy.to_dict(),
                "patch_proposal": proposal.to_dict() if patch else None,
                "patch_applied": False,
            }
            print(json.dumps(out, indent=2))
            return

        verdict_status = verdict.status.value if verdict and hasattr(verdict.status, "value") else "UNKNOWN"
        verdict_color = "red" if verdict_status == "VULNERABLE" else ("green" if verdict_status == "SAFE" else "yellow")

        console.print(
            Panel(
                f"[bold]Finding ID:[/bold] {matched_finding.finding_id}\n"
                f"[bold]Security Verdict:[/bold] [{verdict_color}]{verdict_status}[/{verdict_color}]\n"
                f"[bold]Root Cause Category:[/bold] [bold magenta]{rca_res.root_cause_category.value}[/bold magenta]\n"
                f"[bold]Remediation Strategy Type:[/bold] [bold green]{strategy.strategy_type.value}[/bold green]\n"
                f"[bold]Strategy Fingerprint:[/bold] {strategy.strategy_fingerprint}",
                title="[bold white on blue] DETERMINISTIC SECURITY VERDICT & REMEDIATION PLAN [/bold white on blue]",
                border_style="blue",
            )
        )

        console.print(
            Panel(
                f"[bold]Rationale:[/bold] {strategy.rationale}\n"
                f"[bold]Target File:[/bold] {strategy.target_file}\n"
                f"[bold]Confidence:[/bold] {strategy.confidence}\n"
                f"[bold]Assumptions:[/bold] {', '.join(strategy.assumptions)}",
                title="[bold green]REMEDIATION STRATEGY[/bold green]",
                border_style="green",
            )
        )

        if patch:
            status_color = "green" if proposal.validation_status == "VALID" else "yellow"
            console.print(
                Panel(
                    f"[bold]Proposal ID:[/bold] {proposal.proposal_id}\n"
                    f"[bold]Validation Status:[/bold] [{status_color}]{proposal.validation_status.value}[/{status_color}]\n"
                    f"[bold]Proposal Fingerprint:[/bold] {proposal.proposal_fingerprint}\n\n"
                    f"[bold yellow]UNIFIED DIFF (DATA ONLY):[/bold yellow]\n\n"
                    f"{proposal.unified_diff if proposal.unified_diff else '[No unified diff generated]'}",
                    title="[bold white on yellow] PATCH PROPOSAL — NOT APPLIED (HUMAN REVIEW REQUIRED) [/bold white on yellow]",
                    border_style="yellow",
                )
            )

        return

    if root_cause:
        from karsasec.ai.rca.agent import RCAAgent

        rca_agent = RCAAgent()
        rca_res = rca_agent.analyze(finding=matched_finding, verdict=verdict, knowledge_chunks=knowledge_chunks)

        if json_output:
            import json

            print(json.dumps(rca_res.to_dict(), indent=2))
            return

        # Render RCA UI Sections
        verdict_status = verdict.status.value if verdict and hasattr(verdict.status, "value") else "UNKNOWN"
        verdict_color = "red" if verdict_status == "VULNERABLE" else ("green" if verdict_status == "SAFE" else "yellow")

        console.print(
            Panel(
                f"[bold]Finding ID:[/bold] {matched_finding.finding_id}\n"
                f"[bold]Security Verdict:[/bold] [{verdict_color}]{verdict_status}[/{verdict_color}]\n"
                f"[bold]Root Cause Category:[/bold] [bold magenta]{rca_res.root_cause_category.value}[/bold magenta]\n"
                f"[bold]False Positive Risk Rating:[/bold] [bold cyan]{rca_res.false_positive_risk.value}[/bold cyan]\n"
                f"[bold]RCA Fingerprint:[/bold] {rca_res.rca_fingerprint}",
                title="[bold white on blue] DETERMINISTIC SECURITY VERDICT & RCA SUMMARY [/bold white on blue]",
                border_style="blue",
            )
        )

        # Evidence Chain
        chain_table = Table(title="[bold cyan]EVIDENCE CHAIN[/bold cyan]", show_header=True, header_style="bold cyan")
        chain_table.add_column("Step")
        chain_table.add_column("Kind")
        chain_table.add_column("Location")
        chain_table.add_column("Variable")
        chain_table.add_column("Context")
        for s in rca_res.evidence_chain:
            chain_table.add_row(
                s.step_id, s.evidence_kind, f"{s.file_path}:{s.line_number}", s.variable_version, s.call_context
            )
        console.print(chain_table)

        if rca_res.evidence_gaps:
            console.print(
                Panel(
                    "\n".join(f"- [{g.missing_type}] {g.description}" for g in rca_res.evidence_gaps),
                    title="[bold yellow]EVIDENCE GAPS[/bold yellow]",
                    border_style="yellow",
                )
            )

        if rca_res.contradictions:
            console.print(
                Panel(
                    "\n".join(f"- {c.description}" for c in rca_res.contradictions),
                    title="[bold red]CONTRADICTORY EVIDENCE[/bold red]",
                    border_style="red",
                )
            )

        console.print(
            Panel(
                rca_res.explanation_summary,
                title="[bold magenta]ROOT CAUSE ANALYSIS[/bold magenta]",
                border_style="magenta",
            )
        )
        return

    # Standard Explainer Mode
    agent = ExplainerAgent()
    explanation = agent.explain(finding=matched_finding, verdict=verdict, knowledge_chunks=knowledge_chunks)

    if json_output:
        import json

        print(json.dumps(explanation.model_dump(), indent=2))
        return

    # Render Visual Separation: Section 1 — DETERMINISTIC VERDICT
    verdict_status = verdict.status.value if verdict and hasattr(verdict.status, "value") else "UNKNOWN"
    verdict_fp = verdict.canonical_fingerprint if verdict else matched_finding.fingerprint
    ev_fp = verdict.evidence_fingerprint if verdict else "N/A"

    verdict_color = "red" if verdict_status == "VULNERABLE" else ("green" if verdict_status == "SAFE" else "yellow")
    v_panel_text = (
        f"[bold]Finding ID:[/bold] {matched_finding.finding_id}\n"
        f"[bold]Rule ID:[/bold] {matched_finding.rule_id} ({matched_finding.cwe_id})\n"
        f"[bold]Severity:[/bold] {matched_finding.severity}\n"
        f"[bold]Security Verdict:[/bold] [{verdict_color}]{verdict_status}[/{verdict_color}]\n"
        f"[bold]File & Line:[/bold] {matched_finding.file_path}:{matched_finding.evidence.line if matched_finding.evidence else 0}\n"
        f"[bold]Snippet:[/bold] {matched_finding.evidence.snippet.strip() if matched_finding.evidence else 'N/A'}\n"
        f"[bold]Canonical Fingerprint:[/bold] {verdict_fp}\n"
        f"[bold]Evidence Fingerprint:[/bold] {ev_fp}"
    )
    console.print(
        Panel(
            v_panel_text,
            title="[bold white on blue] DETERMINISTIC SECURITY VERDICT (SAST ENGINE) [/bold white on blue]",
            border_style="blue",
        )
    )

    # Render Visual Separation: Section 2 — AI GENERATED EXPLANATION
    ai_panel_text = (
        f"[bold cyan]Summary:[/bold cyan] {explanation.summary}\n\n"
        f"[bold cyan]Why Vulnerable:[/bold cyan]\n{explanation.why_vulnerable}\n\n"
        f"[bold cyan]Data Flow:[/bold cyan]\n{explanation.data_flow_explanation}\n\n"
        f"[bold cyan]Guard Analysis:[/bold cyan]\n{explanation.guard_analysis}\n\n"
        f"[bold cyan]Sanitizer Analysis:[/bold cyan]\n{explanation.sanitizer_analysis}\n\n"
        f"[bold cyan]Remediation Guidance:[/bold cyan]\n{explanation.remediation_guidance}\n\n"
        f"[bold cyan]Limitations:[/bold cyan] {explanation.limitations}\n\n"
        f"[bold dim]Explanation Fingerprint:[/bold dim] {explanation.explanation_fingerprint}"
    )
    console.print(
        Panel(
            ai_panel_text,
            title="[bold white on magenta] AI-GENERATED EXPLANATION (READ-ONLY CONSUMER) [/bold white on magenta]",
            border_style="magenta",
        )
    )

    if explanation.knowledge_references:
        k_table = Table(title="Retrieved RAG Knowledge References", show_header=True, header_style="bold green")
        k_table.add_column("Chunk ID")
        k_table.add_column("Title")
        k_table.add_column("Source")
        k_table.add_column("Score")
        for k in explanation.knowledge_references:
            k_table.add_row(k.chunk_id, k.title, k.source, str(k.relevance_score))
        console.print(k_table)
