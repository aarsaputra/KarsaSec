"""CLI command module for patch approval and controlled patch application (Sprint E13-4)."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from rich.panel import Panel
from rich.table import Table
import typer

from karsasec.ai.remediation.application_agent import RemediationApplicationAgent
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.ledger import RemediationLedger
from karsasec.ai.remediation.models import PatchProposal
from karsasec.ai.remediation.provenance import RemediationProvenanceGraph
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.cli.commands.scan import _run_scan_pipeline
from karsasec.utils.logging import console

remediation_app = typer.Typer(
    name="remediation",
    help="Manage patch approval tokens and execute controlled patch applications.",
    no_args_is_help=True,
)


@remediation_app.command("approve")
def approve_command(
    finding_id: str = typer.Option(..., "--finding", help="ID of the finding to approve."),
    proposal_file: Path = typer.Option(..., "--proposal", help="Path to JSON file containing PatchProposal."),
    repo: Path = typer.Option(Path("."), "--repo", help="Target repository directory."),
    approved_by: str = typer.Option("security_reviewer", "--approved-by", help="Identity of reviewer."),
    out_file: Path = typer.Option(Path("approval_token.json"), "--out", help="Output path for approval token."),
) -> None:
    """Generate a single-use cryptographically bound PatchApprovalToken (H1, H3, H18)."""
    repo_path = repo.resolve()
    if not proposal_file.exists():
        console.print(f"[bold red]Error:[/bold red] Proposal file '{proposal_file}' not found.")
        sys.exit(1)

    try:
        prop_data = json.loads(proposal_file.read_text(encoding="utf-8"))
        proposal = PatchProposal(
            proposal_id=prop_data["proposal_id"],
            finding_id=prop_data["finding_id"],
            target_files=tuple(prop_data["target_files"]),
            hunks=(),
            unified_diff=prop_data.get("unified_diff", ""),
            rationale=prop_data.get("rationale", ""),
            root_cause_reference=prop_data.get("root_cause_reference", ""),
            evidence_references=tuple(prop_data.get("evidence_references", [])),
            expected_effect=prop_data.get("expected_effect", ""),
            risk_level=prop_data.get("risk_level", "MEDIUM"),
            assumptions=tuple(prop_data.get("assumptions", [])),
            validation_status=prop_data.get("validation_status", "VALID"),
            proposal_fingerprint=prop_data["proposal_fingerprint"],
        )
    except Exception as e:
        console.print(f"[bold red]Error parsing proposal file:[/bold red] {e}")
        sys.exit(1)

    # Capture current SourceSnapshot
    snapshot = SourceSnapshot.capture(repo_path, proposal.target_files)

    # Create PatchApprovalToken
    token = PatchApprovalToken.create(
        finding_id=finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snapshot.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(repo_path),
        approved_by=approved_by,
        approval_context="CLI_HUMAN_APPROVAL",
    )

    out_file.write_text(json.dumps(token.to_dict(), indent=2), encoding="utf-8")
    console.print(
        Panel(
            f"[bold green]Patch Approval Token Created[/bold green]\n"
            f"[bold]Token ID:[/bold] {token.token_id}\n"
            f"[bold]Finding ID:[/bold] {token.finding_id}\n"
            f"[bold]Proposal FP:[/bold] {token.proposal_fingerprint[:16]}...\n"
            f"[bold]Snapshot Hash:[/bold] {token.source_snapshot_hash[:16]}...\n"
            f"[bold]Exported to:[/bold] {out_file}",
            title="KarsaSec Remediation Approval",
        )
    )


@remediation_app.command("apply")
def apply_command(
    token_file: Path = typer.Option(..., "--token", help="Path to JSON file containing PatchApprovalToken."),
    proposal_file: Path = typer.Option(..., "--proposal", help="Path to JSON file containing PatchProposal."),
    repo: Path = typer.Option(Path("."), "--repo", help="Target repository directory."),
) -> None:
    """Execute controlled patch application and post-apply SAST verification (H4, H5, H6)."""
    repo_path = repo.resolve()
    if not token_file.exists() or not proposal_file.exists():
        console.print("[bold red]Error:[/bold red] Token file or proposal file missing.")
        sys.exit(1)

    token_data = json.loads(token_file.read_text(encoding="utf-8"))
    token = PatchApprovalToken.from_dict(token_data)

    prop_data = json.loads(proposal_file.read_text(encoding="utf-8"))
    proposal = PatchProposal(
        proposal_id=prop_data["proposal_id"],
        finding_id=prop_data["finding_id"],
        target_files=tuple(prop_data["target_files"]),
        hunks=(),
        unified_diff=prop_data.get("unified_diff", ""),
        rationale=prop_data.get("rationale", ""),
        root_cause_reference=prop_data.get("root_cause_reference", ""),
        evidence_references=tuple(prop_data.get("evidence_references", [])),
        expected_effect=prop_data.get("expected_effect", ""),
        risk_level=prop_data.get("risk_level", "MEDIUM"),
        assumptions=tuple(prop_data.get("assumptions", [])),
        validation_status=prop_data.get("validation_status", "VALID"),
        proposal_fingerprint=prop_data["proposal_fingerprint"],
    )

    agent = RemediationApplicationAgent(repository_root=repo_path)

    # SAST scan callback
    def _rescan():
        result = _run_scan_pipeline(target_path=repo_path, config_file=None, rules_dir=None, diff_scan=False)
        return result.findings

    # Finding placeholder
    first_res = _run_scan_pipeline(target_path=repo_path, config_file=None, rules_dir=None, diff_scan=False)
    finding = first_res.findings[0] if first_res.findings else None

    if not finding:
        console.print("[bold yellow]No findings detected in target repository for initial contract.[/bold yellow]")
        sys.exit(0)

    app_res, ver_res, used_token = agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=_rescan,
    )

    # Save updated used token
    token_file.write_text(json.dumps(used_token.to_dict(), indent=2), encoding="utf-8")

    table = Table(title="KarsaSec Patch Application Execution Summary")
    table.add_column("Property", style="bold cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Transaction ID", app_res.transaction_id)
    table.add_row("Application Status", str(app_res.status))
    table.add_row("Post-Apply Verification", str(ver_res.status) if ver_res else "N/A")
    table.add_row("Rollback Status", app_res.rollback_status)

    if app_res.failure_reason:
        table.add_row("Failure Reason", app_res.failure_reason)

    console.print(table)


@remediation_app.command("status")
def status_command(
    finding_id: str = typer.Argument(..., help="ID of the finding to inspect status for."),
    ledger_file: Path = typer.Option(Path("remediation_ledger.json"), "--ledger", help="Path to ledger JSON file."),
    result_file: Path = typer.Option(Path("remediation_result.json"), "--result", help="Path to lifecycle result JSON file."),
) -> None:
    """Read-only inspection of current remediation lifecycle state for a finding."""
    if result_file.exists():
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            if data.get("finding_id") == finding_id:
                table = Table(title=f"Remediation Lifecycle Status: {finding_id}")
                table.add_column("Property", style="bold cyan")
                table.add_column("Value", style="bold white")
                table.add_row("Finding ID", str(data.get("finding_id", "N/A")))
                table.add_row("Current State", str(data.get("current_state", "N/A")))
                table.add_row("Repository Identity", str(data.get("repository_identity", "N/A")))
                table.add_row("Application Status", str(data.get("application_status", "N/A")))
                table.add_row("Verification Status", str(data.get("verification_status", "N/A")))
                table.add_row("Provenance Fingerprint", str(data.get("provenance_fingerprint", "N/A")))
                table.add_row("Ledger Fingerprint", str(data.get("ledger_fingerprint", "N/A")))
                table.add_row("Failure Reason", str(data.get("failure_reason") or "None"))
                console.print(table)
                return
        except Exception as e:
            console.print(f"[bold yellow]Warning reading result file:[/bold yellow] {e}")

    if ledger_file.exists():
        try:
            data = json.loads(ledger_file.read_text(encoding="utf-8"))
            ledger = RemediationLedger.from_dict(data)
            evs = ledger.get_events_for_finding(finding_id)
            if evs:
                latest = evs[-1]
                table = Table(title=f"Remediation Lifecycle Status (from Ledger): {finding_id}")
                table.add_column("Property", style="bold cyan")
                table.add_column("Value", style="bold white")
                table.add_row("Finding ID", finding_id)
                table.add_row("Latest State", str(latest.lifecycle_state))
                table.add_row("Latest Event Type", str(latest.event_type))
                table.add_row("Actor", str(latest.actor))
                table.add_row("Timestamp", str(latest.timestamp))
                table.add_row("Provenance Fingerprint", str(latest.provenance_fingerprint or "N/A"))
                table.add_row("Ledger Fingerprint", str(ledger.ledger_fingerprint))
                console.print(table)
                return
        except Exception as e:
            console.print(f"[bold yellow]Warning reading ledger file:[/bold yellow] {e}")

    console.print(f"[bold red]No remediation record found for finding ID '{finding_id}'.[/bold red]")


@remediation_app.command("history")
def history_command(
    finding_id: str = typer.Argument(..., help="ID of the finding to inspect audit history for."),
    ledger_file: Path = typer.Option(Path("remediation_ledger.json"), "--ledger", help="Path to ledger JSON file."),
) -> None:
    """Read-only inspection of append-only audit event history for a finding."""
    if not ledger_file.exists():
        console.print(f"[bold red]Ledger file '{ledger_file}' not found.[/bold red]")
        sys.exit(1)

    try:
        data = json.loads(ledger_file.read_text(encoding="utf-8"))
        ledger = RemediationLedger.from_dict(data)
        evs = ledger.get_events_for_finding(finding_id)
        if not evs:
            console.print(f"[bold yellow]No audit events found for finding ID '{finding_id}'.[/bold yellow]")
            return

        table = Table(title=f"Remediation Audit Event History: {finding_id}")
        table.add_column("Event ID", style="bold cyan")
        table.add_column("Event Type", style="bold yellow")
        table.add_column("Lifecycle State", style="bold green")
        table.add_column("Actor", style="bold white")
        table.add_column("Timestamp", style="dim white")
        table.add_column("Predecessor ID", style="dim cyan")

        for e in evs:
            table.add_row(
                e.event_id,
                str(e.event_type),
                str(e.lifecycle_state),
                str(e.actor),
                str(e.timestamp),
                str(e.predecessor_event_id or "NONE"),
            )
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error inspecting ledger history:[/bold red] {e}")
        sys.exit(1)


@remediation_app.command("provenance")
def provenance_command(
    finding_id: str = typer.Argument(..., help="ID of the finding to inspect provenance graph for."),
    provenance_file: Path = typer.Option(Path("remediation_provenance.json"), "--provenance", help="Path to provenance graph JSON file."),
) -> None:
    """Read-only inspection of provenance evidence graph for a finding."""
    if not provenance_file.exists():
        console.print(f"[bold red]Provenance file '{provenance_file}' not found.[/bold red]")
        sys.exit(1)

    try:
        data = json.loads(provenance_file.read_text(encoding="utf-8"))
        graph = RemediationProvenanceGraph.from_dict(data)
        nodes = [n for n in graph.nodes.values() if n.finding_id == finding_id]
        if not nodes:
            console.print(f"[bold yellow]No provenance nodes found for finding ID '{finding_id}'.[/bold yellow]")
            return

        table = Table(title=f"Remediation Provenance Nodes: {finding_id}")
        table.add_column("Node ID", style="bold cyan")
        table.add_column("Node Type", style="bold yellow")
        table.add_column("Predecessor IDs", style="dim white")
        table.add_column("Fingerprint", style="bold green")

        for n in nodes:
            table.add_row(
                n.node_id,
                str(n.node_type),
                ", ".join(n.predecessor_node_ids) or "NONE",
                n.node_fingerprint[:16] + "...",
            )
        console.print(table)
        console.print(f"[bold cyan]Graph Fingerprint:[/bold cyan] {graph.graph_fingerprint}")
    except Exception as e:
        console.print(f"[bold red]Error inspecting provenance graph:[/bold red] {e}")
        sys.exit(1)
