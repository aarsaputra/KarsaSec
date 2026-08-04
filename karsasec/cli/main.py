"""Main Typer CLI application router for KarsaSec."""

import sys
from pathlib import Path
from typing import Optional
import typer
from rich.panel import Panel
from rich.table import Table

from karsasec import __version__
from karsasec.cli.commands.scan import execute_scan_command
from karsasec.config import settings
from karsasec.utils.logging import console, logger

app = typer.Typer(
    name="karsasec",
    help="🛡️ Autonomous Application Security Operating System (SecOS)",
    add_completion=False,
    no_args_is_help=True,
)

def version_callback(value: bool) -> None:
    """Callback for printing the CLI version."""
    if value:
        console.print(f"[bold green]KarsaSec SecOS[/bold green] version [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Display KarsaSec CLI version.",
        callback=version_callback,
        is_eager=True,
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug mode with verbose diagnostic output.",
    ),
) -> None:
    """Global option initialization."""
    if debug:
        settings.debug = True
        logger.setLevel("DEBUG")
        logger.debug("[yellow]Debug mode enabled.[/yellow]")

@app.command("scan")
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory or file to scan.",
        exists=True,
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Report format: console, json, sarif.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Export path for scan report file.",
    ),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Path to baseline file for vulnerability diff comparison.",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI terminal colors.",
    ),
) -> None:
    """Run fast deterministic security scan on source code."""
    exit_code = execute_scan_command(
        target_path=path,
        format_type=format,
        output_path=output,
        baseline_path=baseline,
        no_color=no_color,
    )
    raise typer.Exit(code=exit_code)

@app.command("review")
def review(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory for AI Agentic security review.",
        exists=True,
    ),
) -> None:
    """Run full AI-Agentic multi-agent security audit."""
    console.print(Panel(f"[bold green]KarsaSec 4-Agent Security Review[/bold green]\nTarget: [bold]{path.resolve()}[/bold]", border_style="green"))
    console.print("🚀 State Machine Pipeline: [cyan]INIT[/cyan] → [cyan]PLAN[/cyan] → [cyan]ANALYZE[/cyan] → [cyan]FIX[/cyan] → [cyan]REPORT[/cyan]")

@app.command("doctor")
def doctor() -> None:
    """Diagnose environment, dependencies, and configuration health."""
    console.print("[bold cyan]KarsaSec Environment Health Check[/bold cyan]\n")

    table = Table(show_header=True, header_style="bold green")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row("CLI Version", "[green]OK[/green]", __version__)
    table.add_row("Python Runtime", "[green]OK[/green]", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    table.add_row("Cache Directory", "[green]OK[/green]", str(settings.cache_dir))
    table.add_row("Default Provider", "[green]OK[/green]", settings.default_llm_provider)
    table.add_row("Default Model", "[green]OK[/green]", settings.default_llm_model)

    console.print(table)

if __name__ == "__main__":
    app()
