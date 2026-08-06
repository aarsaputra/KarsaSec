"""Main Typer CLI application router for KarsaSec."""

import sys
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from karsasec import __version__
from karsasec.cli.commands.cfg import cfg_app
from karsasec.cli.commands.debug import debug_app
from karsasec.cli.commands.rules import rules_app
from karsasec.cli.commands.scan import execute_scan_command
from karsasec.cli.commands.taint import taint_app
from karsasec.config import settings
from karsasec.utils.logging import console, logger

app = typer.Typer(
    name="karsasec",
    help="Autonomous Application Security Operating System (SecOS)",
    add_completion=False,
    no_args_is_help=True,
)

app.add_typer(rules_app, name="rules")
app.add_typer(cfg_app, name="cfg")
app.add_typer(debug_app, name="debug")
app.add_typer(taint_app, name="taint")

def version_callback(value: bool) -> None:
    """Callback for printing the CLI version."""
    if value:
        console.print(f"[bold green]KarsaSec SecOS[/bold green] version [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()

@app.callback()
def main(
    version: bool | None = typer.Option(
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
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Export path for scan report file.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Path to baseline file for vulnerability diff comparison.",
    ),
    use_rag: bool = typer.Option(
        False,
        "--rag",
        "--context-search",
        help="Enable hybrid RAG retrieval context during scan.",
    ),
    rag_query: str | None = typer.Option(
        None,
        "--rag-query",
        "--context-query",
        help="Explicit text query used for RAG context retrieval.",
    ),
    rag_corpus: Path | None = typer.Option(
        None,
        "--rag-corpus",
        help="Path to an external RAG corpus directory, e.g. a local clone of a public security/code corpus.",
    ),
    rag_rebuild: bool = typer.Option(
        False,
        "--rag-rebuild",
        help="Force rebuild the RAG corpus index before retrieval.",
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
        use_rag=use_rag,
        rag_query=rag_query,
        rag_corpus=rag_corpus,
        rag_rebuild=rag_rebuild,
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


@app.command("config")
def config() -> None:
    """Print a starter configuration template for KarsaSec."""
    config_template = """scan:
  format: console
  baseline: null
  rag: false
  rag_query: null
  rag_corpus: null
  exclude:
    - vendor
    - node_modules
    - dist
    - build

runtime:
  default_llm_provider: litellm
  default_llm_model: gemini-2.5-flash
  max_token_budget_per_scan: 50000
"""
    console.print(config_template)


@app.command("init")
def init_config(path: Path | None = typer.Argument(None, help="Path to write the default configuration file.")) -> None:
    """Create a starter karsasec.yaml configuration file."""
    output_path = path or Path("karsasec.yaml")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        """scan:
  format: console
  baseline: null
  rag: false
  rag_query: null
  rag_corpus: null
  exclude:
    - vendor
    - node_modules
    - dist
    - build

runtime:
  default_llm_provider: litellm
  default_llm_model: gemini-2.5-flash
  max_token_budget_per_scan: 50000
""",
        encoding="utf-8",
    )
    console.print(f"Created configuration file at [bold green]{output_path.resolve()}[/bold green]")

if __name__ == "__main__":
    app()
