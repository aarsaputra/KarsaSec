"""CLI commands for Framework Semantic Layer inspection, detection, visualization, and export."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from karsasec.analysis.framework import FrameworkPass
from karsasec.framework.reporter import FrameworkReporter
from karsasec.parser import PythonParserPlugin
from karsasec.runtime.artifact_store import ArtifactStore

console = Console()
framework_app = typer.Typer(
    name="framework",
    help="Inspect, detect, export, and visualize project Framework Semantic Graph.",
    no_args_is_help=True,
)


def _run_pass_for_path(path: Path) -> ArtifactStore:
    store = ArtifactStore()
    plugin = PythonParserPlugin()
    files = list(path.glob("**/*.py")) if path.is_dir() else ([path] if path.suffix == ".py" else [])
    parsed = [plugin.parse_file(f) for f in files]
    file_nodes = [p.file_node for p in parsed if hasattr(p, "file_node")]
    store.put("AST", file_nodes)

    f_pass = FrameworkPass(target_path=path)
    f_pass.run(store)
    return store


@framework_app.command("detect")
def detect_frameworks(
    path: Path = typer.Argument(Path("."), help="Path to project directory or file."),
) -> None:
    """Detect web frameworks and capabilities in a target project."""
    store = _run_pass_for_path(path)
    metadata = store.get("framework_metadata")

    if not metadata or not metadata.detected_frameworks:
        console.print("[bold yellow]No framework markers detected.[/bold yellow]")
        return

    table = Table(title=f"Framework Detection Results ({path.resolve()})", show_header=True, header_style="bold green")
    table.add_column("Framework", style="bold cyan")
    table.add_column("Confidence", style="yellow")
    table.add_column("Version", style="magenta")
    table.add_column("Detection Reason", style="white")

    for res in metadata.detected_frameworks:
        table.add_row(
            res.framework.value,
            f"{res.confidence * 100:.1f}%",
            res.version.raw_version,
            res.reason[:60],
        )

    console.print(table)


@framework_app.command("stats")
def framework_stats(
    path: Path = typer.Argument(Path("."), help="Path to project directory."),
) -> None:
    """Display statistical summary of Framework Graph nodes and topology."""
    store = _run_pass_for_path(path)
    graph = store.get("framework_graph")
    metadata = store.get("framework_metadata")

    node_count = len(graph.nodes) if graph else 0
    edge_count = len(graph.edges) if graph else 0
    fw_count = len(metadata.detected_frameworks) if metadata else 0

    panel_text = (
        f"[bold cyan]Detected Frameworks[/bold cyan]: {fw_count}\n"
        f"[bold green]FrameworkGraph Nodes[/bold green]: {node_count}\n"
        f"[bold yellow]FrameworkGraph Edges[/bold yellow]: {edge_count}\n"
        f"[bold magenta]Entrypoint Files[/bold magenta]: {len(metadata.entrypoints) if metadata else 0}\n"
        f"[bold blue]Config Files[/bold blue]: {len(metadata.config_files) if metadata else 0}"
    )
    console.print(Panel(panel_text, title="Framework Statistics", border_style="blue"))


@framework_app.command("export")
def export_framework(
    path: Path = typer.Argument(Path("."), help="Path to project directory."),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, dot, mermaid, html"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Optional output file path."),
) -> None:
    """Export FrameworkGraph into JSON, DOT, Mermaid, or HTML format."""
    store = _run_pass_for_path(path)
    graph = store.get("framework_graph")
    metadata = store.get("framework_metadata")

    if not graph:
        console.print("[bold red]Failed to construct FrameworkGraph.[/bold red]")
        raise typer.Exit(code=1)

    reporter = FrameworkReporter()
    fmt = format.lower()

    if fmt == "json":
        res = reporter.export_json(graph, metadata)
    elif fmt == "mermaid":
        res = reporter.export_mermaid(graph)
    elif fmt == "dot":
        res = reporter.export_dot(graph)
    elif fmt == "html":
        res = reporter.export_html(graph, metadata)
    else:
        console.print(f"[bold red]Unsupported format: {format}[/bold red]")
        raise typer.Exit(code=1)

    if output:
        output.write_text(res, encoding="utf-8")
        console.print(f"[bold green]Exported FrameworkGraph to {output.resolve()}[/bold green]")
    else:
        console.print(res)


@framework_app.command("visualize")
def visualize_framework(
    path: Path = typer.Argument(Path("."), help="Path to project directory."),
) -> None:
    """Visualize FrameworkGraph topology as a Mermaid diagram in terminal."""
    store = _run_pass_for_path(path)
    graph = store.get("framework_graph")

    if not graph:
        console.print("[bold red]No FrameworkGraph available.[/bold red]")
        return

    reporter = FrameworkReporter()
    console.print(Panel(reporter.export_mermaid(graph), title="Framework Topology (Mermaid)", border_style="cyan"))
