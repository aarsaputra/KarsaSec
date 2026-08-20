"""CLI Commands for Intraprocedural Taint Analysis (build, export, visualize)."""

from __future__ import annotations

from pathlib import Path

import typer

from karsasec.analysis.cfg import CFGBuilder
from karsasec.analysis.dataflow import DataFlowBuilder
from karsasec.analysis.ssa import SSABuilder
from karsasec.analysis.taint import IntraproceduralTaintEngine, TaintReporter
from karsasec.ir import IRBuilder
from karsasec.parser.ast_nodes import FileNode
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.utils.logging import console

taint_app = typer.Typer(help="Manage and visualize Taint Flow analysis artifacts.")
reporter = TaintReporter()


def _parse_file(p: Path) -> FileNode | None:
    try:
        plugin = parser_registry.get_parser_for_file(p)
        if not plugin and p.suffix == ".py":
            plugin = PythonParserPlugin()
        if plugin and hasattr(plugin, "parse_file"):
            res = plugin.parse_file(p)
            return res.root
    except Exception as e:
        console.print(f"[yellow]Warning parsing {p.name}: {e}[/yellow]")
    return None


@taint_app.command("build")
def build_taint(
    target_path: Path = typer.Argument(Path("."), help="Source file or directory to build TaintGraphs for."),
) -> None:
    """Builds TaintGraphs across target source code files and reports detected flows."""
    console.print(f"[bold cyan]Building Taint Analysis for:[/bold cyan] {target_path}")

    file_nodes: list[FileNode] = []
    if target_path.is_file():
        fn = _parse_file(target_path)
        if fn:
            file_nodes.append(fn)
    elif target_path.is_dir():
        for p in target_path.rglob("*"):
            if p.is_file() and p.suffix in [".py", ".go", ".js", ".ts", ".php", ".rs"]:
                fn = _parse_file(p)
                if fn:
                    file_nodes.append(fn)

    if not file_nodes:
        console.print("[yellow]No supported source files parsed for Taint Analysis.[/yellow]")
        raise typer.Exit(code=0)

    ir_funcs = IRBuilder().build_from_file_nodes(file_nodes)
    cfgs = CFGBuilder().build_cfg_for_functions(ir_funcs)
    engine = IntraproceduralTaintEngine()

    total_vuln = 0
    total_safe = 0

    for name, cfg in cfgs.items():
        ssa_func = SSABuilder().build_ssa(cfg)
        dfg = DataFlowBuilder().build_dataflow_graph(cfg, ssa_func)
        taint_graph = engine.analyze_function(cfg, ssa_func, dfg)

        vuln_count = len(taint_graph.vulnerable_paths)
        safe_count = len(taint_graph.safe_paths)
        total_vuln += vuln_count
        total_safe += safe_count

        if vuln_count > 0:
            console.print(
                f"[bold red][VULNERABLE][/bold red] Function '{name}': {vuln_count} unsanitized flow(s) detected!"
            )
        else:
            console.print(
                f"[bold green][SAFE][/bold green] Function '{name}': 0 vulnerable flows, {safe_count} safe/sanitized path(s)."
            )

    console.print(
        f"\n[bold white]Taint Analysis Summary:[/bold white] {total_vuln} vulnerable flow(s), {total_safe} safe flow(s)."
    )


@taint_app.command("export")
def export_taint(
    file_path: Path = typer.Argument(..., help="Source code file path to export TaintGraph JSON for."),
    output_path: Path = typer.Option(
        Path("taint_export.json"), "--output", "-o", help="Output JSON artifact file path."
    ),
) -> None:
    """Exports TaintGraph artifact as JSON."""
    fn = _parse_file(file_path)
    if not fn:
        console.print(f"[bold red]Failed to parse file:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    ir_funcs = IRBuilder().build_from_file_nodes([fn])
    cfgs = CFGBuilder().build_cfg_for_functions(ir_funcs)

    if not cfgs:
        console.print("[yellow]No functions found for Taint export.[/yellow]")
        raise typer.Exit(code=0)

    first_name, first_cfg = next(iter(cfgs.items()))
    ssa_func = SSABuilder().build_ssa(first_cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(first_cfg, ssa_func)
    taint_graph = IntraproceduralTaintEngine().analyze_function(first_cfg, ssa_func, dfg)

    output_path.write_text(taint_graph.to_json(indent=2))
    console.print(f"[bold green]Exported TaintGraph JSON for '{first_name}':[/bold green] {output_path}")


@taint_app.command("visualize")
def visualize_taint(
    file_path: Path = typer.Argument(..., help="Source code file path to generate interactive HTML visualizer for."),
    output_html: Path = typer.Option(Path("taint_visualizer.html"), "--output", "-o", help="Output HTML file path."),
) -> None:
    """Generates an interactive HTML page color-coding Source, Propagation, Sanitizer, and Sink nodes."""
    fn = _parse_file(file_path)
    if not fn:
        console.print(f"[bold red]Failed to parse file:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    ir_funcs = IRBuilder().build_from_file_nodes([fn])
    cfgs = CFGBuilder().build_cfg_for_functions(ir_funcs)

    if not cfgs:
        console.print("[yellow]No functions found for Taint visualizer.[/yellow]")
        raise typer.Exit(code=0)

    first_name, first_cfg = next(iter(cfgs.items()))
    ssa_func = SSABuilder().build_ssa(first_cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(first_cfg, ssa_func)
    taint_graph = IntraproceduralTaintEngine().analyze_function(first_cfg, ssa_func, dfg)

    html_content = reporter.render_html_report(taint_graph)
    output_html.write_text(html_content)
    console.print(f"[bold green][SUCCESS] Exported Taint Visualizer HTML:[/bold green] {output_html}")
