"""CLI Commands for Interprocedural Taint Analysis (build, export, visualize, summary, stats)."""

from __future__ import annotations

from pathlib import Path

import typer

from karsasec.analysis.cfg import CFGBuilder
from karsasec.analysis.dataflow import DataFlowBuilder
from karsasec.analysis.interprocedural import InterproceduralReporter, InterproceduralTaintEngine
from karsasec.analysis.ssa import SSABuilder
from karsasec.analysis.taint import IntraproceduralTaintEngine
from karsasec.ir import IRBuilder
from karsasec.parser.ast_nodes import FileNode
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.utils.logging import console

interprocedural_app = typer.Typer(help="Manage and visualize Interprocedural (cross-function) Taint analysis artifacts.")
reporter = InterproceduralReporter()


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


def _build_itg_from_path(target_path: Path):
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
        return None

    ir_funcs = IRBuilder().build_from_file_nodes(file_nodes)
    cfgs = CFGBuilder().build_cfg_for_functions(ir_funcs)

    intra_engine = IntraproceduralTaintEngine()
    dfg_builder = DataFlowBuilder()
    ssa_builder = SSABuilder()

    taint_graphs = {}
    dfg_map = {}

    for name, cfg in cfgs.items():
        ssa_func = ssa_builder.build_ssa(cfg)
        dfg = dfg_builder.build_dataflow_graph(cfg, ssa_func)
        tg = intra_engine.analyze_function(cfg, ssa_func, dfg)
        taint_graphs[name] = tg
        dfg_map[name] = dfg

    return InterproceduralTaintEngine().analyze_program(taint_graphs, dfg_map)


@interprocedural_app.command("build")
def build_interprocedural(
    target_path: Path = typer.Argument(Path("."), help="Source file or directory to build InterproceduralTaintGraph for."),
) -> None:
    """Builds Interprocedural (cross-function) TaintGraphs across target source code files."""
    console.print(f"[bold magenta]Building Interprocedural Taint Analysis for:[/bold magenta] {target_path}")

    itg = _build_itg_from_path(target_path)
    if not itg:
        console.print("[yellow]No supported source files parsed for Interprocedural Analysis.[/yellow]")
        raise typer.Exit(code=0)

    console.print("\n[bold white]Interprocedural Taint Analysis Summary:[/bold white]")
    console.print(f"Total Function Summaries: {len(itg.function_summaries)}")
    console.print(f"[bold red]Vulnerable Cross-Function Call Chains:[/bold red] {len(itg.vulnerable_paths)}")
    console.print(f"[bold green]Safe/Sanitized Cross-Function Chains:[/bold green] {len(itg.safe_paths)}")


@interprocedural_app.command("export")
def export_interprocedural(
    target_path: Path = typer.Argument(..., help="Source code path to export InterproceduralTaintGraph JSON for."),
    output_path: Path = typer.Option(Path("interprocedural_export.json"), "--output", "-o", help="Output JSON artifact file path."),
) -> None:
    """Exports InterproceduralTaintGraph artifact as JSON."""
    itg = _build_itg_from_path(target_path)
    if not itg:
        console.print(f"[bold red]Failed to parse target:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    output_path.write_text(itg.to_json(indent=2))
    console.print(f"[bold green]Exported InterproceduralTaintGraph JSON:[/bold green] {output_path}")


@interprocedural_app.command("visualize")
def visualize_interprocedural(
    target_path: Path = typer.Argument(..., help="Source code path to generate cross-function HTML visualizer for."),
    output_html: Path = typer.Option(Path("interprocedural_visualizer.html"), "--output", "-o", help="Output HTML file path."),
) -> None:
    """Generates an interactive HTML page rendering cross-function call chains."""
    itg = _build_itg_from_path(target_path)
    if not itg:
        console.print(f"[bold red]Failed to parse target:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    html_content = reporter.render_html_report(itg)
    output_html.write_text(html_content)
    console.print(f"[bold green][SUCCESS] Exported Interprocedural Visualizer HTML:[/bold green] {output_html}")


@interprocedural_app.command("summary")
def summary_interprocedural(
    target_path: Path = typer.Argument(Path("."), help="Source code path to print function summaries for."),
) -> None:
    """Displays compiled FunctionSummary contracts for all functions."""
    itg = _build_itg_from_path(target_path)
    if not itg:
        console.print("[yellow]No function summaries found.[/yellow]")
        raise typer.Exit(code=0)

    console.print("\n[bold cyan]Compiled Function Summaries:[/bold cyan]")
    for fn_name, s in itg.function_summaries.items():
        console.print(f"- [bold white]{fn_name}[/bold white]: Source={s.contains_source}, Sink={s.contains_sink}, Sanitizer={s.contains_sanitizer}")


@interprocedural_app.command("stats")
def stats_interprocedural(
    target_path: Path = typer.Argument(Path("."), help="Source code path to print interprocedural analysis statistics for."),
) -> None:
    """Displays interprocedural taint statistics."""
    itg = _build_itg_from_path(target_path)
    if not itg:
        console.print("[yellow]No stats available.[/yellow]")
        raise typer.Exit(code=0)

    console.print("\n[bold yellow]Interprocedural Taint Engine Statistics:[/bold yellow]")
    console.print(f"Total Summaries Cached: {len(itg.function_summaries)}")
    console.print(f"Vulnerable Paths: {len(itg.vulnerable_paths)}")
    console.print(f"Safe Paths: {len(itg.safe_paths)}")
