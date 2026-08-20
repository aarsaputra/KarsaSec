"""CLI Commands for Code Property Graph (build, export, validate, visualize, stats, diff)."""

from __future__ import annotations

from pathlib import Path

import typer

from karsasec.analysis.cfg import CFGBuilder
from karsasec.analysis.dataflow import DataFlowBuilder
from karsasec.analysis.interprocedural import InterproceduralTaintEngine
from karsasec.analysis.ssa import SSABuilder
from karsasec.analysis.taint import IntraproceduralTaintEngine
from karsasec.cpg import CPGBuilder, CPGGraph, CPGReporter, CPGSerializer, CPGValidator, GraphDiff
from karsasec.ir import IRBuilder
from karsasec.parser.ast_nodes import FileNode
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.utils.logging import console

cpg_app = typer.Typer(help="Manage, validate, visualize, and diff Code Property Graph (CPG) artifacts.")
reporter = CPGReporter()
serializer = CPGSerializer()
validator = CPGValidator()


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


def _build_cpg_from_path(target_path: Path) -> CPGGraph | None:
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
    ssa_map = {}

    for name, cfg in cfgs.items():
        ssa_func = ssa_builder.build_ssa(cfg)
        dfg = dfg_builder.build_dataflow_graph(cfg, ssa_func)
        tg = intra_engine.analyze_function(cfg, ssa_func, dfg)
        taint_graphs[name] = tg
        dfg_map[name] = dfg
        ssa_map[name] = ssa_func

    itg = InterproceduralTaintEngine().analyze_program(taint_graphs, dfg_map)

    cpg = CPGBuilder().build_cpg(
        file_nodes=file_nodes,
        ir_functions=ir_funcs,
        cfgs=cfgs,
        ssa_functions=ssa_map,
        dfg_map=dfg_map,
        taint_graphs=taint_graphs,
        itg=itg,
        project_name=target_path.name,
    )
    return cpg


@cpg_app.command("build")
def build_cpg(
    target_path: Path = typer.Argument(Path("."), help="Source file or directory to build CPG for."),
) -> None:
    """Builds Code Property Graph (CPG) across target source code files."""
    console.print(f"[bold magenta]Building Enterprise Code Property Graph for:[/bold magenta] {target_path}")

    cpg = _build_cpg_from_path(target_path)
    if not cpg:
        console.print("[yellow]No supported source files parsed for CPG.[/yellow]")
        raise typer.Exit(code=0)

    console.print("\n[bold white]CPG Construction Summary:[/bold white]")
    console.print(f"Project: {cpg.metadata.project_name}")
    console.print(f"Total CPG Nodes: {len(cpg.nodes)}")
    console.print(f"Total CPG Edges: {len(cpg.edges)}")
    console.print(f"Build Time: {cpg.metadata.duration_seconds}s")


@cpg_app.command("export")
def export_cpg(
    target_path: Path = typer.Argument(..., help="Source code path to export CPG for."),
    output_path: Path = typer.Option(
        Path("cpg_export.json"), "--output", "-o", help="Output CPG artifact file path (.json or .cpg.gz)."
    ),
) -> None:
    """Exports Code Property Graph artifact as JSON or compressed .cpg.gz."""
    cpg = _build_cpg_from_path(target_path)
    if not cpg:
        console.print(f"[bold red]Failed to parse target:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    if output_path.name.endswith(".cpg.gz") or output_path.name.endswith(".gz"):
        serializer.save_compressed(cpg, output_path)
    else:
        serializer.save_json(cpg, output_path)

    console.print(f"[bold green]Exported CPG Artifact:[/bold green] {output_path}")


@cpg_app.command("validate")
def validate_cpg(
    target_path: Path = typer.Argument(..., help="Source code path or JSON artifact to validate CPG integrity for."),
) -> None:
    """Validates structural integrity of Code Property Graph."""
    if target_path.is_file() and (target_path.suffix == ".json" or target_path.name.endswith(".gz")):
        if target_path.name.endswith(".gz"):
            cpg = serializer.load_compressed(target_path)
        else:
            cpg = serializer.from_json(target_path.read_text())
    else:
        cpg = _build_cpg_from_path(target_path)

    if not cpg:
        console.print(f"[bold red]Failed to load CPG for validation:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    issues = validator.validate(cpg)
    if not issues:
        console.print(
            "[bold green][VALIDATED] CPG Graph structural integrity verified (0 errors, 0 broken edges).[/bold green]"
        )
    else:
        console.print(f"[yellow]Validation Findings: {len(issues)} issues detected.[/yellow]")
        for iss in issues:
            console.print(f"[{iss.severity}] {iss.issue_type}: {iss.message}")


@cpg_app.command("visualize")
def visualize_cpg(
    target_path: Path = typer.Argument(..., help="Source code path to generate CPG HTML visualizer for."),
    output_html: Path = typer.Option(Path("cpg_visualizer.html"), "--output", "-o", help="Output HTML file path."),
) -> None:
    """Generates an interactive HTML page rendering the Code Property Graph."""
    cpg = _build_cpg_from_path(target_path)
    if not cpg:
        console.print(f"[bold red]Failed to parse target:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    html_content = reporter.render_html_report(cpg)
    output_html.write_text(html_content)
    console.print(f"[bold green][SUCCESS] Exported CPG Visualizer HTML:[/bold green] {output_html}")


@cpg_app.command("stats")
def stats_cpg(
    target_path: Path = typer.Argument(Path("."), help="Source code path to display CPG statistics for."),
) -> None:
    """Displays detailed graph statistics for CPG."""
    cpg = _build_cpg_from_path(target_path)
    if not cpg:
        console.print("[yellow]No CPG statistics available.[/yellow]")
        raise typer.Exit(code=0)

    console.print("\n[bold yellow]Code Property Graph (CPG) Statistics:[/bold yellow]")
    console.print(f"Schema Version: {cpg.metadata.schema_version}")
    console.print(f"Node Count: {cpg.metadata.node_count}")
    console.print(f"Edge Count: {cpg.metadata.edge_count}")
    console.print(f"Languages: {', '.join(cpg.metadata.languages)}")


@cpg_app.command("diff")
def diff_cpg(
    old_path: Path = typer.Argument(..., help="Old CPG JSON / source path."),
    new_path: Path = typer.Argument(..., help="New CPG JSON / source path."),
) -> None:
    """Computes IncrementalPatch diff between two CPG graphs."""
    cpg_old = _build_cpg_from_path(old_path)
    cpg_new = _build_cpg_from_path(new_path)

    if not cpg_old or not cpg_new:
        console.print("[bold red]Failed to build graphs for comparison.[/bold red]")
        raise typer.Exit(code=1)

    patch = GraphDiff().compare(cpg_old, cpg_new)
    console.print("\n[bold cyan]CPG Incremental Patch Summary:[/bold cyan]")
    console.print(f"Added Nodes: {len(patch.added_nodes)}")
    console.print(f"Removed Node IDs: {len(patch.removed_node_ids)}")
    console.print(f"Modified Nodes: {len(patch.modified_nodes)}")
    console.print(f"Added Edges: {len(patch.added_edges)}")
    console.print(f"Removed Edges: {len(patch.removed_edges)}")
