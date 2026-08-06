"""CLI Commands for Graph Debugger (AST, IR, CFG, CallGraph, Symbols)."""

from __future__ import annotations

from pathlib import Path

import typer

from karsasec.analysis.cfg import CFGBuilder
from karsasec.analysis.debug.exporter import GraphDebuggerExporter
from karsasec.ir import IRBuilder
from karsasec.parser.ast_nodes import FileNode
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.utils.logging import console

debug_app = typer.Typer(help="Graph Visualization Debugger for Analysis Engine artifacts.")
exporter = GraphDebuggerExporter()


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


@debug_app.command("ast")
def debug_ast(
    file_path: Path = typer.Argument(..., help="Path to source file to inspect AST."),
    output_html: Path = typer.Option(Path("ast_debug.html"), "--output", "-o", help="Output HTML visualization file."),
) -> None:
    """Exports interactive AST HTML visualization for a source file."""
    fn = _parse_file(file_path)
    if not fn:
        console.print(f"[bold red]Failed to parse file for AST debug:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    mmd, json_str = exporter.export_ast(fn)
    html = exporter.render_html_page(f"AST for {file_path.name}", mmd, json_str)
    output_html.write_text(html)
    console.print(f"[bold green][SUCCESS] Exported AST Debugger HTML:[/bold green] {output_html}")


@debug_app.command("ir")
def debug_ir(
    file_path: Path = typer.Argument(..., help="Path to source file to inspect Universal IR."),
    output_html: Path = typer.Option(Path("ir_debug.html"), "--output", "-o", help="Output HTML visualization file."),
) -> None:
    """Exports interactive Universal IR HTML visualization for a source file."""
    fn = _parse_file(file_path)
    if not fn:
        console.print(f"[bold red]Failed to parse file for IR debug:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    builder = IRBuilder()
    ir_funcs = builder.build_from_file_nodes([fn])

    mmd, json_str = exporter.export_ir(ir_funcs)
    html = exporter.render_html_page(f"Universal IR for {file_path.name}", mmd, json_str)
    output_html.write_text(html)
    console.print(f"[bold green][SUCCESS] Exported IR Debugger HTML:[/bold green] {output_html}")


@debug_app.command("cfg")
def debug_cfg(
    file_path: Path = typer.Argument(..., help="Path to source file to inspect CFG."),
    output_html: Path = typer.Option(Path("cfg_debug.html"), "--output", "-o", help="Output HTML visualization file."),
) -> None:
    """Exports interactive Control Flow Graph (CFG) HTML visualization for a source file."""
    fn = _parse_file(file_path)
    if not fn:
        console.print(f"[bold red]Failed to parse file for CFG debug:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    ir_builder = IRBuilder()
    ir_funcs = ir_builder.build_from_file_nodes([fn])

    cfg_builder = CFGBuilder()
    cfgs = cfg_builder.build_cfg_for_functions(ir_funcs)

    if not cfgs:
        console.print("[yellow]No CFGs generated for file.[/yellow]")
        raise typer.Exit(code=0)

    first_cfg = next(iter(cfgs.values()))
    mmd = first_cfg.to_mermaid()
    json_str = first_cfg.to_json()

    html = exporter.render_html_page(f"CFG for {file_path.name} ({first_cfg.function_name})", mmd, json_str)
    output_html.write_text(html)
    console.print(f"[bold green][SUCCESS] Exported CFG Debugger HTML:[/bold green] {output_html}")
