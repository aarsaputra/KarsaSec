"""CLI Commands for Control Flow Graph (CFG) validation and diagram export."""

from __future__ import annotations

from pathlib import Path

import typer

from karsasec.analysis.cfg import CFGBuilder, CFGValidator
from karsasec.ir import IRBuilder
from karsasec.parser.ast_nodes import FileNode
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.utils.logging import console

cfg_app = typer.Typer(help="Manage and validate Control Flow Graphs (CFG).")


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


@cfg_app.command("validate")
def validate_cfg(
    target_path: Path = typer.Argument(Path("."), help="Path to file or project directory to validate CFGs for."),
) -> None:
    """Validates structural invariants (1 entry, 1 exit, 100% reachability) of CFGs across targets."""
    console.print(f"[bold cyan]Validating CFGs for:[/bold cyan] {target_path}")

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
        console.print("[yellow]No supported source files parsed for CFG validation.[/yellow]")
        raise typer.Exit(code=0)

    ir_builder = IRBuilder()
    ir_funcs = ir_builder.build_from_file_nodes(file_nodes)

    builder = CFGBuilder()
    cfgs = builder.build_cfg_for_functions(ir_funcs)

    validator = CFGValidator()
    valid_count = 0

    for name, cfg in cfgs.items():
        try:
            validator.validate(cfg)
            valid_count += 1
        except Exception as e:
            console.print(f"[bold red][FAIL][/bold red] CFG '{name}': {e}")
            raise typer.Exit(code=1)

    console.print(f"[bold green][SUCCESS][/bold green] Validated {valid_count} CFGs with 100% structural reachability.")


@cfg_app.command("export")
def export_cfg(
    file_path: Path = typer.Argument(..., help="Source code file path to export CFGs for."),
    output_dir: Path = typer.Option(Path("."), "--output-dir", "-o", help="Output directory for generated diagram files."),
) -> None:
    """Exports Control Flow Graphs for a file in JSON, Mermaid (.mmd), and Graphviz DOT (.dot) formats."""
    if not file_path.exists() or not file_path.is_file():
        console.print(f"[bold red]File not found:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    fn = _parse_file(file_path)
    if not fn:
        console.print(f"[bold red]Failed to parse file for CFG generation:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    ir_builder = IRBuilder()
    ir_funcs = ir_builder.build_from_file_nodes([fn])

    builder = CFGBuilder()
    cfgs = builder.build_cfg_for_functions(ir_funcs)

    output_dir.mkdir(parents=True, exist_ok=True)

    for name, cfg in cfgs.items():
        safe_name = name.replace(":", "_").replace("/", "_")

        json_path = output_dir / f"cfg_{safe_name}.json"
        json_path.write_text(cfg.to_json())

        mmd_path = output_dir / f"cfg_{safe_name}.mmd"
        mmd_path.write_text(cfg.to_mermaid())

        dot_path = output_dir / f"cfg_{safe_name}.dot"
        dot_path.write_text(cfg.to_dot())

        console.print(f"[bold green]Exported CFG for '{name}':[/bold green] {json_path.name}, {mmd_path.name}, {dot_path.name}")
