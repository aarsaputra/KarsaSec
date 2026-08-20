"""CLI Commands for CPG Query Engine (run, explain, profile, benchmark, dump-plan, dump-ast, stats, cache)."""

from __future__ import annotations

from pathlib import Path

import typer

from karsasec.analysis.cfg import CFGBuilder
from karsasec.cpg import CPGBuilder
from karsasec.ir import IRBuilder
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.query import (
    Function,
    QueryCache,
    QueryExecutor,
    QueryOptimizer,
    QueryPlanner,
    QueryProfiler,
)
from karsasec.rules.runtime import SemanticRuleRuntime
from karsasec.utils.logging import console

query_app = typer.Typer(help="Manage, profile, benchmark, and execute CPG Queries.")
_cache = QueryCache()


@query_app.command("run")
def run_query(
    path: Path = typer.Argument(..., help="Path to target file or directory"),
    rule: Path = typer.Option(None, "--rule", "-r", help="Path to YAML rule file"),
) -> None:
    """Executes a CPG Query or Rule against target source code."""
    console.print(f"[bold blue]Building CPG for:[/bold blue] {path}")
    plugin = PythonParserPlugin()
    files = list(path.glob("**/*.py")) if path.is_dir() else [path]
    parsed_results = [plugin.parse_file(f) for f in files]
    file_nodes = [pr.file_node for pr in parsed_results if hasattr(pr, "file_node")]

    ir_funcs = []
    cfgs = {}
    ir_builder = IRBuilder()
    for fn_node in file_nodes:
        funcs = ir_builder.build_from_file_nodes([fn_node])
        ir_funcs.extend(funcs)
        for fn in funcs:
            cfg = CFGBuilder().build_cfg(fn)
            cfgs[fn.name] = cfg

    builder = CPGBuilder()
    cpg = builder.build_cpg(file_nodes=file_nodes, ir_functions=ir_funcs, cfgs=cfgs)

    if rule and rule.exists():
        import yaml

        rule_data = yaml.safe_load(rule.read_text(encoding="utf-8"))
        runtime = SemanticRuleRuntime()
        findings = runtime.execute_rule(rule_data, cpg)
        console.print(f"[bold green]Query Execution Finished.[/bold green] Found {len(findings)} findings.")
        for f in findings:
            console.print(f" - [{f.severity.value}] {f.title} ({f.file_path}:{f.evidence.line})")
    else:
        # Default query
        q_ast = Function().build()
        plan = QueryOptimizer().optimize(QueryPlanner().create_plan(q_ast))
        results = QueryExecutor().execute(plan, cpg)
        console.print(f"[bold green]Default Function Query Finished.[/bold green] Matched {len(results)} nodes.")


@query_app.command("dump-ast")
def dump_ast(
    name: str = typer.Option("execute", "--name", "-n", help="Function name to query"),
) -> None:
    """Dumps Query AST JSON for a given target query."""
    q_ast = Function(name).build()
    console.print_json(q_ast.to_json())


@query_app.command("dump-plan")
def dump_plan(
    name: str = typer.Option("execute", "--name", "-n", help="Function name to query"),
) -> None:
    """Dumps Execution Plan JSON for a given target query."""
    q_ast = Function(name).build()
    plan = QueryOptimizer().optimize(QueryPlanner().create_plan(q_ast))
    console.print_json(data=plan.to_dict())


@query_app.command("cache")
def show_cache() -> None:
    """Displays Query Cache statistics."""
    console.print_json(data=_cache.stats())


@query_app.command("profile")
def profile_query() -> None:
    """Profiles Query Engine phases."""
    profiler = QueryProfiler()
    profiler.start_stage("Planning")
    q_ast = Function("test").build()
    plan = QueryPlanner().create_plan(q_ast)
    profiler.stop_stage("Planning")

    profiler.start_stage("Optimization")
    QueryOptimizer().optimize(plan)
    profiler.stop_stage("Optimization")

    console.print_json(data=profiler.report())


@query_app.command("benchmark")
def run_benchmark() -> None:
    """Executes CPG Query Engine Benchmark Suite."""
    import time

    start = time.time()
    for _ in range(100):
        q_ast = Function("bench").build()
        plan = QueryPlanner().create_plan(q_ast)
        QueryOptimizer().optimize(plan)
    elapsed = (time.time() - start) * 1000.0
    console.print(
        f"[bold green]Benchmark Completed:[/bold green] 100 Query Plan & Optimization runs in {elapsed:.2f}ms (Avg {elapsed / 100:.3f}ms/run)."
    )
