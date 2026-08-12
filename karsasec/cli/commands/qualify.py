"""KarsaSec `qualify` CLI command (E12-2).

Usage:
    karsasec qualify --benchmark dvwa --target /path/to/dvwa/vulnerabilities
    karsasec qualify --benchmark dvwa --target /path --format json
    karsasec qualify --benchmark dvwa --save-snapshot

The command:
  1. Loads the benchmark manifest from benchmarks/<benchmark>/manifest.yaml
  2. Runs a KarsaSec scan against --target
  3. Passes raw findings through FindingCorrelator
  4. Runs QualificationEngine
  5. Outputs human-readable (text) or machine-readable (json) report
  6. Optionally saves latest snapshot to benchmarks/results/<benchmark>/latest.json
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.panel import Panel
from rich.table import Table

from karsasec.utils.logging import console

if TYPE_CHECKING:
    from karsasec.qualification.engine import QualificationResult

qualify_app = typer.Typer(help="Qualification & benchmark metrics for KarsaSec detection quality.")

# Default paths
_BENCHMARKS_DIR = Path(__file__).parents[3] / "benchmarks"
_RESULTS_DIR = Path(__file__).parents[3] / "benchmarks" / "results"


@qualify_app.callback(invoke_without_command=True)
def run_qualify(
    benchmark: str = typer.Option(..., "--benchmark", "-b", help="Benchmark ID (e.g. 'dvwa')"),
    target: Path | None = typer.Option(None, "--target", "-t", help="Directory to scan (e.g. /path/to/dvwa/vulnerabilities)"),
    format: str = typer.Option("text", "--format", "-f", help="Output format: 'text' or 'json'"),
    save_snapshot: bool = typer.Option(False, "--save-snapshot", help="Save snapshot to benchmarks/results/<benchmark>/latest.json"),
    benchmarks_dir: Path | None = typer.Option(None, "--benchmarks-dir", hidden=True, help="Override benchmarks directory"),
) -> None:
    """Run qualification benchmark and report TP/FP/FN/TN/precision/recall/F1."""
    from karsasec.qualification.engine import QualificationEngine
    from karsasec.qualification.model import ManifestLoader

    bm_root = benchmarks_dir or _BENCHMARKS_DIR
    manifest_path = bm_root / benchmark / "manifest.yaml"

    if not manifest_path.exists():
        console.print(f"[red]Manifest not found:[/red] {manifest_path}")
        console.print(f"[dim]Available benchmarks: {', '.join(d.name for d in bm_root.iterdir() if d.is_dir()) if bm_root.exists() else 'none'}[/dim]")
        raise typer.Exit(code=1)

    # Load ground truth
    loader = ManifestLoader()
    try:
        gt_benchmark = loader.load(manifest_path)
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[red]Manifest error:[/red] {e}")
        raise typer.Exit(code=1)

    # Resolve target
    scan_root = target
    if scan_root is None:
        candidates = [
            Path("/home/lota1337/pentest/DVWA/vulnerabilities"),
            Path("/var/www/html/DVWA/vulnerabilities"),
            Path("/opt/DVWA/vulnerabilities"),
        ]
        for c in candidates:
            if c.exists():
                scan_root = c
                break
        if scan_root is None:
            console.print("[yellow]No --target specified and no default DVWA path found.[/yellow]")
            console.print("[dim]Use: karsasec qualify --benchmark dvwa --target /path/to/dvwa/vulnerabilities[/dim]")
            raise typer.Exit(code=1)

    if not scan_root.exists():
        console.print(f"[red]Target directory not found:[/red] {scan_root}")
        raise typer.Exit(code=1)

    # Run scan via internal PHP scanner
    console.print(f"[cyan]Scanning:[/cyan] {scan_root}")
    raw_findings, final_findings = _scan_target(scan_root)

    raw_count = len(raw_findings)
    console.print(f"[dim]Raw findings: {raw_count} → Correlated: {len(final_findings)}[/dim]")

    # Qualify
    engine = QualificationEngine()
    result = engine.qualify(
        benchmark=gt_benchmark,
        final_findings=final_findings,
        scan_root=scan_root,
        raw_finding_count=raw_count,
        raw_findings=raw_findings,
    )

    if format.lower() == "json":
        json_doc = _output_json(result)
        print(json_doc)
    else:
        _output_text(result)

    if save_snapshot:
        _save_snapshot_file(benchmark, result)

    raise typer.Exit(code=0)


def _scan_target(scan_root: Path) -> tuple[list, list]:
    """Run a KarsaSec scan and return (raw_findings, final_findings)."""
    from karsasec.cli.commands.scan import get_default_rules_directory
    from karsasec.core.execution import RuleExecutor, ScanContext
    from karsasec.core.finding.correlator import FindingCorrelator
    from karsasec.rules.loader import YAMLRuleLoader

    loader = YAMLRuleLoader()
    rules = loader.load_directory(get_default_rules_directory())

    executor = RuleExecutor()
    correlator = FindingCorrelator()

    all_raw: list = []
    php_files = sorted(list(scan_root.rglob("*.php")))

    project_files: dict[str, str] = {}
    for pf in php_files:
        try:
            project_files[str(pf)] = pf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass

    from karsasec.graph.taint_verifier import taint_verifier
    taint_verifier.project_files = project_files

    from unittest.mock import patch

    from karsasec.parser.generic_parser import php_parser
    from karsasec.parser.tree_sitter import ts_engine

    for php_file in php_files:
        try:
            source = php_file.read_bytes()
            with patch.object(ts_engine, "get_language", return_value=None):
                parse_result = php_parser.parse_file(php_file)
            parse_result.root.language = "PHP"
            ctx = ScanContext(
                file_node=parse_result.root,
                source_bytes=source,
                file_path=php_file,
                symbol_table=parse_result.symbol_table,
                language="PHP",
            )
            scan_result = executor.execute_scan(ctx, rules)
            all_raw.extend(scan_result.findings)
        except Exception:
            continue

    canonical = correlator.correlate(all_raw)
    final = list(correlator.to_findings(canonical))
    from karsasec.core.finding.model import QualificationState
    active_final = [f for f in final if getattr(f, "qualification_state", None) != QualificationState.REJECTED]
    return all_raw, active_final


def _output_text(result: QualificationResult) -> None:
    """Render human-readable qualification report."""
    console.print()
    console.print(Panel(
        f"[bold cyan]KarsaSec Qualification — {result.benchmark_id.upper()}[/bold cyan]\n"
        f"Benchmark : [bold]{result.benchmark_id}[/bold] (v{result.version})\n"
        f"Cases     : {result.total_cases}  "
        f"[green]TP={result.true_positives}[/green]  "
        f"[red]FP={result.false_positives}[/red]  "
        f"[yellow]FN={result.false_negatives}[/yellow]  "
        f"[blue]TN={result.true_negatives}[/blue]  "
        f"[dim]UNKNOWN={result.unknown_findings}[/dim]",
        title="Qualification", border_style="cyan",
    ))

    console.print("\n[bold]Accuracy Metrics[/bold]")
    console.print(f"  Precision : [cyan]{result.precision:.2%}[/cyan]")
    console.print(f"  Recall    : [cyan]{result.recall:.2%}[/cyan]")
    console.print(f"  F1 Score  : [cyan]{result.f1:.2%}[/cyan]")

    console.print("\n[bold]Finding Quality & Provenance (E12-4)[/bold]")
    console.print(f"  Candidates          : {result.candidate_count}")
    console.print(f"  Qualified           : {result.qualified_count}")
    console.print(f"  Rejected            : {result.rejected_count}")
    console.print(f"  Unresolved          : {result.unresolved_count}")
    console.print(f"  Conflicts           : {result.conflict_count}")
    console.print(f"  Exact Duplicates    : {result.exact_duplicates} ({result.exact_duplicate_rate:.2%})")
    console.print(f"  Semantic Duplicates : {result.semantic_duplicates}")
    console.print(f"  Evidence Incomplete : {result.evidence_incomplete_count}")
    console.print(f"  Cross-Rule Overlaps : {result.cross_rule_overlaps} ({result.cross_rule_overlap_rate:.2%})")
    console.print(f"  UNKNOWN Rate        : {result.unknown_rate:.2%}")

    # Per-category table
    if result.per_category:
        console.print()
        tbl_cat = Table(title="Per-Category Results", border_style="dim")
        tbl_cat.add_column("Category", style="magenta", no_wrap=True)
        tbl_cat.add_column("TP", justify="right")
        tbl_cat.add_column("FP", justify="right")
        tbl_cat.add_column("FN", justify="right")
        tbl_cat.add_column("TN", justify="right")
        tbl_cat.add_column("Precision", justify="right")
        tbl_cat.add_column("Recall", justify="right")
        tbl_cat.add_column("F1", justify="right")
        for cat, cr in sorted(result.per_category.items()):
            tbl_cat.add_row(
                cat,
                str(cr.tp), str(cr.fp), str(cr.fn), str(cr.tn),
                f"{cr.precision:.0%}", f"{cr.recall:.0%}", f"{cr.f1:.0%}",
            )
        console.print(tbl_cat)

    # Per-rule table
    if result.per_rule:
        console.print()
        tbl = Table(title="Per-Rule Results", border_style="dim")
        tbl.add_column("Rule", style="cyan", no_wrap=True)
        tbl.add_column("TP", justify="right")
        tbl.add_column("FP", justify="right")
        tbl.add_column("FN", justify="right")
        tbl.add_column("UNKNOWN", justify="right")
        tbl.add_column("Precision", justify="right")
        tbl.add_column("Recall", justify="right")
        tbl.add_column("F1", justify="right")
        for rid, rr in sorted(result.per_rule.items()):
            tbl.add_row(
                rid,
                str(rr.tp), str(rr.fp), str(rr.fn), str(rr.unknown),
                f"{rr.precision:.0%}", f"{rr.recall:.0%}", f"{rr.f1:.0%}",
            )
        console.print(tbl)

    console.print("\n[bold dim]STATUS: QUALIFICATION BASELINE[/bold dim]  "
                  "[dim](E12-4 — evidence quality & correlation active)[/dim]\n")


def _output_json(result: QualificationResult) -> str:
    """Construct stable, machine-readable JSON string."""
    doc = {
        "benchmark": result.benchmark_id,
        "version": result.version,
        "schema_version": "1.0",
        "cases": {
            "total": result.total_cases,
            "tp": result.true_positives,
            "fp": result.false_positives,
            "fn": result.false_negatives,
            "tn": result.true_negatives,
            "unknown": result.unknown_findings,
        },
        "metrics": {
            "precision": round(result.precision, 4),
            "recall": round(result.recall, 4),
            "f1": round(result.f1, 4),
        },
        "findings": {
            "raw": result.raw_findings,
            "final": result.final_findings,
            "duplicates": result.duplicate_findings,
            "duplicate_rate": round(result.duplicate_rate, 4),
        },
        "finding_quality": {
            "candidates": result.candidate_count,
            "qualified": result.qualified_count,
            "rejected": result.rejected_count,
            "unresolved": result.unresolved_count,
            "conflicts": result.conflict_count,
            "exact_duplicates": result.exact_duplicates,
            "exact_duplicate_rate": round(result.exact_duplicate_rate, 4),
            "semantic_duplicates": result.semantic_duplicates,
            "evidence_incomplete": result.evidence_incomplete_count,
            "cross_rule_overlaps": result.cross_rule_overlaps,
            "cross_rule_overlap_rate": round(result.cross_rule_overlap_rate, 4),
            "unknown_rate": round(result.unknown_rate, 4),
        },
        "per_category": {
            cat: {
                "tp": cr.tp, "fp": cr.fp, "fn": cr.fn, "tn": cr.tn, "unknown": cr.unknown,
                "precision": round(cr.precision, 4),
                "recall": round(cr.recall, 4),
                "f1": round(cr.f1, 4),
            }
            for cat, cr in sorted(result.per_category.items())
        },
        "per_rule": {
            rid: {
                "tp": rr.tp, "fp": rr.fp, "fn": rr.fn, "unknown": rr.unknown,
                "precision": round(rr.precision, 4),
                "recall": round(rr.recall, 4),
                "f1": round(rr.f1, 4),
            }
            for rid, rr in sorted(result.per_rule.items())
        },
    }
    return json.dumps(doc, indent=2)


def _save_snapshot_file(benchmark: str, result: QualificationResult) -> None:
    """Save qualification snapshot to benchmarks/results/<benchmark>/latest.json."""
    out_dir = _RESULTS_DIR / benchmark
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "latest.json"
    doc_str = _output_json(result)
    out_file.write_text(doc_str, encoding="utf-8")
    console.print(f"[green]Saved snapshot to:[/green] {out_file}")
