from __future__ import annotations

import re
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory
from karsasec.utils.logging import console

rules_app = typer.Typer(
    name="rules",
    help="Manage, validate, lint, generate docs, and check coverage for security rules.",
    no_args_is_help=True,
)

VALID_CWES = re.compile(r"^CWE-\d+$")
VALID_OWASP = re.compile(r"^A(0[1-9]|10):\d{4}-.+$")

@rules_app.command("list")
def list_rules(
    language: str | None = typer.Option(None, "--language", "-l", help="Filter by target language."),
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by tag or category."),
) -> None:
    """List all loaded rules in KarsaSec rule registry."""
    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()
    rules = loader.load_directory(rules_dir)

    table = Table(title="KarsaSec Security Rule Registry", show_header=True, header_style="bold green")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Language", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("CWE")

    count = 0
    for r in rules:
        langs = [str(x) for x in r.target.languages] if r.target else []
        if language and language.lower() not in [l.lower() for l in langs]:
            continue
        tags = r.metadata.tags or []
        if category and category.lower() not in [t.lower() for t in tags]:
            continue
        table.add_row(r.id, r.metadata.name, ", ".join(langs), str(r.output.severity.value), r.metadata.cwe or "N/A")
        count += 1

    console.print(table)
    console.print(f"Total Rules Displayed: {count} / {len(rules)}")

@rules_app.command("validate")
def validate_rules() -> None:
    """Validate all YAML rules for structural correctness, regex validity, and required metadata."""
    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()

    seen_ids: dict[str, Path] = {}
    seen_names: dict[str, Path] = {}
    errors: list[str] = []
    warnings: list[str] = []

    for yaml_path in sorted(rules_dir.rglob("*.yaml")):
        try:
            file_rules = loader.load_file_multi(yaml_path)
            for r in file_rules:
                # 1. Duplicate ID check
                if r.id in seen_ids:
                    errors.append(f"Duplicate Rule ID '{r.id}' in {yaml_path.name} (already defined in {seen_ids[r.id].name})")
                else:
                    seen_ids[r.id] = yaml_path

                # 2. Duplicate Name check
                if r.metadata.name in seen_names:
                    warnings.append(f"Duplicate Rule Name '{r.metadata.name}' in {yaml_path.name}")
                else:
                    seen_names[r.metadata.name] = yaml_path

                # 3. CWE Check
                if r.metadata.cwe and not VALID_CWES.match(r.metadata.cwe):
                    errors.append(f"Rule '{r.id}': Invalid CWE format '{r.metadata.cwe}' (expected e.g. CWE-78)")

                # 4. OWASP Check
                if r.metadata.owasp and not VALID_OWASP.match(r.metadata.owasp):
                    errors.append(f"Rule '{r.id}': Invalid OWASP format '{r.metadata.owasp}' (expected e.g. A03:2021-Injection)")

                # 5. Regex Pattern Compilation
                if r.condition and r.condition.pattern:
                    try:
                        re.compile(r.condition.pattern)
                    except re.error as ex:
                        errors.append(f"Rule '{r.id}': Regex compilation failed: {ex}")

                # 6. Missing Remediation
                if not r.output.remediation or r.output.remediation == "N/A":
                    warnings.append(f"Rule '{r.id}': Missing explicit remediation text")

                # 7. Missing References
                if not r.metadata.references:
                    warnings.append(f"Rule '{r.id}': Missing external reference links")

        except Exception as ex:
            errors.append(f"YAML parsing error in {yaml_path}: {ex}")

    console.print(Panel("KarsaSec Rule Validation Engine Report", border_style="cyan"))
    console.print(f"Total Rules Scanned: {len(seen_ids)}")
    console.print(f"Errors Found: {len(errors)}")
    console.print(f"Warnings Found: {len(warnings)}")

    if errors:
        console.print("\nValidation Errors:")
        for err in errors:
            console.print(f"  [red]ERROR[/red] {err}")

    if warnings:
        console.print("\nValidation Warnings:")
        for warn in warnings:
            console.print(f"  [yellow]WARN[/yellow] {warn}")

    if errors:
        raise typer.Exit(code=1)
    else:
        console.print("\n[green]All security rules passed validation checks successfully.[/green]")

@rules_app.command("lint")
def lint_rules() -> None:
    """Lint rule YAML files for formatting, deprecated fields, and duplicate triggers."""
    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()
    rules = loader.load_directory(rules_dir)
    lint_issues: list[str] = []

    for r in rules:
        # Check duplicate symbol triggers
        triggers = r.condition.symbol_triggers or []
        if len(triggers) != len(set(triggers)):
            lint_issues.append(f"Rule '{r.id}': Duplicate symbol triggers found: {triggers}")

        # Check empty tags
        if not r.metadata.tags:
            lint_issues.append(f"Rule '{r.id}': Empty metadata tags list")

        # Check description length
        if r.metadata.name and len(r.metadata.name) < 5:
            lint_issues.append(f"Rule '{r.id}': Title '{r.metadata.name}' is too short")

    console.print(Panel("KarsaSec Rule Linter Report", border_style="magenta"))
    console.print(f"Rules Evaluated: {len(rules)}")
    console.print(f"Lint Issues: {len(lint_issues)}")

    for issue in lint_issues:
        console.print(f"  [yellow]LINT[/yellow] {issue}")

    if not lint_issues:
        console.print("[green]No lint issues detected across all YAML rules.[/green]")

@rules_app.command("docs")
def generate_rule_docs(
    output_dir: Path = typer.Option(Path("docs/rules"), "--output-dir", "-o", help="Target output directory for rule markdown files.")
) -> None:
    """Generate Markdown documentation for every rule under docs/rules/."""
    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()
    rules = loader.load_directory(rules_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_count = 0
    for r in rules:
        doc_filename = output_dir / f"{r.id}.md"
        doc_content = f"""# {r.id}: {r.metadata.name}

## Metadata
- **Severity**: {r.output.severity.value}
- **Confidence**: {r.output.confidence.value}
- **CWE**: {r.metadata.cwe or 'N/A'}
- **OWASP**: {r.metadata.owasp or 'N/A'}
- **Author**: {r.metadata.author or 'KarsaSec Team'}
- **Version**: {r.metadata.version or '1.0'}
- **Target Languages**: {', '.join([str(l) for l in r.target.languages]) if r.target else 'N/A'}
- **Tags**: {', '.join(r.metadata.tags or [])}

## Description
{r.output.message}

## Remediation Strategy
{r.output.remediation}

## External References
"""
        refs = r.metadata.references or []
        if refs:
            for ref in refs:
                doc_content += f"- [{ref}]({ref})\n"
        else:
            doc_content += "- N/A\n"

        doc_filename.write_text(doc_content, encoding="utf-8")
        generated_count += 1

    console.print(f"[green]Successfully generated {generated_count} rule documentation pages in {output_dir.resolve()}[/green]")

@rules_app.command("coverage")
def rule_coverage() -> None:
    """Display category-level rule coverage visual bar breakdown across target languages."""
    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()
    rules = loader.load_directory(rules_dir)

    lang_category_map: dict[str, dict[str, int]] = {}

    for r in rules:
        langs = [getattr(x, "value", str(x)) for x in r.target.languages] if r.target else ["Generic"]
        tags = r.metadata.tags or ["general"]
        cat = tags[0] if tags else "general"

        for l in langs:
            if l not in lang_category_map:
                lang_category_map[l] = {}
            lang_category_map[l][cat] = lang_category_map[l].get(cat, 0) + 1

    console.print(Panel("KarsaSec Rule Coverage Matrix", border_style="blue"))

    for lang in sorted(lang_category_map.keys()):
        console.print(f"\n[bold green]Language: {lang}[/bold green]")
        cats = lang_category_map[lang]
        max_count = max(cats.values()) if cats else 1

        for cat_name, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
            bar_len = int((count / max_count) * 25)
            bar = "#" * max(bar_len, 1)
            console.print(f"  {cat_name:<18} [{bar:<25}] {count} rules")

    console.print(f"\nTotal Rules Across Repository: {len(rules)}")

@rules_app.command("profile")
def profile_rules(
    top: int = typer.Option(10, "--top", "-t", help="Number of slowest rules to display.")
) -> None:
    """Profile latency and evaluation performance across all loaded rules."""
    from karsasec.quality.profiler import RuleProfiler

    profiler = RuleProfiler()
    results = profiler.profile_execution()

    table = Table(title="KarsaSec Rule Performance Profile", show_header=True, header_style="bold yellow")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Rule Name", style="bold")
    table.add_column("Severity", style="magenta")
    table.add_column("Elapsed Time (ms)", style="green")

    for item in results[:top]:
        table.add_row(item["id"], item["name"], str(item["severity"]), str(item["elapsed_ms"]))

    console.print(table)
    console.print(f"Total Rules Profiling Evaluated: {len(results)}")

@rules_app.command("conflicts")
def detect_rule_conflicts() -> None:
    """Detect pattern overlaps and duplicate names across all YAML rules."""
    from karsasec.quality.conflicts import ConflictDetector

    detector = ConflictDetector()
    report = detector.detect_conflicts()

    console.print(Panel("KarsaSec Rule Conflict & Overlap Report", border_style="red"))
    duplicates = report["duplicate_names"]
    overlaps = report["pattern_overlaps"]

    console.print(f"Duplicate Names: {len(duplicates)}")
    for d in duplicates:
        console.print(f"  [yellow]DUP NAME[/yellow] '{d['name']}': {d['rule_a']} <-> {d['rule_b']}")

    console.print(f"Pattern Overlaps: {len(overlaps)}")
    for o in overlaps:
        console.print(f"  [yellow]OVERLAP[/yellow] Pattern '{o['pattern']}': {o['rule_a']} <-> {o['rule_b']}")

    if not duplicates and not overlaps:
        console.print("[green]No rule conflicts or pattern overlaps detected.[/green]")

@rules_app.command("dead-code")
def detect_dead_code() -> None:
    """Detect unused, incomplete, or dead rules across the repository."""
    from karsasec.quality.dead_code import DeadCodeDetector

    detector = DeadCodeDetector()
    issues = detector.detect_dead_rules()

    console.print(Panel("KarsaSec Rule Dead Code Report", border_style="magenta"))
    console.print(f"Dead/Incomplete Rules Identified: {len(issues)}")

    for item in issues:
        console.print(f"  [red]DEAD RULE[/red] {item['id']} ({item['name']}): {', '.join(item['issues'])}")

    if not issues:
        console.print("[green]No dead or incomplete rules found across the repository.[/green]")

