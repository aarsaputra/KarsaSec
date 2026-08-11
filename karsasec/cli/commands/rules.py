from __future__ import annotations

import re
from pathlib import Path

import typer
import yaml
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
            content = yaml_path.read_text(encoding="utf-8")
            raw_doc = yaml.safe_load(content)

            # Check if this is a Graph Security Rule (E10-3D schema)
            if isinstance(raw_doc, dict) and isinstance(raw_doc.get("target"), dict) and "node_type" in raw_doc["target"]:
                from karsasec.framework.framework_semantics.rules.loader import GraphRuleLoader
                g_loader = GraphRuleLoader()
                gr = g_loader.load_file(yaml_path)

                # 1. Duplicate ID check
                if gr.id in seen_ids:
                    errors.append(f"Duplicate Rule ID '{gr.id}' in {yaml_path.name} (already defined in {seen_ids[gr.id].name})")
                else:
                    seen_ids[gr.id] = yaml_path

                # 2. Duplicate Name check
                gr_name = str(gr.metadata.get("name", gr.id))
                if gr_name in seen_names:
                    warnings.append(f"Duplicate Rule Name '{gr_name}' in {yaml_path.name}")
                else:
                    seen_names[gr_name] = yaml_path

                # 3. CWE Check
                cwe_val = str(gr.metadata.get("cwe", ""))
                if cwe_val and not VALID_CWES.match(cwe_val):
                    errors.append(f"Rule '{gr.id}': Invalid CWE format '{cwe_val}' (expected e.g. CWE-78)")

                # 4. OWASP Check
                owasp_val = str(gr.metadata.get("owasp", ""))
                if owasp_val and not VALID_OWASP.match(owasp_val):
                    errors.append(f"Rule '{gr.id}': Invalid OWASP format '{owasp_val}' (expected e.g. A03:2021-Injection)")

                # 5. Missing Remediation
                if not gr.output.remediation or gr.output.remediation == "N/A":
                    warnings.append(f"Rule '{gr.id}': Missing explicit remediation text")

                # 6. Missing References
                if not gr.metadata.get("references"):
                    warnings.append(f"Rule '{gr.id}': Missing external reference links")

                continue

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

@rules_app.command("contract")
def validate_contracts(
    rule_id: str | None = typer.Option(None, "--rule", "-r", help="Validate a specific rule ID only."),
    coverage: bool = typer.Option(False, "--coverage", help="Show Rule Contract Coverage metric only."),
) -> None:
    """Validate rule fixture contracts (E10-3J quality gate).

    Runs positive/negative fixtures through ASTMatcher.
    Positive fixtures MUST match. Negative fixtures MUST NOT match.
    """
    from karsasec.rules.contract_validator import RuleContractValidator
    from karsasec.rules.matcher.matcher import ASTMatcher

    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()
    all_rules = loader.load_directory(rules_dir)

    if rule_id:
        all_rules = [r for r in all_rules if r.id == rule_id]
        if not all_rules:
            console.print(f"[red]No rule found with ID \'{rule_id}\'[/red]")
            raise typer.Exit(code=1)

    validator = RuleContractValidator()
    matcher = ASTMatcher()
    suite = validator.validate_all(all_rules, matcher)

    total = len(suite.results)
    with_contract = suite.rules_with_contract
    all_passing = suite.rules_all_passing

    status_color = "green" if all_passing == with_contract else "red"
    console.print(Panel(
        f"[bold cyan]KarsaSec Rule Contract Validation[/bold cyan]\n"
        f"Rules Evaluated    : {total}\n"
        f"Rules with Contract: [cyan]{with_contract}[/cyan] / {total} "
        f"([bold]{suite.contract_coverage_pct}%[/bold])\n"
        f"All Fixtures Passing: [{status_color}]{all_passing}[/{status_color}] / {with_contract}",
        border_style="cyan",
        title="Rule Contract Coverage",
    ))

    if coverage:
        raise typer.Exit(code=0)

    total_failures = suite.total_failures
    if total_failures > 0:
        console.print(f"\n[red]Contract Fixture Failures: {total_failures}[/red]\n")
        for res in suite.results:
            if res.failures:
                console.print(f"[bold red]FAIL[/bold red] {res.rule_id} — {len(res.failures)} fixture(s) failed")
                for fail in res.failures:
                    expected = "FINDING" if fail.expected_matched else "NO_FINDING"
                    actual = "FINDING" if fail.actual_matched else "NO_FINDING"
                    console.print(
                        f"  [{fail.fixture_kind.upper()}] Expected={expected} Got={actual}\n"
                        f"  Snippet: [dim]{fail.snippet[:120]}[/dim]"
                    )
        raise typer.Exit(code=1)

    if with_contract == 0:
        console.print("[yellow]No rules carry a contract section yet.[/yellow]")
    else:
        console.print(f"[green]All {with_contract} contract(s) passed {all_passing}/{with_contract} fixture suites.[/green]")

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

