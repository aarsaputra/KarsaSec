"""Modular scan CLI command connecting RuleExecutor, BaselineManager, and Reporting targets."""

import concurrent.futures
import os
import sys
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from rich.panel import Panel

from karsasec.config import get_scan_exclusions, load_project_config
from karsasec.core.baseline import baseline_manager
from karsasec.core.container import container
from karsasec.core.execution import RuleExecutor, ScanContext, rule_executor
from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.model import Finding
from karsasec.core.reporting import (
    ConsoleReporter,
    FileTarget,
    JSONReporter,
    ReportTarget,
    SARIFReporter,
    StreamTarget,
)
from karsasec.parser.docker_parser import docker_parser_plugin  # ensure Dockerfile parser plugin registers
from karsasec.parser.generic_parser import GenericParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.parser.target_detector import TargetDetector
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory
from karsasec.utils.logging import console

IGNORE_DIRS = {".git", ".hg", ".svn", ".venv", "venv", ".pytest_cache", "__pycache__", "build", "dist", ".gemini", "node_modules", "vendor"}
ALLOWED_HIDDEN_DIRS = {".github", ".vscode", ".devcontainer"}
DEFAULT_IGNORED_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock"}

SUPPORTED_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".php", ".inc", ".phtml", ".go", ".rs", ".java", ".yaml", ".yml", ".json", ".dockerfile", ".tf", ".tfvars"
}
SUPPORTED_FILENAMES = {"dockerfile", "containerfile"}


def normalize_scan_path(path: Path) -> Path:
    """Return a normalized path that is safe to traverse across platforms."""
    return Path(os.path.normpath(str(path))).expanduser()


def _load_gitignore_patterns(root: Path) -> List[Tuple[str, bool]]:
    """Load simple .gitignore-style patterns from the project root."""
    patterns: List[Tuple[str, bool]] = []
    if not root.exists():
        return patterns

    for gitignore in sorted(root.rglob(".gitignore")):
        if not gitignore.is_file():
            continue
        try:
            for raw_line in gitignore.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                is_negation = line.startswith("!")
                if is_negation:
                    line = line[1:]
                patterns.append((line.rstrip("/"), is_negation))
        except OSError:
            continue
    return patterns


def _matches_gitignore_pattern(path: Path, root: Path, patterns: List[Tuple[str, bool]]) -> bool:
    """Match a path against a lightweight subset of .gitignore semantics."""
    res_path = path.resolve()
    res_root = root.resolve()
    try:
        relative_path = res_path.relative_to(res_root).as_posix()
    except ValueError:
        relative_path = res_path.as_posix()

    if not relative_path or relative_path == ".":
        return False

    normalized_parts = [part for part in relative_path.split("/") if part]
    basename = normalized_parts[-1] if normalized_parts else ""
    for pattern, is_negation in patterns:
        if not pattern:
            continue
        if pattern.endswith("/"):
            pattern = pattern.rstrip("/")
        if "/" in pattern:
            match_value = relative_path
            if pattern.startswith("**/"):
                pattern = pattern[3:]
            if fnmatch(relative_path, pattern):
                return not is_negation
        else:
            if fnmatch(basename, pattern) or any(fnmatch(part, pattern) for part in normalized_parts):
                return not is_negation
    return False


def should_skip_path(
    path: Path,
    root: Path,
    gitignore_patterns: List[Tuple[str, bool]],
    exclude_patterns: Optional[Set[str]] = None,
) -> bool:
    """Return True when a path should not be scanned."""
    res_path = path.resolve()
    res_root = root.resolve()
    normalized_path = res_path
    normalized_root = res_root

    try:
        rel_parts = res_path.relative_to(res_root).parts
    except ValueError:
        rel_parts = res_path.parts

    for part in rel_parts:
        if part in IGNORE_DIRS:
            return True
        if part.startswith(".") and part not in ALLOWED_HIDDEN_DIRS and part != ".gitignore":
            return True

    if normalized_path.name.lower() in DEFAULT_IGNORED_FILES or normalized_path.name.lower() in {"karsasec.yaml", "karsasec.yml"}:
        return True

    if normalized_path.suffix.lower() == ".pyc":
        return True

    if normalized_path.name.lower().endswith(".generated.py"):
        return True

    if exclude_patterns:
        for pattern in exclude_patterns:
            pattern_text = pattern.strip()
            if not pattern_text:
                continue
            if pattern_text in rel_parts:
                return True
            if fnmatch(normalized_path.name, pattern_text):
                return True
            if "/" in pattern_text and fnmatch(res_path.as_posix(), pattern_text):
                return True

    return _matches_gitignore_pattern(res_path, res_root, gitignore_patterns)


def is_scannable_file(path: Path) -> bool:
    """Returns True if file path matches supported source/config extensions and is not ignored."""
    name_lower = path.name.lower()
    if name_lower in SUPPORTED_FILENAMES or name_lower.startswith("dockerfile."):
        return True
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def iter_candidate_files(root: Path, exclude_patterns: Optional[Set[str]] = None) -> List[Path]:
    """Collect candidate files while respecting ignore rules and common production exclusions."""
    normalized_root = normalize_scan_path(root)
    gitignore_patterns = _load_gitignore_patterns(normalized_root)
    files: List[Path] = []
    effective_excludes = exclude_patterns or set()

    if not normalized_root.exists():
        return files

    for dirpath, dirnames, filenames in os.walk(normalized_root, topdown=True, followlinks=False):
        current_dir = Path(dirpath)
        filtered_dirnames: List[str] = []
        for dirname in dirnames:
            child_path = current_dir / dirname
            if should_skip_path(child_path, normalized_root, gitignore_patterns, effective_excludes):
                continue
            filtered_dirnames.append(dirname)
        dirnames[:] = filtered_dirnames

        for filename in filenames:
            candidate = current_dir / filename
            if should_skip_path(candidate, normalized_root, gitignore_patterns, effective_excludes):
                continue
            if is_scannable_file(candidate):
                files.append(candidate)

    return sorted(files)

def scan_file_task(
    file_path: Path,
    target_detector: TargetDetector,
    exec_engine: RuleExecutor,
    rules: Any,
    rag_context: List[Dict[str, Any]],
) -> Tuple[List[Finding], int, float, List[str]]:
    """Isolated task scanner for a single file path suitable for parallel worker pools."""
    findings: List[Finding] = []
    nodes_processed = 0
    exec_time_ms = 0.0
    errors: List[str] = []

    try:
        source_bytes = file_path.read_bytes()
        source_text = source_bytes.decode("utf-8", errors="ignore")

        detection = target_detector.detect(file_path, source_text)
        detected_lang = detection.target_format.value

        parser = parser_registry.get_parser_for_file(file_path) or parser_registry.get_parser_by_language(detected_lang)
        if not parser:
            parser = GenericParserPlugin(detected_lang, [file_path.suffix or file_path.name])

        parse_res = parser.parse_file(file_path)

        if parse_res.root:
            scan_ctx = ScanContext(
                file_node=parse_res.root,
                source_bytes=source_bytes,
                file_path=file_path,
                symbol_table=parse_res.symbol_table,
                language=detected_lang,
                rag_context=tuple(rag_context),
            )
            res = exec_engine.execute_scan(scan_ctx, rules)
            findings.extend(res.findings)
            nodes_processed += res.nodes_processed
            exec_time_ms += res.execution_time_ms
            errors.extend(res.errors)

    except Exception as err:
        errors.append(f"Failed to scan {file_path}: {str(err)}")

    return findings, nodes_processed, exec_time_ms, errors


def execute_scan_command(
    target_path: Path,
    format_type: str = "console",
    output_path: Optional[Path] = None,
    baseline_path: Optional[Path] = None,
    use_rag: bool = False,
    rag_query: Optional[str] = None,
    rag_rebuild: bool = False,
    no_color: bool = False,
    rag_corpus: Optional[Path] = None,
    executor: Optional[RuleExecutor] = None,
) -> int:
    """Executes deterministic security scan on target_path across multi-language source & IaC files.

    Returns:
        int: Semantic exit code (0 = clean, 1 = findings detected, 2 = execution error, 3 = rule load error).
    """
    exec_engine = executor or rule_executor
    resolved_path = target_path.resolve()
    rag_service: Optional["RAGService"] = None
    rag_context: List[Dict[str, Any]] = []

    if not resolved_path.exists():
        sys.stderr.write(f"Error: Target path '{resolved_path}' does not exist.\n")
        return 3

    # Load rules from default rules directory
    rules_dir = get_default_rules_directory()
    loader = YAMLRuleLoader()

    try:
        rules = loader.load_directory(rules_dir)
    except Exception as err:
        sys.stderr.write(f"Rule Loading Error: {str(err)}\n")
        return 3

    if use_rag:
        from karsasec.rag.service import RAGService

        repository_root = Path(__file__).resolve().parents[3]
        corpus_path = rag_corpus or repository_root / "security_corpus"
        try:
            container.register_rag_service(corpus_path, force_rebuild=rag_rebuild)
            rag_service = container.resolve(RAGService)
        except Exception as err:
            console.print(f"[yellow]Warning:[/yellow] failed to initialize RAG corpus: {err}")
            rag_service = None

    # Read target file or directory
    project_config = load_project_config(search_root=resolved_path)
    exclude_patterns = {pattern for pattern in get_scan_exclusions(project_config)}

    if resolved_path.is_file():
        files_to_scan = [resolved_path] if not should_skip_path(resolved_path, resolved_path.parent, [], exclude_patterns) else []
    else:
        files_to_scan = iter_candidate_files(resolved_path, exclude_patterns)

    files_to_scan = files_to_scan or []

    if use_rag and rag_service:
        query_text = rag_query or ""
        if not query_text and resolved_path.is_file():
            try:
                query_text = resolved_path.read_text(encoding="utf-8", errors="ignore").strip()[:512]
            except Exception:
                query_text = resolved_path.name
        elif not query_text:
            query_text = resolved_path.name

        if query_text:
            rag_results = rag_service.retrieve(query_text, top_k=5)
            if rag_results:
                rag_context = [
                    {
                        "document_id": result.document_id,
                        "score": result.score,
                        "source_path": result.metadata.get("source_path"),
                        "text": result.text,
                    }
                    for result in rag_results
                ]
                if format_type == "console":
                    console.print(Panel(f"[bold green]RAG context retrieval[/bold green]\nQuery: [cyan]{query_text[:120]}[/cyan]", border_style="green"))
                    for result in rag_results:
                        console.print(
                            f"[yellow]{result.metadata.get('source_path')}[/yellow] (score={result.score:.4f})\n{result.text[:240]}...\n"
                        )

    all_findings = []
    total_nodes = 0
    total_files = len(files_to_scan)
    total_time_ms = 0.0
    scan_errors = []

    target_detector = TargetDetector()
    scan_started = time.perf_counter()

    scan_progress: Optional[Progress] = None
    if format_type.lower() == "console" and files_to_scan:
        scan_progress = Progress(
            TextColumn("[bold blue]Scanning[/bold blue]"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        scan_progress.start()
        task_id = scan_progress.add_task("files", total=len(files_to_scan))

    max_workers = min(32, max(1, (os.cpu_count() or 4) * 2)) if total_files > 1 else 1

    if max_workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_file = {
                pool.submit(scan_file_task, f, target_detector, exec_engine, rules, rag_context): f
                for f in files_to_scan
            }
            for future in concurrent.futures.as_completed(future_to_file):
                f_path = future_to_file[future]
                try:
                    if scan_progress is not None:
                        scan_progress.update(task_id, description=f_path.name)
                    res_findings, res_nodes, res_time, res_errs = future.result()
                    all_findings.extend(res_findings)
                    total_nodes += res_nodes
                    total_time_ms += res_time
                    scan_errors.extend(res_errs)
                except Exception as err:
                    scan_errors.append(f"Failed to scan {f_path}: {str(err)}")
                finally:
                    if scan_progress is not None:
                        scan_progress.advance(task_id)
    else:
        for file_path in files_to_scan:
            try:
                if scan_progress is not None:
                    scan_progress.update(task_id, description=file_path.name)
                res_findings, res_nodes, res_time, res_errs = scan_file_task(
                    file_path, target_detector, exec_engine, rules, rag_context
                )
                all_findings.extend(res_findings)
                total_nodes += res_nodes
                total_time_ms += res_time
                scan_errors.extend(res_errs)
            except Exception as err:
                scan_errors.append(f"Failed to scan {file_path}: {str(err)}")
            finally:
                if scan_progress is not None:
                    scan_progress.advance(task_id)

    if scan_progress is not None:
        scan_progress.stop()

    scan_duration_ms = round((time.perf_counter() - scan_started) * 1000, 2)

    # Handle Baseline Comparison if requested
    findings_tuple = tuple(all_findings)
    if baseline_path and baseline_path.exists():
        try:
            baseline = baseline_manager.load_baseline(baseline_path)
            comparison = baseline_manager.compare(findings_tuple, baseline)
            findings_tuple = comparison.new_findings
        except Exception as err:
            sys.stderr.write(f"Baseline Error: {str(err)}\n")
            return 3

    combined_res = ExecutionResult(
        scan_id=f"scan-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        files_scanned=total_files,
        rules_checked=len(rules),
        nodes_processed=total_nodes,
        findings=findings_tuple,
        execution_time_ms=total_time_ms,
        errors=tuple(scan_errors),
        rag_context=tuple(rag_context),
    )

    # Determine Target
    target: ReportTarget
    if output_path:
        target = FileTarget(output_path)
    else:
        target = StreamTarget(sys.stdout)

    # Determine Reporter
    fmt = format_type.lower()
    if fmt == "json":
        reporter = JSONReporter()
    elif fmt == "sarif":
        reporter = SARIFReporter()
    else:
        reporter = ConsoleReporter(no_color=no_color)

    reporter.generate(combined_res, target)

    if format_type.lower() == "console":
        console.print(
            Panel(
                f"Files scanned: [bold cyan]{len(files_to_scan)}[/bold cyan]\n"
                f"Findings: [bold red]{len(findings_tuple)}[/bold red]\n"
                f"Errors: [bold yellow]{len(scan_errors)}[/bold yellow]\n"
                f"Duration: [bold green]{scan_duration_ms:.2f} ms[/bold green]",
                title="Scan Summary",
                border_style="green",
            )
        )

    if scan_errors:
        return 2

    return 1 if len(findings_tuple) > 0 else 0
