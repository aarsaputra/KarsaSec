"""Modular scan CLI command connecting RuleExecutor, BaselineManager, and Reporting targets."""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from karsasec.core.baseline import baseline_manager
from karsasec.core.execution import RuleExecutor, ScanContext, rule_executor
from karsasec.core.execution.result import ExecutionResult
from karsasec.core.reporting import (
    ConsoleReporter,
    FileTarget,
    JSONReporter,
    ReportTarget,
    SARIFReporter,
    StreamTarget,
)
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory

IGNORE_DIRS = {".git", ".venv", "venv", ".pytest_cache", "__pycache__", "build", "dist", ".gemini"}

def execute_scan_command(
    target_path: Path,
    format_type: str = "console",
    output_path: Optional[Path] = None,
    baseline_path: Optional[Path] = None,
    no_color: bool = False,
    executor: Optional[RuleExecutor] = None,
) -> int:
    """Executes deterministic security scan on target_path.

    Returns:
        int: Semantic exit code (0 = clean, 1 = findings detected, 2 = execution error, 3 = rule load error).
    """
    exec_engine = executor or rule_executor
    resolved_path = target_path.resolve()

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

    # Read target file or directory
    if resolved_path.is_file():
        files_to_scan = [resolved_path]
    else:
        files_to_scan = [
            p
            for p in resolved_path.glob("**/*.py")
            if not any(part in IGNORE_DIRS or part.startswith(".") for part in p.parts)
        ]

    all_findings = []
    total_nodes = 0
    total_files = len(files_to_scan)
    total_time_ms = 0.0
    scan_errors = []

    parser_plugin = PythonParserPlugin()

    for file_path in files_to_scan:
        try:
            source_bytes = file_path.read_bytes()
            parse_res = parser_plugin.parse_file(file_path)

            if parse_res.root:
                scan_ctx = ScanContext(
                    file_node=parse_res.root,
                    source_bytes=source_bytes,
                    file_path=file_path,
                    symbol_table=parse_res.symbol_table,
                    language="python",
                )
                res = exec_engine.execute_scan(scan_ctx, rules)
                all_findings.extend(res.findings)
                total_nodes += res.nodes_processed
                total_time_ms += res.execution_time_ms
                scan_errors.extend(res.errors)

        except Exception as err:
            scan_errors.append(f"Failed to scan {file_path}: {str(err)}")

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

    if scan_errors:
        return 2

    return 1 if len(findings_tuple) > 0 else 0
