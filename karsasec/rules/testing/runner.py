"""Rule Testing Framework for verifying security rules against vulnerable, safe, and regression corpus files."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from karsasec.core.execution import RuleExecutor, ScanContext, rule_executor
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import parser_registry
from karsasec.parser.generic_parser import GenericParserPlugin
from karsasec.rules.schema import Rule

@dataclass
class RuleTestCase:
    """TestCase DTO specifying rule validation files and expectations."""
    rule_id: str
    vulnerable_files: List[Path] = field(default_factory=list)
    safe_files: List[Path] = field(default_factory=list)
    regression_files: List[Path] = field(default_factory=list)
    min_expected_findings: int = 1

@dataclass
class RuleTestReport:
    """Report DTO summarizing rule verification test results."""
    rule_id: str
    passed: bool
    vulnerable_passed: bool
    safe_passed: bool
    regression_passed: bool
    vulnerable_findings_count: int
    safe_findings_count: int
    details: List[str] = field(default_factory=list)

class RuleTestRunner:
    """Reusable runner executing a Rule against security corpus files.

    Designed for reuse by automated pytest suites and future 'karsasec rule test' CLI commands.
    """

    def __init__(self, executor: Optional[RuleExecutor] = None) -> None:
        self.executor = executor or rule_executor
        self.default_python_parser = PythonParserPlugin()

    def run_case(self, rule: Rule, test_case: RuleTestCase) -> RuleTestReport:
        """Executes a RuleTestCase against vulnerable, safe, and regression files."""
        details: List[str] = []

        # 1. Test Vulnerable Files (Positive Control)
        vuln_findings = self._scan_files(rule, test_case.vulnerable_files)
        vulnerable_passed = len(vuln_findings) >= test_case.min_expected_findings
        if not vulnerable_passed:
            details.append(
                f"Vulnerable Test Failed: Expected >= {test_case.min_expected_findings} findings, got {len(vuln_findings)}"
            )

        # 2. Test Safe Files (Negative Control - Zero False Positives)
        safe_findings = self._scan_files(rule, test_case.safe_files)
        safe_passed = len(safe_findings) == 0
        if not safe_passed:
            details.append(f"Safe Test Failed (False Positive Detected): Got {len(safe_findings)} unexpected findings")

        # 3. Test Regression Files
        reg_findings = self._scan_files(rule, test_case.regression_files)
        regression_passed = True
        if test_case.regression_files and len(reg_findings) == 0:
            regression_passed = False
            details.append("Regression Test Failed: 0 findings detected in regression suite")

        overall_passed = vulnerable_passed and safe_passed and regression_passed

        return RuleTestReport(
            rule_id=rule.id,
            passed=overall_passed,
            vulnerable_passed=vulnerable_passed,
            safe_passed=safe_passed,
            regression_passed=regression_passed,
            vulnerable_findings_count=len(vuln_findings),
            safe_findings_count=len(safe_findings),
            details=details,
        )

    def _scan_files(self, rule: Rule, files: List[Path]) -> List[Any]:
        findings = []
        for file_path in files:
            if not file_path.exists():
                continue
            source_bytes = file_path.read_bytes()

            parser = parser_registry.get_parser_for_file(file_path) or parser_registry.get_parser_by_language(
                rule.match.language.value
            )
            if not parser:
                parser = GenericParserPlugin(rule.match.language.value)

            parse_res = parser.parse_file(file_path)
            if parse_res.root:
                scan_ctx = ScanContext(
                    file_node=parse_res.root,
                    source_bytes=source_bytes,
                    file_path=file_path,
                    symbol_table=parse_res.symbol_table,
                    language=rule.match.language.value,
                )
                res = self.executor.execute_scan(scan_ctx, [rule])
                findings.extend(res.findings)
        return findings
