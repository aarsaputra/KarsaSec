"""Execution subpackage exporting ScanContext, RuleIndexer, ExecutionResult, and RuleExecutor."""

from karsasec.core.execution.context import ScanContext
from karsasec.core.execution.errors import EvidenceUnavailableError, ExecutionError, RuleError
from karsasec.core.execution.executor import RuleExecutor, rule_executor
from karsasec.core.execution.indexer import RuleIndexer
from karsasec.core.execution.result import ExecutionResult

__all__ = [
    "ScanContext",
    "RuleIndexer",
    "ExecutionResult",
    "RuleExecutor",
    "rule_executor",
    "ExecutionError",
    "RuleError",
    "EvidenceUnavailableError",
]
