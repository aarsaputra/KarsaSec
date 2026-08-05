"""ExecutionResult model storing scan telemetry, deduplicated findings, errors, and performance metrics."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
from karsasec.core.finding.model import Finding
from karsasec.rules.matcher.statistics import MatcherStatistics

@dataclass(frozen=True)
class ExecutionResult:
    """Immutable result structure containing scan metrics, deduplicated findings, and error telemetry."""
    scan_id: str
    timestamp: str
    files_scanned: int
    rules_checked: int
    nodes_processed: int
    findings: Tuple[Finding, ...] = field(default_factory=tuple)
    execution_time_ms: float = 0.0
    errors: Tuple[str, ...] = field(default_factory=tuple)
    warnings: Tuple[str, ...] = field(default_factory=tuple)
    statistics: Optional[MatcherStatistics] = None
    rag_context: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
