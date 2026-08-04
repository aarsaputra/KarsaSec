"""Abstract Reporter base class using streamable ReportTarget."""

from abc import ABC, abstractmethod
from karsasec.core.execution.result import ExecutionResult
from karsasec.core.reporting.target import ReportTarget

class Reporter(ABC):
    """Abstract base class for streaming report generators."""

    @abstractmethod
    def generate(self, result: ExecutionResult, target: ReportTarget) -> None:
        """Generates report and streams output chunks to ReportTarget."""
        pass
