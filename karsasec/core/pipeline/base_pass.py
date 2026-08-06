"""Abstract Base Class for Compiler Analysis Passes in KarsaSec Pipeline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from karsasec.core.pipeline.context import PassContext


class AnalysisPass(ABC):
    """Abstract base class representing a single deterministic analysis pass in the compiler pipeline."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the unique name identifier of the analysis pass."""
        pass

    @property
    @abstractmethod
    def requires(self) -> list[str]:
        """Returns list of artifact names required by this pass prior to execution."""
        pass

    @property
    @abstractmethod
    def produces(self) -> list[str]:
        """Returns list of artifact names generated and produced by this pass."""
        pass

    @abstractmethod
    def run(self, context: PassContext) -> Any:
        """Executes the analysis pass using the provided PassContext."""
        pass
