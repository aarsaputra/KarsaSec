"""Analysis Pass Manager defining modular input/output pass contracts, failure isolation, and performance telemetry."""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from karsasec.rules.enums import AnalysisCapability
from karsasec.runtime.artifact_store import ArtifactStore

logger = logging.getLogger("karsasec.runtime.pass_manager")


@dataclass(frozen=True)
class PassDescriptor:
    """Metadata describing inputs, outputs, budget constraints, and capability dependencies for an AnalysisPass."""

    name: str
    inputs: list[str]
    outputs: list[str]
    required_capabilities: list[AnalysisCapability] = field(default_factory=list)
    time_budget_ms: float = 1000.0
    memory_budget_mb: float = 100.0


@dataclass(frozen=True)
class PassTelemetry:
    """Execution telemetry recorded for each pass execution."""

    pass_name: str
    success: bool
    elapsed_ms: float
    error_message: str | None = None


class AnalysisPass(ABC):
    """Abstract base class for all compiler analysis passes (ParserPass, HIRPass, MIRPass, LIRPass, etc.)."""

    def __init__(self, descriptor: PassDescriptor) -> None:
        self.descriptor = descriptor

    @abstractmethod
    def run(self, store: ArtifactStore) -> bool:
        """Executes the pass, reading input artifacts from store and writing output artifacts."""
        pass


class PassManager:
    """Manages pass registration, dependency resolution, failure isolation, and execution telemetry."""

    def __init__(self) -> None:
        self._passes: dict[str, AnalysisPass] = {}
        self._execution_order: list[str] = []
        self._telemetry: list[PassTelemetry] = []

    def register_pass(self, pass_instance: AnalysisPass) -> None:
        self._passes[pass_instance.descriptor.name] = pass_instance
        if pass_instance.descriptor.name not in self._execution_order:
            self._execution_order.append(pass_instance.descriptor.name)

    def run_passes(self, store: ArtifactStore) -> dict[str, bool]:
        """Executes registered passes sequentially with strict failure isolation."""
        results: dict[str, bool] = {}
        self._telemetry.clear()

        for pass_name in self._execution_order:
            p = self._passes[pass_name]
            start = time.perf_counter()
            try:
                success = p.run(store)
                elapsed = (time.perf_counter() - start) * 1000.0
                results[pass_name] = success
                self._telemetry.append(
                    PassTelemetry(pass_name=pass_name, success=success, elapsed_ms=elapsed)
                )
            except Exception as err:
                elapsed = (time.perf_counter() - start) * 1000.0
                logger.error(f"Pass '{pass_name}' failed with exception: {err}. Isolating failure.")
                results[pass_name] = False
                self._telemetry.append(
                    PassTelemetry(
                        pass_name=pass_name,
                        success=False,
                        elapsed_ms=elapsed,
                        error_message=str(err),
                    )
                )

        return results

    def get_telemetry(self) -> list[PassTelemetry]:
        return list(self._telemetry)


pass_manager = PassManager()
