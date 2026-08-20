"""PassManager module for orchestrating dependency resolution and execution of analysis passes."""

from __future__ import annotations

from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext


class PassDependencyError(Exception):
    """Raised when pass dependencies cannot be resolved or missing required artifacts."""

    pass


class PassManager:
    """Orchestrates pass registration, topological dependency ordering, and execution."""

    def __init__(self) -> None:
        self._passes: list[AnalysisPass] = []
        self._pass_map: dict[str, AnalysisPass] = {}

    def register_pass(self, analysis_pass: AnalysisPass) -> None:
        """Registers an AnalysisPass instance into the manager."""
        if analysis_pass.name in self._pass_map:
            return
        self._passes.append(analysis_pass)
        self._pass_map[analysis_pass.name] = analysis_pass

    def run_passes(self, context: PassContext) -> PassContext:
        """Executes all registered passes in topological dependency order."""
        ordered_passes = self._topological_sort()

        for ap in ordered_passes:
            # Check required artifacts exist
            for req in ap.requires:
                if not context.artifact_store.has(req):
                    raise PassDependencyError(
                        f"Pass '{ap.name}' requires artifact '{req}', which is missing from ArtifactStore."
                    )

            output = ap.run(context)
            if ap.produces:
                for prod in ap.produces:
                    context.artifact_store.store(prod, output)

        return context

    def _topological_sort(self) -> list[AnalysisPass]:
        """Resolves pass execution order based on artifact requirements and productions."""
        resolved: list[AnalysisPass] = []
        available_artifacts: set[str] = set()

        unresolved = list(self._passes)
        max_attempts = len(unresolved) * 2

        for _ in range(max_attempts):
            if not unresolved:
                break
            progress = False
            for ap in list(unresolved):
                if all(req in available_artifacts for req in ap.requires):
                    resolved.append(ap)
                    for prod in ap.produces:
                        available_artifacts.add(prod)
                    unresolved.remove(ap)
                    progress = True
                    break
            if not progress and unresolved:
                # If dependencies remain unresolved, append remaining passes
                resolved.extend(unresolved)
                break

        return resolved
