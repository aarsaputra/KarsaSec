"""CFGPass compiler pipeline pass for generating and validating CFGs."""

from __future__ import annotations

from typing import Any

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.cfg.validator import CFGValidator
from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext


class CFGPass(AnalysisPass):
    """Compiler pipeline pass that converts UniversalIR into validated CFGs."""

    def __init__(self) -> None:
        self.builder = CFGBuilder()
        self.validator = CFGValidator()

    @property
    def name(self) -> str:
        return "CFGPass"

    @property
    def requires(self) -> list[str]:
        return ["UniversalIR"]

    @property
    def produces(self) -> list[str]:
        return ["CFG"]

    def run(self, context: PassContext) -> dict[str, Any]:
        ir_functions = context.artifact_store.get("UniversalIR")
        if not ir_functions or not isinstance(ir_functions, list):
            return {}

        cfgs = self.builder.build_cfg_for_functions(ir_functions)
        for cfg in cfgs.values():
            self.validator.validate(cfg)

        return cfgs
