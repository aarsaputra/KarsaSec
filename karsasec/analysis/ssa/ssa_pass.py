"""SSAPass compiler pipeline pass converting CFGs to SSA form."""

from __future__ import annotations

from typing import Any

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.ssa.builder import SSABuilder
from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext


class SSAPass(AnalysisPass):
    """Compiler pipeline pass executing SSA transformation on CFGs."""

    def __init__(self) -> None:
        self.builder = SSABuilder()

    @property
    def name(self) -> str:
        return "SSAPass"

    @property
    def requires(self) -> list[str]:
        return ["CFG"]

    @property
    def produces(self) -> list[str]:
        return ["SSA"]

    def run(self, context: PassContext) -> dict[str, Any]:
        cfgs = context.artifact_store.get("CFG")
        if not cfgs or not isinstance(cfgs, dict):
            return {}

        ssa_map = {}
        for fn_name, cfg in cfgs.items():
            if isinstance(cfg, CFG):
                ssa_map[fn_name] = self.builder.build_ssa(cfg)

        return ssa_map
