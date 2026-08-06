"""Constant and Copy Propagation Solver."""

from __future__ import annotations

import ast
from typing import Any

from karsasec.analysis.dataflow.lattice import LatticeElement
from karsasec.analysis.ssa.models import SSAFunction


class ConstantPropagation:
    """Evaluates literal expressions and propagates constant values along SSA variables."""

    def propagate(self, ssa_func: SSAFunction) -> dict[str, Any]:
        """Returns map of ssa_variable_name -> constant_value."""
        env: dict[str, LatticeElement] = {}

        for node in ssa_func.nodes:
            if not node.target:
                continue

            var_name = node.target.ssa_name
            label = node.label

            # Extract expression after =
            if "=" in label:
                expr_str = label.split("=", 1)[1].strip()
                try:
                    # Evaluate simple numeric/string literal constants safely
                    lit_val = ast.literal_eval(expr_str)
                    env[var_name] = LatticeElement.constant(lit_val)
                except Exception:
                    # Check if it's a simple variable copy x = y
                    if expr_str in env and env[expr_str].is_constant():
                        env[var_name] = env[expr_str]
                    else:
                        env[var_name] = LatticeElement.bottom()

        # Filter out constants
        return {var: elem.value for var, elem in env.items() if elem.is_constant()}
