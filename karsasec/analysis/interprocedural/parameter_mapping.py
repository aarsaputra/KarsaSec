"""ParameterMapper mapping caller arguments to callee parameters."""

from __future__ import annotations

from karsasec.analysis.interprocedural.models import CallSite, ParameterSummary


class ParameterMapper:
    """Maps call site arguments to formal function parameter indices."""

    def map_arguments_to_parameters(
        self, call_site: CallSite, callee_params: dict[int, ParameterSummary]
    ) -> dict[int, str]:
        """Returns mapping of parameter_index -> argument_name passed at call site."""
        mapped: dict[int, str] = {}
        for idx, arg_expr in enumerate(call_site.arguments):
            mapped[idx] = arg_expr
        return mapped
