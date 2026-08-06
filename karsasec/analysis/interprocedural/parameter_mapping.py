"""ParameterMapper mapping caller arguments to callee parameters (positional, keyword, default, variadic)."""

from __future__ import annotations

from karsasec.analysis.interprocedural.models import CallSite, ParameterSummary


class ParameterMapper:
    """Maps call site arguments to formal function parameter indices and keyword mappings."""

    def map_arguments_to_parameters(
        self, call_site: CallSite, callee_params: dict[int, ParameterSummary]
    ) -> dict[int, str]:
        """Returns mapping of parameter_index -> argument_name passed at call site."""
        mapped: dict[int, str] = {}

        # Map positional arguments
        for idx, arg_expr in enumerate(call_site.arguments):
            mapped[idx] = arg_expr

        # Map keyword arguments
        if call_site.keyword_args:
            for idx, param in callee_params.items():
                if param.param_name in call_site.keyword_args:
                    mapped[idx] = call_site.keyword_args[param.param_name]

        return mapped
