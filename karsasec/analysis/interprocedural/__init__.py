"""KarsaSec Interprocedural Taint Analysis Engine Module."""

from karsasec.analysis.interprocedural.cache import SummaryCache
from karsasec.analysis.interprocedural.engine import InterproceduralTaintEngine
from karsasec.analysis.interprocedural.interprocedural_pass import InterproceduralTaintPass
from karsasec.analysis.interprocedural.models import (
    CallContext,
    CallSite,
    FunctionSummary,
    InterproceduralTaintGraph,
    InterproceduralTaintPath,
    ParameterSummary,
    ReturnSummary,
)
from karsasec.analysis.interprocedural.parameter_mapping import ParameterMapper
from karsasec.analysis.interprocedural.reporter import InterproceduralReporter
from karsasec.analysis.interprocedural.resolver import CallResolver
from karsasec.analysis.interprocedural.summary import FunctionSummaryEngine

__all__ = [
    "CallSite",
    "CallContext",
    "ParameterSummary",
    "ReturnSummary",
    "FunctionSummary",
    "InterproceduralTaintPath",
    "InterproceduralTaintGraph",
    "SummaryCache",
    "ParameterMapper",
    "FunctionSummaryEngine",
    "CallResolver",
    "InterproceduralTaintEngine",
    "InterproceduralReporter",
    "InterproceduralTaintPass",
]
