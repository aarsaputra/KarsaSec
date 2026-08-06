"""CallResolver resolving callee function signatures across CallGraph and SymbolGraph."""

from __future__ import annotations

from karsasec.analysis.callgraph.models import CallGraph
from karsasec.analysis.symbol.models import SymbolGraph


class CallResolver:
    """Resolves function call targets across CallGraph and SymbolGraph artifacts."""

    def resolve_callee(self, callee_name: str, callgraph: CallGraph | None, symbolgraph: SymbolGraph | None) -> str:
        """Resolves target callee qualified name."""
        if callgraph and hasattr(callgraph, "nodes"):
            for node_id in callgraph.nodes:
                if callee_name in node_id:
                    return node_id
        return callee_name
