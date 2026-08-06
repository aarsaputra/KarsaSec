"""Capability Dependency Graph module defining prerequisites and graph traversal."""


from karsasec.rules.enums import AnalysisCapability


class CapabilityGraph:
    """Graph structure representing dependency hierarchy between analysis engine capabilities."""

    def __init__(self) -> None:
        self.adj_list: dict[AnalysisCapability, list[AnalysisCapability]] = {
            AnalysisCapability.AST: [],
            AnalysisCapability.POSITION: [AnalysisCapability.AST],
            AnalysisCapability.COMMENTS: [AnalysisCapability.AST],
            AnalysisCapability.HIERARCHY: [AnalysisCapability.AST],
            AnalysisCapability.SEMANTIC: [AnalysisCapability.AST, AnalysisCapability.HIERARCHY],
            AnalysisCapability.TYPE_INFO: [AnalysisCapability.SEMANTIC],
            AnalysisCapability.CONTROL_FLOW: [AnalysisCapability.AST],
            AnalysisCapability.CALLGRAPH: [AnalysisCapability.SEMANTIC],
            AnalysisCapability.DATAFLOW: [AnalysisCapability.SEMANTIC, AnalysisCapability.CALLGRAPH],
        }

    def get_prerequisites(self, capability: AnalysisCapability) -> list[AnalysisCapability]:
        """Returns direct prerequisites for a given capability."""
        return self.adj_list.get(capability, [])

    def get_all_transitive_prerequisites(self, capability: AnalysisCapability) -> set[AnalysisCapability]:
        """Returns all transitive prerequisites for a capability."""
        visited: set[AnalysisCapability] = set()

        def dfs(curr: AnalysisCapability) -> None:
            for prereq in self.get_prerequisites(curr):
                if prereq not in visited:
                    visited.add(prereq)
                    dfs(prereq)

        dfs(capability)
        return visited


capability_graph = CapabilityGraph()
