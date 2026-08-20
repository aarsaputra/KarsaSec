"""MatcherStatistics tracker for ASTMatcher performance and predicate evaluation telemetry."""

from dataclasses import dataclass


@dataclass
class MatcherStatistics:
    """Telemetry counter tracking matching efficiency, predicate checks, and short-circuits."""

    nodes_checked: int = 0
    rules_checked: int = 0
    predicates_checked: int = 0
    regex_calls: int = 0
    short_circuit: int = 0
    total_time_ns: int = 0

    def reset(self) -> None:
        """Resets all telemetry counters to zero."""
        self.nodes_checked = 0
        self.rules_checked = 0
        self.predicates_checked = 0
        self.regex_calls = 0
        self.short_circuit = 0
        self.total_time_ns = 0

    def to_dict(self) -> dict[str, int]:
        """Returns statistics summary dictionary."""
        return {
            "nodes_checked": self.nodes_checked,
            "rules_checked": self.rules_checked,
            "predicates_checked": self.predicates_checked,
            "regex_calls": self.regex_calls,
            "short_circuit": self.short_circuit,
            "total_time_ns": self.total_time_ns,
        }
