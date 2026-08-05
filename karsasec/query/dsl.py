"""Fluent Query and Predicate DSL for security pattern queries."""

from typing import Any, Callable, List, Optional


class Predicate:
    """Represents a rule matcher predicate filter."""

    def __init__(self, evaluator: Callable[[Any], bool], name: str = "custom_predicate") -> None:
        self.evaluator = evaluator
        self.name = name

    def evaluate(self, target: Any) -> bool:
        return self.evaluator(target)


class Query:
    """Fluent query builder for security pattern queries."""

    def __init__(self, target_kind: str = "Call") -> None:
        self.target_kind = target_kind
        self._predicates: List[Predicate] = []

    @classmethod
    def function_call(cls) -> "Query":
        return cls(target_kind="Call")

    def where_callee(self, callee_name: str) -> "Query":
        self._predicates.append(
            Predicate(lambda node: getattr(node, "callee", None) == callee_name, name=f"callee=={callee_name}")
        )
        return self

    def and_predicate(self, predicate: Predicate) -> "Query":
        self._predicates.append(predicate)
        return self

    def matches(self, node: Any) -> bool:
        return all(p.evaluate(node) for p in self._predicates)
