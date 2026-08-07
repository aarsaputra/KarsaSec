"""Typed Fluent DSL Builder for CPG Query Engine."""

from __future__ import annotations

from typing import Any

from karsasec.query.ast import PredicateNode, QueryNode, QueryStep, StepType


class CPGQueryBuilder:
    """Typed Fluent Query Builder for constructing Query ASTs."""

    def __init__(self, target_label: str) -> None:
        self._target_label = target_label
        self._steps: list[QueryStep] = []
        self._projection_fields: list[str] = []

    def where(
        self,
        target: str = "label",
        equals: Any = None,
        contains: str | None = None,
        regex: str | None = None,
        predicate: PredicateNode | None = None,
        **kwargs: Any,
    ) -> CPGQueryBuilder:
        if predicate:
            p = predicate
        elif contains is not None:
            p = PredicateNode(operator="CONTAINS", target=target, value=contains)
        elif regex is not None:
            p = PredicateNode(operator="REGEX", target=target, value=regex)
        elif equals is not None:
            p = PredicateNode(operator="EQUALS", target=target, value=equals)
        elif kwargs:
            sub_preds = []
            for k, v in kwargs.items():
                sub_preds.append(PredicateNode(operator="EQUALS", target=k, value=v))
            if len(sub_preds) == 1:
                p = sub_preds[0]
            else:
                p = PredicateNode(operator="AND", target="compound", args=tuple(sub_preds))
        else:
            p = PredicateNode(operator="EQUALS", target=target, value=equals)

        self._steps.append(QueryStep(step_type=StepType.WHERE, predicate=p))
        return self

    def outgoing(self, edge_type: str = "", target_type: str = "") -> CPGQueryBuilder:
        self._steps.append(
            QueryStep(
                step_type=StepType.TRAVERSE,
                direction="OUTGOING",
                edge_type=edge_type,
                target_type=target_type,
            )
        )
        return self

    def incoming(self, edge_type: str = "", target_type: str = "") -> CPGQueryBuilder:
        self._steps.append(
            QueryStep(
                step_type=StepType.TRAVERSE,
                direction="INCOMING",
                edge_type=edge_type,
                target_type=target_type,
            )
        )
        return self

    def limit(self, count: int) -> CPGQueryBuilder:
        self._steps.append(QueryStep(step_type=StepType.LIMIT, limit=count))
        return self

    def select(self, *fields: str) -> CPGQueryBuilder:
        self._projection_fields.extend(fields)
        return self

    def build(self) -> QueryNode:
        return QueryNode(
            target_label=self._target_label,
            steps=tuple(self._steps),
            projection_fields=tuple(self._projection_fields),
        )


def Node(label: str = "") -> CPGQueryBuilder:
    return CPGQueryBuilder(target_label=label)


def Function(name: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="FUNCTION")
    if name:
        builder.where(target="function_name", equals=name)
    return builder


def Variable(name: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="SSA")
    if name:
        builder.where(target="variable", equals=name)
    return builder


def File(path: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="AST")
    if path:
        builder.where(target="file_path", equals=path)
    return builder


def Module(name: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="MODULE")
    if name:
        builder.where(target="module_name", equals=name)
    return builder


def Package(name: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="PACKAGE")
    if name:
        builder.where(target="package_name", equals=name)
    return builder


def Source(label: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="SOURCE")
    if label:
        builder.where(target="label", equals=label)
    return builder


def Sink(label: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="SINK")
    if label:
        builder.where(target="label", equals=label)
    return builder


def Sanitizer(label: str = "") -> CPGQueryBuilder:
    builder = CPGQueryBuilder(target_label="SANITIZER")
    if label:
        builder.where(target="label", equals=label)
    return builder


def Edge(edge_type: str) -> CPGQueryBuilder:
    return CPGQueryBuilder(target_label="EDGE").where(target="edge_type", equals=edge_type)


def Literal(value: Any) -> PredicateNode:
    return PredicateNode(operator="LITERAL", target="literal", value=value)


def Identifier(name: str) -> PredicateNode:
    return PredicateNode(operator="IDENTIFIER", target="identifier", value=name)


class LegacyQueryWrapper:
    """Wrapper for legacy Query API compatibility."""

    def __init__(self) -> None:
        self.callee_name = ""

    @classmethod
    def function_call(cls) -> LegacyQueryWrapper:
        return cls()

    def where_callee(self, callee: str) -> LegacyQueryWrapper:
        self.callee_name = callee
        return self

    def matches(self, node: Any) -> bool:
        if hasattr(node, "callee"):
            return bool(node.callee == self.callee_name)
        return False


Query = LegacyQueryWrapper
