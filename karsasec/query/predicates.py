"""Predicate Engine for lazy evaluation of logical and string operators."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from karsasec.cpg.models import CPGNode
from karsasec.query.ast import PredicateNode


class PredicateEngine:
    """Lazy evaluation engine for PredicateNode against CPGNode or dict values."""

    @classmethod
    def evaluate(cls, node: PredicateNode, target_obj: CPGNode | dict[str, Any]) -> bool:
        op = node.operator.upper()

        if op == "AND":
            return all(cls.evaluate(arg, target_obj) for arg in node.args)
        if op == "OR":
            return any(cls.evaluate(arg, target_obj) for arg in node.args)
        if op == "NOT":
            return not all(cls.evaluate(arg, target_obj) for arg in node.args)

        val = cls._extract_field(node.target, target_obj)

        if op == "EQUALS":
            return bool(val == node.value)
        if op == "NOT_EQUALS":
            return bool(val != node.value)
        if op == "CONTAINS":
            return bool(val and str(node.value) in str(val))
        if op == "STARTSWITH":
            return bool(val and str(val).startswith(str(node.value)))
        if op == "ENDSWITH":
            return bool(val and str(val).endswith(str(node.value)))
        if op == "REGEX" or op == "MATCHES":
            if not val or not node.value:
                return False
            return bool(re.search(str(node.value), str(val)))
        if op == "IN":
            return bool(val in (node.value if isinstance(node.value, (list, tuple, set)) else [node.value]))
        if op == "NOT_IN":
            return bool(val not in (node.value if isinstance(node.value, (list, tuple, set)) else [node.value]))
        if op == "EXISTS":
            return bool(val is not None)
        if op == "COUNT":
            if isinstance(val, (list, tuple, set, dict)):
                return bool(len(val) == node.value)
            return False

        # Fallback to equality
        return bool(val == node.value)

    @classmethod
    def _extract_field(cls, field_name: str, target_obj: CPGNode | dict[str, Any]) -> Any:
        if isinstance(target_obj, dict):
            return target_obj.get(field_name)

        if target_obj.attributes and field_name in target_obj.attributes:
            return target_obj.attributes[field_name]

        if hasattr(target_obj, field_name):
            val = getattr(target_obj, field_name)
            if val != "Generic" or field_name != "language":
                return val

        if field_name == "type" or field_name == "node_type":
            return target_obj.node_type.value

        if field_name == "label":
            return target_obj.label

        return None


def AND(*predicates: PredicateNode) -> PredicateNode:
    return PredicateNode(operator="AND", target="compound", args=predicates)


def OR(*predicates: PredicateNode) -> PredicateNode:
    return PredicateNode(operator="OR", target="compound", args=predicates)


def NOT(predicate: PredicateNode) -> PredicateNode:
    return PredicateNode(operator="NOT", target="compound", args=(predicate,))


def EXISTS(target: str) -> PredicateNode:
    return PredicateNode(operator="EXISTS", target=target)


def COUNT(target: str, expected_count: int) -> PredicateNode:
    return PredicateNode(operator="COUNT", target=target, value=expected_count)


def REGEX(target: str, pattern: str) -> PredicateNode:
    return PredicateNode(operator="REGEX", target=target, value=pattern)


def CONTAINS(target: str, substring: str) -> PredicateNode:
    return PredicateNode(operator="CONTAINS", target=target, value=substring)


def IN(target: str, values: Sequence[Any]) -> PredicateNode:
    return PredicateNode(operator="IN", target=target, value=tuple(values))


def NOT_IN(target: str, values: Sequence[Any]) -> PredicateNode:
    return PredicateNode(operator="NOT_IN", target=target, value=tuple(values))
