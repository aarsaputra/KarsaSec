"""Legacy Rule Adapter converting legacy YAML rules to Query AST structures."""

from __future__ import annotations

from typing import Any

from karsasec.query.ast import PredicateNode, QueryNode
from karsasec.query.dsl import Node


class LegacyRuleAdapter:
    """Adapter converting 134+ legacy pattern/regex/predicate YAML rules to Query AST structures."""

    def adapt(self, rule_data: dict[str, Any]) -> QueryNode:
        rule_id = str(rule_data.get("id", "legacy_rule"))
        target_lang = str(rule_data.get("language", "python")).lower()

        pattern = rule_data.get("pattern")
        patterns = rule_data.get("patterns", [])
        regex_pattern = rule_data.get("regex")

        builder = Node("FUNCTION")
        builder.where(target="language", contains=target_lang)

        if pattern and isinstance(pattern, str):
            # Parse simple call pattern like "execute(...)" or "eval(...)"
            callee_name = pattern.split("(")[0].strip() if "(" in pattern else pattern
            builder.where(target="label", contains=callee_name)

        if patterns and isinstance(patterns, list):
            sub_preds = []
            for p in patterns:
                if isinstance(p, str):
                    callee_name = p.split("(")[0].strip() if "(" in p else p
                    sub_preds.append(PredicateNode(operator="CONTAINS", target="label", value=callee_name))
            if sub_preds:
                builder.where(predicate=PredicateNode(operator="OR", target="compound", args=tuple(sub_preds)))

        if regex_pattern and isinstance(regex_pattern, str):
            builder.where(target="label", regex=regex_pattern)

        return builder.build()
