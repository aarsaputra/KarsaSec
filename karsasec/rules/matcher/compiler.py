"""RuleCompiler module for pre-compiling regular expressions and set lookups ahead of execution."""

import re
from dataclasses import dataclass, field

from karsasec.rules.schema import Rule


@dataclass(slots=True)
class CompiledRule:
    """Pre-compiled rule containing compiled regex patterns and indexed lookup sets."""

    rule: Rule
    compiled_pattern: re.Pattern[str] | None = None
    cleaned_symbol_triggers: tuple[str, ...] = field(default_factory=tuple)
    ast_node_types_set: set[str] = field(default_factory=set)

    @property
    def id(self) -> str:
        return self.rule.id


class RuleCompiler:
    """Compiles raw Rule definitions into optimized CompiledRule instances."""

    def compile(self, rule: Rule) -> CompiledRule:
        """Pre-compiles regex pattern and index sets for a Rule."""
        compiled_pattern: re.Pattern[str] | None = None
        if rule.condition.pattern:
            try:
                compiled_pattern = re.compile(rule.condition.pattern)
            except re.error as err:
                raise ValueError(f"Invalid regex pattern in rule '{rule.id}': {str(err)}")

        symbols = tuple(s for s in rule.condition.symbol_triggers if s)
        node_types_set = {t.lower() for t in rule.match.ast_node_types}

        return CompiledRule(
            rule=rule,
            compiled_pattern=compiled_pattern,
            cleaned_symbol_triggers=symbols,
            ast_node_types_set=node_types_set,
        )


# Singleton compiler instance
rule_compiler = RuleCompiler()
