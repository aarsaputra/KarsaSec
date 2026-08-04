"""Rule Registry module indexed by Language -> Node Type for O(1) matching lookup."""

from collections import defaultdict
from typing import Dict, List, Optional, Set, Union
from karsasec.rules.enums import LanguageEnum
from karsasec.rules.schema import Rule

class RuleRegistry:
    """Registry managing loaded security rules indexed by Language and AST Node Type."""

    def __init__(self) -> None:
        self._rules_by_id: Dict[str, Rule] = {}
        # Index: language_str -> node_type_str -> List[Rule]
        self._rules_by_lang_and_node: Dict[str, Dict[str, List[Rule]]] = defaultdict(lambda: defaultdict(list))

    def register(self, rule: Rule) -> None:
        """Registers a Rule object into the registry.

        Raises:
            ValueError: If a duplicate Rule ID is detected.
        """
        # Ignore disabled rules
        if not rule.metadata.enabled:
            return

        if rule.id in self._rules_by_id:
            raise ValueError(f"Duplicate Rule ID '{rule.id}' detected in registry.")

        self._rules_by_id[rule.id] = rule
        lang_str = rule.match.language.value if isinstance(rule.match.language, LanguageEnum) else str(rule.match.language)

        if not rule.match.ast_node_types:
            # Universal match for all node types under this language
            self._rules_by_lang_and_node[lang_str]["*"].append(rule)
        else:
            for node_type in rule.match.ast_node_types:
                clean_type = node_type.lower()
                self._rules_by_lang_and_node[lang_str][clean_type].append(rule)

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Retrieves a rule by its unique Rule ID."""
        return self._rules_by_id.get(rule_id)

    def get_rules_for_node(self, language: Union[str, LanguageEnum], node_type: str) -> List[Rule]:
        """Retrieves candidate rules matching the target language and AST node_type in O(1) time."""
        lang_str = language.value if isinstance(language, LanguageEnum) else str(language)
        clean_node_type = node_type.lower()

        specific_rules = self._rules_by_lang_and_node[lang_str].get(clean_node_type, [])
        wildcard_rules = self._rules_by_lang_and_node[lang_str].get("*", [])

        # Deduplicate while maintaining order
        combined: List[Rule] = []
        seen: Set[str] = set()

        for r in specific_rules + wildcard_rules:
            if r.id not in seen:
                seen.add(r.id)
                combined.append(r)

        return combined

    def list_rules(self) -> List[Rule]:
        """Returns all registered active rules."""
        return list(self._rules_by_id.values())

    def clear(self) -> None:
        """Clears all registered rules."""
        self._rules_by_id.clear()
        self._rules_by_lang_and_node.clear()

# Global default rule registry instance
rule_registry = RuleRegistry()
