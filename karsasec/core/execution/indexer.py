"""RuleIndexer module indexing compiled rules by AST node_type for O(1) candidate lookup."""


from karsasec.rules.matcher.compiler import CompiledRule, rule_compiler
from karsasec.rules.schema import Rule


class RuleIndexer:
    """Indexes compiled rules by AST node_type, reducing matching complexity from O(N x R) to O(N x RelevantRules)."""

    def __init__(self, rules: list[Rule | CompiledRule] | None = None) -> None:
        self._index: dict[str, list[CompiledRule]] = {}
        self._wildcard_rules: list[CompiledRule] = []
        if rules:
            self.index_rules(rules)

    def index_rules(self, rules: list[Rule | CompiledRule]) -> None:
        """Builds lookup index table mapping AST node_types to candidate CompiledRule instances."""
        self._index.clear()
        self._wildcard_rules.clear()

        for rule_item in rules:
            compiled: CompiledRule = (
                rule_item if isinstance(rule_item, CompiledRule) else rule_compiler.compile(rule_item)
            )

            types = compiled.ast_node_types_set
            if not types or "*" in types:
                self._wildcard_rules.append(compiled)
            else:
                for node_type in types:
                    node_type_clean = node_type.lower()
                    if node_type_clean not in self._index:
                        self._index[node_type_clean] = []
                    self._index[node_type_clean].append(compiled)

    def get_candidate_rules(self, node_type: str) -> list[CompiledRule]:
        """Retrieves only candidate rules relevant to the given node_type."""
        node_type_clean = node_type.lower()
        specific = self._index.get(node_type_clean, [])
        return specific + self._wildcard_rules
