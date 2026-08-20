"""RuleContractValidator: deterministic fixture-based validation of security rule contracts.

Verifies that every positive fixture produces a Finding and every negative fixture
produces no Finding, as declared in the rule's RuleContract.

Called:
  - In CI via test_rule_contracts.py
  - Via `karsasec rules validate` CLI command
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.rules.schema import Rule

if TYPE_CHECKING:
    from karsasec.rules.matcher.matcher import ASTMatcher


@dataclass
class ContractFixtureFailure:
    """Records a single fixture validation failure."""

    fixture_kind: str  # "positive" or "negative"
    snippet: str
    expected_matched: bool  # True for positive, False for negative
    actual_matched: bool
    rule_id: str


@dataclass
class ContractValidationResult:
    """Result of validating a single rule's contract fixtures."""

    rule_id: str
    has_contract: bool
    positive_total: int = 0
    positive_passed: int = 0
    negative_total: int = 0
    negative_passed: int = 0
    failures: list[ContractFixtureFailure] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return self.positive_passed + self.negative_passed

    @property
    def total(self) -> int:
        return self.positive_total + self.negative_total

    @property
    def all_passed(self) -> bool:
        return len(self.failures) == 0 and self.total > 0

    @property
    def coverage_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return round(self.passed / self.total * 100, 1)


@dataclass
class ContractSuiteResult:
    """Aggregate result across all validated rules."""

    results: list[ContractValidationResult] = field(default_factory=list)

    @property
    def rules_with_contract(self) -> int:
        return sum(1 for r in self.results if r.has_contract)

    @property
    def rules_all_passing(self) -> int:
        return sum(1 for r in self.results if r.has_contract and r.all_passed)

    @property
    def total_failures(self) -> int:
        return sum(len(r.failures) for r in self.results)

    @property
    def contract_coverage_pct(self) -> float:
        if not self.results:
            return 0.0
        return round(self.rules_with_contract / len(self.results) * 100, 1)


class RuleContractValidator:
    """Validates a rule's fixture contract by running positive/negative snippets through ASTMatcher.

    For each positive fixture: asserts matched == True.
    For each negative fixture: asserts matched == False.

    Uses node_type='call' and language derived from rule target (defaults to PHP for
    generic/multi-language rules to maximize coverage of common FP patterns).
    """

    def validate(self, rule: Rule, matcher: ASTMatcher) -> ContractValidationResult:
        """Validate all fixtures declared in rule.contract."""
        result = ContractValidationResult(
            rule_id=rule.id,
            has_contract=rule.contract is not None,
        )

        if rule.contract is None:
            return result

        fixtures = rule.contract.fixtures
        # Determine language hint for context
        lang = "PHP"
        if rule.target and rule.target.languages:
            first_lang = rule.target.languages[0]
            lang = first_lang.value if hasattr(first_lang, "value") else str(first_lang)

        for snippet in fixtures.positive:
            result.positive_total += 1
            matched = self._run_fixture(snippet, rule, matcher, lang)
            if matched:
                result.positive_passed += 1
            else:
                result.failures.append(
                    ContractFixtureFailure(
                        fixture_kind="positive",
                        snippet=snippet,
                        expected_matched=True,
                        actual_matched=False,
                        rule_id=rule.id,
                    )
                )

        for snippet in fixtures.negative:
            result.negative_total += 1
            matched = self._run_fixture(snippet, rule, matcher, lang)
            if not matched:
                result.negative_passed += 1
            else:
                result.failures.append(
                    ContractFixtureFailure(
                        fixture_kind="negative",
                        snippet=snippet,
                        expected_matched=False,
                        actual_matched=True,
                        rule_id=rule.id,
                    )
                )

        return result

    def validate_all(self, rules: list[Rule], matcher: ASTMatcher) -> ContractSuiteResult:
        """Validate all rules that carry a contract. Rules without contracts are recorded but skipped."""
        suite = ContractSuiteResult()
        for rule in rules:
            suite.results.append(self.validate(rule, matcher))
        return suite

    @staticmethod
    def _run_fixture(snippet: str, rule: Rule, matcher: ASTMatcher, lang: str) -> bool:
        """Run a single code snippet through the matcher and return whether it matched.

        Tries all node types declared in the rule's match.ast_node_types so that
        fixtures for rules matching 'assignment' (e.g. A05) are correctly evaluated.
        Returns True if ANY declared node type produces a match.
        """
        encoded = snippet.encode("utf-8")
        fn = FileNode(file_path=Path("fixture.php"), language=lang)
        ctx = VisitorContext(file_node=fn, file_path=Path("fixture.php"), language=lang)

        # Collect declared node types; fall back to 'call' for legacy rules
        node_types = list(rule.match.ast_node_types) if rule.match.ast_node_types else ["call"]
        if not node_types:
            node_types = ["call"]

        for nt in node_types:
            try:
                node = ASTNode(node_type=nt, byte_start=0, byte_end=len(encoded))
                result = matcher.match(node, rule, ctx, source_bytes=encoded)
                if result.matched:
                    return True
            except Exception:
                continue
        return False
