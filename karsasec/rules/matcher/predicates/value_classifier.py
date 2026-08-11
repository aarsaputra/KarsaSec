"""ValueEvidenceClassifier analyzing AST node values and expressions for semantic security rule evaluation."""

import re

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.enums import ValueEvidenceKind
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics

ENV_PATTERNS = re.compile(
    r"(?i)\b(env|getenv|os\.getenv|os\.environ|process\.env)\b"
)

SECRET_PROVIDER_PATTERNS = re.compile(
    r"(?i)\b(config|Secret::|Vault::|secrets_manager|key_vault|aws_secrets|Vault|SecretsManager)\b"
)

PATH_CONSTANT_PATTERNS = re.compile(
    r"(?i)\b(storage_path|database_path|base_path|app_path|resource_path|path\.join|Path)\b"
)


class ValueEvidenceClassifier:
    """Classifies AST node values and right-hand side expressions into ValueEvidenceKind."""

    @staticmethod
    def classify(node_text: str) -> ValueEvidenceKind:
        """Determines the ValueEvidenceKind of an AST node text snippet."""
        clean_text = node_text.strip()
        if not clean_text:
            return ValueEvidenceKind.EMPTY_LITERAL

        # Extract value portion if key-value or assignment
        value_part = ValueEvidenceClassifier._extract_value_portion(clean_text)

        # 1. Check ENV_REFERENCE
        if ENV_PATTERNS.search(value_part):
            return ValueEvidenceKind.ENV_REFERENCE

        # 2. Check SECRET_PROVIDER_REFERENCE
        if SECRET_PROVIDER_PATTERNS.search(value_part):
            return ValueEvidenceKind.SECRET_PROVIDER_REFERENCE

        # 3. Check PATH_CONSTANT / STATIC_CONSTANT
        if PATH_CONSTANT_PATTERNS.search(value_part):
            return ValueEvidenceKind.STATIC_CONSTANT

        # 4. Check EMPTY_LITERAL / NULL_LITERAL
        val_strip = value_part.strip()
        if val_strip in ("''", '""', "b''", 'b""', ""):
            return ValueEvidenceKind.EMPTY_LITERAL
        if val_strip.lower() in ("null", "none", "undefined"):
            return ValueEvidenceKind.NULL_LITERAL

        # 5. Check LITERAL_SECRET (non-empty quoted string literal)
        if (val_strip.startswith("'") and val_strip.endswith("'") and len(val_strip) > 2) or \
           (val_strip.startswith('"') and val_strip.endswith('"') and len(val_strip) > 2):
            return ValueEvidenceKind.LITERAL_SECRET

        return ValueEvidenceKind.UNKNOWN

    @staticmethod
    def _extract_value_portion(text: str) -> str:
        """Extracts the right-hand side value expression from an assignment or key-value pair."""
        # Check PHP array key-value =>
        if "=>" in text:
            parts = text.split("=>", 1)
            return parts[1].strip()

        # Check Python / JS assignment or dict key-value = or :
        if "=" in text and not text.startswith("if") and not text.startswith("while"):
            parts = text.split("=", 1)
            return parts[1].strip()

        if ":" in text and not text.startswith("case"):
            parts = text.split(":", 1)
            return parts[1].strip()

        return text


class ValueEvidencePredicate(BasePredicate):
    """Evaluates ValueEvidenceKind requirements against AST node values."""

    @property
    def name(self) -> str:
        return "ValueEvidencePredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> tuple[bool, str | None, str | None]:
        condition = getattr(compiled_rule.rule, "condition", None)
        if not condition:
            return True, None, None

        req_equals = getattr(condition, "value_evidence_equals", None)
        not_in = getattr(condition, "value_evidence_not_in", [])

        if not req_equals and not not_in:
            return True, None, None

        stats.predicates_checked += 1
        node_text = node.get_text(source_bytes)
        kind = ValueEvidenceClassifier.classify(node_text)

        if req_equals and kind.value != req_equals and kind != req_equals:
            stats.short_circuit += 1
            return False, None, None

        if not_in:
            not_in_strs = [str(x) for x in not_in]
            if kind.value in not_in_strs or kind in not_in_strs:
                stats.short_circuit += 1
                return False, None, None

        return True, None, node_text
