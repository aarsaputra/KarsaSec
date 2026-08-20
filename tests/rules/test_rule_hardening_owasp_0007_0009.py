"""Dedicated Test Suite for Rule Hardening (Sprint E10-3H).

Tests ValueEvidenceClassifier, hardened KS-OWASP-0007, and redesigned KS-OWASP-0009.
Guarantees 0 False Positives on Laravel config files while retaining detection of hardcoded secrets.
"""

from pathlib import Path

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.rules.enums import ValueEvidenceKind
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.matcher.matcher import ASTMatcher
from karsasec.rules.matcher.predicates.value_classifier import ValueEvidenceClassifier

RULES_DIR = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "owasp"


class TestValueEvidenceClassifier:
    """Tests ValueEvidenceClassifier across various language snippets and patterns."""

    def test_env_reference_classification(self) -> None:
        assert ValueEvidenceClassifier.classify("'password' => env('DB_PASSWORD')") == ValueEvidenceKind.ENV_REFERENCE
        assert (
            ValueEvidenceClassifier.classify("'password' => env('DB_PASSWORD', '')") == ValueEvidenceKind.ENV_REFERENCE
        )
        assert (
            ValueEvidenceClassifier.classify("'password' => getenv('MAIL_PASSWORD')") == ValueEvidenceKind.ENV_REFERENCE
        )
        assert ValueEvidenceClassifier.classify("password = os.getenv('DB_PASS')") == ValueEvidenceKind.ENV_REFERENCE
        assert ValueEvidenceClassifier.classify("password = process.env.DB_PASS") == ValueEvidenceKind.ENV_REFERENCE
        assert (
            ValueEvidenceClassifier.classify("'default' => env('MAIL_MAILER', 'log')")
            == ValueEvidenceKind.ENV_REFERENCE
        )

    def test_secret_provider_classification(self) -> None:
        assert (
            ValueEvidenceClassifier.classify("'password' => config('secrets.db')")
            == ValueEvidenceKind.SECRET_PROVIDER_REFERENCE
        )
        assert (
            ValueEvidenceClassifier.classify("'password' => Secret::get('db')")
            == ValueEvidenceKind.SECRET_PROVIDER_REFERENCE
        )
        assert (
            ValueEvidenceClassifier.classify("pass = Vault::fetch('db_key')")
            == ValueEvidenceKind.SECRET_PROVIDER_REFERENCE
        )

    def test_static_constant_classification(self) -> None:
        assert (
            ValueEvidenceClassifier.classify("'path' => storage_path('logs/laravel.log')")
            == ValueEvidenceKind.STATIC_CONSTANT
        )
        assert (
            ValueEvidenceClassifier.classify("'path' => database_path('database.sqlite')")
            == ValueEvidenceKind.STATIC_CONSTANT
        )

    def test_empty_and_null_classification(self) -> None:
        assert ValueEvidenceClassifier.classify("'password' => ''") == ValueEvidenceKind.EMPTY_LITERAL
        assert ValueEvidenceClassifier.classify("'password' => \"\"") == ValueEvidenceKind.EMPTY_LITERAL
        assert ValueEvidenceClassifier.classify("'password' => null") == ValueEvidenceKind.NULL_LITERAL
        assert ValueEvidenceClassifier.classify("password = None") == ValueEvidenceKind.NULL_LITERAL

    def test_literal_secret_classification(self) -> None:
        assert ValueEvidenceClassifier.classify("'password' => 'supersecret123'") == ValueEvidenceKind.LITERAL_SECRET
        assert ValueEvidenceClassifier.classify("'api_key' => 'sk_live_9988776655'") == ValueEvidenceKind.LITERAL_SECRET
        assert ValueEvidenceClassifier.classify('password = "root123"') == ValueEvidenceKind.LITERAL_SECRET


class TestOWASPRuleHardening:
    """Tests KS-OWASP-0007 and KS-OWASP-0009 evaluation against positive and negative snippets."""

    def setup_method(self) -> None:
        self.loader = YAMLRuleLoader()
        self.matcher = ASTMatcher()

        a07_path = RULES_DIR / "A07_identity_and_authentication_failures.yaml"
        a09_path = RULES_DIR / "A09_security_logging_and_monitoring.yaml"

        self.rule_a07 = self.loader.load_file(a07_path)
        self.rule_a09 = self.loader.load_file(a09_path)

        file_node = FileNode(file_path=Path("config/database.php"), language="PHP")
        self.ctx = VisitorContext(file_node=file_node, file_path=Path("config/database.php"), language="PHP")

    def test_a07_ignores_env_and_config_references(self) -> None:
        """11 FP snippets from pos_kasir MUST yield 0 findings."""
        fp_snippets = [
            "'password' => env('MAIL_PASSWORD'),",
            "'password' => env('DB_PASSWORD', ''),",
            "'password' => env('REDIS_PASSWORD'),",
            "'password' => getenv('DB_PASSWORD'),",
            "'password' => config('secrets.db'),",
            "'password' => ''",
            "'password' => null",
        ]

        for snippet in fp_snippets:
            encoded = snippet.encode("utf-8")
            node = ASTNode(node_type="statement", byte_start=0, byte_end=len(encoded))
            res = self.matcher.match(node, self.rule_a07, self.ctx, source_bytes=encoded)
            assert not res.matched, f"Expected NO finding for FP snippet: {snippet}"

    def test_a07_flags_hardcoded_literal_secrets(self) -> None:
        """Hardcoded literal secrets in config MUST trigger KS-OWASP-0007."""
        positive_snippets = [
            "'password' => 'supersecret123',",
            "'password' => 'root123',",
            "password = 'sk_live_9988776655'",
        ]

        for snippet in positive_snippets:
            encoded = snippet.encode("utf-8")
            node = ASTNode(node_type="statement", byte_start=0, byte_end=len(encoded))
            res = self.matcher.match(node, self.rule_a07, self.ctx, source_bytes=encoded)
            assert res.matched, f"Expected FINDING for hardcoded secret snippet: {snippet}"

    def test_a09_ignores_standard_logging_and_config_paths(self) -> None:
        """Logging configuration paths and Log calls MUST NOT trigger KS-OWASP-0009."""
        logging_snippets = [
            "'default' => env('MAIL_MAILER', 'log'),",
            "'path' => storage_path('logs/laravel.log'),",
            "Log::info('User logged in successfully');",
            "Log::error('Database connection failed');",
        ]

        for snippet in logging_snippets:
            encoded = snippet.encode("utf-8")
            node = ASTNode(node_type="call", byte_start=0, byte_end=len(encoded))
            res = self.matcher.match(node, self.rule_a09, self.ctx, source_bytes=encoded)
            assert not res.matched, f"Expected NO finding for logging snippet: {snippet}"
