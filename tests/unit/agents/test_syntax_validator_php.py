"""Unit test suite for PHP SyntaxValidator (Task 1).

Verifies that:
1. Invalid PHP code constructs (including missing statement separators, semicolons inside args, etc.)
   are detected as syntax_valid: False.
2. Valid PHP statements pass syntax validation cleanly without false positives.
3. Fallback fails loud with syntax_valid: False if the tree-sitter-php parser binding is unavailable.
"""

import pytest
from pathlib import Path
from karsasec.agents.validation.syntax_check import SyntaxValidator
from karsasec.parser.tree_sitter import ts_engine


class TestPHPSyntaxValidator:
    """Test suite covering PHP syntax validation via Tree-Sitter & defense-in-depth checks."""

    def test_invalid_php_missing_semicolon_separator(self) -> None:
        """Test Case 1: Two PHP statements without semicolon separator ($a = 5 $b = 6;)."""
        code = "$a = 5 $b = 6;"
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None
        assert "Syntax error in PHP AST" in err or "PHP" in err

    def test_invalid_php_semicolon_in_args(self) -> None:
        """Test Case 2: Semicolon inside function call arguments / assignment."""
        code = 'echo htmlspecialchars($api_key = "AKIAIOSFODNN7EXAMPLE";, ENT_QUOTES, \'UTF-8\');'
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None

    def test_invalid_php_unbalanced_parentheses(self) -> None:
        """Test Case 3: Unbalanced parentheses."""
        code = "$x = (1 + 2;"
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None

    def test_invalid_php_unclosed_string(self) -> None:
        """Test Case 4: Unclosed string literal quote."""
        code = '$foo = "unclosed string;'
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None

    def test_invalid_php_empty_assignment(self) -> None:
        """Test Case 5: Semicolon right after assignment operator."""
        code = "$a = ;"
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None

    def test_invalid_php_bare_assignment_no_dollar(self) -> None:
        """Test Case 6: PHP assignment without $ variable prefix."""
        code = "val = input();"
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None

    def test_invalid_php_dangling_operator(self) -> None:
        """Test Case 7: Binary operator before delimiter."""
        code = "$b = 1 + ;"
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is False
        assert err is not None

    def test_valid_php_mysqli_prepare(self) -> None:
        """Test Case 8: Valid PHP mysqli_prepare parameterized query."""
        code = '$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE id = ?");'
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is True
        assert err is None

    def test_valid_php_mysqli_query(self) -> None:
        """Test Case 9: Valid PHP query statement."""
        code = '$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);'
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is True
        assert err is None

    def test_valid_php_getenv_secret(self) -> None:
        """Test Case 10: Valid PHP getenv secret assignment."""
        code = "$api_key = getenv('API_KEY');"
        valid, err = SyntaxValidator.validate_source(code, "test.php")
        assert valid is True
        assert err is None

    def test_php_parser_unavailable_fails_loud(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Case 11: Fail-loud if tree-sitter-php parser language binding is not loaded."""
        monkeypatch.setattr(ts_engine, "get_language", lambda lang: None if lang == "php" else "mock")
        valid, err = SyntaxValidator.validate_source("$api_key = getenv('API_KEY');", "test.php")
        assert valid is False
        assert err is not None
        assert "tree-sitter-php binding not loaded" in err
