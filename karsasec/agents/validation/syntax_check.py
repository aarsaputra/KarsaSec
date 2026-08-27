"""Native Syntax Validator for KarsaSec Remediation Proposals (Task Z-3 / Task 1).

Enforces H6 Safety Boundary (No subprocess / shell calls). Uses native ast.parse for Python,
TreeSitter AST parsing as Layer 1, and native language grammar validation as Layer 2 (Defense-in-Depth).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from karsasec.parser.tree_sitter import ts_engine


class SyntaxValidator:
    """Native syntax validation engine."""

    EXT_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".php": "php",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
    }

    @classmethod
    def validate_source(cls, code: str, file_path: str | Path) -> tuple[bool, str | None]:
        """Validates source code syntax natively without subprocess execution.

        Returns:
            tuple[bool, str | None]: (is_valid, error_message)
        """
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext == ".py":
            try:
                ast.parse(code, filename=str(path))
                return True, None
            except SyntaxError as err:
                return False, f"Python SyntaxError at line {err.lineno}: {err.msg}"
            except Exception as ex:
                return False, f"Python parse error: {str(ex)}"

        if ext == ".php":
            return cls._validate_php_syntax(code, path)

        # Multi-language validation via Tree-Sitter engine or fail-loud fallback
        lang = cls.EXT_MAP.get(ext, "python")
        if not ts_engine.get_language(lang):
            return False, f"Syntax validator unavailable: tree-sitter-{lang} binding not loaded"

        try:
            file_node = ts_engine.parse_code(code.encode("utf-8"), language_name=lang, file_path=path)
            # Check for ERROR/MISSING nodes in parsed AST tree
            if file_node.nodes_map:
                for node in file_node.nodes_map.values():
                    if node.node_type in ("ERROR", "MISSING"):
                        return False, f"Syntax error in {lang} AST at line {node.start.line}, column {node.start.column}"
            return True, None
        except Exception as ex:
            return False, f"Syntax parsing exception for {lang}: {str(ex)}"

    @classmethod
    def _validate_php_syntax(cls, code: str, path: Path) -> tuple[bool, str | None]:
        """Multi-stage PHP syntax validator combining Tree-Sitter (Layer 1) and hand-rolled structural check (Layer 2)."""
        # 1. Fail-loud check: Tree-Sitter PHP parser language binding must be loaded
        php_lang = ts_engine.get_language("php")
        if php_lang is None:
            return False, "PHP syntax validator unavailable: tree-sitter-php binding not loaded"

        # 2. Layer 1: Primary Tree-Sitter AST Parsing
        file_node = ts_engine.parse_code(code.encode("utf-8"), language_name="php", file_path=path)
        if file_node.nodes_map:
            for node in file_node.nodes_map.values():
                if node.node_type in ("ERROR", "MISSING"):
                    return False, f"Syntax error in PHP AST at line {node.start.line}, column {node.start.column}"

        # 3. Layer 2: Defense-in-Depth Structural & Token Syntax Validation
        lines = code.splitlines()
        in_single = False
        in_double = False
        escaped = False
        bracket_stack = []
        code_without_strings = []

        clean_code = code
        if "<?php" in clean_code:
            clean_code = clean_code.split("<?php", 1)[1]
        if "?>" in clean_code:
            clean_code = clean_code.split("?>", 1)[0]

        for line_idx, line in enumerate(lines, start=1):
            i = 0
            while i < len(line):
                ch = line[i]

                if escaped:
                    escaped = False
                    i += 1
                    continue

                if ch == "\\" and (in_single or in_double):
                    escaped = True
                    i += 1
                    continue

                if ch == "'" and not in_double:
                    in_single = not in_single
                    code_without_strings.append(ch)
                    i += 1
                    continue

                if ch == '"' and not in_single:
                    in_double = not in_double
                    code_without_strings.append(ch)
                    i += 1
                    continue

                if in_single or in_double:
                    i += 1
                    continue

                code_without_strings.append(ch)

                # Ignore line comments
                if ch == "#" or (ch == "/" and i + 1 < len(line) and line[i + 1] == "/"):
                    break

                if ch in ("(", "[", "{"):
                    bracket_stack.append((ch, line_idx, i + 1))
                elif ch in (")", "]", "}"):
                    if not bracket_stack:
                        return False, f"Unmatched closing bracket {ch} at line {line_idx}, col {i + 1}"
                    last_ch, last_line, last_col = bracket_stack.pop()
                    expected = {"(": ")", "[": "]", "{": "}"}[last_ch]
                    if ch != expected:
                        return (
                            False,
                            f"Mismatched bracket {ch} at line {line_idx}, expected {expected} for {last_ch} from line {last_line}",
                        )

                # Semicolon inside expression / function call arguments
                if ch == ";":
                    if bracket_stack and bracket_stack[-1][0] == "(":
                        return (
                            False,
                            f"Unexpected semicolon inside expression / function arguments at line {line_idx}, col {i + 1}",
                        )

                i += 1

        if in_single or in_double:
            return False, "Unclosed string literal in PHP source"

        if bracket_stack:
            ch, l_idx, c_idx = bracket_stack[-1]
            return False, f"Unclosed bracket {ch} opened at line {l_idx}, col {c_idx}"

        no_strings = "".join(code_without_strings)

        if re.search(r"=[ \t]*[;,\)]", no_strings):
            return False, "Empty assignment operand before delimiter"

        if re.search(r"[\+\-\*/%][ \t]*[;,\)]", no_strings):
            return False, "Dangling binary operator before delimiter"

        if re.search(r",[ \t]*,", no_strings):
            return False, "Empty argument (double comma)"

        bare_assign = re.search(r"(?<![\$\w])([a-zA-Z_][a-zA-Z0-9_]*)\s*=(?!=)", no_strings)
        if bare_assign and bare_assign.group(1) not in ("const",):
            return False, f"Invalid PHP assignment without $ prefix: '{bare_assign.group(0).strip()}'"

        if re.search(r"\$\w+\s*=\s*[\w\d\"']+\s+\$\w+\s*=", no_strings):
            return False, "Syntax error in PHP AST: Missing semicolon between statements"

        return True, None
