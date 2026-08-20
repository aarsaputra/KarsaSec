"""Pre-Dataflow Constant Propagation Engine (E12-12).

Structural constant evaluation over AST/source expressions and symbol scope tables.
Establishes value provenance and constant folding prior to dataflow and taint verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class LatticeKind(StrEnum):
    """Three-state Value Lattice for constant evaluation.

    Safety Invariant: UNKNOWN != SAFE.
    Only positively proven static values resolve to CONSTANT.
    """

    CONSTANT = "CONSTANT"
    DYNAMIC = "DYNAMIC"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class LatticeValue:
    """Lattice state object representing expression value provenance."""

    kind: LatticeKind
    literal_value: str = ""
    provenance_node_id: str = ""
    provenance_description: str = ""

    def is_constant(self) -> bool:
        return self.kind == LatticeKind.CONSTANT

    def is_dynamic(self) -> bool:
        return self.kind == LatticeKind.DYNAMIC

    def is_unknown(self) -> bool:
        return self.kind == LatticeKind.UNKNOWN


# Language-level dynamic sources (PHP superglobals and input streams)
_DYNAMIC_SOURCES: frozenset[str] = frozenset(
    {
        "$_GET",
        "$_POST",
        "$_REQUEST",
        "$_COOKIE",
        "$_FILES",
        "$_SERVER",
        "$_ENV",
        "$HTTP_RAW_POST_DATA",
        "php://input",
        "php://stdin",
    }
)

# Magic constants
_MAGIC_CONSTANTS: frozenset[str] = frozenset(
    {
        "__DIR__",
        "__FILE__",
        "__LINE__",
        "__FUNCTION__",
        "__CLASS__",
        "__METHOD__",
        "__NAMESPACE__",
    }
)

# Regex patterns for literals
_RE_STRING_LITERAL = re.compile(r"""^(['"])(?:(?!\1).)*\1$""")
_RE_SCALAR_LITERAL = re.compile(r"""^(?:true|false|null|-?\d+(?:\.\d+)?)$""", re.IGNORECASE)


class ConstantEvaluator:
    """Intraprocedural Constant Evaluator performing pre-dataflow constant propagation."""

    def __init__(self, max_depth: int = 10) -> None:
        self.max_depth = max_depth

    def build_scope_environment(
        self,
        source_text: str,
        file_path: Path | None = None,
        language: str = "php",
    ) -> dict[str, LatticeValue]:
        """Build scope symbol table mapping variables to LatticeValues from source text."""
        env: dict[str, LatticeValue] = {}

        # 1. Discover magic constants
        for magic in _MAGIC_CONSTANTS:
            env[magic] = LatticeValue(
                kind=LatticeKind.CONSTANT,
                literal_value=f"<{magic}>",
                provenance_description=f"Magic constant {magic}",
            )

        # 2. Extract assignment statements (e.g. $var = expr;)
        if language == "php":
            # Match variable assignments: $var = expr;
            assign_pattern = re.compile(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);", re.DOTALL)

            # Track assignment counts to handle loop reassignments and branch divergence
            assign_counts: dict[str, int] = {}
            raw_assigns: dict[str, list[str]] = {}

            for match in assign_pattern.finditer(source_text):
                var_name = match.group(1).strip()
                expr = match.group(2).strip()

                assign_counts[var_name] = assign_counts.get(var_name, 0) + 1
                raw_assigns.setdefault(var_name, []).append(expr)

            # Evaluate each variable
            for var_name, expr_list in raw_assigns.items():
                # If variable assigned multiple times, check if values diverge or loop reassignment
                if len(expr_list) > 1:
                    # Check if all expressions evaluate to the same constant
                    first_val = self.evaluate_expression(expr_list[0], source_text, env, language=language)
                    all_same = True
                    for expr in expr_list[1:]:
                        next_val = self.evaluate_expression(expr, source_text, env, language=language)
                        if first_val.kind != next_val.kind or first_val.literal_value != next_val.literal_value:
                            all_same = False
                            break

                    if all_same and first_val.is_constant():
                        env[var_name] = first_val
                    else:
                        # Divergent branch or loop reassignment -> UNKNOWN
                        env[var_name] = LatticeValue(
                            kind=LatticeKind.UNKNOWN,
                            provenance_description=f"Divergent assignment or loop reassignment for {var_name}",
                        )
                else:
                    val = self.evaluate_expression(expr_list[0], source_text, env, language=language)
                    env[var_name] = val

        return env

    def evaluate_expression(
        self,
        expression: str,
        source_text: str = "",
        env: dict[str, LatticeValue] | None = None,
        language: str = "php",
        depth: int = 0,
    ) -> LatticeValue:
        """Evaluate an expression recursively against the current symbol environment."""
        if depth > self.max_depth:
            return LatticeValue(
                kind=LatticeKind.UNKNOWN,
                provenance_description="Max evaluation depth exceeded",
            )

        expr = expression.strip()
        if not expr:
            return LatticeValue(
                kind=LatticeKind.UNKNOWN,
                provenance_description="Empty expression",
            )

        local_env = env if env is not None else {}

        # 1. Check direct dynamic sources
        for src in _DYNAMIC_SOURCES:
            if src in expr:
                return LatticeValue(
                    kind=LatticeKind.DYNAMIC,
                    provenance_description=f"Direct dynamic source {src}",
                )

        # 2. Check Magic Constants
        if expr in _MAGIC_CONSTANTS:
            return LatticeValue(
                kind=LatticeKind.CONSTANT,
                literal_value=f"<{expr}>",
                provenance_description=f"Magic constant {expr}",
            )

        # 3. String literal
        if _RE_STRING_LITERAL.match(expr):
            # Double-quoted strings in PHP may contain interpolated variables ($var or {$var})
            if expr.startswith('"') and language == "php":
                if re.search(r"\{?\$[a-zA-Z_][a-zA-Z0-9_]*\}?", expr):
                    return LatticeValue(
                        kind=LatticeKind.DYNAMIC,
                        provenance_description=f"Interpolated double-quoted string '{expr[:40]}'",
                    )
            literal_val = expr[1:-1]
            return LatticeValue(
                kind=LatticeKind.CONSTANT,
                literal_value=literal_val,
                provenance_description=f"String literal '{literal_val}'",
            )

        # 4. Scalar literal (numbers, booleans, null)
        if _RE_SCALAR_LITERAL.match(expr):
            return LatticeValue(
                kind=LatticeKind.CONSTANT,
                literal_value=expr,
                provenance_description=f"Scalar literal '{expr}'",
            )

        # 5. String Concatenation (`.` in PHP)
        if "." in expr and language == "php":
            return self._eval_php_concat(expr, source_text, local_env, depth)

        # 6. Single Variable lookup in env ($var)
        if language == "php" and re.match(r"^\$[a-zA-Z_][a-zA-Z0-9_]*$", expr):
            if expr in local_env:
                return local_env[expr]
            # Check if variable is a dynamic superglobal or unknown
            if any(src in expr for src in _DYNAMIC_SOURCES):
                return LatticeValue(
                    kind=LatticeKind.DYNAMIC,
                    provenance_description=f"Dynamic superglobal {expr}",
                )
            return LatticeValue(
                kind=LatticeKind.UNKNOWN,
                provenance_description=f"Unresolved variable {expr}",
            )

        # 7. Function call (e.g. strlen("static") or some_func())
        fn_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*)\)$", expr, re.DOTALL)
        if fn_match:
            fn_name = fn_match.group(1).lower()
            raw_args = fn_match.group(2).strip()

            # Constant functions with constant arguments
            if fn_name in ("strlen", "strtolower", "strtoupper", "trim") and raw_args:
                arg_val = self.evaluate_expression(raw_args, source_text, local_env, language, depth + 1)
                if arg_val.is_constant():
                    return LatticeValue(
                        kind=LatticeKind.CONSTANT,
                        literal_value=f"{fn_name}({arg_val.literal_value})",
                        provenance_description=f"Constant function {fn_name} on constant argument",
                    )

            # Unknown function result -> UNKNOWN
            return LatticeValue(
                kind=LatticeKind.UNKNOWN,
                provenance_description=f"Unknown function result for {fn_name}()",
            )

        # Fallback conservative default
        return LatticeValue(
            kind=LatticeKind.UNKNOWN,
            provenance_description=f"Unresolved complex expression: {expr[:40]}",
        )

    def _eval_php_concat(
        self,
        expr: str,
        source_text: str,
        env: dict[str, LatticeValue],
        depth: int,
    ) -> LatticeValue:
        """Evaluate a PHP concatenation expression (`.`), joining constant parts."""
        parts = self._split_php_concat(expr)

        evaluated_parts: list[LatticeValue] = []
        for part in parts:
            part_val = self.evaluate_expression(part, source_text, env, language="php", depth=depth + 1)
            evaluated_parts.append(part_val)

        # If any part is DYNAMIC -> overall expression is DYNAMIC
        if any(p.is_dynamic() for p in evaluated_parts):
            return LatticeValue(
                kind=LatticeKind.DYNAMIC,
                provenance_description=f"Dynamic component in concatenation '{expr[:40]}'",
            )

        # If ALL parts are CONSTANT -> overall expression is CONSTANT
        if all(p.is_constant() for p in evaluated_parts):
            concatenated_str = "".join(p.literal_value for p in evaluated_parts)
            return LatticeValue(
                kind=LatticeKind.CONSTANT,
                literal_value=concatenated_str,
                provenance_description=f"Constant concatenation of {len(parts)} parts",
            )

        # Otherwise (contains UNKNOWN parts) -> overall expression is UNKNOWN
        return LatticeValue(
            kind=LatticeKind.UNKNOWN,
            provenance_description=f"Unresolved component in concatenation '{expr[:40]}'",
        )

    @staticmethod
    def _split_php_concat(expr: str) -> list[str]:
        """Split a PHP concatenation expression on '.' operators while respecting quoted strings."""
        parts: list[str] = []
        current: list[str] = []
        in_single = False
        in_double = False
        i = 0
        while i < len(expr):
            ch = expr[i]
            if ch == "'" and not in_double:
                in_single = not in_single
                current.append(ch)
            elif ch == '"' and not in_single:
                in_double = not in_double
                current.append(ch)
            elif ch == "." and not in_single and not in_double:
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
            else:
                current.append(ch)
            i += 1
        last = "".join(current).strip()
        if last:
            parts.append(last)
        return parts if parts else [expr]


# Global instance
constant_evaluator = ConstantEvaluator()
