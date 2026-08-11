"""ConstantResolver: Lightweight static constant resolution for PHP define() and const.

Bridge layer between AST-level rule matching and full data-flow analysis (E11).
Does NOT build a CFG. Does NOT perform interprocedural analysis.

Architecture (E10-3K):
    AST / Source
         |
         +-- ConstantResolver --> ConstantEvidence
         |
         +-- TaintVerifier    --> TaintAnalysisResult

Design invariants:
  - Deterministic: same source text -> same result
  - Cycle-safe: A -> B -> A -> UNKNOWN
  - Scope-conservative: multiple declarations for same name -> UNKNOWN
  - constant identity != constant safety (only resolved value provenance matters)
  - No filesystem access, no subprocess, no runtime imports
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ConstantResolution(StrEnum):
    """Value provenance classification for a constant identifier.

    Maps to ValueEvidenceKind for Rule Contract integration:
        STATIC_LITERAL  -> STATIC_CONSTANT (safe per contract)
        STATIC_CONSTANT -> STATIC_CONSTANT (safe per contract)
        DERIVED_STATIC  -> STATIC_CONSTANT (safe — all parts verified static)
        DYNAMIC         -> UNKNOWN         (suppress per E10-3J policy)
        TAINTED         -> USER_INPUT      (finding)
        UNKNOWN         -> UNKNOWN         (suppress per E10-3J policy)
    """
    UNKNOWN = "UNKNOWN"
    STATIC_LITERAL = "STATIC_LITERAL"
    STATIC_CONSTANT = "STATIC_CONSTANT"
    DERIVED_STATIC = "DERIVED_STATIC"
    DYNAMIC = "DYNAMIC"
    TAINTED = "TAINTED"


# Set of safe resolutions — all parts must be in this set for an expression to be safe
_STATIC_RESOLUTIONS: frozenset[ConstantResolution] = frozenset({
    ConstantResolution.STATIC_LITERAL,
    ConstantResolution.STATIC_CONSTANT,
    ConstantResolution.DERIVED_STATIC,
})

# PHP superglobals — constant defined from these is TAINTED
_PHP_TAINT_SOURCES: frozenset[str] = frozenset({
    "$_GET", "$_POST", "$_REQUEST", "$_SERVER",
    "$_COOKIE", "$_FILES", "$_ENV", "$HTTP_RAW_POST_DATA",
})

# define('NAME', value) — group 1=name, group 2=raw value expr
_RE_DEFINE = re.compile(
    r"""\bdefine\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*([^)]+?)\s*\)""",
    re.DOTALL,
)

# const NAME = value;
_RE_CONST = re.compile(
    r"""\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+?)\s*;""",
    re.DOTALL,
)

# Plain string literal: 'x' or "x" (no nesting)
_RE_STRING_LITERAL = re.compile(r"""^(['"])(?:(?!\1).)*\1$""")

# Numeric / bool / null scalar
_RE_SCALAR = re.compile(r"""^(?:true|false|null|-?\d+(?:\.\d+)?)$""", re.IGNORECASE)

# getenv() / env() call
_RE_ENV = re.compile(r"""\b(?:getenv|env)\s*\(""", re.IGNORECASE)

# PHP constant identifier in an expression: UPPER_CASE (no $ prefix, no trailing `(`)
_RE_CONST_IDENT = re.compile(r"""(?<!\$)\b([A-Z][A-Z0-9_]{1,})\b(?!\s*\()""")

# Maximum recursion depth for nested constant resolution
_MAX_RESOLVE_DEPTH: int = 8


@dataclass(frozen=True)
class ConstantDeclaration:
    """A single constant declaration found in source text."""
    name: str
    value_expr: str
    decl_kind: str  # "define" | "const"


@dataclass(frozen=True)
class ConstantEvidence:
    """Result of resolving a constant or expression."""
    name: str
    resolution: ConstantResolution
    resolved_value: str = ""
    provenance: str = ""


class ConstantResolver:
    """Resolves PHP constant identifiers to their value provenance.

    Entry points:
        resolve(identifier, source_text)      -- single constant lookup
        resolve_expression(expr, source_text)  -- full expression (e.g. require_once argument)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_declarations(self, source_text: str) -> dict[str, list[ConstantDeclaration]]:
        """Extract all define() and const declarations from source text."""
        decls: dict[str, list[ConstantDeclaration]] = {}
        for m in _RE_DEFINE.finditer(source_text):
            d = ConstantDeclaration(m.group(1), m.group(2).strip(), "define")
            decls.setdefault(d.name, []).append(d)
        for m in _RE_CONST.finditer(source_text):
            d = ConstantDeclaration(m.group(1), m.group(2).strip(), "const")
            decls.setdefault(d.name, []).append(d)
        return decls

    def resolve(
        self,
        identifier: str,
        source_text: str,
        _visited: frozenset[str] | None = None,
        _decls: dict[str, list[ConstantDeclaration]] | None = None,
        _depth: int = 0,
    ) -> ConstantEvidence:
        """Resolve a constant identifier to its value provenance."""
        if _depth > _MAX_RESOLVE_DEPTH:
            return ConstantEvidence(identifier, ConstantResolution.UNKNOWN,
                                    provenance="Max resolution depth exceeded")

        visited = _visited or frozenset()
        if identifier in visited:
            return ConstantEvidence(identifier, ConstantResolution.UNKNOWN,
                                    provenance=f"Cycle detected: {identifier}")
        visited = visited | {identifier}

        decls = _decls if _decls is not None else self.discover_declarations(source_text)

        if identifier not in decls:
            return ConstantEvidence(identifier, ConstantResolution.UNKNOWN,
                                    provenance=f"No declaration found for '{identifier}'")

        decl_list = decls[identifier]
        # Multiple declarations -> ambiguous scope -> conservative UNKNOWN
        if len(decl_list) > 1:
            return ConstantEvidence(identifier, ConstantResolution.UNKNOWN,
                                    provenance=f"Multiple declarations for '{identifier}' (ambiguous scope)")

        return self._classify_value(identifier, decl_list[0].value_expr, source_text, visited, decls, _depth)

    def resolve_expression(self, expression: str, source_text: str) -> ConstantEvidence:
        """Resolve an arbitrary PHP expression as used in a sink (e.g. the argument to require_once).

        Handles: string literals, constant identifiers, concatenation (`.`), PHP variables.
        """
        decls = self.discover_declarations(source_text)
        return self._classify_part(expression.strip(), source_text, frozenset(), decls, 0)

    # ------------------------------------------------------------------
    # Internal classification
    # ------------------------------------------------------------------

    def _classify_value(
        self,
        name: str,
        value_expr: str,
        source_text: str,
        visited: frozenset[str],
        decls: dict[str, list[ConstantDeclaration]],
        depth: int,
    ) -> ConstantEvidence:
        expr = value_expr.strip()

        # 1. String literal
        if _RE_STRING_LITERAL.match(expr):
            return ConstantEvidence(name, ConstantResolution.STATIC_CONSTANT,
                                    resolved_value=expr[1:-1],
                                    provenance=f"String literal: {expr}")

        # 2. Scalar literal
        if _RE_SCALAR.match(expr):
            return ConstantEvidence(name, ConstantResolution.STATIC_CONSTANT,
                                    resolved_value=expr,
                                    provenance=f"Scalar literal: {expr}")

        # 3. Tainted superglobal
        for src in _PHP_TAINT_SOURCES:
            if src in expr:
                return ConstantEvidence(name, ConstantResolution.TAINTED,
                                        provenance=f"Tainted source: {src}")

        # 4. Environment reference
        if _RE_ENV.search(expr):
            return ConstantEvidence(name, ConstantResolution.UNKNOWN,
                                    provenance=f"Environment reference: {expr[:60]}")

        # 5. PHP variable -> DYNAMIC
        if re.search(r'\$[A-Za-z_]', expr):
            return ConstantEvidence(name, ConstantResolution.DYNAMIC,
                                    provenance=f"Variable reference in value: {expr[:60]}")

        # 6. Concatenation
        if "." in expr:
            return self._resolve_concat(name, expr, source_text, visited, decls, depth)

        # 7. Another constant identifier (nested lookup)
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', expr) and not _RE_SCALAR.match(expr):
            nested = self.resolve(expr, source_text, visited, decls, depth + 1)
            if nested.resolution == ConstantResolution.STATIC_CONSTANT:
                return ConstantEvidence(name, ConstantResolution.STATIC_CONSTANT,
                                        resolved_value=nested.resolved_value,
                                        provenance=f"Nested constant '{expr}': {nested.provenance}")
            return ConstantEvidence(name, nested.resolution,
                                    resolved_value=nested.resolved_value,
                                    provenance=f"Inherits from '{expr}': {nested.provenance}")

        return ConstantEvidence(name, ConstantResolution.UNKNOWN,
                                provenance=f"Cannot classify: {expr[:60]}")

    def _resolve_concat(
        self,
        name: str,
        expr: str,
        source_text: str,
        visited: frozenset[str],
        decls: dict[str, list[ConstantDeclaration]],
        depth: int,
    ) -> ConstantEvidence:
        """Resolve a concatenation expression by classifying each PHP `.`-joined part.

        Uses a quote-aware tokenizer to avoid splitting on dots inside string literals.
        """
        parts = self._split_php_concat(expr)
        resolved: list[str] = []
        all_static = True
        for part in parts:
            ev = self._classify_part(part, source_text, visited, decls, depth)
            if ev.resolution == ConstantResolution.TAINTED:
                return ConstantEvidence(name, ConstantResolution.TAINTED,
                                        provenance=f"Concat part tainted: {part}")
            if ev.resolution not in _STATIC_RESOLUTIONS:
                all_static = False
            resolved.append(ev.resolved_value)

        if all_static:
            return ConstantEvidence(name, ConstantResolution.DERIVED_STATIC,
                                    resolved_value="".join(resolved),
                                    provenance=f"All concat parts static: {expr[:80]}")
        return ConstantEvidence(name, ConstantResolution.UNKNOWN,
                                provenance=f"Concat has non-static part: {expr[:80]}")

    @staticmethod
    def _split_php_concat(expr: str) -> list[str]:
        """Split a PHP concatenation expression on '.' operators, respecting quoted strings.

        Example:
            "BASE_PATH . 'foo.php'" -> ["BASE_PATH", "'foo.php'"]
            "BASE . 'dir/file.php'" -> ["BASE", "'dir/file.php'"]
        """
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
                # PHP concat operator — split here
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

    def _classify_part(
        self,
        part: str,
        source_text: str,
        visited: frozenset[str],
        decls: dict[str, list[ConstantDeclaration]],
        depth: int,
    ) -> ConstantEvidence:
        """Classify a single part (literal, constant, variable, or sub-concat)."""
        p = part.strip()

        # Sub-concatenation
        if "." in p and not _RE_STRING_LITERAL.match(p):
            return self._resolve_concat(p, p, source_text, visited, decls, depth)

        if _RE_STRING_LITERAL.match(p):
            return ConstantEvidence(p, ConstantResolution.STATIC_LITERAL,
                                    resolved_value=p[1:-1], provenance="String literal")

        if _RE_SCALAR.match(p):
            return ConstantEvidence(p, ConstantResolution.STATIC_LITERAL,
                                    resolved_value=p, provenance="Scalar literal")

        for src in _PHP_TAINT_SOURCES:
            if src in p:
                return ConstantEvidence(p, ConstantResolution.TAINTED, provenance=f"Tainted: {src}")

        if _RE_ENV.search(p):
            return ConstantEvidence(p, ConstantResolution.UNKNOWN, provenance="Env reference")

        if re.search(r'\$[A-Za-z_]', p):
            # Check for interpolated string like "foo/{$id}/bar" — contains variable inside
            return ConstantEvidence(p, ConstantResolution.DYNAMIC,
                                    provenance=f"Variable reference: {p[:40]}")

        # Constant identifier
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', p) and not _RE_SCALAR.match(p):
            return self.resolve(p, source_text, visited, decls, depth + 1)

        return ConstantEvidence(p, ConstantResolution.UNKNOWN, provenance=f"Unknown: {p[:40]}")
