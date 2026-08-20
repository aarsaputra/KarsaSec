"""SymbolResolver: Project-wide tiered symbol and constant resolver (E12-14).

Design Principles & Guardrails:
  - Extends ConstantResolver to resolve defines and consts across file boundaries.
  - Tiered Multi-Definition Resolution:
        0 definitions              -> UNKNOWN
        1 definition               -> RESOLVED
        N identical definitions    -> RESOLVED
        N conflicting definitions  -> UNKNOWN (conservative fallback)
  - Evaluation Order Sensitivity:
        DEFINED_BEFORE_USE         -> Valid resolution
        DEFINED_AFTER_USE          -> UNKNOWN at program points preceding definition
        CONDITIONAL_DEFINITION     -> UNKNOWN at program points
  - Cycle Safety: Detects reference loops (A -> B -> A) -> UNKNOWN.
  - Anti-hardcoding: Pure static symbol table resolver. Zero benchmark or rule strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from karsasec.graph.constant_resolver import (
    ConstantEvidence,
    ConstantResolution,
    ConstantResolver,
)
from karsasec.graph.resource_graph import EvaluationOrder, ResourceGraph

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True)
class SymbolLocation:
    """Location metadata for a constant declaration."""

    file_path: str
    line_number: int = 0
    is_conditional: bool = False


@dataclass(frozen=True)
class SymbolEntry:
    """Project-wide symbol table entry."""

    name: str
    value_expr: str
    decl_kind: str  # "define" | "const"
    location: SymbolLocation


class SymbolResolver:
    """Project-wide cross-file symbol and constant resolver."""

    def __init__(self, resource_graph: ResourceGraph | None = None) -> None:
        self.resource_graph = resource_graph or ResourceGraph()
        self._local_resolver = ConstantResolver()

    def build_symbol_table(self, file_contents: Mapping[str, str]) -> dict[str, list[SymbolEntry]]:
        """Scan multiple file contents and construct a project-wide symbol index."""
        symbol_table: dict[str, list[SymbolEntry]] = {}

        for file_path, source_text in file_contents.items():
            if not source_text:
                continue

            lines = source_text.splitlines()
            in_conditional = False
            brace_depth = 0

            for idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                starts_cond = "if (" in clean_line or "if(" in clean_line or "if " in clean_line
                if starts_cond:
                    in_conditional = True

                was_conditional = in_conditional or starts_cond

                if "{" in clean_line:
                    brace_depth += clean_line.count("{")
                if "}" in clean_line:
                    brace_depth -= clean_line.count("}")
                    if brace_depth <= 0:
                        in_conditional = False
                        brace_depth = 0

                decls = self._local_resolver.discover_declarations(line)
                for name, decl_list in decls.items():
                    for decl in decl_list:
                        loc = SymbolLocation(
                            file_path=file_path,
                            line_number=idx,
                            is_conditional=was_conditional,
                        )
                        entry = SymbolEntry(
                            name=name,
                            value_expr=decl.value_expr,
                            decl_kind=decl.decl_kind,
                            location=loc,
                        )
                        symbol_table.setdefault(name, []).append(entry)

        return symbol_table

    def resolve_constant(
        self,
        identifier: str,
        file_contents: Mapping[str, str],
        requesting_file: str = "",
        requesting_line: int = 0,
        _visited: frozenset[str] | None = None,
        _symbol_table: dict[str, list[SymbolEntry]] | None = None,
    ) -> ConstantEvidence:
        """Resolve a constant identifier across the project with evaluation order and tiering checks."""
        visited = _visited or frozenset()
        if identifier in visited:
            return ConstantEvidence(
                identifier,
                ConstantResolution.UNKNOWN,
                provenance=f"Cycle detected in cross-file resolution: {identifier}",
            )
        visited = visited | {identifier}

        symbol_table = _symbol_table if _symbol_table is not None else self.build_symbol_table(file_contents)

        if identifier not in symbol_table:
            return ConstantEvidence(
                identifier,
                ConstantResolution.UNKNOWN,
                provenance=f"No global declaration found for '{identifier}'",
            )

        entries = symbol_table[identifier]

        # Filter entries by evaluation order if requesting location is known
        valid_entries: list[SymbolEntry] = []
        for entry in entries:
            eval_order = self._check_evaluation_order(entry, requesting_file, requesting_line)
            if eval_order == EvaluationOrder.DEFINED_AFTER_USE:
                continue
            if eval_order == EvaluationOrder.CONDITIONAL_DEFINITION:
                # Conditional definition cannot be guaranteed static
                continue
            valid_entries.append(entry)

        if not valid_entries:
            return ConstantEvidence(
                identifier,
                ConstantResolution.UNKNOWN,
                provenance=f"No definition available before program point for '{identifier}'",
            )

        # Tiered Multi-Definition Resolution
        # Case A: Single valid entry
        if len(valid_entries) == 1:
            target_entry = valid_entries[0]
            return self._resolve_entry(target_entry, identifier, file_contents, visited, symbol_table)

        # Case B: Multiple valid entries — check for identical vs. conflicting definitions
        resolved_values: list[ConstantEvidence] = [
            self._resolve_entry(e, identifier, file_contents, visited, symbol_table) for e in valid_entries
        ]

        # Check if all resolutions produce the exact same resolved_value and resolution
        first_res = resolved_values[0]
        all_identical = all(
            r.resolution == first_res.resolution and r.resolved_value == first_res.resolved_value
            for r in resolved_values
        )

        if all_identical and first_res.resolution != ConstantResolution.UNKNOWN:
            return ConstantEvidence(
                identifier,
                first_res.resolution,
                resolved_value=first_res.resolved_value,
                provenance=f"Identical multi-definition across files ({len(valid_entries)} entries)",
            )

        # Case C: Conflicting multi-definition -> Conservative UNKNOWN
        return ConstantEvidence(
            identifier,
            ConstantResolution.UNKNOWN,
            provenance=f"Conflicting multi-definition for '{identifier}' across project files",
        )

    def resolve_expression(
        self,
        expression: str,
        file_contents: Mapping[str, str],
        requesting_file: str = "",
        requesting_line: int = 0,
    ) -> ConstantEvidence:
        """Resolve a full PHP expression (e.g. require_once argument) across project files."""
        expr_clean = expression.strip()
        symbol_table = self.build_symbol_table(file_contents)

        # Split PHP string concat on '.'
        parts = self._local_resolver._split_php_concat(expr_clean)
        resolved_parts: list[str] = []
        all_static = True

        for part in parts:
            p = part.strip()
            # If plain string literal or scalar
            if re.match(r"""^(['"])(?:(?!\1).)*\1$""", p) or re.match(
                r"""^(?:true|false|null|-?\d+(?:\.\d+)?)$""", p, re.IGNORECASE
            ):
                ev = self._local_resolver._classify_part(p, "", frozenset(), {}, 0)
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p):
                # Try cross-file constant lookup
                ev = self.resolve_constant(
                    p,
                    file_contents,
                    requesting_file=requesting_file,
                    requesting_line=requesting_line,
                    _symbol_table=symbol_table,
                )
            else:
                ev = ConstantEvidence(p, ConstantResolution.UNKNOWN, provenance=f"Dynamic/unsupported part: {p[:30]}")

            if ev.resolution not in (
                ConstantResolution.STATIC_LITERAL,
                ConstantResolution.STATIC_CONSTANT,
                ConstantResolution.DERIVED_STATIC,
            ):
                all_static = False

            resolved_parts.append(ev.resolved_value)

        if all_static:
            return ConstantEvidence(
                expr_clean,
                ConstantResolution.DERIVED_STATIC,
                resolved_value="".join(resolved_parts),
                provenance=f"Cross-file static concat resolved: {expr_clean[:60]}",
            )

        return ConstantEvidence(
            expr_clean,
            ConstantResolution.UNKNOWN,
            provenance=f"Non-static expression part in cross-file resolution: {expr_clean[:60]}",
        )

    def _resolve_entry(
        self,
        entry: SymbolEntry,
        identifier: str,
        file_contents: Mapping[str, str],
        visited: frozenset[str],
        symbol_table: dict[str, list[SymbolEntry]],
    ) -> ConstantEvidence:
        if entry.location.is_conditional:
            return ConstantEvidence(
                identifier,
                ConstantResolution.UNKNOWN,
                provenance=f"Conditional definition for '{identifier}'",
            )

        source_text = file_contents.get(entry.location.file_path, "")

        # Try local resolution first
        local_ev = self._local_resolver.resolve(identifier, source_text)
        if local_ev.resolution != ConstantResolution.UNKNOWN:
            return local_ev

        # If RHS references another constant not in local file, try cross-file lookup
        rhs_expr = entry.value_expr.strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", rhs_expr):
            return self.resolve_constant(
                rhs_expr,
                file_contents,
                requesting_file=entry.location.file_path,
                requesting_line=entry.location.line_number,
                _visited=visited,
                _symbol_table=symbol_table,
            )

        # Concatenation expression
        if "." in rhs_expr:
            parts = self._local_resolver._split_php_concat(rhs_expr)
            resolved_parts: list[str] = []
            all_static = True
            for part in parts:
                p = part.strip()
                if re.match(r"""^(['"])(?:(?!\1).)*\1$""", p):
                    resolved_parts.append(p[1:-1])
                elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p):
                    nested = self.resolve_constant(
                        p,
                        file_contents,
                        requesting_file=entry.location.file_path,
                        requesting_line=entry.location.line_number,
                        _visited=visited,
                        _symbol_table=symbol_table,
                    )
                    if nested.resolution in (
                        ConstantResolution.STATIC_CONSTANT,
                        ConstantResolution.STATIC_LITERAL,
                        ConstantResolution.DERIVED_STATIC,
                    ):
                        resolved_parts.append(nested.resolved_value)
                    else:
                        all_static = False
                else:
                    all_static = False

            if all_static:
                return ConstantEvidence(
                    identifier,
                    ConstantResolution.DERIVED_STATIC,
                    resolved_value="".join(resolved_parts),
                    provenance=f"Cross-file nested concat: {rhs_expr[:60]}",
                )

        return ConstantEvidence(
            identifier,
            ConstantResolution.UNKNOWN,
            provenance=f"Cannot resolve entry: {entry.value_expr[:60]}",
        )

    def _check_evaluation_order(
        self,
        entry: SymbolEntry,
        requesting_file: str,
        requesting_line: int,
    ) -> EvaluationOrder:
        if entry.location.is_conditional:
            return EvaluationOrder.CONDITIONAL_DEFINITION

        if requesting_file and entry.location.file_path == requesting_file:
            if requesting_line > 0 and entry.location.line_number > requesting_line:
                return EvaluationOrder.DEFINED_AFTER_USE
            return EvaluationOrder.DEFINED_BEFORE_USE

        return EvaluationOrder.DEFINED_BEFORE_USE
