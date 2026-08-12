"""Declarative Guard Capability Registry for KarsaSec (E12-13).

Design Principles:
  - Strict separation of PredicateCapabilities (branch condition refinement) from ValueTransformations (assignments/casts).
  - PredicateCapability refines variable state on TRUE_BRANCH or FALSE_BRANCH.
  - ValueTransformation creates a new versioned variable with attached constraints.
  - Declarative lookup without regex or hardcoded function branches in the solver engine.
  - Anti-hardcoding: Pure security capability specifications. Zero rule-ID or benchmark strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.graph.dataflow.abstract_state import SemanticConstraint


@dataclass(frozen=True, slots=True)
class PredicateCapability:
    """Capability specification for a boolean predicate guard (e.g. is_numeric($x))."""
    name: str
    target_arg_idx: int = 0
    true_branch_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    false_branch_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class ValueTransformation:
    """Capability specification for a value transformation/cast (e.g. intval($x), escapeshellarg($x))."""
    name: str
    target_arg_idx: int = 0
    produced_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)


class GuardCapabilityRegistry:
    """Declarative registry for security guard predicates and value transformations."""

    def __init__(self) -> None:
        self._predicates: dict[str, PredicateCapability] = {}
        self._transformations: dict[str, ValueTransformation] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        # Predicate Capabilities
        self.register_predicate(PredicateCapability(
            name="is_numeric",
            target_arg_idx=0,
            true_branch_constraints=frozenset({SemanticConstraint.NUMERIC}),
        ))
        self.register_predicate(PredicateCapability(
            name="ctype_digit",
            target_arg_idx=0,
            true_branch_constraints=frozenset({SemanticConstraint.DIGITS_ONLY, SemanticConstraint.NUMERIC}),
        ))
        self.register_predicate(PredicateCapability(
            name="is_int",
            target_arg_idx=0,
            true_branch_constraints=frozenset({SemanticConstraint.INTEGER, SemanticConstraint.NUMERIC}),
        ))
        self.register_predicate(PredicateCapability(
            name="is_integer",
            target_arg_idx=0,
            true_branch_constraints=frozenset({SemanticConstraint.INTEGER, SemanticConstraint.NUMERIC}),
        ))
        self.register_predicate(PredicateCapability(
            name="is_long",
            target_arg_idx=0,
            true_branch_constraints=frozenset({SemanticConstraint.INTEGER, SemanticConstraint.NUMERIC}),
        ))

        # Value Transformations
        self.register_transformation(ValueTransformation(
            name="intval",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.INTEGER, SemanticConstraint.NUMERIC}),
        ))
        self.register_transformation(ValueTransformation(
            name="(int)",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.INTEGER, SemanticConstraint.NUMERIC}),
        ))
        self.register_transformation(ValueTransformation(
            name="floatval",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.NUMERIC}),
        ))
        self.register_transformation(ValueTransformation(
            name="escapeshellarg",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.SHELL_ESCAPED}),
        ))
        self.register_transformation(ValueTransformation(
            name="escapeshellcmd",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.SHELL_ESCAPED}),
        ))
        self.register_transformation(ValueTransformation(
            name="htmlspecialchars",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
        ))
        self.register_transformation(ValueTransformation(
            name="htmlentities",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.HTML_ESCAPED}),
        ))
        self.register_transformation(ValueTransformation(
            name="basename",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.PATH_NORMALIZED}),
        ))
        self.register_transformation(ValueTransformation(
            name="realpath",
            target_arg_idx=0,
            produced_constraints=frozenset({SemanticConstraint.PATH_NORMALIZED}),
        ))

    def register_predicate(self, cap: PredicateCapability) -> None:
        self._predicates[cap.name.lower()] = cap

    def register_transformation(self, trans: ValueTransformation) -> None:
        self._transformations[trans.name.lower()] = trans

    def lookup_predicate(self, name: str) -> PredicateCapability | None:
        return self._predicates.get(name.lower().strip())

    def lookup_transformation(self, name: str) -> ValueTransformation | None:
        return self._transformations.get(name.lower().strip())

    def match_predicate_ast(self, expr_ast: Any) -> tuple[PredicateCapability | None, str, bool]:
        """Parse condition AST and return (capability, var_name, is_negated)."""
        if not expr_ast:
            return None, "", False

        text = ""
        if isinstance(expr_ast, str):
            text = expr_ast
        elif isinstance(expr_ast, dict):
            text = str(expr_ast.get("text", expr_ast.get("raw", "")))
        else:
            text = str(getattr(expr_ast, "text", ""))

        text_clean = text.strip()
        is_negated = False
        if text_clean.startswith("!"):
            is_negated = True
            text_clean = text_clean[1:].strip()

        # Extract function call e.g. is_numeric($id)
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*(\$[a-zA-Z0-9_]+)\s*\)', text_clean)
        if match:
            fn_name = match.group(1)
            var_name = match.group(2)
            cap = self.lookup_predicate(fn_name)
            if cap:
                return cap, var_name, is_negated

        return None, "", False


# Global Registry Instance
guard_registry = GuardCapabilityRegistry()
