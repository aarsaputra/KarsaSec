"""Path-Sensitive Abstract State Model for KarsaSec (E12-13).

Design Principles:
  - Independent 3-dimensional state: TaintState + TypeFacts + SanitizationFacts.
  - Taint Immutability: Guards do NOT mutate TAINTED -> SAFE globally.
  - SSA-like Variable Versioning (x#1, x#2) & Assignment Kill.
  - Conservative Lattice Join: Fact Intersection (left & right).
  - Anti-hardcoding: Generic value domain without rule-ID or benchmark strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ConstraintCategory(StrEnum):
    """Broad taxonomy of semantic constraints."""
    TYPE_CONSTRAINT = "TYPE_CONSTRAINT"
    SANITIZATION = "SANITIZATION"
    NORMALIZATION = "NORMALIZATION"


class SemanticConstraint(StrEnum):
    """Specific semantic constraints established by predicates or transformations."""
    # Type constraints
    NUMERIC = "NUMERIC"
    INTEGER = "INTEGER"
    DIGITS_ONLY = "DIGITS_ONLY"

    # Sanitization constraints
    SHELL_ESCAPED = "SHELL_ESCAPED"
    HTML_ESCAPED = "HTML_ESCAPED"
    SQL_ESCAPED = "SQL_ESCAPED"

    # Normalization constraints
    PATH_NORMALIZED = "PATH_NORMALIZED"

    @property
    def category(self) -> ConstraintCategory:
        if self in (SemanticConstraint.NUMERIC, SemanticConstraint.INTEGER, SemanticConstraint.DIGITS_ONLY):
            return ConstraintCategory.TYPE_CONSTRAINT
        if self in (SemanticConstraint.SHELL_ESCAPED, SemanticConstraint.HTML_ESCAPED, SemanticConstraint.SQL_ESCAPED):
            return ConstraintCategory.SANITIZATION
        return ConstraintCategory.NORMALIZATION


class TaintState(StrEnum):
    """Lattice states for dataflow provenance."""
    UNTAINTED = "UNTAINTED"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"
    CONSTRAINED = "CONSTRAINED"
    UNKNOWN = "UNKNOWN"


def join_taint_state(a: TaintState, b: TaintState) -> TaintState:
    """Canonical conservative join of two lattice TaintStates.

    Join Matrix & Partial Order:
      - Identical states join to themselves.
      - Any path with TAINTED or CONSTRAINED mixed with unproven/untainted states joins to TAINTED.
      - UNKNOWN mixed with UNTAINTED/SANITIZED joins conservatively to UNKNOWN.
      - TAINTED mixed with SANITIZED joins to TAINTED (never downgrades taint without matrix proof).
    """
    if a == b:
        return a
    if TaintState.TAINTED in (a, b) or TaintState.CONSTRAINED in (a, b):
        return TaintState.TAINTED
    if TaintState.UNKNOWN in (a, b):
        return TaintState.UNKNOWN
    return TaintState.UNKNOWN


def join_constraints(
    a: set[SemanticConstraint] | frozenset[SemanticConstraint] | tuple[SemanticConstraint, ...],
    b: set[SemanticConstraint] | frozenset[SemanticConstraint] | tuple[SemanticConstraint, ...],
) -> frozenset[SemanticConstraint]:
    """Canonical conservative constraint join (Must-Proven Fact Intersection)."""
    return frozenset(set(a) & set(b))



@dataclass(frozen=True, slots=True)
class AbstractValue:
    """Immutable representation of a variable's abstract state at a specific program point."""
    var_name: str
    var_version: str
    taint: TaintState = TaintState.UNKNOWN
    type_facts: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    sanitization_facts: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    provenance_node_id: str = ""
    provenance_description: str = ""

    @property
    def all_constraints(self) -> frozenset[SemanticConstraint]:
        return self.type_facts | self.sanitization_facts

    def with_constraints(self, new_constraints: set[SemanticConstraint] | frozenset[SemanticConstraint]) -> AbstractValue:
        types = set(self.type_facts)
        sans = set(self.sanitization_facts)
        for c in new_constraints:
            if c.category == ConstraintCategory.TYPE_CONSTRAINT:
                types.add(c)
            else:
                sans.add(c)
        return AbstractValue(
            var_name=self.var_name,
            var_version=self.var_version,
            taint=TaintState.CONSTRAINED if (self.taint == TaintState.TAINTED and new_constraints) else self.taint,
            type_facts=frozenset(types),
            sanitization_facts=frozenset(sans),
            provenance_node_id=self.provenance_node_id,
            provenance_description=self.provenance_description,
        )


@dataclass(slots=True)
class AbstractEnvironment:
    """Symbol environment mapping variables (and versions) to AbstractValues."""
    version_counters: dict[str, int] = field(default_factory=dict)
    values: dict[str, AbstractValue] = field(default_factory=dict)

    def get_version(self, var_name: str) -> str:
        count = self.version_counters.get(var_name, 1)
        return f"{var_name}#{count}"

    def get_value(self, var_name: str) -> AbstractValue:
        version = self.get_version(var_name)
        if version in self.values:
            return self.values[version]
        # Fallback if unassigned
        return AbstractValue(
            var_name=var_name,
            var_version=version,
            taint=TaintState.UNKNOWN,
        )

    def set_value(self, value: AbstractValue) -> None:
        self.values[value.var_version] = value

    def assignment_kill(self, var_name: str, new_taint: TaintState = TaintState.TAINTED, prov_id: str = "", prov_desc: str = "") -> AbstractValue:
        """Kills prior constraints by creating a new version of var_name."""
        curr_counter = self.version_counters.get(var_name, 0) + 1
        self.version_counters[var_name] = curr_counter
        new_version = f"{var_name}#{curr_counter}"

        new_val = AbstractValue(
            var_name=var_name,
            var_version=new_version,
            taint=new_taint,
            type_facts=frozenset(),
            sanitization_facts=frozenset(),
            provenance_node_id=prov_id,
            provenance_description=prov_desc,
        )
        self.values[new_version] = new_val
        return new_val

    def copy(self) -> AbstractEnvironment:
        return AbstractEnvironment(
            version_counters=dict(self.version_counters),
            values=dict(self.values),
        )

    def join(self, other: AbstractEnvironment) -> AbstractEnvironment:
        """Conservative Lattice Join (Intersection of proven facts)."""
        joined_counters: dict[str, int] = {}
        joined_values: dict[str, AbstractValue] = {}

        all_vars = set(self.version_counters.keys()) | set(other.version_counters.keys())

        for var_name in sorted(all_vars):
            v_self = self.get_value(var_name)
            v_other = other.get_value(var_name)

            v_count_self = self.version_counters.get(var_name, 1)
            v_count_other = other.version_counters.get(var_name, 1)
            max_count = max(v_count_self, v_count_other)
            joined_counters[var_name] = max_count

            # Join TaintState & Fact Intersection
            joined_taint = join_taint_state(v_self.taint, v_other.taint)
            joined_types = join_constraints(v_self.type_facts, v_other.type_facts)
            joined_sans = join_constraints(v_self.sanitization_facts, v_other.sanitization_facts)

            joined_version = f"{var_name}#{max_count}"
            joined_val = AbstractValue(
                var_name=var_name,
                var_version=joined_version,
                taint=joined_taint,
                type_facts=joined_types,
                sanitization_facts=joined_sans,
                provenance_node_id=v_self.provenance_node_id or v_other.provenance_node_id,
                provenance_description=f"Join({v_self.var_version}, {v_other.var_version})",
            )
            joined_values[joined_version] = joined_val

        return AbstractEnvironment(
            version_counters=joined_counters,
            values=joined_values,
        )
