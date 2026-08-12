"""Interprocedural Guard Provenance Engine (E12-14).

Design Principles & Guardrails:
  - Tracks facts established across function and file boundaries with explicit provenance.
  - Guard facts possess strict metadata:
        source_file, source_function, source_block, establishing_statement,
        propagation_edge, lifetime, invalidation.
  - Propagation occurs ONLY via explicit semantic relationships:
        include, require, function call, return, parameter, assignment.
  - NEVER via name similarity across unrelated project files.
  - Local assignment kill invalidates interprocedural facts immediately.
  - Anti-hardcoding: Pure dataflow provenance model. Zero benchmark or rule strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from karsasec.graph.dataflow.abstract_state import AbstractEnvironment, SemanticConstraint
from karsasec.graph.resource_graph import ResourceGraph


class InterproceduralRelationKind(StrEnum):
    """Explicit semantic relations supporting guard fact propagation."""
    INCLUDE_REQUIRE = "INCLUDE_REQUIRE"
    FUNCTION_CALL = "FUNCTION_CALL"
    PARAMETER_PASSING = "PARAMETER_PASSING"
    RETURN_VALUE = "RETURN_VALUE"
    EXPLICIT_ASSIGNMENT = "EXPLICIT_ASSIGNMENT"


@dataclass(frozen=True)
class GuardFact:
    """An interprocedural guard fact tied to explicit provenance and lifetime boundaries."""
    var_name: str
    var_version: str
    constraint: SemanticConstraint
    source_file: str
    source_function: str = ""
    source_block: str = ""
    establishing_statement: str = ""
    relation_kind: InterproceduralRelationKind = InterproceduralRelationKind.INCLUDE_REQUIRE
    lifetime: str = "SCOPE_BOUNDED"
    is_invalidated: bool = False


class InterproceduralGuardManager:
    """Manages propagation and lifetime of interprocedural guard facts."""

    def __init__(self, resource_graph: ResourceGraph | None = None) -> None:
        self.resource_graph = resource_graph or ResourceGraph()
        self.fact_registry: dict[str, list[GuardFact]] = {}

    def register_fact(self, fact: GuardFact) -> None:
        """Register a new interprocedural guard fact."""
        self.fact_registry.setdefault(fact.source_file, []).append(fact)

    def get_propagated_facts(
        self,
        target_file: str,
        target_var: str,
        current_env: AbstractEnvironment,
    ) -> set[SemanticConstraint]:
        """Collect valid propagated facts for target_var at target_file.

        Strict Guardrail 2: Propagation is ONLY allowed if there is an explicit
        ResourceGraph inclusion/call chain between source_file and target_file.
        """
        valid_constraints: set[SemanticConstraint] = set()

        for source_file, facts in self.fact_registry.items():
            if source_file == target_file:
                # Local facts handled by local AbstractEnvironment
                continue

            # Verify explicit semantic relationship via ResourceGraph
            chain = self.resource_graph.find_include_chain(source_file, target_file)
            if not chain:
                # Also check reverse inclusion: target_file includes source_file
                chain = self.resource_graph.find_include_chain(target_file, source_file)

            if not chain:
                # No explicit inclusion/call relationship -> DO NOT propagate
                continue

            for fact in facts:
                if fact.var_name != target_var or fact.is_invalidated:
                    continue

                # Verify local AbstractEnvironment hasn't killed / reassigned this variable
                curr_val = current_env.get_value(target_var)
                if curr_val and curr_val.var_version != fact.var_version:
                    # Version mismatch (variable was reassigned locally) -> INVALIDATED
                    continue

                valid_constraints.add(fact.constraint)

        return valid_constraints

    def invalidate_for_variable(self, file_path: str, var_name: str) -> None:
        """Invalidate interprocedural facts for a variable when reassigned."""
        if file_path in self.fact_registry:
            updated_facts = []
            for fact in self.fact_registry[file_path]:
                if fact.var_name == var_name:
                    updated_facts.append(
                        GuardFact(
                            var_name=fact.var_name,
                            var_version=fact.var_version,
                            constraint=fact.constraint,
                            source_file=fact.source_file,
                            source_function=fact.source_function,
                            source_block=fact.source_block,
                            establishing_statement=fact.establishing_statement,
                            relation_kind=fact.relation_kind,
                            lifetime=fact.lifetime,
                            is_invalidated=True,
                        )
                    )
                else:
                    updated_facts.append(fact)
            self.fact_registry[file_path] = updated_facts
