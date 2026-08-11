"""Deterministic Tier 1-5 Resolution Engine for Flask Semantic Correlation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from karsasec.framework.framework_semantics.correlation.contracts import ResolutionMethod, ResolutionStatus
from karsasec.framework.framework_semantics.correlation.state import CorrelationState


@dataclass(frozen=True)
class ResolutionResult:
    """Result of attempting to resolve a target relationship across Tiers 1-5."""
    status: ResolutionStatus
    method: ResolutionMethod
    matched_id: str | None = None
    matched_ids: tuple[str, ...] = ()


class RelationshipResolver:
    """5-Tier deterministic resolution engine."""

    @staticmethod
    def resolve_target(
        target_ref: str,
        state: CorrelationState,
        candidate_pool: dict[str, Any],  # maps id -> entity
        name_index: dict[str, list[Any]] | None = None,
        explicit_ref_attr: str | None = None,
    ) -> ResolutionResult:
        """Resolve a target reference against candidate pool using Tier 1-5 hierarchy with early-stop."""
        if not target_ref:
            return ResolutionResult(status=ResolutionStatus.UNRESOLVED, method=ResolutionMethod.UNRESOLVED)

        # Tier 1 — Explicit ISR reference (semantic_id, cpg_ref, or explicit reference metadata string present in ISR)
        # Rule: ast_ref MUST NOT be dereferenced.
        for entity_id, entity in candidate_pool.items():
            cpg_ref = getattr(entity, "cpg_ref", None)
            if cpg_ref and cpg_ref == target_ref:
                return ResolutionResult(
                    status=ResolutionStatus.RESOLVED,
                    method=ResolutionMethod.TIER1_EXPLICIT_REFERENCE,
                    matched_id=entity_id,
                    matched_ids=(entity_id,),
                )

        # Tier 2 — Exact semantic_id match
        if target_ref in candidate_pool:
            return ResolutionResult(
                status=ResolutionStatus.RESOLVED,
                method=ResolutionMethod.TIER2_EXACT_SEMANTIC_ID,
                matched_id=target_ref,
                matched_ids=(target_ref,),
            )

        # Tier 3 — Exact qualified_name match
        qualified_matches: list[str] = []
        for entity_id, entity in candidate_pool.items():
            name = getattr(entity, "name", getattr(entity, "function_name", getattr(entity, "class_name", "")))
            if name and name == target_ref:
                qualified_matches.append(entity_id)

        if len(qualified_matches) == 1:
            return ResolutionResult(
                status=ResolutionStatus.RESOLVED,
                method=ResolutionMethod.TIER3_EXACT_QUALIFIED_NAME,
                matched_id=qualified_matches[0],
                matched_ids=tuple(qualified_matches),
            )
        elif len(qualified_matches) > 1:
            # Early stop on ambiguity!
            return ResolutionResult(
                status=ResolutionStatus.AMBIGUOUS,
                method=ResolutionMethod.TIER3_EXACT_QUALIFIED_NAME,
                matched_ids=tuple(qualified_matches),
            )

        # Tier 4 — Exact module + symbol match
        if name_index and target_ref in name_index:
            indexed_matches = [getattr(e, "semantic_id", str(i)) for i, e in enumerate(name_index[target_ref])]
            if len(indexed_matches) == 1:
                return ResolutionResult(
                    status=ResolutionStatus.RESOLVED,
                    method=ResolutionMethod.TIER4_EXACT_MODULE_SYMBOL,
                    matched_id=indexed_matches[0],
                    matched_ids=tuple(indexed_matches),
                )
            elif len(indexed_matches) > 1:
                # Early stop on ambiguity!
                return ResolutionResult(
                    status=ResolutionStatus.AMBIGUOUS,
                    method=ResolutionMethod.TIER4_EXACT_MODULE_SYMBOL,
                    matched_ids=tuple(indexed_matches),
                )

        # Tier 5 — Explicit relationship metadata emitted by an upstream extractor (e.g. route.handler)
        if explicit_ref_attr:
            meta_matches: list[str] = []
            for entity_id, entity in candidate_pool.items():
                attr_val = getattr(entity, explicit_ref_attr, None)
                if attr_val and (attr_val == target_ref or (isinstance(attr_val, (tuple, list)) and target_ref in attr_val)):
                    meta_matches.append(entity_id)

            if len(meta_matches) == 1:
                return ResolutionResult(
                    status=ResolutionStatus.RESOLVED,
                    method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                    matched_id=meta_matches[0],
                    matched_ids=tuple(meta_matches),
                )
            elif len(meta_matches) > 1:
                # Early stop on ambiguity!
                return ResolutionResult(
                    status=ResolutionStatus.AMBIGUOUS,
                    method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                    matched_ids=tuple(meta_matches),
                )

        # Tier 6 — Unresolved
        return ResolutionResult(status=ResolutionStatus.UNRESOLVED, method=ResolutionMethod.UNRESOLVED)
