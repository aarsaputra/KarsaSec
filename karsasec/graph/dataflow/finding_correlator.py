"""Semantic Finding Correlator for Sprint E12-18.

Implements SemanticFindingCorrelator for multi-path finding correlation and deduplication,
ensuring equivalent semantic flows to the same sink are correlated while preserving distinct evidence
for different sources, call contexts, SSA versions, or branch polarities.

Invariants:
  - G4: SSA versions ($x#1 vs $x#2) remain distinct.
  - G5: Call contexts remain distinct.
  - G6: Path sensitivity & branch polarities remain distinct.
  - G8: Deterministic output ordering stable across PYTHONHASHSEED=1..5.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from karsasec.graph.dataflow.security_verdict import SecurityVerdict


@dataclass(frozen=True)
class CorrelatedFindingGroup:
    """Group of correlated findings sharing exact semantic identity."""

    correlation_id: str
    primary_verdict: SecurityVerdict
    associated_verdicts: tuple[SecurityVerdict, ...] = field(default_factory=tuple)
    evidence_fingerprint: str = ""

    @property
    def verdict_count(self) -> int:
        return 1 + len(self.associated_verdicts)


class SemanticFindingCorrelator:
    """Stateless semantic finding correlator (E12-18)."""

    def compute_correlation_key(self, verdict: SecurityVerdict) -> str:
        """Computes a deterministic correlation identity key for a SecurityVerdict.

        Preserves semantic distinctions: rule_id, file, line, function, var_version, call_context, branch_polarity.
        """
        norm_file = str(verdict.file_path).replace("\\", "/").strip().lower()
        while norm_file.startswith("./"):
            norm_file = norm_file[2:]

        sources_key = ",".join(sorted(verdict.source_ids))
        key_raw = (
            f"{verdict.rule_id}|{norm_file}|{verdict.function_name}|{verdict.line_number}|"
            f"{verdict.sink_category}|{verdict.variable_version}|{verdict.call_context or ''}|"
            f"{verdict.branch_polarity}|{sources_key}|{verdict.status.value}"
        )
        return hashlib.sha256(key_raw.encode("utf-8")).hexdigest()[:32]

    def correlate_verdicts(
        self, verdicts: tuple[SecurityVerdict, ...] | list[SecurityVerdict]
    ) -> tuple[CorrelatedFindingGroup, ...]:
        """Groups semantic verdicts into correlated equivalence classes."""
        if not verdicts:
            return ()

        groups: dict[str, list[SecurityVerdict]] = {}
        for v in verdicts:
            key = self.compute_correlation_key(v)
            if key not in groups:
                groups[key] = []
            groups[key].append(v)

        result_groups: list[CorrelatedFindingGroup] = []
        for key in sorted(groups.keys()):
            v_list = groups[key]
            # Primary verdict is the one with richest provenance or highest confidence
            sorted_v = sorted(
                v_list,
                key=lambda x: (
                    x.confidence.value,
                    len(x.provenance_path),
                    len(x.evidence_references),
                    x.verdict_id,
                ),
                reverse=True,
            )
            primary = sorted_v[0]
            associated = tuple(sorted_v[1:])
            corr_id = f"corr_{key[:16]}"
            result_groups.append(
                CorrelatedFindingGroup(
                    correlation_id=corr_id,
                    primary_verdict=primary,
                    associated_verdicts=associated,
                    evidence_fingerprint=primary.evidence_fingerprint,
                )
            )

        # Deterministic sorting
        result_groups.sort(
            key=lambda g: (
                str(g.primary_verdict.file_path).replace("\\", "/"),
                g.primary_verdict.line_number,
                g.primary_verdict.rule_id,
                g.primary_verdict.variable_version,
            )
        )
        return tuple(result_groups)
