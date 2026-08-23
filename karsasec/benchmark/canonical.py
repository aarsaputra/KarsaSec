"""Canonical Data Model for G5.3 External Benchmark Evaluation.

Enforces strict architectural boundary between blind detector inputs and
evaluator ground-truth metadata in accordance with INV-G5.3-02 & INV-G5.3-03.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CanonicalCase:
    """Canonical benchmark case model."""

    case_id: str
    source_code: str
    language: str
    framework: str
    dataset: str
    dataset_version: str
    source_artifact: str
    source_file: str
    source_line_start: int | None
    source_line_end: int | None
    ground_truth_source: str
    ground_truth_status: str
    provenance_sha256: str

    def to_blind_input(self) -> dict[str, str]:
        """Extracts ONLY the fields permitted to cross the detector boundary.

        SECURITY INVARIANT (INV-G5.3-03):
        Detector receives ONLY source_code, language, framework.
        Ground truth, CWE, and case_id are STRICLY HIDDEN.
        """
        return {
            "source_code": self.source_code,
            "language": self.language,
            "framework": self.framework,
        }

    def to_provenance_dict(self) -> dict[str, Any]:
        """Extracts complete provenance metadata."""
        return {
            "dataset": self.dataset,
            "dataset_version": self.dataset_version,
            "source_artifact": self.source_artifact,
            "source_file": self.source_file,
            "source_line_start": self.source_line_start,
            "source_line_end": self.source_line_end,
            "ground_truth_source": self.ground_truth_source,
            "adapter": f"{self.dataset}Adapter",
            "artifact_sha256": self.provenance_sha256,
        }
