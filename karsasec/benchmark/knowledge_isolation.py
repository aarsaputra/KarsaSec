"""Knowledge Pack Isolation Module (INV-G5.4-02 & INV-G5.4-03).

Ensures conceptual and cryptographic separation between baseline detector engine
and newly introduced knowledge expansion packs.
"""

from dataclasses import dataclass
from typing import Any

from karsasec.benchmark.baseline_freeze import verify_baseline_integrity


@dataclass
class BaselineArtifact:
    name: str
    path: str
    sha256: str


@dataclass
class KnowledgePack:
    pack_id: str
    version: str
    rules_dir: str


@dataclass
class IsolationReport:
    status: str
    classification: str
    baseline_modified: bool
    historical_modified: bool
    details: dict[str, Any]


def detect_baseline_modifications(baseline_manifest: dict[str, Any]) -> dict[str, Any]:
    """Detects any modifications to the cryptographically frozen baseline."""
    return verify_baseline_integrity(baseline_manifest)


def detect_historical_artifact_modifications(historical_files: dict[str, str]) -> dict[str, Any]:
    """Detects modifications to historical G5 benchmark manifests, fixtures, or evaluation results."""
    res = verify_baseline_integrity({"paths": [], "file_hashes": historical_files})
    return res


def classify_change(change_dict: dict[str, Any]) -> str:
    """Classifies repository changes into architectural categories.

    Classifications:
    - KNOWLEDGE_ONLY: Only files in benchmarks/k1/ or new rule packs modified.
    - ENGINE_CHANGE_REQUIRED: Files in karsasec/analysis/ or core solver modified.
    - BENCHMARK_MUTATION: Historical benchmark files or manifests modified.
    - EVALUATOR_MUTATION: Evaluator logic modified.
    - UNKNOWN_CHANGE: Unrecognized modification pattern.
    """
    modified = change_dict.get("modified_files", []) + change_dict.get("added_files", [])

    if not modified:
        return "KNOWLEDGE_ONLY"

    has_engine = any("karsasec/analysis/" in f for f in modified)
    has_benchmark = any("benchmarks/" in f and "k1" not in f for f in modified)
    has_evaluator = any("independent_evaluator.py" in f for f in modified)

    if has_engine:
        return "ENGINE_CHANGE_REQUIRED"
    if has_benchmark:
        return "BENCHMARK_MUTATION"
    if has_evaluator:
        return "EVALUATOR_MUTATION"

    if all("benchmarks/k1/" in f or "karsasec/rules/patterns/k1/" in f for f in modified):
        return "KNOWLEDGE_ONLY"

    return "UNKNOWN_CHANGE"
