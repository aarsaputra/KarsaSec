"""Independent GroundTruthProvider for External Security Benchmarking (Gate 5).

Strict Requirement (Chief Architect Directive):
GroundTruthProvider is a pure data ingestion provider. It reads external ground truth
manifests (vulnerability_id, CWE, expected_status, file_path, line_number, sink_function, metadata).
It DOES NOT invoke KarsaSec engine rules or perform vulnerability detection.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from karsasec.benchmark.models import GroundTruthManifest, GroundTruthStatus


class GroundTruthProvider:
    """Independent ground truth provider decoupled from engine detection logic."""

    def __init__(self, manifests: list[GroundTruthManifest] | None = None) -> None:
        self._manifests: dict[str, GroundTruthManifest] = {}
        if manifests:
            for m in manifests:
                self.register_manifest(m)

    def register_manifest(self, manifest: GroundTruthManifest) -> None:
        """Registers a single ground truth manifest."""
        self._manifests[manifest.test_case_id] = manifest

    def get_manifest(self, test_case_id: str) -> GroundTruthManifest | None:
        """Retrieves ground truth manifest for a test case ID."""
        return self._manifests.get(test_case_id)

    def list_manifests(self) -> list[GroundTruthManifest]:
        """Returns list of all registered ground truth manifests."""
        return list(self._manifests.values())

    def load_from_dict_list(self, data: list[dict[str, Any]], dataset_name: str = "custom") -> int:
        """Loads ground truth manifests from raw dict list."""
        count = 0
        for item in data:
            manifest = GroundTruthManifest(
                test_case_id=item["test_case_id"],
                dataset_name=item.get("dataset_name", dataset_name),
                vulnerability_class=item.get("vulnerability_class", "UNKNOWN"),
                cwe=item.get("cwe", "CWE-000"),
                expected_status=GroundTruthStatus(item["expected_status"]),
                file_path=item.get("file_path", ""),
                line_number=item.get("line_number", 0),
                sink_function=item.get("sink_function", ""),
                metadata=item.get("metadata", {}),
            )
            self.register_manifest(manifest)
            count += 1
        return count

    def load_from_json_file(self, json_path: str | Path) -> int:
        """Loads ground truth manifests from JSON file path."""
        p = Path(json_path)
        if not p.exists():
            raise FileNotFoundError(f"Ground truth manifest file not found: {json_path}")
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return self.load_from_dict_list(data)
        elif isinstance(data, dict) and "manifests" in data:
            return self.load_from_dict_list(data["manifests"])
        else:
            raise ValueError(f"Invalid manifest format in {json_path}")
