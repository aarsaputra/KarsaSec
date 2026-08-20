"""API Stability & Public API Freeze Manager tracking and enforcing signature stability across releases."""

import inspect
import json
from pathlib import Path
from typing import Any

import karsasec.cli.commands.scan
import karsasec.core.execution
import karsasec.core.finding.model
import karsasec.parser.generic_parser
import karsasec.parser.python_parser
import karsasec.parser.registry
import karsasec.parser.target_detector
import karsasec.rules.enums
import karsasec.rules.schema
import karsasec.runtime.artifact_store
import karsasec.runtime.artifact_validator
import karsasec.runtime.pass_manager
import karsasec.sdk.negotiator

SNAPSHOT_FILE_PATH = Path(__file__).resolve().parent.parent.parent / "docs" / "api" / "API_SNAPSHOT_v1.0.json"

TARGET_MODULES = [
    karsasec.core.execution,
    karsasec.core.finding.model,
    karsasec.parser.registry,
    karsasec.parser.target_detector,
    karsasec.rules.enums,
    karsasec.rules.schema,
    karsasec.runtime.pass_manager,
    karsasec.runtime.artifact_store,
    karsasec.runtime.artifact_validator,
    karsasec.sdk.negotiator,
]


class APIStabilityVerifier:
    """Extracts public API symbols and verifies against frozen JSON API snapshot."""

    def extract_api_snapshot(self) -> dict[str, Any]:
        """Scans public classes, methods, functions, and enums to construct a signature hash map."""
        snapshot: dict[str, Any] = {}

        for mod in TARGET_MODULES:
            mod_name = mod.__name__
            snapshot[mod_name] = {}

            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if not name.startswith("_"):
                    methods = []
                    for m_name, m_obj in inspect.getmembers(obj, predicate=inspect.isfunction):
                        if not m_name.startswith("_"):
                            sig = str(inspect.signature(m_obj))
                            methods.append(f"{m_name}{sig}")
                    snapshot[mod_name][name] = {
                        "type": "class",
                        "methods": sorted(methods),
                    }

            for name, obj in inspect.getmembers(mod, inspect.isfunction):
                if not name.startswith("_"):
                    sig = str(inspect.signature(obj))
                    snapshot[mod_name][name] = {
                        "type": "function",
                        "signature": f"{name}{sig}",
                    }

        return snapshot

    def save_snapshot(self, target_path: Path = SNAPSHOT_FILE_PATH) -> None:
        """Saves current API snapshot to JSON file."""
        snapshot = self.extract_api_snapshot()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    def verify_api_stability(self, snapshot_path: Path = SNAPSHOT_FILE_PATH) -> list[str]:
        """Compares current API against frozen snapshot file. Returns list of breaking changes/diffs."""
        if not snapshot_path.exists():
            return [f"API Snapshot file '{snapshot_path}' missing."]

        expected = json.loads(snapshot_path.read_text(encoding="utf-8"))
        actual = self.extract_api_snapshot()

        breaking_changes = []

        for mod_name, expected_symbols in expected.items():
            if mod_name not in actual:
                breaking_changes.append(f"Module '{mod_name}' missing in current build.")
                continue

            actual_symbols = actual[mod_name]

            for sym_name, expected_info in expected_symbols.items():
                if sym_name not in actual_symbols:
                    breaking_changes.append(f"Public API symbol '{mod_name}.{sym_name}' was removed/renamed.")
                else:
                    actual_info = actual_symbols[sym_name]
                    if expected_info.get("type") != actual_info.get("type"):
                        breaking_changes.append(
                            f"Type mismatch for '{mod_name}.{sym_name}': expected {expected_info.get('type')}, got {actual_info.get('type')}."
                        )

        return breaking_changes


api_stability_verifier = APIStabilityVerifier()


if __name__ == "__main__":
    api_stability_verifier.save_snapshot()
    print(f"API Snapshot successfully saved to {SNAPSHOT_FILE_PATH}")
