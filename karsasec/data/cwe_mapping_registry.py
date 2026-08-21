"""CWEMappingRegistry for loading and resolving CWE, OWASP, CAPEC, and impact mappings for KarsaSec rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml


class CWEMappingRegistry:
    """Registry managing rule ID to CWE, OWASP, CAPEC, and impact mappings."""

    _instance: CWEMappingRegistry | None = None

    def __init__(self, mapping_dir: Path | None = None) -> None:
        self.mapping_dir = mapping_dir or (Path(__file__).parent / "cwe_mapping")
        self._mappings: dict[str, dict[str, Any]] = {}
        self.reload()

    @classmethod
    def get_instance(cls) -> CWEMappingRegistry:
        if cls._instance is None:
            cls._instance = CWEMappingRegistry()
        return cls._instance

    def reload(self) -> None:
        """Loads all YAML mapping files in the cwe_mapping directory."""
        self._mappings.clear()
        if not self.mapping_dir.exists():
            return

        for path in sorted(self.mapping_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if not data or "mappings" not in data:
                    continue
                for item in data["mappings"]:
                    rule_id = item.get("rule_id")
                    if rule_id:
                        self._mappings[rule_id] = item
            except Exception:
                pass

    def get_mapping(self, rule_id: str) -> dict[str, Any] | None:
        return self._mappings.get(rule_id)

    def get_capec(self, rule_id: str) -> list[str]:
        mapping = self.get_mapping(rule_id)
        return mapping.get("capec", []) if mapping else []

    def get_impact(self, rule_id: str) -> list[str]:
        mapping = self.get_mapping(rule_id)
        return mapping.get("impact", []) if mapping else []
