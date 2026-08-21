"""Canonical Taxonomy Registry for KarsaSec Security Reasoning Engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml


class TaxonomyRegistry:
    """Registry maintaining canonical vulnerability taxonomies, CWE/OWASP mappings, and preconditions."""

    _instance: TaxonomyRegistry | None = None

    def __init__(self, taxonomy_dir: Path | None = None) -> None:
        self.taxonomy_dir = taxonomy_dir or (Path(__file__).parent / "taxonomy")
        self._categories: dict[str, dict[str, Any]] = {}
        self._subcategories: dict[str, dict[str, Any]] = {}
        self.reload()

    @classmethod
    def get_instance(cls) -> TaxonomyRegistry:
        if cls._instance is None:
            cls._instance = TaxonomyRegistry()
        return cls._instance

    def reload(self) -> None:
        """Loads all taxonomy YAML files in the taxonomy directory."""
        self._categories.clear()
        self._subcategories.clear()

        if not self.taxonomy_dir.exists():
            return

        for path in sorted(self.taxonomy_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if not data or "category" not in data:
                    continue
                cat = data["category"]
                cat_id = cat.get("id")
                if cat_id:
                    self._categories[cat_id] = cat

                for sub in data.get("subcategories", []):
                    sub_id = sub.get("id")
                    if sub_id:
                        sub["parent_category"] = cat_id
                        self._subcategories[sub_id] = sub
            except Exception:
                pass

    def get_category(self, cat_id: str) -> dict[str, Any] | None:
        return self._categories.get(cat_id)

    def get_subcategory(self, sub_id: str) -> dict[str, Any] | None:
        return self._subcategories.get(sub_id)

    def get_preconditions(self, sub_id: str) -> list[str]:
        sub = self.get_subcategory(sub_id)
        if sub:
            return sub.get("preconditions", [])
        return []

    def get_cwe_owasp(self, sub_id: str) -> tuple[str, str]:
        sub = self.get_subcategory(sub_id)
        if sub:
            parent_cat = self.get_category(sub.get("parent_category", ""))
            cwe = sub.get("cwe") or (parent_cat.get("cwe") if parent_cat else "CWE-UNKNOWN")
            owasp = sub.get("owasp") or (parent_cat.get("owasp") if parent_cat else "OWASP-UNKNOWN")
            return cwe, owasp
        return "CWE-UNKNOWN", "OWASP-UNKNOWN"
