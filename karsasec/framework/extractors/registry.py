"""Registry for managing and resolving semantic extractors."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from karsasec.framework.extractors.base import ExtractorCapability, SemanticExtractor

logger = logging.getLogger("karsasec.framework.extractors.registry")


class ExtractorRegistry:
    """Registry maintaining active SemanticExtractor instances."""

    def __init__(self) -> None:
        self._extractors: dict[str, SemanticExtractor] = {}

    def register(self, extractor: SemanticExtractor) -> None:
        """Registers a SemanticExtractor instance."""
        if extractor.name in self._extractors:
            logger.warning("Overwriting registered extractor: %s", extractor.name)
        self._extractors[extractor.name] = extractor

    def unregister(self, extractor_name: str) -> bool:
        """Unregisters an extractor by name."""
        if extractor_name in self._extractors:
            del self._extractors[extractor_name]
            return True
        return False

    def resolve(self, extractor_name: str) -> SemanticExtractor | None:
        """Retrieves extractor by name."""
        return self._extractors.get(extractor_name)

    def resolve_by_framework(self, framework: str) -> Sequence[SemanticExtractor]:
        """Resolves extractors supporting specified framework, ordered deterministically by priority then name."""
        target_fw = framework.upper()
        matched = [
            ext
            for ext in self._extractors.values()
            if "GENERIC" in ext.supported_frameworks or target_fw in [f.upper() for f in ext.supported_frameworks]
        ]
        return sorted(matched, key=lambda e: (e.priority, e.name))

    def resolve_by_capability(self, capability: ExtractorCapability | str) -> Sequence[SemanticExtractor]:
        """Resolves extractors supporting specified capability, ordered deterministically by priority then name."""
        target_cap = ExtractorCapability(capability) if isinstance(capability, str) else capability
        matched = [ext for ext in self._extractors.values() if target_cap in ext.capabilities]
        return sorted(matched, key=lambda e: (e.priority, e.name))

    def list(self) -> Sequence[SemanticExtractor]:
        """Returns all registered extractors sorted deterministically by priority then name."""
        return sorted(self._extractors.values(), key=lambda e: (e.priority, e.name))

    def extract_all(self, ctx: Any) -> tuple[Any, list[dict[str, Any]]]:
        """Executes all matching extractors with strict error isolation (INV-E10-SEM-08)."""
        from karsasec.framework.extractors.base import ExtractionResult
        extractors = self.resolve_by_framework(ctx.framework)
        merged_res = ExtractionResult()
        diagnostics: list[dict[str, Any]] = []

        for ext in extractors:
            if not ext.can_extract(ctx):
                continue
            try:
                res = ext.extract(ctx)
                merged_res = merged_res.merge(res)
            except Exception as exc:
                logger.error("Extractor %s execution failed: %s", ext.name, exc, exc_info=True)
                diagnostics.append({
                    "extractor_name": ext.name,
                    "error_message": str(exc),
                    "error_type": exc.__class__.__name__,
                })

        return merged_res, diagnostics

    def clear(self) -> None:
        """Clears all registered extractors."""
        self._extractors.clear()



# Global default ExtractorRegistry singleton
extractor_registry = ExtractorRegistry()
