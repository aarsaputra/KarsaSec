"""Framework Semantic Pipeline orchestrating manifest loading, extractor execution, ISR merging, and validation."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from karsasec.framework.diagnostics import SemanticDiagnostic
from karsasec.framework.extractors.base import ExtractionResult, ExtractorContext, SemanticExtractor
from karsasec.framework.extractors.registry import ExtractorRegistry, extractor_registry
from karsasec.framework.intermediate import IntermediateSemanticRepresentation
from karsasec.framework.manifest import FrameworkManifest, ManifestLoader
from karsasec.framework.validator import ISRValidator

logger = logging.getLogger("karsasec.framework.pipeline")


class FrameworkSemanticPipeline:
    """Orchestrates semantic extraction pipeline: load manifest -> resolve extractors -> run -> merge ISR -> validate ISR."""

    def __init__(
        self,
        registry: ExtractorRegistry | None = None,
        validator: ISRValidator | None = None,
    ) -> None:
        self.registry: ExtractorRegistry = registry or extractor_registry
        self.validator: ISRValidator = validator or ISRValidator()

    def run(
        self,
        context: ExtractorContext,
        manifest: FrameworkManifest | dict | str | None = None,
        extractors: Sequence[SemanticExtractor] | None = None,
    ) -> tuple[IntermediateSemanticRepresentation, list[SemanticDiagnostic]]:
        """Executes the extraction pipeline and returns merged ISR along with validation diagnostics."""
        logger.info("Starting FrameworkSemanticPipeline for framework=%s, lang=%s", context.framework, context.language)

        # 1. Load manifest if provided
        loaded_manifest: FrameworkManifest | None = None
        if isinstance(manifest, FrameworkManifest):
            loaded_manifest = manifest
        elif isinstance(manifest, dict):
            loaded_manifest = ManifestLoader.load_from_dict(manifest)
        elif isinstance(manifest, str):
            loaded_manifest = ManifestLoader.load_from_yaml(manifest)

        # 2. Resolve extractors to execute
        target_extractors: list[SemanticExtractor] = []
        if extractors:
            target_extractors = list(extractors)
        else:
            resolved = self.registry.resolve_by_framework(context.framework)
            target_extractors = list(resolved)

        if loaded_manifest and loaded_manifest.extractors:
            for ext_name in loaded_manifest.extractors:
                ext = self.registry.resolve(ext_name)
                if ext and ext not in target_extractors:
                    target_extractors.append(ext)

        # Sort extractors by priority
        target_extractors.sort(key=lambda e: e.priority)

        # 3. Run extractors and merge ISR
        accumulated_result = ExtractionResult()

        for ext in target_extractors:
            if ext.can_extract(context):
                logger.debug("Executing semantic extractor: %s (priority=%d)", ext.name, ext.priority)
                try:
                    res = ext.extract(context)
                    accumulated_result = accumulated_result.merge(res)
                except Exception as exc:
                    logger.error("Extractor '%s' failed: %s", ext.name, exc, exc_info=True)
                    accumulated_result.warnings.append(f"Extractor {ext.name} failed: {exc}")

        # 4. Validate merged ISR
        diagnostics = self.validator.validate(accumulated_result.isr)
        diagnostics.extend(accumulated_result.diagnostics)

        logger.info(
            "Pipeline completed: %d routes, %d handlers, %d diagnostics",
            len(accumulated_result.isr.routes),
            len(accumulated_result.isr.handlers),
            len(diagnostics),
        )

        return accumulated_result.isr, diagnostics
