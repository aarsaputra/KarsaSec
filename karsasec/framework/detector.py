"""FrameworkDetector performing multi-source manifest and AST scanning with confidence scoring."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karsasec.framework.cache import framework_cache
from karsasec.framework.capabilities import get_framework_capabilities
from karsasec.framework.models import DetectorResult, FrameworkType, FrameworkVersion
from karsasec.framework.registry import framework_registry
from karsasec.framework.resolver import FrameworkResolver
from karsasec.plugins.frameworks import BUILTIN_PLUGINS

logger = logging.getLogger("karsasec.framework.detector")


@dataclass(frozen=True)
class FrameworkDetectionResult:
    """Detailed result of deterministic framework detection."""

    framework: str
    version: str = "1.0.0"
    language: str = "Generic"
    confidence: float = 1.0
    capabilities: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    reason: str = "Extracted via AST and dependency scan"

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "version": self.version,
            "language": self.language,
            "confidence": self.confidence,
            "capabilities": list(self.capabilities),
            "evidence": list(self.evidence),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkDetectionResult:
        return cls(
            framework=data.get("framework", "GENERIC"),
            version=data.get("version", "1.0.0"),
            language=data.get("language", "Generic"),
            confidence=float(data.get("confidence", 1.0)),
            capabilities=tuple(data.get("capabilities", [])),
            evidence=tuple(data.get("evidence", [])),
            reason=data.get("reason", ""),
        )


class FrameworkDetector:
    """Multi-source framework detector calculating weighted confidence scores across project manifests and ASTs."""

    def __init__(self) -> None:
        self.resolver = FrameworkResolver()

    def detect_framework(self, project_path: Path, file_nodes: Sequence[Any] | None = None) -> FrameworkDetectionResult:
        """Runs deterministic framework detection returning a single primary FrameworkDetectionResult."""
        results = self.detect(project_path, file_nodes)
        best = max(results, key=lambda r: r.confidence) if results else None

        if not best:
            return FrameworkDetectionResult(
                framework="GENERIC",
                version="1.0.0",
                language="Generic",
                confidence=0.5,
                capabilities=(),
                evidence=(),
                reason="Generic fallback (no markers matched)",
            )

        f_type_str = best.framework.name.upper() if hasattr(best.framework, "name") else str(best.framework).upper()

        # Language deduction
        lang = "Generic"
        if f_type_str in ("FLASK", "FASTAPI", "DJANGO"):
            lang = "Python"
        elif f_type_str in ("EXPRESS", "NEXTJS"):
            lang = "JavaScript"
        elif f_type_str == "LARAVEL":
            lang = "PHP"
        elif f_type_str == "GIN":
            lang = "Go"

        caps = tuple(c.value if hasattr(c, "value") else str(c) for c in get_framework_capabilities(f_type_str))
        v_str = str(best.version) if best.version else "1.0.0"

        return FrameworkDetectionResult(
            framework=f_type_str,
            version=v_str,
            language=lang,
            confidence=best.confidence,
            capabilities=caps,
            evidence=best.evidence,
            reason=best.reason,
        )

    def detect(self, project_path: Path, file_nodes: Sequence[Any] | None = None) -> list[DetectorResult]:
        """Runs framework detection over project manifests and AST file nodes."""
        file_nodes = file_nodes or []
        project_path = project_path.resolve()

        # Gather manifest files
        manifest_files: list[Path] = []
        if project_path.is_dir():
            for m_name in [
                "requirements.txt",
                "pyproject.toml",
                "package.json",
                "composer.json",
                "go.mod",
                "Cargo.toml",
                "Pipfile",
            ]:
                m_file = project_path / m_name
                if m_file.exists():
                    manifest_files.append(m_file)
        elif project_path.is_file():
            manifest_files.append(project_path)

        # Check cache
        fingerprint = framework_cache.compute_fingerprint(manifest_files)
        cached = framework_cache.get(fingerprint)
        if cached is not None and not file_nodes:
            logger.debug(f"Cache hit for framework detection fingerprint: {fingerprint}")
            return cached

        results: list[DetectorResult] = []
        # Extract AST aliases
        if file_nodes:
            self.resolver.extract_aliases_from_ast(file_nodes)

        # Scan each registered plugin
        for plugin in BUILTIN_PLUGINS:
            f_type = plugin.framework_type
            definition = framework_registry.lookup(f_type)
            if not definition:
                continue

            confidence = 0.0
            reasons: list[str] = []
            evidences: list[str] = []
            version_str = "1.0.0"

            # 1. Manifest scan (Weight: 0.6)
            for m_file in manifest_files:
                if m_file.name in plugin.get_manifest_names():
                    try:
                        content = m_file.read_text(encoding="utf-8", errors="ignore").lower()
                        for marker in plugin.get_package_markers():
                            if marker.lower() in content:
                                confidence = max(confidence, 0.6)
                                reasons.append(f"Found '{marker}' in {m_file.name}")
                                evidences.append(f"{m_file.name}: {marker}")
                    except OSError:
                        pass

            # 2. AST Import scan (Weight: 0.9)
            if file_nodes:
                for fn in file_nodes:
                    if not hasattr(fn, "nodes_map"):
                        continue
                    file_path_str = str(getattr(fn, "file_path", ""))
                    for node in fn.nodes_map.values():
                        node_type = getattr(node, "node_type", "").lower()
                        text = getattr(node, "text", "") or getattr(node, "name", "")
                        for imp_marker in plugin.get_import_markers():
                            if self.resolver.is_alias_of(text, imp_marker) or imp_marker.lower() in text.lower():
                                confidence = max(confidence, 0.9)
                                reasons.append(f"Import marker '{imp_marker}' in AST node {node_type}")
                                evidences.append(f"{file_path_str}:{getattr(node.start, 'line', 1)}: {text[:40]}")

                                # 3. Instantiation check (Boost to 1.0)
                                if any(inst in text for inst in ["()", "new ", "createApp", "Default()", "router()"]):
                                    confidence = 1.0
                                    reasons.append(f"Instantiation call detected for {definition.name}")

            if confidence > 0.0:
                det_res = DetectorResult(
                    framework=f_type,
                    confidence=confidence,
                    reason=" + ".join(dict.fromkeys(reasons)),
                    evidence=tuple(evidences[:5]),
                    version=FrameworkVersion.parse(version_str),
                )
                results.append(det_res)

        # Fallback GENERIC framework if nothing detected
        if not results:
            results.append(
                DetectorResult(
                    framework=FrameworkType.GENERIC,
                    confidence=0.5,
                    reason="Generic fallback (no framework markers matched)",
                    evidence=(),
                    version=FrameworkVersion(1, 0, 0, "1.0.0"),
                )
            )

        framework_cache.put(fingerprint, results)
        return results
