"""Framework Manifest Loader and Capability Resolver for plugin.yaml specs."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karsasec.framework.extractors.base import ExtractorCapability

logger = logging.getLogger("karsasec.framework.manifest")


@dataclass(frozen=True)
class FrameworkManifest:
    """Dataclass representing a framework plugin.yaml manifest definition (V2 Schema)."""

    framework: str
    language: str = "Generic"
    version: str = ">=1.0"
    supported_versions: tuple[str, ...] = ("*",)
    capabilities: tuple[ExtractorCapability, ...] = ()
    supported_capabilities: tuple[str, ...] = ()
    extractors: tuple[str, ...] = ()
    priority: int = 100
    entrypoints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.capabilities and not self.supported_capabilities:
            object.__setattr__(self, "supported_capabilities", tuple(c.value for c in self.capabilities))
        elif self.supported_capabilities and not self.capabilities:
            caps = []
            for c in self.supported_capabilities:
                try:
                    caps.append(ExtractorCapability(c))
                except ValueError:
                    pass
            object.__setattr__(self, "capabilities", tuple(caps))

    def to_dict(self) -> dict[str, Any]:
        supp_caps = (
            list(self.supported_capabilities) if self.supported_capabilities else [c.value for c in self.capabilities]
        )
        return {
            "framework": self.framework,
            "language": self.language,
            "version": self.version,
            "supported_versions": list(self.supported_versions),
            "capabilities": [c.value for c in self.capabilities],
            "supported_capabilities": supp_caps,
            "extractors": list(self.extractors),
            "priority": self.priority,
            "entrypoints": list(self.entrypoints),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkManifest:
        caps_raw = data.get("capabilities", data.get("supported_capabilities", []))
        caps: list[ExtractorCapability] = []
        for c in caps_raw:
            c_str = c.value if hasattr(c, "value") else str(c)
            try:
                caps.append(ExtractorCapability(c_str))
            except ValueError:
                pass

        supp_raw = data.get("supported_capabilities", [c.value for c in caps])
        supp_caps = tuple(str(c.value if hasattr(c, "value") else c) for c in supp_raw)

        ver = str(data.get("version", data.get("version_spec", ">=1.0")))

        return cls(
            framework=data.get("framework", "GENERIC"),
            language=data.get("language", "Generic"),
            version=ver,
            supported_versions=tuple(data.get("supported_versions", [ver])),
            capabilities=tuple(caps),
            supported_capabilities=supp_caps,
            extractors=tuple(data.get("extractors", [])),
            priority=int(data.get("priority", 100)),
            entrypoints=tuple(data.get("entrypoints", [])),
        )


class ManifestLoader:
    """Loader for plugin.yaml manifest files."""

    @staticmethod
    def load_from_dict(data: dict[str, Any]) -> FrameworkManifest:
        """Parses manifest from dictionary structure."""
        fw_data = data.get("framework") if isinstance(data.get("framework"), dict) else data
        return FrameworkManifest.from_dict(fw_data)

    @staticmethod
    def load_from_yaml(yaml_content: str) -> FrameworkManifest:
        """Parses manifest from YAML string content."""
        import yaml

        raw = yaml.safe_load(yaml_content) or {}
        return ManifestLoader.load_from_dict(raw)

    @staticmethod
    def load_from_file(file_path: str | Path) -> FrameworkManifest:
        """Loads manifest from a file path."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Manifest file not found: {file_path}")
        content = p.read_text(encoding="utf-8")
        return ManifestLoader.load_from_yaml(content)


class CapabilityResolver:
    """Automatic resolver calculating capabilities based on AST/CPG markers and project content."""

    @staticmethod
    def resolve_capabilities(ast_nodes: list[Any], cpg: Any | None = None) -> tuple[ExtractorCapability, ...]:
        """Dynamically calculates detected ExtractorCapability items based on AST and CPG analysis."""
        detected: set[ExtractorCapability] = set()

        # AST inspection
        for node in ast_nodes:
            code_str = str(node).lower()
            if "route" in code_str or "get(" in code_str or "post(" in code_str:
                detected.add(ExtractorCapability.ROUTING)
            if "middleware" in code_str or "use(" in code_str:
                detected.add(ExtractorCapability.MIDDLEWARE)
            if "controller" in code_str or "view" in code_str:
                detected.add(ExtractorCapability.CONTROLLER)
            if "orm" in code_str or "model" in code_str or "column(" in code_str:
                detected.add(ExtractorCapability.ORM)
            if "auth" in code_str or "jwt" in code_str or "login" in code_str:
                detected.add(ExtractorCapability.AUTH)
            if "config" in code_str or "setting" in code_str or "env" in code_str:
                detected.add(ExtractorCapability.CONFIG)
            if "render" in code_str or "template" in code_str or "html" in code_str:
                detected.add(ExtractorCapability.TEMPLATE)
            if "depends(" in code_str or "inject" in code_str:
                detected.add(ExtractorCapability.DEPENDENCY_INJECTION)

        return tuple(sorted(list(detected), key=lambda c: c.value))
