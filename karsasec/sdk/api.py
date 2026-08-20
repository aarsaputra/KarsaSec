from dataclasses import dataclass, field
from enum import StrEnum


class AnalysisAPIVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"


@dataclass(frozen=True)
class PluginManifest:
    """Descriptor manifest for KarsaSec extensions."""

    name: str
    version: str
    author: str
    api_version: AnalysisAPIVersion = AnalysisAPIVersion.V2
    capabilities_provided: list[str] = field(default_factory=list)


class PluginSDK:
    """Plugin Registry SDK validating compatibility and registering third-party extensions."""

    def __init__(self) -> None:
        self._plugins: list[PluginManifest] = []

    def register_plugin(self, manifest: PluginManifest) -> bool:
        if manifest.api_version not in (AnalysisAPIVersion.V1, AnalysisAPIVersion.V2, AnalysisAPIVersion.V3):
            raise ValueError(f"Unsupported Analysis API Version: {manifest.api_version}")
        self._plugins.append(manifest)
        return True

    def list_plugins(self) -> list[PluginManifest]:
        return list(self._plugins)


plugin_sdk = PluginSDK()
