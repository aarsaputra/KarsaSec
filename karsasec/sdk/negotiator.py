"""Plugin Capability Negotiator validating extension contracts, API versions, and system prerequisites."""

from dataclasses import dataclass, field

from karsasec.sdk.api import AnalysisAPIVersion, PluginManifest


@dataclass(frozen=True)
class NegotiationResult:
    is_compatible: bool
    rejection_reasons: list[str] = field(default_factory=list)


class CapabilityNegotiator:
    """Validates compatibility between third-party plugin manifests and system engine capabilities."""

    def __init__(self, supported_versions: list[AnalysisAPIVersion] = None) -> None:
        self.supported_versions = supported_versions or [
            AnalysisAPIVersion.V1,
            AnalysisAPIVersion.V2,
            AnalysisAPIVersion.V3,
        ]

    def negotiate(self, manifest: PluginManifest) -> NegotiationResult:
        rejections: list[str] = []

        if manifest.api_version not in self.supported_versions:
            rejections.append(
                f"Incompatible API Version '{manifest.api_version}'. Supported: {self.supported_versions}"
            )

        if not manifest.name or not manifest.version:
            rejections.append("Plugin manifest missing name or version descriptor.")

        return NegotiationResult(is_compatible=len(rejections) == 0, rejection_reasons=rejections)


capability_negotiator = CapabilityNegotiator()
