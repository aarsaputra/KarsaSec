"""KarsaSec Plugin SDK and Versioned Analysis API.

Provides stable extension interfaces for third-party parsers, rule packs, custom reporters,
and AI extension modules.
"""

from karsasec.sdk.api import PluginSDK, PluginManifest, AnalysisAPIVersion

__all__ = [
    "PluginSDK",
    "PluginManifest",
    "AnalysisAPIVersion",
]
